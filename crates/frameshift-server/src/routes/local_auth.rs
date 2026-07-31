//! Invite-bound first-party registration, password login, and session logout.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use frameshift_catalog::{
    AccountPasswordCredentialRecord, AccountRecord, AccountSessionClientKind, AccountSessionRecord,
    AccountStatus, CatalogError, LocalAccountRegistrationRequest,
};
use rand_core::{OsRng, RngCore as _};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Semaphore, SemaphorePermit};
use uuid::Uuid;

use crate::error::AppError;
use crate::middleware::account::AuthenticatedAccount;
use crate::password_auth::{PasswordAuthError, PasswordService};
use crate::routes::invite_requests::{normalize_email, normalize_optional_display_name};
use crate::state::AppState;

/// Minimum accepted password length in Unicode scalar values.
const MIN_PASSWORD_CHARS: usize = 12;
/// Maximum accepted password size before Argon2 processing.
const MAX_PASSWORD_BYTES: usize = 1_024;
/// Tight body limit for registration and login credentials.
const MAX_LOCAL_AUTH_BYTES: usize = 8 * 1_024;
/// Application schema version for newly persisted password records.
const PASSWORD_VERSION: i16 = 1;
/// Process-wide cap on concurrent 64 MiB Argon2id operations.
static PASSWORD_WORK_SLOTS: Semaphore = Semaphore::const_new(2);

/// Browser or explicit bearer presentation selected by the client.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAuthClientKind {
    /// Browser receives a secure HTTP-only cookie.
    Browser,
    /// Desktop application receives an explicit bearer token.
    Desktop,
    /// Command-line client receives an explicit bearer token.
    Cli,
}

/// Browser-submitted fields for invite redemption and account creation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterLocalAccountRequest {
    /// Raw one-time invitation token.
    pub invite_token: String,
    /// Email address that must match the invitation.
    pub email: String,
    /// Optional profile display name.
    pub display_name: Option<String>,
    /// New password processed only inside protected memory.
    pub password: String,
    /// Session presentation required by the caller.
    pub client_kind: LocalAuthClientKind,
}

/// Password login fields for one first-party session.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginLocalAccountRequest {
    /// Normalized sign-in email.
    pub email: String,
    /// Account password processed only inside protected memory.
    pub password: String,
    /// Session presentation required by the caller.
    pub client_kind: LocalAuthClientKind,
}

/// Successful local registration or login response.
#[derive(Debug, Serialize)]
pub struct LocalAuthResponse {
    /// Durable authenticated account.
    pub account: AccountRecord,
    /// Raw bearer token returned only to desktop and CLI clients.
    pub token: Option<String>,
    /// Non-extendable session expiry.
    pub expires_at: DateTime<Utc>,
}

/// Successful local logout response.
#[derive(Debug, Serialize)]
pub struct LocalLogoutResponse {
    /// Stable acknowledgement.
    pub logged_out: bool,
}

/// Build public first-party registration and login routes.
pub fn local_auth_public_router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register_local_account))
        .route("/login", post(login_local_account))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_LOCAL_AUTH_BYTES,
        ))
}

/// Build local session routes that require resolved account authentication.
pub fn local_auth_protected_router() -> Router<AppState> {
    Router::new().route("/logout", post(logout_local_account))
}

/// Redeem one invitation into a local account and initial session.
async fn register_local_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterLocalAccountRequest>,
) -> Result<Response, AppError> {
    require_local_auth_enabled(&state)?;
    if matches!(request.client_kind, LocalAuthClientKind::Browser) {
        require_trusted_browser_origin(&state, &headers)?;
    }
    let invite_digest = decode_and_digest_token(&request.invite_token)?;
    let normalized_email = normalize_email(&request.email)?;
    let display_name = normalize_optional_display_name(request.display_name)?;
    let password = protected_password(request.password)?;
    let password_hash = hash_password(&state, password).await?;
    let (session_token, session_digest) = generate_token();
    let now = Utc::now();
    let account_id = Uuid::new_v4();
    let session = build_session(&state, account_id, session_digest, request.client_kind, now)?;
    let account = AccountRecord {
        id: account_id,
        issuer: state.config.first_party_auth.issuer.clone(),
        subject: account_id.to_string(),
        email: Some(normalized_email.clone()),
        display_name,
        status: AccountStatus::Active,
        created_at: now,
        updated_at: now,
    };
    let result = state
        .catalog
        .register_local_account(LocalAccountRegistrationRequest {
            invite_token_digest: invite_digest,
            account: account.clone(),
            credential: AccountPasswordCredentialRecord {
                account_id,
                normalized_email,
                password_hash,
                password_version: PASSWORD_VERSION,
                pepper_version: state.config.first_party_auth.pepper_version,
                email_verified_at: Some(now),
                created_at: now,
                password_changed_at: now,
                updated_at: now,
            },
            session: session.clone(),
        })
        .await
        .map_err(map_registration_error)?;
    local_auth_response(
        &state,
        result.account,
        result.session,
        request.client_kind,
        session_token,
    )
}

/// Verify one password and create a new local session.
async fn login_local_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LoginLocalAccountRequest>,
) -> Result<Response, AppError> {
    require_local_auth_enabled(&state)?;
    if matches!(request.client_kind, LocalAuthClientKind::Browser) {
        require_trusted_browser_origin(&state, &headers)?;
    }
    let normalized_email = normalize_email(&request.email)?;
    let password = protected_password(request.password)?;
    let credential = match state
        .catalog
        .get_account_password_credential(&normalized_email)
        .await
    {
        Ok(credential) => Some(credential),
        Err(CatalogError::NotFound { .. }) => None,
        Err(error) => return Err(AppError::from_catalog(error, "password credential")),
    };
    let password_matches =
        verify_or_absorb_password_work(&state, password, credential.as_ref()).await?;
    let credential = credential
        .filter(|_| password_matches)
        .ok_or_else(|| AppError::Unauthorized("email or password is incorrect".to_string()))?;
    warn_if_credential_uses_rotated_out_pepper(&state, &credential);
    let account = state
        .catalog
        .get_account(credential.account_id)
        .await
        .map_err(|error| AppError::from_catalog(error, "account"))?;
    if account.status != AccountStatus::Active {
        return Err(AppError::Unauthorized(
            "email or password is incorrect".to_string(),
        ));
    }
    let (session_token, session_digest) = generate_token();
    let now = Utc::now();
    let session = build_session(&state, account.id, session_digest, request.client_kind, now)?;
    state
        .catalog
        .create_account_session(session.clone())
        .await
        .map_err(|error| AppError::from_catalog(error, "account session"))?;
    local_auth_response(&state, account, session, request.client_kind, session_token)
}

/// Revoke the current local session and clear its browser cookie when applicable.
async fn logout_local_account(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
) -> Result<Response, AppError> {
    let session_id = auth.local_session_id.ok_or_else(|| {
        AppError::BadRequest("the current authentication is not a local session".to_string())
    })?;
    state
        .catalog
        .revoke_account_session(session_id, auth.account.id, Utc::now())
        .await
        .map_err(|error| AppError::from_catalog(error, "account session"))?;
    let mut response = (
        StatusCode::OK,
        Json(LocalLogoutResponse { logged_out: true }),
    )
        .into_response();
    if auth.via_cookie {
        let cleared = format!(
            "{}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
            state.config.first_party_auth.cookie_name
        );
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cleared)
                .map_err(|_| AppError::Internal("invalid session cookie configuration".into()))?,
        );
    }
    Ok(response)
}

/// Reject routes when the deployment has no valid first-party password configuration.
fn require_local_auth_enabled(state: &AppState) -> Result<(), AppError> {
    if state.config.first_party_auth.enabled() {
        Ok(())
    } else {
        Err(AppError::NotFound(
            "first-party account routes are disabled".to_string(),
        ))
    }
}

/// Require an exact configured browser origin before cookie creation.
fn require_trusted_browser_origin(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::Forbidden("trusted browser origin required".to_string()))?;
    if !state
        .config
        .cors_origins()
        .any(|configured| configured == origin)
    {
        return Err(AppError::Forbidden(
            "trusted browser origin required".to_string(),
        ));
    }
    Ok(())
}

/// Validate password bounds and move the value into protected memory.
fn protected_password(password: String) -> Result<SecretString, AppError> {
    let character_count = password.chars().count();
    if character_count < MIN_PASSWORD_CHARS || password.len() > MAX_PASSWORD_BYTES {
        return Err(AppError::BadRequest(format!(
            "password must contain at least {MIN_PASSWORD_CHARS} characters and at most {MAX_PASSWORD_BYTES} bytes"
        )));
    }
    Ok(SecretString::new(password))
}

/// Hash one password on the blocking pool using the deployment pepper.
///
/// New hashes always use the CURRENT pepper (never a previous one) so every
/// freshly created credential is stamped with `pepper_version ==
/// state.config.first_party_auth.pepper_version` at the call site in
/// [`register_local_account`].
async fn hash_password(state: &AppState, password: SecretString) -> Result<String, AppError> {
    let _permit = password_work_permit()?;
    let service = PasswordService::new(state.config.first_party_auth.password_pepper.clone())
        .map_err(map_password_configuration_error)?;
    tokio::task::spawn_blocking(move || service.hash_password(&password))
        .await
        .map_err(|_| AppError::Internal("password hashing task failed".to_string()))?
        .map_err(map_password_hash_error)
}

/// Select the pepper that was current when `pepper_version` was stamped
/// beside a stored credential.
///
/// Falls back to the CURRENT deployment pepper when `pepper_version` already
/// matches it, or when no matching entry exists in
/// `first_party_auth.previous_peppers` (an operator error or a version older
/// than any retained pepper). The fallback is safe rather than fail-closed:
/// verifying against the wrong pepper is already indistinguishable from an
/// ordinary password mismatch in [`PasswordService::verify_password`], so no
/// credential can be accepted with an incorrect pepper either way -- this
/// choice only affects which normal rejection path is taken.
fn pepper_for_version(state: &AppState, pepper_version: i16) -> SecretString {
    if pepper_version == state.config.first_party_auth.pepper_version {
        return state.config.first_party_auth.password_pepper.clone();
    }
    state
        .config
        .first_party_auth
        .previous_peppers
        .get(&pepper_version)
        .cloned()
        .unwrap_or_else(|| state.config.first_party_auth.password_pepper.clone())
}

/// Verify a credential or perform equivalent Argon2 work for an unknown email.
///
/// Verification uses the pepper that was active when the stored credential's
/// `pepper_version` was stamped (see [`pepper_for_version`]), not
/// unconditionally the current deployment pepper -- rotating
/// `LOCAL_AUTH_PASSWORD_PEPPER` would otherwise permanently lock out every
/// existing account (F-05).
async fn verify_or_absorb_password_work(
    state: &AppState,
    password: SecretString,
    credential: Option<&AccountPasswordCredentialRecord>,
) -> Result<bool, AppError> {
    let _permit = password_work_permit()?;
    let pepper = credential
        .map(|record| pepper_for_version(state, record.pepper_version))
        .unwrap_or_else(|| state.config.first_party_auth.password_pepper.clone());
    let service = PasswordService::new(pepper).map_err(map_password_configuration_error)?;
    let encoded_hash = credential.map(|record| record.password_hash.clone());
    tokio::task::spawn_blocking(move || match encoded_hash {
        Some(encoded_hash) => service
            .verify_password(&password, &encoded_hash)
            .map_err(map_password_hash_error),
        None => service
            .hash_password(&password)
            .map(|_| false)
            .map_err(map_password_hash_error),
    })
    .await
    .map_err(|_| AppError::Internal("password verification task failed".to_string()))?
}

/// Log (without persisting) that a successful login verified against a
/// rotated-out pepper version.
///
/// TODO(F-05 follow-up): once `CatalogBackend` exposes a mutator for
/// [`AccountPasswordCredentialRecord`] (there is currently none -- only
/// [`frameshift_catalog::CatalogBackend::get_account_password_credential`]
/// exists), re-hash this password with the CURRENT pepper here and persist
/// it so the credential migrates off the rotated-out pepper. Deliberately
/// NOT inventing a schema change to do that persistence now; the login above
/// already verified correctly against the credential's own historical
/// pepper, so there is no security gap, only a missed migration opportunity
/// until that catalog mutator exists.
fn warn_if_credential_uses_rotated_out_pepper(
    state: &AppState,
    credential: &AccountPasswordCredentialRecord,
) {
    if credential.pepper_version != state.config.first_party_auth.pepper_version {
        tracing::info!(
            account_id = %credential.account_id,
            credential_pepper_version = credential.pepper_version,
            current_pepper_version = state.config.first_party_auth.pepper_version,
            "first-party login verified against a rotated-out pepper version; \
             rehash-on-login is not yet wired pending a catalog credential mutator"
        );
    }
}

/// Reserve one bounded Argon2 memory-work slot or reject excess parallel work.
fn password_work_permit() -> Result<SemaphorePermit<'static>, AppError> {
    PASSWORD_WORK_SLOTS
        .try_acquire()
        .map_err(|_| AppError::ServiceUnavailable("password service is at capacity".to_string()))
}

/// Map a deployment password configuration failure without exposing its secret.
fn map_password_configuration_error(_error: PasswordAuthError) -> AppError {
    AppError::Internal("first-party password configuration is invalid".to_string())
}

/// Map password primitive failures without exposing password or PHC contents.
fn map_password_hash_error(error: PasswordAuthError) -> AppError {
    AppError::Internal(format!("first-party password operation failed: {error}"))
}

/// Map invite redemption failures to a generic public response.
fn map_registration_error(error: CatalogError) -> AppError {
    match error {
        CatalogError::Unauthorized { .. } | CatalogError::NotFound { .. } => {
            AppError::Unauthorized("invitation is invalid or expired".to_string())
        }
        CatalogError::Conflict { .. } => {
            AppError::Conflict("invitation or account has already been used".to_string())
        }
        other => AppError::from_catalog(other, "local account registration"),
    }
}

/// Generate one random 256-bit token and its SHA-256 digest.
pub(crate) fn generate_token() -> (String, Vec<u8>) {
    let mut raw = [0_u8; 32];
    OsRng.fill_bytes(&mut raw);
    (URL_SAFE_NO_PAD.encode(raw), Sha256::digest(raw).to_vec())
}

/// Decode one canonical 256-bit token and return its SHA-256 digest.
pub(crate) fn decode_and_digest_token(token: &str) -> Result<Vec<u8>, AppError> {
    if token.len() > 128 || token.chars().any(char::is_whitespace) {
        return Err(AppError::Unauthorized(
            "token is invalid or expired".to_string(),
        ));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| AppError::Unauthorized("token is invalid or expired".to_string()))?;
    if raw.len() != 32 || URL_SAFE_NO_PAD.encode(&raw) != token {
        return Err(AppError::Unauthorized(
            "token is invalid or expired".to_string(),
        ));
    }
    Ok(Sha256::digest(raw).to_vec())
}

/// Build one session with transport-specific idle duration and a shared absolute cap.
fn build_session(
    state: &AppState,
    account_id: Uuid,
    token_digest: Vec<u8>,
    client_kind: LocalAuthClientKind,
    now: DateTime<Utc>,
) -> Result<AccountSessionRecord, AppError> {
    let (client_kind, idle_ttl) = match client_kind {
        LocalAuthClientKind::Browser => (
            AccountSessionClientKind::Browser,
            state.config.first_party_auth.browser_idle_ttl,
        ),
        LocalAuthClientKind::Desktop => (
            AccountSessionClientKind::Desktop,
            state.config.first_party_auth.bearer_idle_ttl,
        ),
        LocalAuthClientKind::Cli => (
            AccountSessionClientKind::Cli,
            state.config.first_party_auth.bearer_idle_ttl,
        ),
    };
    let idle_ttl = Duration::from_std(idle_ttl)
        .map_err(|_| AppError::Internal("session idle duration is invalid".to_string()))?;
    let absolute_ttl = Duration::from_std(state.config.first_party_auth.absolute_ttl)
        .map_err(|_| AppError::Internal("session absolute duration is invalid".to_string()))?;
    Ok(AccountSessionRecord {
        id: Uuid::new_v4(),
        account_id,
        token_digest,
        client_kind,
        created_at: now,
        last_seen_at: now,
        idle_expires_at: now + idle_ttl,
        absolute_expires_at: now + absolute_ttl,
        revoked_at: None,
    })
}

/// Build the transport-specific successful authentication response.
fn local_auth_response(
    state: &AppState,
    account: AccountRecord,
    session: AccountSessionRecord,
    client_kind: LocalAuthClientKind,
    raw_token: String,
) -> Result<Response, AppError> {
    let explicit_token =
        (!matches!(client_kind, LocalAuthClientKind::Browser)).then(|| raw_token.clone());
    let mut response = (
        StatusCode::OK,
        Json(LocalAuthResponse {
            account,
            token: explicit_token,
            expires_at: session.absolute_expires_at,
        }),
    )
        .into_response();
    if matches!(client_kind, LocalAuthClientKind::Browser) {
        let max_age = state.config.first_party_auth.absolute_ttl.as_secs();
        let cookie = format!(
            "{}={raw_token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}",
            state.config.first_party_auth.cookie_name
        );
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie)
                .map_err(|_| AppError::Internal("invalid session cookie configuration".into()))?,
        );
    }
    Ok(response)
}

#[cfg(test)]
/// Unit tests for token canonicalization and password input bounds.
mod tests {
    use super::*;

    /// Generated tokens decode to the exact digest returned alongside them.
    #[test]
    fn generated_token_digest_round_trips() {
        let (token, digest) = generate_token();
        assert_eq!(decode_and_digest_token(&token).unwrap(), digest);
    }

    /// Non-canonical and undersized tokens fail before catalog access.
    #[test]
    fn invalid_token_encoding_is_rejected() {
        assert!(decode_and_digest_token("short").is_err());
        assert!(decode_and_digest_token(&format!("{}=", "a".repeat(43))).is_err());
    }

    /// Password bounds reject short and oversized inputs.
    #[test]
    fn password_bounds_are_enforced() {
        assert!(protected_password("short".to_string()).is_err());
        assert!(protected_password("x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
        assert!(protected_password("correct horse battery staple".to_string()).is_ok());
    }
}
