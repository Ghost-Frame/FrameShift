//! Invite-bound first-party registration, password login, and session logout.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use chrono::{DateTime, Duration, Utc};
use frameshift_catalog::{
    AccountAuthAuditEventKind, AccountAuthAuditOutcome, AccountMfaChallengeCreationRequest,
    AccountMfaLoginChallengeRecord, AccountPasswordCredentialRecord, AccountPasswordRehashRequest,
    AccountRecord, AccountSessionClientKind, AccountSessionCreationRequest, AccountSessionRecord,
    AccountSessionRefreshRequest, AccountSessionRefreshResult, AccountStatus, CatalogError,
    EncryptedPasswordRecoveryDelivery, LocalAccountRegistrationRequest,
    PasswordRecoveryCompletionRequest, PasswordRecoveryEnqueueRequest,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, SemaphorePermit};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::first_party_auth::{
    add_std_duration, auth_audit_event, decode_access_token, decode_refresh_token,
    generate_access_token, generate_bound_token, generate_refresh_token, identifier_tag,
    issue_session, AuthAuditContext,
};
use crate::middleware::account::AuthenticatedAccount;
use crate::password_auth::{PasswordAuthError, PasswordService};
use crate::password_blocklist;
use crate::recovery_delivery::RecoveryDeliveryCipher;
use crate::routes::invite_requests::{normalize_email, normalize_optional_display_name};
use crate::state::AppState;

/// Minimum accepted password length in Unicode scalar values.
const MIN_PASSWORD_CHARS: usize = 15;
/// Maximum accepted password size before Argon2 processing.
const MAX_PASSWORD_BYTES: usize = 1_024;
/// Tight body limit for registration and login credentials.
const MAX_LOCAL_AUTH_BYTES: usize = 8 * 1_024;
/// Application schema version for newly persisted password records.
const PASSWORD_VERSION: i16 = 1;
/// Process-wide cap on concurrent 64 MiB Argon2id operations.
static PASSWORD_WORK_SLOTS: Semaphore = Semaphore::const_new(2);
/// Minimum wall-clock duration for every valid recovery-request response.
const MIN_RECOVERY_REQUEST_DURATION: std::time::Duration = std::time::Duration::from_millis(250);
/// Maximum time allowed for delivery of the post-change notification.
const PASSWORD_CHANGED_DELIVERY_TTL: Duration = Duration::hours(24);

/// Backward-compatible name for the catalog-owned session client class.
pub type LocalAuthClientKind = AccountSessionClientKind;

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

/// Browser request for an indistinguishable password-recovery email response.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestPasswordRecoveryRequest {
    /// Account email normalized only inside the server boundary.
    pub email: String,
}

/// Browser submission of one reset bearer and replacement password.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletePasswordRecoveryRequest {
    /// Opaque single-use reset bearer received in an email URL fragment.
    pub token: String,
    /// Replacement password processed under the new-password policy.
    pub password: String,
}

/// Refresh-token input selected by transport class.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshLocalSessionRequest {
    /// Browser, desktop, or CLI presentation required by the caller.
    pub client_kind: LocalAuthClientKind,
    /// Rotating raw refresh token accepted only from desktop and CLI clients.
    pub refresh_token: Option<String>,
}

/// Generic recovery-request acknowledgement shared by known and unknown emails.
#[derive(Debug, Serialize)]
pub struct PasswordRecoveryAcceptedResponse {
    /// Stable indication that the bounded request was accepted for processing.
    pub accepted: bool,
}

/// Successful first-party session issuance or refresh response.
#[derive(Debug, Serialize)]
pub struct LocalAuthResponse {
    /// Durable authenticated account.
    pub account: AccountRecord,
    /// Raw access token returned only to desktop and CLI clients.
    pub access_token: Option<String>,
    /// Raw refresh token returned only to desktop and CLI clients.
    pub refresh_token: Option<String>,
    /// Stable OAuth bearer-token presentation type.
    pub token_type: &'static str,
    /// Short-lived access-token expiry.
    pub expires_at: DateTime<Utc>,
    /// Current refresh-token generation expiry.
    pub refresh_expires_at: DateTime<Utc>,
    /// Non-extendable session-family expiry.
    pub session_expires_at: DateTime<Utc>,
}

/// Password-login response requiring browser-side second-factor completion.
#[derive(Debug, Serialize)]
pub struct MfaChallengeRequiredResponse {
    /// Stable signal that no session was issued yet.
    pub mfa_required: bool,
    /// Opaque one-time challenge bearer.
    pub challenge_token: String,
    /// Exclusive challenge completion deadline.
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
        .route("/refresh", post(refresh_local_session))
        .route(
            "/password-recovery/request",
            post(request_password_recovery),
        )
        .route(
            "/password-recovery/complete",
            post(complete_password_recovery),
        )
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
    if request.client_kind != LocalAuthClientKind::Browser {
        return Err(AppError::BadRequest(
            "password registration is available only in the trusted browser portal".into(),
        ));
    }
    require_trusted_browser_origin(&state, &headers)?;
    let invite_digest = decode_and_digest_token(&request.invite_token)?;
    let normalized_email = normalize_email(&request.email)?;
    let registration_identifier_tag =
        identifier_tag(&state.config.first_party_auth, &normalized_email);
    let display_name = normalize_optional_display_name(request.display_name)?;
    let password = protected_new_password(request.password)?;
    let password_hash = hash_password(&state, password).await?;
    let now = Utc::now();
    let account_id = Uuid::new_v4();
    let issued = issue_session(
        &state.config.first_party_auth,
        account_id,
        request.client_kind,
        now,
        None,
    )?;
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
            session: issued.issuance.clone(),
            audit_event: auth_audit_event(
                AccountAuthAuditEventKind::SessionCreated,
                AccountAuthAuditOutcome::Success,
                AuthAuditContext {
                    account_id: Some(account_id),
                    session_id: Some(issued.issuance.session.id),
                    client_kind: Some(request.client_kind),
                    identifier_tag: Some(registration_identifier_tag),
                    reason_code: None,
                },
                now,
            ),
        })
        .await
        .map_err(map_registration_error)?;
    local_auth_response(
        &state,
        result.account,
        result.session,
        request.client_kind,
        issued.access_token,
        issued.refresh_token,
        issued.issuance.refresh_expires_at,
    )
}

/// Verify one password and create a new local session.
async fn login_local_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LoginLocalAccountRequest>,
) -> Result<Response, AppError> {
    require_local_auth_enabled(&state)?;
    if request.client_kind != LocalAuthClientKind::Browser {
        return Err(AppError::BadRequest(
            "password login is available only in the trusted browser portal".into(),
        ));
    }
    require_trusted_browser_origin(&state, &headers)?;
    let normalized_email = normalize_email(&request.email)?;
    let login_identifier_tag = identifier_tag(&state.config.first_party_auth, &normalized_email);
    let password = protected_login_password(request.password)?;
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
        verify_or_absorb_password_work(&state, password.clone(), credential.as_ref()).await?;
    let Some(credential) = credential.filter(|_| password_matches) else {
        append_rejection_audit(
            &state,
            None,
            None,
            Some(request.client_kind),
            Some(login_identifier_tag),
            "invalid_password",
        )
        .await;
        return Err(AppError::Unauthorized(
            "email or password is incorrect".to_string(),
        ));
    };
    let account = state
        .catalog
        .get_account(credential.account_id)
        .await
        .map_err(|error| AppError::from_catalog(error, "account"))?;
    if account.status != AccountStatus::Active {
        append_rejection_audit(
            &state,
            Some(account.id),
            None,
            Some(request.client_kind),
            Some(login_identifier_tag),
            "inactive_account",
        )
        .await;
        return Err(AppError::Unauthorized(
            "email or password is incorrect".to_string(),
        ));
    }
    rehash_password_if_rotated(&state, &password, &credential).await?;
    let now = Utc::now();
    match state
        .catalog
        .get_active_account_mfa_authenticator(account.id)
        .await
    {
        Ok(_) => {
            let (challenge_token, challenge_digest) =
                generate_bound_token(account.id, request.client_kind);
            let expires_at = add_std_duration(
                now,
                state.config.first_party_auth.mfa_challenge_ttl,
                "MFA challenge TTL",
            )?;
            state
                .catalog
                .create_account_mfa_challenge(AccountMfaChallengeCreationRequest {
                    challenge: AccountMfaLoginChallengeRecord {
                        id: Uuid::new_v4(),
                        account_id: account.id,
                        token_digest: challenge_digest,
                        client_kind: request.client_kind,
                        created_at: now,
                        expires_at,
                        consumed_at: None,
                    },
                    audit_event: auth_audit_event(
                        AccountAuthAuditEventKind::MfaChallengeCreated,
                        AccountAuthAuditOutcome::Success,
                        AuthAuditContext {
                            account_id: Some(account.id),
                            client_kind: Some(request.client_kind),
                            identifier_tag: Some(login_identifier_tag),
                            ..AuthAuditContext::default()
                        },
                        now,
                    ),
                })
                .await
                .map_err(|error| AppError::from_catalog(error, "MFA challenge"))?;
            Ok((
                StatusCode::ACCEPTED,
                Json(MfaChallengeRequiredResponse {
                    mfa_required: true,
                    challenge_token,
                    expires_at,
                }),
            )
                .into_response())
        }
        Err(CatalogError::NotFound { .. }) => {
            let issued = issue_session(
                &state.config.first_party_auth,
                account.id,
                request.client_kind,
                now,
                None,
            )?;
            let session = state
                .catalog
                .create_account_session(AccountSessionCreationRequest {
                    issuance: issued.issuance.clone(),
                    audit_event: auth_audit_event(
                        AccountAuthAuditEventKind::SessionCreated,
                        AccountAuthAuditOutcome::Success,
                        AuthAuditContext {
                            account_id: Some(account.id),
                            session_id: Some(issued.issuance.session.id),
                            client_kind: Some(request.client_kind),
                            identifier_tag: Some(login_identifier_tag),
                            reason_code: None,
                        },
                        now,
                    ),
                })
                .await
                .map_err(|error| AppError::from_catalog(error, "account session"))?;
            local_auth_response(
                &state,
                account,
                session,
                request.client_kind,
                issued.access_token,
                issued.refresh_token,
                issued.issuance.refresh_expires_at,
            )
        }
        Err(error) => Err(AppError::from_catalog(error, "MFA authenticator")),
    }
}

/// Rotate one refresh generation and replace the short-lived access token.
async fn refresh_local_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RefreshLocalSessionRequest>,
) -> Result<Response, AppError> {
    require_local_auth_enabled(&state)?;
    let raw_refresh = match request.client_kind {
        LocalAuthClientKind::Browser => {
            require_trusted_browser_origin(&state, &headers)?;
            if request.refresh_token.is_some() {
                return Err(AppError::BadRequest(
                    "browser refresh tokens are accepted only from the secure cookie".into(),
                ));
            }
            extract_named_cookie(&headers, &state.config.first_party_auth.refresh_cookie_name)
                .ok_or_else(|| {
                    AppError::Unauthorized("refresh token is invalid or expired".into())
                })?
                .to_string()
        }
        LocalAuthClientKind::Desktop | LocalAuthClientKind::Cli => request
            .refresh_token
            .ok_or_else(|| AppError::Unauthorized("refresh token is invalid or expired".into()))?,
    };
    let raw_refresh = Zeroizing::new(raw_refresh);
    let decoded = decode_refresh_token(raw_refresh.as_str())?;
    if decoded.client_kind != request.client_kind {
        append_rejection_audit(
            &state,
            Some(decoded.account_id),
            Some(decoded.session_id),
            Some(request.client_kind),
            None,
            "refresh_client_mismatch",
        )
        .await;
        return Err(AppError::Unauthorized(
            "refresh token is invalid or expired".into(),
        ));
    }
    let now = Utc::now();
    if decoded.absolute_expires_at <= now {
        append_rejection_audit(
            &state,
            Some(decoded.account_id),
            Some(decoded.session_id),
            Some(decoded.client_kind),
            None,
            "refresh_expired",
        )
        .await;
        return Err(AppError::Unauthorized(
            "refresh token is invalid or expired".into(),
        ));
    }
    let (replacement_access_token, replacement_access_digest) = generate_access_token();
    let (replacement_refresh_token, replacement_refresh_digest) = generate_refresh_token(
        decoded.account_id,
        decoded.session_id,
        decoded.absolute_expires_at,
        decoded.client_kind,
    );
    let idle_ttl = match decoded.client_kind {
        AccountSessionClientKind::Browser => state.config.first_party_auth.browser_idle_ttl,
        AccountSessionClientKind::Desktop | AccountSessionClientKind::Cli => {
            state.config.first_party_auth.bearer_idle_ttl
        }
    };
    let replacement_access_expires_at = std::cmp::min(
        add_std_duration(
            now,
            state.config.first_party_auth.access_ttl,
            "access-token TTL",
        )?,
        decoded.absolute_expires_at,
    );
    let replacement_idle_expires_at = std::cmp::min(
        add_std_duration(now, idle_ttl, "session idle TTL")?,
        decoded.absolute_expires_at,
    );
    let replacement_refresh_expires_at = std::cmp::min(
        add_std_duration(
            now,
            state.config.first_party_auth.refresh_ttl,
            "refresh-token TTL",
        )?,
        replacement_idle_expires_at,
    );
    let result = state
        .catalog
        .refresh_account_session(AccountSessionRefreshRequest {
            presented_refresh_token_digest: decoded.digest,
            replacement_access_token_digest: replacement_access_digest,
            replacement_access_expires_at,
            replacement_idle_expires_at,
            replacement_refresh_token_id: Uuid::new_v4(),
            replacement_refresh_token_digest: replacement_refresh_digest,
            replacement_refresh_expires_at,
            rotated_at: now,
            success_audit_event: auth_audit_event(
                AccountAuthAuditEventKind::SessionRefreshed,
                AccountAuthAuditOutcome::Success,
                AuthAuditContext {
                    account_id: Some(decoded.account_id),
                    session_id: Some(decoded.session_id),
                    client_kind: Some(decoded.client_kind),
                    ..AuthAuditContext::default()
                },
                now,
            ),
            replay_audit_event: auth_audit_event(
                AccountAuthAuditEventKind::SessionReplayRevoked,
                AccountAuthAuditOutcome::Success,
                AuthAuditContext {
                    account_id: Some(decoded.account_id),
                    session_id: Some(decoded.session_id),
                    client_kind: Some(decoded.client_kind),
                    ..AuthAuditContext::default()
                },
                now,
            ),
        })
        .await
        .map_err(|error| AppError::from_catalog(error, "account session refresh"))?;
    match result {
        AccountSessionRefreshResult::Rotated(session) => {
            let account = state
                .catalog
                .get_account(session.account_id)
                .await
                .map_err(|error| AppError::from_catalog(error, "account"))?;
            if account.status != AccountStatus::Active {
                return Err(AppError::Unauthorized(
                    "refresh token is invalid or expired".into(),
                ));
            }
            local_auth_response(
                &state,
                account,
                session,
                request.client_kind,
                replacement_access_token,
                replacement_refresh_token,
                replacement_refresh_expires_at,
            )
        }
        AccountSessionRefreshResult::ReplayRevoked => Err(AppError::Unauthorized(
            "refresh token is invalid or expired".into(),
        )),
        AccountSessionRefreshResult::Rejected => {
            append_rejection_audit(
                &state,
                Some(decoded.account_id),
                Some(decoded.session_id),
                Some(decoded.client_kind),
                None,
                "refresh_rejected",
            )
            .await;
            Err(AppError::Unauthorized(
                "refresh token is invalid or expired".into(),
            ))
        }
    }
}

/// Enqueue one encrypted reset delivery without disclosing account existence.
async fn request_password_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RequestPasswordRecoveryRequest>,
) -> Result<Response, AppError> {
    require_local_auth_enabled(&state)?;
    require_trusted_browser_origin(&state, &headers)?;
    let cipher = require_password_recovery_enabled(&state)?;
    let started_at = tokio::time::Instant::now();
    let normalized_email = normalize_email(&request.email)?;
    let (raw_token, token_digest) = generate_token();
    let raw_token = Zeroizing::new(raw_token);
    let token_id = Uuid::new_v4();
    let delivery_id = Uuid::new_v4();
    let encrypted = cipher
        .encrypt_reset(
            delivery_id,
            &state.config.first_party_auth.recovery.reset_url,
            raw_token.as_str(),
        )
        .map_err(|_| AppError::Internal("password recovery encryption failed".to_string()))?;
    let requested_at = Utc::now();
    let token_ttl = Duration::from_std(state.config.first_party_auth.recovery.token_ttl)
        .map_err(|_| AppError::Internal("password recovery token TTL is invalid".to_string()))?;
    let cooldown = Duration::from_std(state.config.first_party_auth.recovery.request_cooldown)
        .map_err(|_| AppError::Internal("password recovery cooldown is invalid".to_string()))?;
    let token_expires_at = requested_at + token_ttl;
    let catalog = Arc::clone(&state.catalog);
    tokio::spawn(async move {
        if catalog
            .enqueue_account_password_recovery(PasswordRecoveryEnqueueRequest {
                token_id,
                normalized_email,
                token_digest,
                requested_at,
                token_expires_at,
                cooldown_cutoff: requested_at - cooldown,
                delivery: EncryptedPasswordRecoveryDelivery {
                    id: delivery_id,
                    ciphertext: encrypted.ciphertext,
                    nonce: encrypted.nonce,
                    key_version: encrypted.key_version,
                    expires_at: token_expires_at,
                },
            })
            .await
            .is_err()
        {
            tracing::warn!("password recovery enqueue failed");
        }
    });
    tokio::time::sleep_until(started_at + MIN_RECOVERY_REQUEST_DURATION).await;
    Ok((
        StatusCode::ACCEPTED,
        Json(PasswordRecoveryAcceptedResponse { accepted: true }),
    )
        .into_response())
}

/// Consume one reset bearer, change its credential, and revoke every session.
async fn complete_password_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CompletePasswordRecoveryRequest>,
) -> Result<Response, AppError> {
    require_local_auth_enabled(&state)?;
    require_trusted_browser_origin(&state, &headers)?;
    let cipher = require_password_recovery_enabled(&state)?;
    let raw_token = Zeroizing::new(request.token);
    let token_digest =
        decode_and_digest_token(raw_token.as_str()).map_err(|_| invalid_recovery_token_error())?;
    let password = protected_new_password(request.password)?;
    let new_password_hash = hash_password(&state, password).await?;
    let completed_at = Utc::now();
    let delivery_id = Uuid::new_v4();
    let encrypted = cipher
        .encrypt_password_changed(delivery_id)
        .map_err(|_| AppError::Internal("password recovery encryption failed".to_string()))?;
    let completed = state
        .catalog
        .complete_account_password_recovery(PasswordRecoveryCompletionRequest {
            token_digest,
            new_password_hash,
            new_password_version: PASSWORD_VERSION,
            new_pepper_version: state.config.first_party_auth.pepper_version,
            completed_at,
            delivery: EncryptedPasswordRecoveryDelivery {
                id: delivery_id,
                ciphertext: encrypted.ciphertext,
                nonce: encrypted.nonce,
                key_version: encrypted.key_version,
                expires_at: completed_at + PASSWORD_CHANGED_DELIVERY_TTL,
            },
        })
        .await
        .map_err(map_recovery_catalog_error)?;
    if !completed {
        return Err(invalid_recovery_token_error());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
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
        append_cleared_cookie(&mut response, &state.config.first_party_auth.cookie_name)?;
        append_cleared_cookie(
            &mut response,
            &state.config.first_party_auth.refresh_cookie_name,
        )?;
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

/// Return a validated recovery cipher or one uniform unavailable response.
fn require_password_recovery_enabled(state: &AppState) -> Result<RecoveryDeliveryCipher, AppError> {
    RecoveryDeliveryCipher::from_config(&state.config)
        .ok()
        .flatten()
        .ok_or_else(|| {
            AppError::ServiceUnavailable("password recovery is not configured".to_string())
        })
}

/// Require an exact configured browser origin before cookie creation or mutation.
pub(crate) fn require_trusted_browser_origin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), AppError> {
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

/// Validate a newly created password and move its exact bytes into protected memory.
pub(crate) fn protected_new_password(password: String) -> Result<SecretString, AppError> {
    let password = SecretString::new(password);
    let exposed = password.expose_secret();
    let character_count = exposed.chars().count();
    if character_count < MIN_PASSWORD_CHARS || exposed.len() > MAX_PASSWORD_BYTES {
        return Err(AppError::BadRequest(format!(
            "password must contain at least {MIN_PASSWORD_CHARS} characters and at most {MAX_PASSWORD_BYTES} bytes"
        )));
    }
    if password_blocklist::is_blocklisted(exposed) {
        return Err(AppError::BadRequest(
            "password is too common or specific to FrameShift".to_string(),
        ));
    }
    Ok(password)
}

/// Bound a login password without applying creation policy to legacy credentials.
fn protected_login_password(password: String) -> Result<SecretString, AppError> {
    let password = SecretString::new(password);
    if password.expose_secret().len() > MAX_PASSWORD_BYTES {
        return Err(AppError::BadRequest(format!(
            "password must contain at most {MAX_PASSWORD_BYTES} bytes"
        )));
    }
    Ok(password)
}

/// Hash one password on the blocking pool using the deployment pepper.
///
/// New hashes always use the CURRENT pepper (never a previous one) so every
/// freshly created credential is stamped with `pepper_version ==
/// state.config.first_party_auth.pepper_version` at the call site in
/// [`register_local_account`] and [`rehash_password_if_rotated`].
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

/// Rehash a historically peppered credential with the current deployment pepper.
///
/// The catalog mutation compares every security-relevant field observed by
/// verification before replacing the hash. A concurrent password change or
/// competing rehash therefore fails closed before a session is issued.
async fn rehash_password_if_rotated(
    state: &AppState,
    password: &SecretString,
    credential: &AccountPasswordCredentialRecord,
) -> Result<(), AppError> {
    let current_pepper_version = state.config.first_party_auth.pepper_version;
    if credential.pepper_version == current_pepper_version {
        return Ok(());
    }
    let new_password_hash = hash_password(state, password.clone()).await?;
    let updated = state
        .catalog
        .rehash_account_password_credential(AccountPasswordRehashRequest {
            account_id: credential.account_id,
            normalized_email: credential.normalized_email.clone(),
            expected_password_hash: credential.password_hash.clone(),
            expected_password_version: credential.password_version,
            expected_pepper_version: credential.pepper_version,
            expected_updated_at: credential.updated_at,
            new_password_hash,
            new_password_version: PASSWORD_VERSION,
            new_pepper_version: current_pepper_version,
            updated_at: Utc::now(),
        })
        .await
        .map_err(|error| AppError::from_catalog(error, "password credential"))?;
    if !updated {
        return Err(AppError::Unauthorized(
            "email or password is incorrect".to_string(),
        ));
    }
    tracing::info!(
        account_id = %credential.account_id,
        previous_pepper_version = credential.pepper_version,
        current_pepper_version,
        "first-party password credential rehashed with the current pepper"
    );
    Ok(())
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

/// Hide all catalog details from the public recovery surface.
fn map_recovery_catalog_error(_error: CatalogError) -> AppError {
    AppError::Internal("password recovery catalog operation failed".to_string())
}

/// Return the single public error shared by every unusable recovery bearer.
fn invalid_recovery_token_error() -> AppError {
    AppError::BadRequest("password recovery token is invalid or expired".to_string())
}

/// Generate one random 256-bit token and its SHA-256 digest.
pub(crate) fn generate_token() -> (String, Vec<u8>) {
    generate_access_token()
}

/// Decode one canonical 256-bit token and return its SHA-256 digest.
pub(crate) fn decode_and_digest_token(token: &str) -> Result<Vec<u8>, AppError> {
    decode_access_token(token)
}

/// Append one standalone sanitized rejection audit without changing its public response.
pub(crate) async fn append_rejection_audit(
    state: &AppState,
    account_id: Option<Uuid>,
    session_id: Option<Uuid>,
    client_kind: Option<AccountSessionClientKind>,
    identifier_tag: Option<Vec<u8>>,
    reason_code: &'static str,
) {
    let event = auth_audit_event(
        AccountAuthAuditEventKind::AuthenticationRejected,
        AccountAuthAuditOutcome::Rejected,
        AuthAuditContext {
            account_id,
            session_id,
            client_kind,
            identifier_tag,
            reason_code: Some(reason_code),
        },
        Utc::now(),
    );
    if state
        .catalog
        .append_account_auth_audit_event(event)
        .await
        .is_err()
    {
        tracing::warn!(reason_code, "authentication rejection audit failed");
    }
}

/// Build the transport-specific successful authentication response.
pub(crate) fn local_auth_response(
    state: &AppState,
    account: AccountRecord,
    session: AccountSessionRecord,
    client_kind: LocalAuthClientKind,
    access_token: String,
    refresh_token: String,
    refresh_expires_at: DateTime<Utc>,
) -> Result<Response, AppError> {
    let explicit_access_token =
        (client_kind != LocalAuthClientKind::Browser).then(|| access_token.clone());
    let explicit_refresh_token =
        (client_kind != LocalAuthClientKind::Browser).then(|| refresh_token.clone());
    let mut response = (
        StatusCode::OK,
        Json(LocalAuthResponse {
            account,
            access_token: explicit_access_token,
            refresh_token: explicit_refresh_token,
            token_type: "Bearer",
            expires_at: session.access_expires_at,
            refresh_expires_at,
            session_expires_at: session.absolute_expires_at,
        }),
    )
        .into_response();
    if client_kind == LocalAuthClientKind::Browser {
        let now = Utc::now();
        append_session_cookie(
            &mut response,
            &state.config.first_party_auth.cookie_name,
            &access_token,
            (session.access_expires_at - now).num_seconds().max(0),
        )?;
        append_session_cookie(
            &mut response,
            &state.config.first_party_auth.refresh_cookie_name,
            &refresh_token,
            (refresh_expires_at - now).num_seconds().max(0),
        )?;
    }
    Ok(response)
}

/// Extract exactly one non-empty named cookie and reject duplicate-name ambiguity.
pub(crate) fn extract_named_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let mut matches = raw.split(';').filter_map(|part| {
        let (candidate, value) = part.trim().split_once('=')?;
        (candidate == name && !value.is_empty()).then_some(value)
    });
    let token = matches.next()?;
    matches.next().is_none().then_some(token)
}

/// Append one Secure, HTTP-only, Strict browser session cookie.
fn append_session_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    max_age: i64,
) -> Result<(), AppError> {
    let cookie =
        format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}");
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|_| AppError::Internal("invalid session cookie configuration".into()))?,
    );
    Ok(())
}

/// Append one expired Secure, HTTP-only, Strict browser cookie.
fn append_cleared_cookie(response: &mut Response, name: &str) -> Result<(), AppError> {
    let cookie = format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|_| AppError::Internal("invalid session cookie configuration".into()))?,
    );
    Ok(())
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

    /// New-password bounds count Unicode scalars and cap UTF-8 bytes independently.
    #[test]
    fn new_password_bounds_are_enforced() {
        assert!(protected_new_password("é".repeat(MIN_PASSWORD_CHARS - 1)).is_err());
        assert!(protected_new_password("é".repeat(MIN_PASSWORD_CHARS)).is_ok());
        assert!(protected_new_password("x".repeat(MAX_PASSWORD_BYTES)).is_ok());
        assert!(protected_new_password("x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
    }

    /// New-password policy rejects blocklisted values after comparison normalization.
    #[test]
    fn new_password_blocklist_is_enforced() {
        assert!(protected_new_password("  FrameShiftPassword  ".to_string()).is_err());
        assert!(protected_new_password("correct horse battery staple".to_string()).is_ok());
    }

    /// Login accepts legacy short inputs but retains the Argon2 abuse bound.
    #[test]
    fn login_password_preserves_legacy_length_compatibility() {
        assert!(protected_login_password(String::new()).is_ok());
        assert!(protected_login_password("short".to_string()).is_ok());
        assert!(protected_login_password("x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
    }
}
