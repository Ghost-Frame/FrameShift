//! First-party TOTP enrollment, activation, challenge completion, and disable routes.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use frameshift_catalog::{
    AccountAuthAuditEventKind, AccountAuthAuditOutcome, AccountMfaActivationRequest,
    AccountMfaAuthenticatorRecord, AccountMfaAuthenticatorState,
    AccountMfaChallengeCompletionRequest, AccountMfaChallengeCompletionResult,
    AccountMfaChallengeProof, AccountMfaDisableRequest, AccountMfaEnrollmentRequest,
    AccountSessionClientKind, CatalogError,
};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::first_party_auth::{
    add_std_duration, auth_audit_event, base32_no_pad, decode_bound_token, decode_recovery_code,
    generate_recovery_codes, generate_totp_secret, issue_session, verify_totp, AuthAuditContext,
    MfaSecretCipher, MFA_RECOVERY_CODE_COUNT,
};
use crate::middleware::account::{validate_fresh_authentication, AuthenticatedAccount};
use crate::routes::local_auth::{
    append_rejection_audit, local_auth_response, require_trusted_browser_origin,
};
use crate::state::AppState;

/// Tight body limit for MFA proofs and one-time challenge tokens.
const MAX_MFA_BODY_BYTES: usize = 4 * 1_024;

/// TOTP enrollment metadata shown only while beginning enrollment.
#[derive(Debug, Serialize)]
pub struct BeginMfaEnrollmentResponse {
    /// Stable identifier required to activate this exact pending enrollment.
    pub authenticator_id: Uuid,
    /// Base32 TOTP seed shown for enrollment and never returned again.
    pub secret: String,
    /// Standards-compatible HMAC-SHA256 authenticator URI.
    pub otpauth_uri: String,
    /// Exclusive pending-enrollment deadline.
    pub expires_at: DateTime<Utc>,
}

/// Proof-of-possession input for one pending TOTP enrollment.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateMfaRequest {
    /// Canonical UUID string identifying the pending authenticator.
    pub authenticator_id: String,
    /// Current six-digit TOTP code.
    pub totp_code: String,
}

/// One-time recovery-code delivery returned only after activation.
#[derive(Debug, Serialize)]
pub struct ActivateMfaResponse {
    /// Stable signal that the authenticator is active.
    pub enabled: bool,
    /// High-entropy recovery codes shown exactly once.
    pub recovery_codes: Vec<String>,
}

/// Browser-side proof used to finish a password-bound login challenge.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteMfaChallengeRequest {
    /// Opaque one-time challenge token returned after password verification.
    pub challenge_token: String,
    /// Browser presentation binding required by the password flow.
    pub client_kind: AccountSessionClientKind,
    /// Optional current six-digit TOTP code.
    pub totp_code: Option<String>,
    /// Optional high-entropy one-time recovery code.
    pub recovery_code: Option<String>,
}

/// Stable response after an active authenticator is disabled.
#[derive(Debug, Serialize)]
pub struct DisableMfaResponse {
    /// Stable signal that MFA is no longer active.
    pub enabled: bool,
}

/// Build the unauthenticated MFA challenge-completion endpoint.
pub fn mfa_public_router() -> Router<AppState> {
    Router::new()
        .route("/mfa/challenge/complete", post(complete_mfa_challenge))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_MFA_BODY_BYTES,
        ))
}

/// Build protected browser MFA lifecycle endpoints.
pub fn mfa_protected_router() -> Router<AppState> {
    Router::new()
        .route("/mfa/enroll", post(begin_mfa_enrollment))
        .route("/mfa/activate", post(activate_mfa))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_MFA_BODY_BYTES,
        ))
}

/// Build the protected MFA endpoint that itself requires fresh assurance.
pub fn mfa_fresh_router() -> Router<AppState> {
    Router::new()
        .route("/mfa/disable", post(disable_mfa))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_MFA_BODY_BYTES,
        ))
}

/// Begin one encrypted pending TOTP enrollment for the authenticated browser account.
async fn begin_mfa_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthenticatedAccount>,
) -> Result<Response, AppError> {
    require_browser_session(&auth)?;
    require_trusted_browser_origin(&state, &headers)?;
    require_fresh_mfa_for_replacement(&state, &auth).await?;
    let cipher = MfaSecretCipher::from_config(&state.config.first_party_auth)?;
    let secret = generate_totp_secret();
    let authenticator_id = Uuid::new_v4();
    let now = Utc::now();
    let expires_at = add_std_duration(
        now,
        state.config.first_party_auth.mfa_enrollment_ttl,
        "MFA enrollment TTL",
    )?;
    let encrypted = cipher.encrypt(auth.account.id, authenticator_id, secret.as_slice())?;
    state
        .catalog
        .begin_account_mfa_enrollment(AccountMfaEnrollmentRequest {
            authenticator: AccountMfaAuthenticatorRecord {
                id: authenticator_id,
                account_id: auth.account.id,
                state: AccountMfaAuthenticatorState::Pending,
                secret: encrypted,
                pending_expires_at: Some(expires_at),
                last_used_timestep: None,
                created_at: now,
                activated_at: None,
                disabled_at: None,
            },
            audit_event: auth_audit_event(
                AccountAuthAuditEventKind::MfaEnrollmentStarted,
                AccountAuthAuditOutcome::Success,
                AuthAuditContext {
                    account_id: Some(auth.account.id),
                    ..AuthAuditContext::default()
                },
                now,
            ),
        })
        .await
        .map_err(|error| AppError::from_catalog(error, "MFA enrollment"))?;
    let encoded_secret = base32_no_pad(secret.as_slice());
    let otpauth_uri = build_otpauth_uri(&auth, &encoded_secret)?;
    Ok((
        StatusCode::CREATED,
        Json(BeginMfaEnrollmentResponse {
            authenticator_id,
            secret: encoded_secret,
            otpauth_uri,
            expires_at,
        }),
    )
        .into_response())
}

/// Verify and atomically activate one exact pending TOTP enrollment.
async fn activate_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthenticatedAccount>,
    Json(request): Json<ActivateMfaRequest>,
) -> Result<Response, AppError> {
    require_browser_session(&auth)?;
    require_trusted_browser_origin(&state, &headers)?;
    require_fresh_mfa_for_replacement(&state, &auth).await?;
    let authenticator_id = canonical_uuid(&request.authenticator_id)?;
    let now = Utc::now();
    let authenticator = state
        .catalog
        .get_pending_account_mfa_authenticator(auth.account.id, authenticator_id, now)
        .await
        .map_err(map_mfa_proof_catalog_error)?;
    let cipher = MfaSecretCipher::from_config(&state.config.first_party_auth)?;
    let secret = cipher.decrypt(auth.account.id, authenticator.id, &authenticator.secret)?;
    let verified_timestep = verify_totp(secret.as_slice(), &request.totp_code, now)?;
    let (recovery_codes, recovery_code_seeds) = generate_recovery_codes(MFA_RECOVERY_CODE_COUNT);
    state
        .catalog
        .activate_account_mfa(AccountMfaActivationRequest {
            account_id: auth.account.id,
            authenticator_id,
            verified_timestep,
            recovery_codes: recovery_code_seeds,
            activated_at: now,
            audit_event: auth_audit_event(
                AccountAuthAuditEventKind::MfaEnrollmentActivated,
                AccountAuthAuditOutcome::Success,
                AuthAuditContext {
                    account_id: Some(auth.account.id),
                    ..AuthAuditContext::default()
                },
                now,
            ),
        })
        .await
        .map_err(map_mfa_proof_catalog_error)?;
    Ok((
        StatusCode::OK,
        Json(ActivateMfaResponse {
            enabled: true,
            recovery_codes,
        }),
    )
        .into_response())
}

/// Complete one password-bound second-factor challenge and issue a browser session.
async fn complete_mfa_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CompleteMfaChallengeRequest>,
) -> Result<Response, AppError> {
    require_trusted_browser_origin(&state, &headers)?;
    if request.client_kind != AccountSessionClientKind::Browser {
        return Err(AppError::BadRequest(
            "MFA login completion is available only in the trusted browser portal".into(),
        ));
    }
    let bound = decode_bound_token(&request.challenge_token)?;
    if bound.client_kind != request.client_kind {
        return rejected_mfa_challenge(
            &state,
            bound.account_id,
            request.client_kind,
            "mfa_challenge_client_mismatch",
        )
        .await;
    }
    let authenticator = state
        .catalog
        .get_active_account_mfa_authenticator(bound.account_id)
        .await
        .map_err(map_mfa_proof_catalog_error)?;
    let now = Utc::now();
    let proof = match (request.totp_code, request.recovery_code) {
        (Some(totp_code), None) => {
            let cipher = MfaSecretCipher::from_config(&state.config.first_party_auth)?;
            let secret =
                cipher.decrypt(bound.account_id, authenticator.id, &authenticator.secret)?;
            AccountMfaChallengeProof::TotpTimestep(verify_totp(secret.as_slice(), &totp_code, now)?)
        }
        (None, Some(recovery_code)) => {
            let recovery_code = Zeroizing::new(recovery_code);
            AccountMfaChallengeProof::RecoveryCodeDigest(decode_recovery_code(
                recovery_code.as_str(),
            )?)
        }
        _ => {
            return Err(AppError::BadRequest(
                "exactly one MFA proof is required".into(),
            ));
        }
    };
    let issued = issue_session(
        &state.config.first_party_auth,
        bound.account_id,
        request.client_kind,
        now,
        Some(now),
    )?;
    let result = state
        .catalog
        .complete_account_mfa_challenge(AccountMfaChallengeCompletionRequest {
            challenge_token_digest: bound.digest,
            authenticator_id: authenticator.id,
            proof,
            issuance: issued.issuance.clone(),
            completed_at: now,
            audit_event: auth_audit_event(
                AccountAuthAuditEventKind::MfaChallengeCompleted,
                AccountAuthAuditOutcome::Success,
                AuthAuditContext {
                    account_id: Some(bound.account_id),
                    session_id: Some(issued.issuance.session.id),
                    client_kind: Some(request.client_kind),
                    ..AuthAuditContext::default()
                },
                now,
            ),
        })
        .await
        .map_err(|error| AppError::from_catalog(error, "MFA challenge"))?;
    match result {
        AccountMfaChallengeCompletionResult::Completed(session) => {
            let account = state
                .catalog
                .get_account(bound.account_id)
                .await
                .map_err(|error| AppError::from_catalog(error, "account"))?;
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
        AccountMfaChallengeCompletionResult::Rejected => {
            rejected_mfa_challenge(
                &state,
                bound.account_id,
                request.client_kind,
                "mfa_challenge_rejected",
            )
            .await
        }
    }
}

/// Disable active MFA after the router has established fresh MFA assurance.
async fn disable_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthenticatedAccount>,
) -> Result<Response, AppError> {
    require_browser_session(&auth)?;
    require_trusted_browser_origin(&state, &headers)?;
    let now = Utc::now();
    let disabled = state
        .catalog
        .disable_account_mfa(AccountMfaDisableRequest {
            account_id: auth.account.id,
            disabled_at: now,
            audit_event: auth_audit_event(
                AccountAuthAuditEventKind::MfaDisabled,
                AccountAuthAuditOutcome::Success,
                AuthAuditContext {
                    account_id: Some(auth.account.id),
                    ..AuthAuditContext::default()
                },
                now,
            ),
        })
        .await
        .map_err(|error| AppError::from_catalog(error, "MFA authenticator"))?;
    if !disabled {
        return Err(AppError::BadRequest("MFA is not active".into()));
    }
    Ok((StatusCode::OK, Json(DisableMfaResponse { enabled: false })).into_response())
}

/// Require a cookie-backed local session for browser credential management.
fn require_browser_session(auth: &AuthenticatedAccount) -> Result<(), AppError> {
    if auth.via_cookie && auth.local_session_id.is_some() {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "a trusted browser session is required".into(),
        ))
    }
}

/// Require fresh assurance only when the account is replacing active MFA.
async fn require_fresh_mfa_for_replacement(
    state: &AppState,
    auth: &AuthenticatedAccount,
) -> Result<(), AppError> {
    match state
        .catalog
        .get_active_account_mfa_authenticator(auth.account.id)
        .await
    {
        Ok(_) => validate_fresh_authentication(state, auth),
        Err(CatalogError::NotFound { .. }) => Ok(()),
        Err(error) => Err(AppError::from_catalog(error, "MFA authenticator")),
    }
}

/// Build an HMAC-SHA256 otpauth URI without embedding any credential secret elsewhere.
fn build_otpauth_uri(
    auth: &AuthenticatedAccount,
    encoded_secret: &str,
) -> Result<String, AppError> {
    let label = auth
        .account
        .email
        .as_deref()
        .unwrap_or(auth.account.subject.as_str());
    let mut uri = Url::parse("otpauth://totp/")
        .map_err(|_| AppError::Internal("TOTP enrollment URI construction failed".into()))?;
    uri.path_segments_mut()
        .map_err(|_| AppError::Internal("TOTP enrollment URI construction failed".into()))?
        .push(&format!("FrameShift:{label}"));
    uri.query_pairs_mut()
        .append_pair("secret", encoded_secret)
        .append_pair("issuer", "FrameShift")
        .append_pair("algorithm", "SHA256")
        .append_pair("digits", "6")
        .append_pair("period", "30");
    Ok(uri.into())
}

/// Parse only the canonical lowercase-hyphenated UUID representation.
fn canonical_uuid(raw: &str) -> Result<Uuid, AppError> {
    if raw.len() != 36 || raw.chars().any(char::is_whitespace) {
        return Err(AppError::BadRequest("authenticator_id is invalid".into()));
    }
    let parsed = Uuid::parse_str(raw)
        .map_err(|_| AppError::BadRequest("authenticator_id is invalid".into()))?;
    if parsed.to_string() != raw {
        return Err(AppError::BadRequest("authenticator_id is invalid".into()));
    }
    Ok(parsed)
}

/// Convert pending/active lookup errors into one non-disclosing proof response.
fn map_mfa_proof_catalog_error(error: CatalogError) -> AppError {
    match error {
        CatalogError::NotFound { .. } | CatalogError::Unauthorized { .. } => {
            AppError::Unauthorized("MFA proof is invalid or expired".into())
        }
        other => AppError::from_catalog(other, "MFA authenticator"),
    }
}

/// Audit and return the one generic rejected challenge response.
async fn rejected_mfa_challenge(
    state: &AppState,
    account_id: Uuid,
    client_kind: AccountSessionClientKind,
    reason_code: &'static str,
) -> Result<Response, AppError> {
    append_rejection_audit(
        state,
        Some(account_id),
        None,
        Some(client_kind),
        None,
        reason_code,
    )
    .await;
    Err(AppError::Unauthorized(
        "MFA proof is invalid or expired".into(),
    ))
}

#[cfg(test)]
/// Unit tests for canonical MFA identifiers.
mod tests {
    use super::*;

    /// UUID inputs must use the one lowercase hyphenated representation.
    #[test]
    fn authenticator_uuid_is_canonical() {
        let id = Uuid::new_v4();
        assert_eq!(canonical_uuid(&id.to_string()).unwrap(), id);
        assert!(canonical_uuid(&id.simple().to_string()).is_err());
        assert!(canonical_uuid(&id.to_string().to_uppercase()).is_err());
    }
}
