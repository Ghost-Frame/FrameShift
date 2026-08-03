//! Browser-mediated native authorization-code broker with exact loopback and S256 binding.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use frameshift_catalog::{
    AccountAuthAuditEventKind, AccountAuthAuditOutcome, AccountSessionClientKind,
    NativeAuthorizationCodeCreationRequest, NativeAuthorizationCodeExchangeRequest,
    NativeAuthorizationCodeExchangeResult, NativeAuthorizationCodeRecord,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::first_party_auth::{
    add_std_duration, auth_audit_event, authorization_redirect, canonical_loopback_redirect,
    canonical_oauth_state, decode_native_code, decode_pkce_challenge, generate_native_code,
    issue_session, pkce_challenge_for_verifier, AuthAuditContext,
};
use crate::middleware::account::AuthenticatedAccount;
use crate::routes::local_auth::{
    append_rejection_audit, local_auth_response, require_trusted_browser_origin,
};
use crate::state::AppState;

/// Tight body limit for authorization codes and PKCE material.
const MAX_NATIVE_AUTH_BODY_BYTES: usize = 8 * 1_024;

/// Browser authorization request for a desktop or CLI callback.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAuthorizeRequest {
    /// Native client class receiving the one-time code.
    pub client_kind: AccountSessionClientKind,
    /// Exact IP-literal HTTP loopback callback URI.
    pub redirect_uri: String,
    /// Canonical base64url SHA-256 digest of the client verifier.
    pub code_challenge: String,
    /// Required anti-downgrade method identifier, exactly `S256`.
    pub code_challenge_method: String,
    /// Canonical bounded anti-CSRF correlation value reflected to the callback.
    pub state: String,
}

/// Browser navigation target returned after one authorization code is committed.
#[derive(Debug, Serialize)]
pub struct NativeAuthorizeResponse {
    /// Exact loopback URI carrying only the one-time code and reflected state.
    pub redirect_uri: String,
    /// Exclusive authorization-code expiry.
    pub expires_at: DateTime<Utc>,
}

/// Native authorization-code exchange input.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTokenRequest {
    /// Required grant identifier, exactly `authorization_code`.
    pub grant_type: String,
    /// Opaque one-time browser authorization code.
    pub code: String,
    /// RFC 7636 verifier whose SHA-256 digest must match the code binding.
    pub code_verifier: String,
    /// Exact callback URI used during browser authorization.
    pub redirect_uri: String,
    /// Native client class bound during browser authorization.
    pub client_kind: AccountSessionClientKind,
}

/// Build the unauthenticated native authorization-code exchange endpoint.
pub fn native_auth_public_router() -> Router<AppState> {
    Router::new()
        .route("/native/token", post(exchange_native_token))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_NATIVE_AUTH_BODY_BYTES,
        ))
}

/// Build the protected browser endpoint that issues native authorization codes.
pub fn native_auth_protected_router() -> Router<AppState> {
    Router::new()
        .route("/native/authorize", post(authorize_native_client))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_NATIVE_AUTH_BODY_BYTES,
        ))
}

/// Issue one one-time native code from a fresh cookie-backed MFA session.
async fn authorize_native_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthenticatedAccount>,
    Json(request): Json<NativeAuthorizeRequest>,
) -> Result<Response, AppError> {
    if !auth.via_cookie || auth.local_session_id.is_none() {
        return Err(AppError::Forbidden(
            "a trusted browser session is required".into(),
        ));
    }
    require_trusted_browser_origin(&state, &headers)?;
    if request.client_kind == AccountSessionClientKind::Browser {
        return Err(AppError::BadRequest(
            "native authorization requires a desktop or CLI client".into(),
        ));
    }
    if request.code_challenge_method != "S256" {
        return Err(AppError::BadRequest(
            "code_challenge_method must be S256".into(),
        ));
    }
    let redirect_uri = canonical_loopback_redirect(&request.redirect_uri)?;
    let pkce_challenge = decode_pkce_challenge(&request.code_challenge)?;
    let state_value = canonical_oauth_state(&request.state)?;
    let mfa_verified_at = auth
        .mfa_verified_at
        .ok_or_else(|| AppError::Forbidden("fresh MFA verification required".into()))?;
    let (code, code_digest, normalized_mfa_verified_at) =
        generate_native_code(auth.account.id, request.client_kind, mfa_verified_at);
    let now = Utc::now();
    let expires_at = add_std_duration(
        now,
        state.config.first_party_auth.native_code_ttl,
        "native authorization-code TTL",
    )?;
    state
        .catalog
        .create_native_authorization_code(NativeAuthorizationCodeCreationRequest {
            code: NativeAuthorizationCodeRecord {
                id: Uuid::new_v4(),
                account_id: auth.account.id,
                token_digest: code_digest,
                client_kind: request.client_kind,
                redirect_uri: redirect_uri.clone(),
                pkce_challenge,
                mfa_verified_at: Some(normalized_mfa_verified_at),
                created_at: now,
                expires_at,
                consumed_at: None,
            },
            audit_event: auth_audit_event(
                AccountAuthAuditEventKind::NativeAuthorizationCodeCreated,
                AccountAuthAuditOutcome::Success,
                AuthAuditContext {
                    account_id: Some(auth.account.id),
                    client_kind: Some(request.client_kind),
                    ..AuthAuditContext::default()
                },
                now,
            ),
        })
        .await
        .map_err(|error| AppError::from_catalog(error, "native authorization code"))?;
    Ok((
        StatusCode::OK,
        Json(NativeAuthorizeResponse {
            redirect_uri: authorization_redirect(&redirect_uri, &code, &state_value)?,
            expires_at,
        }),
    )
        .into_response())
}

/// Exchange one exact native code, callback URI, client class, and S256 verifier.
async fn exchange_native_token(
    State(state): State<AppState>,
    Json(request): Json<NativeTokenRequest>,
) -> Result<Response, AppError> {
    if request.grant_type != "authorization_code"
        || request.client_kind == AccountSessionClientKind::Browser
    {
        return Err(AppError::BadRequest(
            "native authorization-code request is invalid".into(),
        ));
    }
    let raw_code = Zeroizing::new(request.code);
    let code = match decode_native_code(raw_code.as_str()) {
        Ok(code) => code,
        Err(_) => {
            append_rejection_audit(
                &state,
                None,
                None,
                Some(request.client_kind),
                None,
                "native_code_invalid",
            )
            .await;
            return Err(invalid_native_code());
        }
    };
    if code.client_kind != request.client_kind {
        append_rejection_audit(
            &state,
            Some(code.account_id),
            None,
            Some(request.client_kind),
            None,
            "native_client_mismatch",
        )
        .await;
        return Err(invalid_native_code());
    }
    let redirect_uri = canonical_loopback_redirect(&request.redirect_uri)?;
    let pkce_challenge = pkce_challenge_for_verifier(&request.code_verifier)?;
    let now = Utc::now();
    let issued = issue_session(
        &state.config.first_party_auth,
        code.account_id,
        request.client_kind,
        now,
        Some(code.mfa_verified_at),
    )?;
    let result = state
        .catalog
        .exchange_native_authorization_code(NativeAuthorizationCodeExchangeRequest {
            code_token_digest: code.digest,
            client_kind: request.client_kind,
            redirect_uri,
            pkce_challenge,
            issuance: issued.issuance.clone(),
            exchanged_at: now,
            audit_event: auth_audit_event(
                AccountAuthAuditEventKind::NativeAuthorizationCodeConsumed,
                AccountAuthAuditOutcome::Success,
                AuthAuditContext {
                    account_id: Some(code.account_id),
                    session_id: Some(issued.issuance.session.id),
                    client_kind: Some(request.client_kind),
                    ..AuthAuditContext::default()
                },
                now,
            ),
        })
        .await
        .map_err(|error| AppError::from_catalog(error, "native authorization code"))?;
    match result {
        NativeAuthorizationCodeExchangeResult::Exchanged(session) => {
            let account = state
                .catalog
                .get_account(code.account_id)
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
        NativeAuthorizationCodeExchangeResult::Rejected => {
            append_rejection_audit(
                &state,
                Some(code.account_id),
                None,
                Some(request.client_kind),
                None,
                "native_code_rejected",
            )
            .await;
            Err(invalid_native_code())
        }
    }
}

/// Return the one response shared by unusable native code bindings.
fn invalid_native_code() -> AppError {
    AppError::Unauthorized("authorization code is invalid or expired".into())
}
