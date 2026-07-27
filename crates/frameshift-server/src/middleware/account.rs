//! OIDC and first-party session authentication for protected account routes.

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, COOKIE, ORIGIN};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use frameshift_catalog::{AccountRecord, AccountSessionClientKind, AccountStatus, CatalogError};
use uuid::Uuid;

use crate::account_auth::{OidcAuthError, VerifiedOidcIdentity};
use crate::error::AppError;
use crate::routes::local_auth::decode_and_digest_token;
use crate::state::AppState;

/// Authenticated account and token context inserted into protected requests.
#[derive(Debug, Clone)]
pub struct AuthenticatedAccount {
    /// Durable catalog account resolved from the validated OIDC identity.
    pub account: AccountRecord,
    /// Provider authentication timestamp for fresh-auth checks.
    pub auth_time: Option<u64>,
    /// Local session identifier when authentication used a first-party token.
    pub local_session_id: Option<Uuid>,
    /// Whether the local session token arrived through the secure browser cookie.
    pub via_cookie: bool,
}

/// Require an OIDC bearer token, provision its account, and reject disabled accounts.
pub async fn require_account(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let authenticated = authenticate_account(&state, request.headers()).await?;
    if authenticated.via_cookie && !is_safe_method(request.method()) {
        require_trusted_origin(&state, request.headers())?;
    }
    request.extensions_mut().insert(authenticated);
    Ok(next.run(request).await)
}

/// Authenticate a bearer token when one is present and otherwise continue anonymously.
pub async fn resolve_optional_account(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let has_bearer = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("Bearer "));
    let has_cookie = local_cookie_token(&state, request.headers()).is_some();
    if has_bearer || has_cookie {
        let authenticated = authenticate_account(&state, request.headers()).await?;
        if authenticated.via_cookie && !is_safe_method(request.method()) {
            require_trusted_origin(&state, request.headers())?;
        }
        request.extensions_mut().insert(authenticated);
    }
    Ok(next.run(request).await)
}

/// Validate the request bearer token and resolve its active durable account.
async fn authenticate_account(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<AuthenticatedAccount, AppError> {
    let bearer = optional_bearer(headers)?;
    if state.config.first_party_auth.enabled() {
        if let Some(token) = bearer {
            if let Some(authenticated) = authenticate_local_token(state, token, false).await? {
                return Ok(authenticated);
            }
            if state.account_auth.is_none() {
                return Err(AppError::Unauthorized(
                    "invalid account session".to_string(),
                ));
            }
        }
        if let Some(token) = local_cookie_token(state, headers) {
            return authenticate_local_token(state, token, true)
                .await?
                .ok_or_else(|| AppError::Unauthorized("invalid account session".to_string()));
        }
    }
    let verifier = state.account_auth.as_ref().ok_or_else(|| {
        if state.config.first_party_auth.enabled() {
            AppError::Unauthorized("account authentication required".to_string())
        } else {
            AppError::NotFound("account routes are disabled".to_string())
        }
    })?;
    let token =
        bearer.ok_or_else(|| AppError::Unauthorized("bearer token required".to_string()))?;
    let identity = verifier.verify(token).await.map_err(map_auth_error)?;
    let account = resolve_account(state, &identity).await?;
    match account.status {
        AccountStatus::Active => {}
        AccountStatus::Suspended | AccountStatus::Disabled => {
            return Err(AppError::Forbidden("account is not active".to_string()));
        }
    }
    Ok(AuthenticatedAccount {
        account,
        auth_time: identity.auth_time,
        local_session_id: None,
        via_cookie: false,
    })
}

/// Parse an optional strict `Authorization: Bearer <token>` header.
fn optional_bearer(headers: &axum::http::HeaderMap) -> Result<Option<&str>, AppError> {
    let Some(value) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty() && !token.chars().any(char::is_whitespace))
        .ok_or_else(|| AppError::Unauthorized("invalid bearer authorization".to_string()))?;
    Ok(Some(token))
}

/// Resolve an active first-party session, refresh its sliding window, and load its account.
async fn authenticate_local_token(
    state: &AppState,
    token: &str,
    via_cookie: bool,
) -> Result<Option<AuthenticatedAccount>, AppError> {
    let digest = match decode_and_digest_token(token) {
        Ok(digest) => digest,
        Err(_) => return Ok(None),
    };
    let now = Utc::now();
    let session = match state.catalog.get_active_account_session(&digest, now).await {
        Ok(session) => session,
        Err(CatalogError::NotFound { .. }) => return Ok(None),
        Err(error) => return Err(AppError::from_catalog(error, "account session")),
    };
    let account = state
        .catalog
        .get_account(session.account_id)
        .await
        .map_err(|error| AppError::from_catalog(error, "account"))?;
    if account.status != AccountStatus::Active {
        return Err(AppError::Forbidden("account is not active".to_string()));
    }
    if session.last_seen_at <= now - chrono::Duration::minutes(5) {
        let idle_ttl = match session.client_kind {
            AccountSessionClientKind::Browser => state.config.first_party_auth.browser_idle_ttl,
            AccountSessionClientKind::Desktop | AccountSessionClientKind::Cli => {
                state.config.first_party_auth.bearer_idle_ttl
            }
        };
        let idle_ttl = chrono::Duration::from_std(idle_ttl)
            .map_err(|_| AppError::Internal("session idle duration is invalid".to_string()))?;
        let idle_expires_at = std::cmp::min(now + idle_ttl, session.absolute_expires_at);
        state
            .catalog
            .touch_account_session(session.id, now, idle_expires_at)
            .await
            .map_err(|error| AppError::from_catalog(error, "account session"))?;
    }
    Ok(Some(AuthenticatedAccount {
        account,
        auth_time: u64::try_from(session.created_at.timestamp()).ok(),
        local_session_id: Some(session.id),
        via_cookie,
    }))
}

/// Extract the configured first-party cookie token without accepting duplicate names.
fn local_cookie_token<'a>(state: &AppState, headers: &'a axum::http::HeaderMap) -> Option<&'a str> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    let name = state.config.first_party_auth.cookie_name.as_str();
    let mut matches = raw.split(';').filter_map(|part| {
        let (candidate, value) = part.trim().split_once('=')?;
        (candidate == name && !value.is_empty()).then_some(value)
    });
    let token = matches.next()?;
    matches.next().is_none().then_some(token)
}

/// Return whether a request method is side-effect free for cookie authentication.
fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Require the cookie-authenticated mutation to originate at an exact configured web origin.
fn require_trusted_origin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(), AppError> {
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::Forbidden("trusted browser origin required".to_string()))?;
    if state
        .config
        .cors_origins()
        .any(|configured| configured == origin)
    {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "trusted browser origin required".to_string(),
        ))
    }
}

/// Map verifier failures without exposing provider or token details.
fn map_auth_error(error: OidcAuthError) -> AppError {
    match error {
        OidcAuthError::ProviderUnavailable => {
            AppError::ServiceUnavailable("OIDC provider unavailable".to_string())
        }
        OidcAuthError::InvalidConfiguration => {
            AppError::NotFound("account routes are disabled".to_string())
        }
        OidcAuthError::InvalidToken => AppError::Unauthorized("invalid bearer token".to_string()),
    }
}

/// Resolve an existing account or create it exactly once on first authentication.
async fn resolve_account(
    state: &AppState,
    identity: &VerifiedOidcIdentity,
) -> Result<AccountRecord, AppError> {
    match state
        .catalog
        .get_account_by_subject(&identity.issuer, &identity.subject)
        .await
    {
        Ok(account) => Ok(account),
        Err(CatalogError::NotFound { .. }) => {
            let now = Utc::now();
            let record = AccountRecord {
                id: Uuid::new_v4(),
                issuer: identity.issuer.clone(),
                subject: identity.subject.clone(),
                email: identity.email.clone(),
                display_name: identity.display_name.clone(),
                status: AccountStatus::Active,
                created_at: now,
                updated_at: now,
            };
            match state.catalog.create_account(record.clone()).await {
                Ok(()) => Ok(record),
                Err(CatalogError::Conflict { .. }) => state
                    .catalog
                    .get_account_by_subject(&identity.issuer, &identity.subject)
                    .await
                    .map_err(|error| AppError::from_catalog(error, "account")),
                Err(error) => Err(AppError::from_catalog(error, "account")),
            }
        }
        Err(error) => Err(AppError::from_catalog(error, "account")),
    }
}

#[cfg(test)]
/// Unit tests for strict bearer header parsing.
mod tests {
    use super::*;

    /// Bearer parsing accepts one opaque token without whitespace.
    #[test]
    fn bearer_header_is_strict() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer abc.def.ghi".parse().unwrap());
        assert_eq!(optional_bearer(&headers).unwrap(), Some("abc.def.ghi"));
        headers.insert(AUTHORIZATION, "bearer abc".parse().unwrap());
        assert!(optional_bearer(&headers).is_err());
    }
}
