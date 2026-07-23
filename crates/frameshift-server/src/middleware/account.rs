//! OIDC account authentication middleware for protected account routes.

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use frameshift_catalog::{AccountRecord, AccountStatus, CatalogError};
use uuid::Uuid;

use crate::account_auth::{OidcAuthError, VerifiedOidcIdentity};
use crate::error::AppError;
use crate::state::AppState;

/// Authenticated account and token context inserted into protected requests.
#[derive(Debug, Clone)]
pub struct AuthenticatedAccount {
    /// Durable catalog account resolved from the validated OIDC identity.
    pub account: AccountRecord,
    /// Provider authentication timestamp for fresh-auth checks.
    pub auth_time: Option<u64>,
}

/// Require an OIDC bearer token, provision its account, and reject disabled accounts.
pub async fn require_account(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let verifier = state
        .account_auth
        .as_ref()
        .ok_or_else(|| AppError::NotFound("account routes are disabled".to_string()))?;
    let token = extract_bearer(request.headers())?;
    let identity = verifier.verify(token).await.map_err(map_auth_error)?;
    let account = resolve_account(&state, &identity).await?;
    match account.status {
        AccountStatus::Active => {}
        AccountStatus::Suspended | AccountStatus::Disabled => {
            return Err(AppError::Forbidden("account is not active".to_string()));
        }
    }
    request.extensions_mut().insert(AuthenticatedAccount {
        account,
        auth_time: identity.auth_time,
    });
    Ok(next.run(request).await)
}

/// Parse one strict `Authorization: Bearer <token>` header.
fn extract_bearer(headers: &axum::http::HeaderMap) -> Result<&str, AppError> {
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("bearer token required".to_string()))?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty() && !token.chars().any(char::is_whitespace))
        .ok_or_else(|| AppError::Unauthorized("invalid bearer authorization".to_string()))?;
    Ok(token)
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
        assert_eq!(extract_bearer(&headers).unwrap(), "abc.def.ghi");
        headers.insert(AUTHORIZATION, "bearer abc".parse().unwrap());
        assert!(extract_bearer(&headers).is_err());
    }
}
