//! Cloudflare Access assertion authentication for the remote MCP endpoint.
//!
//! This boundary deliberately does not share the browser or bearer-token
//! extraction used by account routes. The Cloudflare edge is the sole token
//! translator: the origin accepts exactly one signed Access assertion header,
//! verifies its pinned issuer and audience, and exposes only the resulting
//! durable account UUID to MCP dispatch.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use frameshift_catalog::AccountStatus;
use url::Url;
use uuid::Uuid;

use crate::account_auth::{BearerTokenVerifier, OidcAuthError, OidcVerifier};
use crate::config::McpAccessConfig;
use crate::middleware::account::resolve_account;
use crate::state::AppState;

/// Exact edge-injected header carrying the signed Cloudflare Access assertion.
const ACCESS_ASSERTION_HEADER: &str = "cf-access-jwt-assertion";
/// Maximum accepted encoded assertion size before cryptographic verification.
const MAX_ACCESS_ASSERTION_BYTES: usize = 16 * 1024;
/// Maximum accepted configured URL size.
const MAX_ACCESS_URL_BYTES: usize = 2048;
/// Maximum accepted Access application audience size.
const MAX_ACCESS_AUDIENCE_BYTES: usize = 512;
/// Maximum fresh JWKS lifetime accepted from configuration.
const MAX_JWKS_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Maximum additional stale-key outage window accepted from configuration.
const MAX_JWKS_STALE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Maximum assertion clock skew accepted from configuration.
const MAX_ASSERTION_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);
/// Fixed client-facing authentication failure text.
const AUTHENTICATION_REQUIRED: &str = "MCP authentication required";
/// Fixed client-facing provider outage text.
const SERVICE_UNAVAILABLE: &str = "service unavailable";
/// Fixed client-facing inactive-account text.
const FORBIDDEN: &str = "forbidden";

/// Durable account identity inserted only after Access verification succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpAuthenticatedAccount {
    /// Stable catalog account UUID used for authorization and tenant isolation.
    pub account_id: Uuid,
}

/// Fail-closed error returned for an unsafe enabled MCP Access policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum McpAccessConfigError {
    /// One or more enabled policy values violate the pinned Access contract.
    #[error("MCP Access configuration is invalid")]
    InvalidConfiguration,
}

/// Validated immutable authentication runtime for the remote MCP route.
pub struct McpAccessRuntime {
    /// Cryptographic assertion verifier configured with the pinned Access policy.
    verifier: Arc<dyn BearerTokenVerifier>,
    /// Exact issuer independently checked after verifier output.
    issuer: String,
    /// Prevalidated protected-resource challenge emitted on every 401.
    challenge: HeaderValue,
}

/// Construction behavior for [`McpAccessRuntime`].
impl McpAccessRuntime {
    /// Build the production runtime from the configured pinned OIDC verifier.
    pub fn from_config(
        config: &McpAccessConfig,
    ) -> Result<Option<Arc<Self>>, McpAccessConfigError> {
        let Some(policy) = ValidatedAccessPolicy::from_config(config)? else {
            return Ok(None);
        };
        let verifier = OidcVerifier::from_config(&config.assertion)
            .map_err(|_| McpAccessConfigError::InvalidConfiguration)?
            .ok_or(McpAccessConfigError::InvalidConfiguration)?;
        Ok(Some(Arc::new(Self::new(verifier, policy))))
    }

    /// Build a test runtime around an explicit verifier after the same policy validation.
    #[cfg(test)]
    fn with_verifier(
        config: &McpAccessConfig,
        verifier: Arc<dyn BearerTokenVerifier>,
    ) -> Result<Option<Arc<Self>>, McpAccessConfigError> {
        let Some(policy) = ValidatedAccessPolicy::from_config(config)? else {
            return Ok(None);
        };
        Ok(Some(Arc::new(Self::new(verifier, policy))))
    }

    /// Assemble one runtime from already validated immutable components.
    fn new(verifier: Arc<dyn BearerTokenVerifier>, policy: ValidatedAccessPolicy) -> Self {
        Self {
            verifier,
            issuer: policy.issuer,
            challenge: policy.challenge,
        }
    }
}

/// Normalized values retained after complete configuration validation.
struct ValidatedAccessPolicy {
    /// Exact Cloudflare Access issuer.
    issuer: String,
    /// Preparsed `WWW-Authenticate` challenge.
    challenge: HeaderValue,
}

/// Validation behavior for the immutable Access policy.
impl ValidatedAccessPolicy {
    /// Validate an enabled policy or return `None` for the disabled default.
    fn from_config(config: &McpAccessConfig) -> Result<Option<Self>, McpAccessConfigError> {
        if !config.assertion.enabled {
            return Ok(None);
        }
        validate_assertion_policy(config)?;
        let resource = validate_resource_url(&config.resource_url)?;
        validate_metadata_url(&config.resource_metadata_url, &resource)?;
        let challenge = HeaderValue::from_str(&format!(
            "Bearer resource_metadata=\"{}\"",
            config.resource_metadata_url
        ))
        .map_err(|_| McpAccessConfigError::InvalidConfiguration)?;
        Ok(Some(Self {
            issuer: config.assertion.issuer.clone(),
            challenge,
        }))
    }
}

/// Require one verified Access assertion and insert its durable account UUID.
pub async fn require_mcp_access(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(runtime) = state.mcp_access.as_ref() else {
        return fixed_response(StatusCode::NOT_FOUND, "not found", None);
    };
    let assertion = match exact_assertion(request.headers()) {
        Some(assertion) => assertion,
        None => return authentication_response(runtime),
    };
    let identity = match runtime.verifier.verify(assertion).await {
        Ok(identity)
            if identity.issuer == runtime.issuer
                && !identity.subject.is_empty()
                && identity.subject.trim() == identity.subject =>
        {
            identity
        }
        Ok(_) | Err(OidcAuthError::InvalidToken | OidcAuthError::InvalidConfiguration) => {
            return authentication_response(runtime);
        }
        Err(OidcAuthError::ProviderUnavailable) => {
            return fixed_response(StatusCode::SERVICE_UNAVAILABLE, SERVICE_UNAVAILABLE, None);
        }
    };
    let account = match resolve_account(&state, &identity).await {
        Ok(account) => account,
        Err(error) => return no_store(error.into_response()),
    };
    if account.status != AccountStatus::Active {
        return fixed_response(StatusCode::FORBIDDEN, FORBIDDEN, None);
    }
    request.extensions_mut().insert(McpAuthenticatedAccount {
        account_id: account.id,
    });
    next.run(request).await
}

/// Extract exactly one nonempty whitespace-free ASCII assertion within the cap.
fn exact_assertion(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(ACCESS_ASSERTION_HEADER).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let assertion = value.to_str().ok()?;
    (!assertion.is_empty()
        && assertion.len() <= MAX_ACCESS_ASSERTION_BYTES
        && assertion.is_ascii()
        && !assertion.chars().any(char::is_whitespace))
    .then_some(assertion)
}

/// Validate the pinned issuer, audience, JWKS endpoint, algorithm, and lifetimes.
fn validate_assertion_policy(config: &McpAccessConfig) -> Result<(), McpAccessConfigError> {
    let issuer = validate_cloudflare_issuer(&config.assertion.issuer)?;
    if config.assertion.audience.is_empty()
        || config.assertion.audience.len() > MAX_ACCESS_AUDIENCE_BYTES
        || config.assertion.audience.trim() != config.assertion.audience
        || config
            .assertion
            .audience
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || config.assertion.allowed_algorithms.as_slice() != ["RS256"]
        || config.assertion.jwks_cache_ttl.is_zero()
        || config.assertion.jwks_cache_ttl > MAX_JWKS_CACHE_TTL
        || config.assertion.jwks_stale_ttl > MAX_JWKS_STALE_TTL
        || config.assertion.clock_skew > MAX_ASSERTION_CLOCK_SKEW
    {
        return Err(McpAccessConfigError::InvalidConfiguration);
    }
    let expected_jwks = format!("{}/cdn-cgi/access/certs", config.assertion.issuer);
    if config.assertion.jwks_url != expected_jwks {
        return Err(McpAccessConfigError::InvalidConfiguration);
    }
    let jwks = parse_exact_https_url(&config.assertion.jwks_url)?;
    if jwks.origin() != issuer.origin() || jwks.path() != "/cdn-cgi/access/certs" {
        return Err(McpAccessConfigError::InvalidConfiguration);
    }
    Ok(())
}

/// Parse the exact Cloudflare team root issuer and reject lookalike domains.
fn validate_cloudflare_issuer(value: &str) -> Result<Url, McpAccessConfigError> {
    let url = parse_exact_https_url(value)?;
    let host = url
        .host_str()
        .ok_or(McpAccessConfigError::InvalidConfiguration)?;
    let team = host
        .strip_suffix(".cloudflareaccess.com")
        .filter(|team| !team.is_empty() && !team.contains('.'))
        .ok_or(McpAccessConfigError::InvalidConfiguration)?;
    if !valid_dns_label(team) || url.path() != "/" || value != url.origin().ascii_serialization() {
        return Err(McpAccessConfigError::InvalidConfiguration);
    }
    Ok(url)
}

/// Return whether a team subdomain is one valid DNS label.
fn valid_dns_label(value: &str) -> bool {
    value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

/// Validate the exact public HTTPS `/mcp` protected-resource URL.
fn validate_resource_url(value: &str) -> Result<Url, McpAccessConfigError> {
    let url = parse_exact_https_url(value)?;
    if url.path() != "/mcp" || url.as_str() != value {
        return Err(McpAccessConfigError::InvalidConfiguration);
    }
    Ok(url)
}

/// Validate the exact same-origin OAuth authorization-server metadata URL.
fn validate_metadata_url(value: &str, resource: &Url) -> Result<(), McpAccessConfigError> {
    let url = parse_exact_https_url(value)?;
    if url.origin() != resource.origin()
        || url.path() != "/.well-known/oauth-authorization-server"
        || url.as_str() != value
    {
        return Err(McpAccessConfigError::InvalidConfiguration);
    }
    Ok(())
}

/// Parse a canonical credential-free HTTPS URL without query or fragment data.
fn parse_exact_https_url(value: &str) -> Result<Url, McpAccessConfigError> {
    if value.is_empty() || value.len() > MAX_ACCESS_URL_BYTES || value.trim() != value {
        return Err(McpAccessConfigError::InvalidConfiguration);
    }
    let authority = value
        .strip_prefix("https://")
        .and_then(|remainder| remainder.split('/').next())
        .ok_or(McpAccessConfigError::InvalidConfiguration)?;
    let url = Url::parse(value).map_err(|_| McpAccessConfigError::InvalidConfiguration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || authority.contains('@')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(McpAccessConfigError::InvalidConfiguration);
    }
    Ok(url)
}

/// Build the fixed non-cacheable Access authentication response.
fn authentication_response(runtime: &McpAccessRuntime) -> Response {
    fixed_response(
        StatusCode::UNAUTHORIZED,
        AUTHENTICATION_REQUIRED,
        Some(runtime.challenge.clone()),
    )
}

/// Build one fixed JSON error and attach only prevalidated headers.
fn fixed_response(
    status: StatusCode,
    message: &'static str,
    challenge: Option<HeaderValue>,
) -> Response {
    let mut response = (status, Json(serde_json::json!({"error": message}))).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(challenge) = challenge {
        response.headers_mut().insert(WWW_AUTHENTICATE, challenge);
    }
    response
}

/// Mark an existing sanitized response as non-cacheable.
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
/// In-crate security and integration coverage for the Access boundary.
mod tests;
