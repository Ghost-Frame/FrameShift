//! Provider-neutral OIDC Authorization Code session client.
//!
//! The module owns discovery validation, S256 PKCE construction, exact callback
//! validation, bounded token exchange, refresh, and revocation. Callers remain
//! responsible for opening the system browser, receiving the redirect, and
//! persisting returned secrets in an operating-system credential store.

use std::fmt;
use std::io::Read as _;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore as _};
use secrecy::{ExposeSecret as _, SecretString};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use url::Url;
use zeroize::Zeroizing;

/// Maximum accepted discovery or token response body.
const MAX_SESSION_RESPONSE_BYTES: usize = 1024 * 1024;
/// Network timeout for discovery and token endpoint calls.
const SESSION_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
/// Minimum PKCE verifier entropy in random bytes.
const PKCE_RANDOM_BYTES: usize = 32;

/// Provider-neutral OIDC public-client configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionClientConfig {
    /// Exact issuer identifier expected from discovery.
    pub issuer: Url,
    /// Public OAuth client identifier.
    pub client_id: String,
    /// Exact callback URI registered for this client.
    pub redirect_uri: Url,
    /// Requested scopes; `openid` is required.
    pub scopes: Vec<String>,
}

/// Redacted debug output for public client configuration.
impl fmt::Debug for SessionClientConfig {
    /// Render non-secret configuration without URL userinfo.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionClientConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Validated capabilities advertised by an OIDC issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProvider {
    /// Exact discovered issuer.
    pub issuer: Url,
    /// Browser authorization endpoint.
    pub authorization_endpoint: Url,
    /// Authorization-code and refresh-token exchange endpoint.
    pub token_endpoint: Url,
    /// Optional RFC 8628 device authorization endpoint.
    pub device_authorization_endpoint: Option<Url>,
    /// Optional RFC 7009 revocation endpoint.
    pub revocation_endpoint: Option<Url>,
}

/// Pending browser authorization state.
pub struct AuthorizationFlow {
    /// URL that the caller opens in a system browser.
    pub authorization_url: Url,
    /// Exact callback state required on completion.
    state: String,
    /// OIDC nonce sent with the authorization request.
    nonce: String,
    /// Secret PKCE verifier retained until token exchange.
    code_verifier: SecretString,
}

/// Redacted pending-flow diagnostics.
impl fmt::Debug for AuthorizationFlow {
    /// Hide callback state, nonce, and PKCE verifier.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationFlow")
            .field("authorization_endpoint", &safe_url(&self.authorization_url))
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .finish()
    }
}

/// Authenticated OAuth session returned by the configured OIDC issuer.
pub struct OidcSession {
    /// Bearer access token used only through explicit secret accessors.
    pub(crate) access_token: SecretString,
    /// Optional refresh token.
    pub(crate) refresh_token: Option<SecretString>,
    /// Provider-reported access-token lifetime in seconds.
    pub(crate) expires_in: Option<u64>,
    /// Granted scope string when returned by the provider.
    pub(crate) scope: Option<String>,
    /// Local Unix timestamp when this token response was accepted.
    pub(crate) acquired_at: u64,
}

/// Redacted session diagnostics.
impl fmt::Debug for OidcSession {
    /// Render metadata while hiding all token values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcSession")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("acquired_at", &self.acquired_at)
            .finish()
    }
}

/// Public session metadata safe to print in account-status output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// Whether the session has a refresh credential.
    pub refreshable: bool,
    /// Provider-reported access-token lifetime in seconds.
    pub expires_in: Option<u64>,
    /// Granted scope string when returned by the provider.
    pub scope: Option<String>,
    /// Local Unix timestamp when the token response was accepted.
    pub acquired_at: u64,
    /// Calculated expiry timestamp when the provider supplied a lifetime.
    pub expires_at: Option<u64>,
}

/// Provider-neutral session client.
#[derive(Clone)]
pub struct SessionClient {
    /// Validated public-client configuration.
    config: SessionClientConfig,
    /// Validated provider metadata.
    provider: SessionProvider,
    /// HTTP transport boundary.
    http: Arc<dyn SessionHttp>,
}

/// Pending-flow accessors used by an ID-token validator.
impl AuthorizationFlow {
    /// Return the expected OIDC nonce for validating a returned ID token.
    pub fn expected_nonce(&self) -> &str {
        &self.nonce
    }
}

/// Redacted session-client diagnostics.
impl fmt::Debug for SessionClient {
    /// Render public configuration and provider metadata only.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionClient")
            .field("config", &self.config)
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

/// Session establishment or lifecycle failure.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Public-client or provider metadata was invalid.
    #[error("invalid OIDC session configuration: {0}")]
    InvalidConfiguration(String),
    /// OIDC discovery or an endpoint request failed.
    #[error("OIDC request to {url} failed: {detail}")]
    Http {
        /// Credential-free endpoint URL.
        url: String,
        /// Sanitized transport or status detail.
        detail: String,
    },
    /// The callback did not match the pending authorization flow.
    #[error("OIDC callback rejected: {0}")]
    InvalidCallback(String),
    /// The issuer returned a standards-based authorization error.
    #[error("OIDC authorization failed: {error}")]
    Authorization {
        /// Provider error code.
        error: String,
    },
    /// A provider capability required for the operation is absent.
    #[error("OIDC provider does not advertise {0}")]
    Unsupported(&'static str),
}

/// Minimal bounded HTTP response.
struct SessionHttpResponse {
    /// HTTP status code.
    status: u16,
    /// Bounded response bytes.
    body: Vec<u8>,
}

/// Internal transport boundary for deterministic protocol tests.
trait SessionHttp: Send + Sync {
    /// Issue a credential-free GET.
    fn get(&self, url: &Url) -> Result<SessionHttpResponse, SessionError>;
    /// Issue a form-encoded POST.
    fn post_form(
        &self,
        url: &Url,
        fields: &[(&str, &str)],
    ) -> Result<SessionHttpResponse, SessionError>;
}

/// Production blocking HTTP transport.
struct UreqSessionHttp {
    /// Agent with redirects disabled and a bounded timeout.
    agent: ureq::Agent,
}

/// Production transport operations.
impl SessionHttp for UreqSessionHttp {
    /// Fetch one bounded discovery document.
    fn get(&self, url: &Url) -> Result<SessionHttpResponse, SessionError> {
        map_ureq_response(url, self.agent.get(url.as_str()).call())
    }

    /// Send one form body without logging its secret fields.
    fn post_form(
        &self,
        url: &Url,
        fields: &[(&str, &str)],
    ) -> Result<SessionHttpResponse, SessionError> {
        let body = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields.iter().copied())
                .finish(),
        );
        map_ureq_response(
            url,
            self.agent
                .post(url.as_str())
                .set("Content-Type", "application/x-www-form-urlencoded")
                .send_string(&body),
        )
    }
}

/// Raw discovery fields needed by the session client.
#[derive(Deserialize)]
struct DiscoveryDocument {
    /// Exact issuer identifier.
    issuer: String,
    /// Browser authorization endpoint.
    authorization_endpoint: String,
    /// Token endpoint.
    token_endpoint: String,
    /// Advertised grant types when supplied.
    grant_types_supported: Option<Vec<String>>,
    /// Advertised PKCE methods when supplied.
    code_challenge_methods_supported: Option<Vec<String>>,
    /// Optional device authorization endpoint.
    device_authorization_endpoint: Option<String>,
    /// Optional token revocation endpoint.
    revocation_endpoint: Option<String>,
}

/// Raw successful token response.
#[derive(Deserialize)]
struct TokenResponse {
    /// Bearer access token.
    access_token: String,
    /// Token type, which must be Bearer.
    token_type: String,
    /// Optional refresh token.
    refresh_token: Option<String>,
    /// Optional OIDC ID token, intentionally discarded by this resource client.
    #[serde(rename = "id_token")]
    _id_token: Option<String>,
    /// Optional lifetime in seconds.
    expires_in: Option<u64>,
    /// Optional granted scopes.
    scope: Option<String>,
}

/// OAuth error response used for bounded diagnostic extraction.
#[derive(Deserialize)]
struct OAuthErrorResponse {
    /// Stable OAuth error code.
    error: String,
}

/// Parsed successful callback.
struct AuthorizationCallback {
    /// One-time authorization code.
    code: SecretString,
}

/// Session client operations.
impl SessionClient {
    /// Discover and validate an OIDC provider for one public client.
    pub fn discover(config: SessionClientConfig) -> Result<Self, SessionError> {
        let http: Arc<dyn SessionHttp> = Arc::new(UreqSessionHttp {
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(SESSION_HTTP_TIMEOUT)
                .build(),
        });
        Self::discover_with_http(config, http)
    }

    /// Return validated provider capabilities.
    pub fn provider(&self) -> &SessionProvider {
        &self.provider
    }

    /// Begin a browser Authorization Code flow using S256 PKCE.
    pub fn begin_authorization(&self) -> Result<AuthorizationFlow, SessionError> {
        let state = random_token();
        let nonce = random_token();
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut authorization_url = self.provider.authorization_endpoint.clone();
        {
            let mut query = authorization_url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &self.config.client_id);
            query.append_pair("redirect_uri", self.config.redirect_uri.as_str());
            query.append_pair("scope", &self.config.scopes.join(" "));
            query.append_pair("state", &state);
            query.append_pair("nonce", &nonce);
            query.append_pair("code_challenge", &challenge);
            query.append_pair("code_challenge_method", "S256");
        }
        Ok(AuthorizationFlow {
            authorization_url,
            state,
            nonce,
            code_verifier: SecretString::new(verifier),
        })
    }

    /// Validate a callback and exchange its code for an authenticated session.
    pub fn complete_authorization(
        &self,
        flow: &AuthorizationFlow,
        callback_url: &Url,
    ) -> Result<OidcSession, SessionError> {
        let callback = self.validate_callback(flow, callback_url)?;
        let fields = [
            ("grant_type", "authorization_code"),
            ("client_id", self.config.client_id.as_str()),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("code", callback.code.expose_secret()),
            ("code_verifier", flow.code_verifier.expose_secret()),
        ];
        self.exchange_token(&fields)
    }

    /// Refresh an existing session while preserving a rotated refresh token.
    pub fn refresh(&self, session: &OidcSession) -> Result<OidcSession, SessionError> {
        let refresh_token = session
            .refresh_token
            .as_ref()
            .ok_or(SessionError::Unsupported("a refresh token"))?;
        let fields = [
            ("grant_type", "refresh_token"),
            ("client_id", self.config.client_id.as_str()),
            ("refresh_token", refresh_token.expose_secret()),
        ];
        let mut refreshed = self.exchange_token(&fields)?;
        if refreshed.refresh_token.is_none() {
            refreshed.refresh_token =
                Some(SecretString::new(refresh_token.expose_secret().to_owned()));
        }
        Ok(refreshed)
    }

    /// Revoke the refresh token when present, otherwise revoke the access token.
    pub fn revoke(&self, session: &OidcSession) -> Result<(), SessionError> {
        let endpoint = self
            .provider
            .revocation_endpoint
            .as_ref()
            .ok_or(SessionError::Unsupported("a revocation endpoint"))?;
        let (token, hint) = match session.refresh_token.as_ref() {
            Some(token) => (token, "refresh_token"),
            None => (&session.access_token, "access_token"),
        };
        let fields = [
            ("client_id", self.config.client_id.as_str()),
            ("token", token.expose_secret()),
            ("token_type_hint", hint),
        ];
        let response = self.http.post_form(endpoint, &fields)?;
        if (200..300).contains(&response.status) {
            Ok(())
        } else {
            Err(status_error(endpoint, response))
        }
    }

    /// Discover using an injected transport.
    fn discover_with_http(
        config: SessionClientConfig,
        http: Arc<dyn SessionHttp>,
    ) -> Result<Self, SessionError> {
        validate_client_config(&config)?;
        let discovery_url = discovery_url(&config.issuer)?;
        let response = http.get(&discovery_url)?;
        if !(200..300).contains(&response.status) {
            return Err(status_error(&discovery_url, response));
        }
        let document: DiscoveryDocument = decode_json(&discovery_url, &response.body)?;
        let provider = validate_discovery(&config, document)?;
        Ok(Self {
            config,
            provider,
            http,
        })
    }

    /// Validate the exact redirect target and its unambiguous query.
    fn validate_callback(
        &self,
        flow: &AuthorizationFlow,
        callback_url: &Url,
    ) -> Result<AuthorizationCallback, SessionError> {
        if !same_redirect_target(&self.config.redirect_uri, callback_url) {
            return Err(SessionError::InvalidCallback(
                "redirect target did not match the registered callback".to_string(),
            ));
        }
        let mut code = None;
        let mut state = None;
        let mut error = None;
        for (name, value) in callback_url.query_pairs() {
            let slot = match name.as_ref() {
                "code" => &mut code,
                "state" => &mut state,
                "error" => &mut error,
                _ => continue,
            };
            if slot.replace(value.into_owned()).is_some() {
                return Err(SessionError::InvalidCallback(format!(
                    "duplicate {name} parameter"
                )));
            }
        }
        let state = state
            .ok_or_else(|| SessionError::InvalidCallback("callback omitted state".to_string()))?;
        if state.as_bytes() != flow.state.as_bytes() {
            return Err(SessionError::InvalidCallback(
                "callback state did not match".to_string(),
            ));
        }
        if let Some(error) = error {
            if code.is_some() {
                return Err(SessionError::InvalidCallback(
                    "callback contained both code and error".to_string(),
                ));
            }
            return Err(SessionError::Authorization { error });
        }
        let code = code
            .filter(|value| !value.is_empty())
            .ok_or_else(|| SessionError::InvalidCallback("callback omitted code".to_string()))?;
        Ok(AuthorizationCallback {
            code: SecretString::new(code),
        })
    }

    /// Exchange one validated OAuth grant for a bounded token response.
    fn exchange_token(&self, fields: &[(&str, &str)]) -> Result<OidcSession, SessionError> {
        let response = self.http.post_form(&self.provider.token_endpoint, fields)?;
        if !(200..300).contains(&response.status) {
            return Err(status_error(&self.provider.token_endpoint, response));
        }
        let raw: TokenResponse = decode_json(&self.provider.token_endpoint, &response.body)?;
        if !raw.token_type.eq_ignore_ascii_case("bearer") || raw.access_token.is_empty() {
            return Err(SessionError::Http {
                url: safe_url(&self.provider.token_endpoint),
                detail: "provider returned an invalid bearer token response".to_string(),
            });
        }
        Ok(OidcSession {
            access_token: SecretString::new(raw.access_token),
            refresh_token: raw.refresh_token.map(SecretString::new),
            expires_in: raw.expires_in,
            scope: raw.scope,
            acquired_at: unix_now(),
        })
    }
}

/// Secret and metadata accessors for an authenticated session.
impl OidcSession {
    /// Borrow the bearer access token for an authenticated API call.
    pub fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// Borrow the optional refresh credential for secure persistence.
    pub fn refresh_token(&self) -> Option<&SecretString> {
        self.refresh_token.as_ref()
    }

    /// Return public metadata safe for status output.
    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            refreshable: self.refresh_token.is_some(),
            expires_in: self.expires_in,
            scope: self.scope.clone(),
            acquired_at: self.acquired_at,
            expires_at: self
                .expires_in
                .and_then(|lifetime| self.acquired_at.checked_add(lifetime)),
        }
    }

    /// Reconstruct a session from a validated native credential-store payload.
    pub(crate) fn from_stored_parts(
        access_token: SecretString,
        refresh_token: Option<SecretString>,
        expires_in: Option<u64>,
        scope: Option<String>,
        acquired_at: u64,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_in,
            scope,
            acquired_at,
        }
    }
}

/// Build the standard discovery URL beneath the exact issuer path.
fn discovery_url(issuer: &Url) -> Result<Url, SessionError> {
    let mut url = issuer.clone();
    if url.cannot_be_a_base() {
        return Err(SessionError::InvalidConfiguration(
            "issuer cannot be used as a URL base".to_string(),
        ));
    }
    let path = format!(
        "{}/.well-known/openid-configuration",
        issuer.path().trim_end_matches('/')
    );
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// Validate public-client configuration before making a request.
fn validate_client_config(config: &SessionClientConfig) -> Result<(), SessionError> {
    validate_https_endpoint(&config.issuer, "issuer")?;
    if config.issuer.query().is_some() {
        return Err(SessionError::InvalidConfiguration(
            "issuer must not contain a query".to_string(),
        ));
    }
    if config.client_id.trim().is_empty() {
        return Err(SessionError::InvalidConfiguration(
            "client_id must not be empty".to_string(),
        ));
    }
    if config.scopes.is_empty()
        || !config.scopes.iter().any(|scope| scope == "openid")
        || config.scopes.iter().any(|scope| scope.trim().is_empty())
    {
        return Err(SessionError::InvalidConfiguration(
            "scopes must contain openid and no empty values".to_string(),
        ));
    }
    validate_redirect_uri(&config.redirect_uri)
}

/// Validate discovery metadata and supported protocol capabilities.
fn validate_discovery(
    config: &SessionClientConfig,
    document: DiscoveryDocument,
) -> Result<SessionProvider, SessionError> {
    let discovered_issuer = parse_endpoint(&document.issuer, "issuer")?;
    if discovered_issuer != config.issuer {
        return Err(SessionError::InvalidConfiguration(
            "discovered issuer did not exactly match configured issuer".to_string(),
        ));
    }
    if let Some(grants) = document.grant_types_supported {
        if !grants.iter().any(|grant| grant == "authorization_code") {
            return Err(SessionError::InvalidConfiguration(
                "provider does not advertise authorization_code".to_string(),
            ));
        }
    }
    let methods = document.code_challenge_methods_supported.ok_or_else(|| {
        SessionError::InvalidConfiguration("provider did not advertise PKCE methods".to_string())
    })?;
    if !methods.iter().any(|method| method == "S256") {
        return Err(SessionError::InvalidConfiguration(
            "provider does not advertise S256 PKCE".to_string(),
        ));
    }
    Ok(SessionProvider {
        issuer: discovered_issuer,
        authorization_endpoint: parse_endpoint(
            &document.authorization_endpoint,
            "authorization endpoint",
        )?,
        token_endpoint: parse_endpoint(&document.token_endpoint, "token endpoint")?,
        device_authorization_endpoint: document
            .device_authorization_endpoint
            .map(|value| parse_endpoint(&value, "device authorization endpoint"))
            .transpose()?,
        revocation_endpoint: document
            .revocation_endpoint
            .map(|value| parse_endpoint(&value, "revocation endpoint"))
            .transpose()?,
    })
}

/// Parse and validate a credential-free HTTPS provider endpoint.
fn parse_endpoint(value: &str, label: &str) -> Result<Url, SessionError> {
    let url = Url::parse(value).map_err(|error| {
        SessionError::InvalidConfiguration(format!("{label} is not a valid URL: {error}"))
    })?;
    validate_https_endpoint(&url, label)?;
    Ok(url)
}

/// Require a credential-free HTTPS endpoint.
fn validate_https_endpoint(url: &Url, label: &str) -> Result<(), SessionError> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(SessionError::InvalidConfiguration(format!(
            "{label} must be a credential-free HTTPS URL without a fragment"
        )));
    }
    Ok(())
}

/// Permit HTTPS callbacks or native loopback HTTP callbacks.
fn validate_redirect_uri(url: &Url) -> Result<(), SessionError> {
    let is_https = url.scheme() == "https" && url.host_str().is_some();
    let is_loopback_http =
        url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
    if (!is_https && !is_loopback_http)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(SessionError::InvalidConfiguration(
            "redirect_uri must be credential-free HTTPS or loopback HTTP without query or fragment"
                .to_string(),
        ));
    }
    Ok(())
}

/// Compare callback scheme, host, effective port, and path exactly.
fn same_redirect_target(expected: &Url, actual: &Url) -> bool {
    expected.scheme() == actual.scheme()
        && expected.host_str() == actual.host_str()
        && expected.port_or_known_default() == actual.port_or_known_default()
        && expected.path() == actual.path()
        && actual.fragment().is_none()
        && actual.username().is_empty()
        && actual.password().is_none()
}

/// Generate a URL-safe random token with 256 bits of entropy.
fn random_token() -> String {
    let mut bytes = [0_u8; PKCE_RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Return the current Unix timestamp without panicking on a bad system clock.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Decode a bounded JSON response.
fn decode_json<T: DeserializeOwned>(url: &Url, body: &[u8]) -> Result<T, SessionError> {
    if body.len() > MAX_SESSION_RESPONSE_BYTES {
        return Err(SessionError::Http {
            url: safe_url(url),
            detail: "provider response exceeded the size limit".to_string(),
        });
    }
    serde_json::from_slice(body).map_err(|_| SessionError::Http {
        url: safe_url(url),
        detail: "provider returned malformed JSON".to_string(),
    })
}

/// Convert an HTTP status into a bounded OAuth diagnostic.
fn status_error(url: &Url, response: SessionHttpResponse) -> SessionError {
    let provider_code = serde_json::from_slice::<OAuthErrorResponse>(&response.body)
        .ok()
        .map(|body| body.error);
    let detail = provider_code.map_or_else(
        || format!("provider returned HTTP {}", response.status),
        |code| format!("provider returned HTTP {} ({code})", response.status),
    );
    SessionError::Http {
        url: safe_url(url),
        detail,
    }
}

/// Map a ureq result into a bounded response without exposing request bodies.
fn map_ureq_response(
    url: &Url,
    result: Result<ureq::Response, ureq::Error>,
) -> Result<SessionHttpResponse, SessionError> {
    let response = match result {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(error) => {
            return Err(SessionError::Http {
                url: safe_url(url),
                detail: error.to_string(),
            });
        }
    };
    let status = response.status();
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_SESSION_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|error| SessionError::Http {
            url: safe_url(url),
            detail: format!("could not read provider response: {error}"),
        })?;
    if body.len() > MAX_SESSION_RESPONSE_BYTES {
        return Err(SessionError::Http {
            url: safe_url(url),
            detail: "provider response exceeded the size limit".to_string(),
        });
    }
    Ok(SessionHttpResponse { status, body })
}

/// Return a credential-free URL string for diagnostics.
fn safe_url(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

#[cfg(test)]
/// Deterministic protocol tests for the session client.
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    /// Deterministic queued transport.
    struct FakeHttp {
        /// Queued responses returned in call order.
        responses: Mutex<VecDeque<SessionHttpResponse>>,
        /// Captured form bodies.
        forms: Mutex<Vec<Vec<(String, String)>>>,
    }

    /// Fake transport operations.
    impl SessionHttp for FakeHttp {
        /// Return the next queued GET response.
        fn get(&self, _url: &Url) -> Result<SessionHttpResponse, SessionError> {
            self.responses
                .lock()
                .expect("responses lock poisoned")
                .pop_front()
                .ok_or_else(|| SessionError::Http {
                    url: "https://issuer.example".to_string(),
                    detail: "missing fake response".to_string(),
                })
        }

        /// Capture form fields and return the next queued response.
        fn post_form(
            &self,
            _url: &Url,
            fields: &[(&str, &str)],
        ) -> Result<SessionHttpResponse, SessionError> {
            self.forms.lock().expect("forms lock poisoned").push(
                fields
                    .iter()
                    .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                    .collect(),
            );
            self.get(_url)
        }
    }

    /// Build a valid public-client configuration.
    fn config() -> SessionClientConfig {
        SessionClientConfig {
            issuer: Url::parse("https://issuer.example/tenant").expect("issuer URL"),
            client_id: "frameshift-cli".to_string(),
            redirect_uri: Url::parse("http://127.0.0.1:48123/callback").expect("redirect URL"),
            scopes: vec!["openid".to_string(), "profile".to_string()],
        }
    }

    /// Build a successful JSON response.
    fn response(body: serde_json::Value) -> SessionHttpResponse {
        SessionHttpResponse {
            status: 200,
            body: serde_json::to_vec(&body).expect("serialize response"),
        }
    }

    /// Build valid discovery JSON.
    fn discovery() -> serde_json::Value {
        serde_json::json!({
            "issuer": "https://issuer.example/tenant",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "device_authorization_endpoint": "https://issuer.example/device",
            "revocation_endpoint": "https://issuer.example/revoke"
        })
    }

    /// Build a client around a shared fake transport.
    fn client_with(
        fake: Arc<FakeHttp>,
        queued_discovery: serde_json::Value,
    ) -> Result<SessionClient, SessionError> {
        fake.responses
            .lock()
            .expect("responses lock poisoned")
            .push_back(response(queued_discovery));
        SessionClient::discover_with_http(config(), fake)
    }

    /// Discovery and authorization construction preserve required protocol fields.
    #[test]
    fn discovers_provider_and_builds_s256_authorization() {
        let fake = Arc::new(FakeHttp {
            responses: Mutex::new(VecDeque::new()),
            forms: Mutex::new(Vec::new()),
        });
        let client = client_with(fake, discovery()).expect("discovery should pass");
        let flow = client.begin_authorization().expect("flow should begin");
        let pairs: std::collections::HashMap<_, _> =
            flow.authorization_url.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(
            pairs.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(
            pairs.get("client_id").map(String::as_str),
            Some("frameshift-cli")
        );
        assert_eq!(
            client
                .provider()
                .device_authorization_endpoint
                .as_ref()
                .map(Url::as_str),
            Some("https://issuer.example/device")
        );
        let debug = format!("{flow:?}");
        assert!(!debug.contains(flow.code_verifier.expose_secret()));
        assert!(!debug.contains(&flow.state));
        assert!(!debug.contains(flow.expected_nonce()));
    }

    /// Exact callback state is required and secrets remain redacted.
    #[test]
    fn completes_callback_refreshes_and_revokes_without_debug_secret_leaks() {
        let fake = Arc::new(FakeHttp {
            responses: Mutex::new(VecDeque::new()),
            forms: Mutex::new(Vec::new()),
        });
        let client = client_with(Arc::clone(&fake), discovery()).expect("discovery should pass");
        let flow = client.begin_authorization().expect("flow should begin");
        fake.responses
            .lock()
            .expect("responses lock poisoned")
            .push_back(response(serde_json::json!({
                "access_token": "secret-access",
                "token_type": "Bearer",
                "refresh_token": "secret-refresh",
                "expires_in": 300,
                "scope": "openid profile"
            })));
        let callback = Url::parse(&format!(
            "http://127.0.0.1:48123/callback?code=one-time-code&state={}",
            flow.state
        ))
        .expect("callback URL");
        let session = client
            .complete_authorization(&flow, &callback)
            .expect("callback should complete");
        assert!(!format!("{session:?}").contains("secret-access"));
        assert_eq!(
            session.summary(),
            SessionSummary {
                refreshable: true,
                expires_in: Some(300),
                scope: Some("openid profile".to_string()),
                acquired_at: session.summary().acquired_at,
                expires_at: session.summary().acquired_at.checked_add(300),
            }
        );

        fake.responses
            .lock()
            .expect("responses lock poisoned")
            .push_back(response(serde_json::json!({
                "access_token": "rotated-access",
                "token_type": "bearer"
            })));
        let refreshed = client.refresh(&session).expect("refresh should pass");
        assert_eq!(
            refreshed
                .refresh_token()
                .map(|token| token.expose_secret().as_str()),
            Some("secret-refresh")
        );

        fake.responses
            .lock()
            .expect("responses lock poisoned")
            .push_back(SessionHttpResponse {
                status: 200,
                body: Vec::new(),
            });
        client.revoke(&session).expect("revocation should pass");
        let forms = fake.forms.lock().expect("forms lock poisoned");
        assert_eq!(forms.len(), 3);
        assert!(forms[0]
            .iter()
            .any(|(name, value)| name == "code" && value == "one-time-code"));
        assert!(forms[1]
            .iter()
            .any(|(name, value)| name == "grant_type" && value == "refresh_token"));
        assert!(forms[2]
            .iter()
            .any(|(name, value)| name == "token_type_hint" && value == "refresh_token"));
    }

    /// Callback ambiguity, provider errors, and state mismatch fail before exchange.
    #[test]
    fn rejects_ambiguous_or_mismatched_callbacks() {
        let fake = Arc::new(FakeHttp {
            responses: Mutex::new(VecDeque::new()),
            forms: Mutex::new(Vec::new()),
        });
        let client = client_with(fake, discovery()).expect("discovery should pass");
        let flow = client.begin_authorization().expect("flow should begin");
        for callback in [
            "http://127.0.0.1:48123/callback?code=a&code=b&state=x",
            "http://127.0.0.1:48123/callback?code=a&state=wrong",
            "http://127.0.0.1:48123/callback?error=access_denied&state=x",
            "http://localhost:48123/callback?code=a&state=x",
        ] {
            assert!(client
                .complete_authorization(&flow, &Url::parse(callback).expect("callback URL"))
                .is_err());
        }
    }

    /// Discovery rejects issuer substitution, insecure endpoints, and missing S256.
    #[test]
    fn rejects_unsafe_or_incompatible_discovery() {
        let variants = [
            serde_json::json!({
                "issuer": "https://other.example/tenant",
                "authorization_endpoint": "https://issuer.example/authorize",
                "token_endpoint": "https://issuer.example/token",
                "code_challenge_methods_supported": ["S256"]
            }),
            serde_json::json!({
                "issuer": "https://issuer.example/tenant",
                "authorization_endpoint": "http://issuer.example/authorize",
                "token_endpoint": "https://issuer.example/token",
                "code_challenge_methods_supported": ["S256"]
            }),
            serde_json::json!({
                "issuer": "https://issuer.example/tenant",
                "authorization_endpoint": "https://issuer.example/authorize",
                "token_endpoint": "https://issuer.example/token",
                "code_challenge_methods_supported": ["plain"]
            }),
        ];
        for document in variants {
            let fake = Arc::new(FakeHttp {
                responses: Mutex::new(VecDeque::new()),
                forms: Mutex::new(Vec::new()),
            });
            assert!(client_with(fake, document).is_err());
        }
    }

    /// Invalid token responses and oversized bodies fail without echoing secrets.
    #[test]
    fn rejects_invalid_and_oversized_token_responses() {
        let fake = Arc::new(FakeHttp {
            responses: Mutex::new(VecDeque::new()),
            forms: Mutex::new(Vec::new()),
        });
        let client = client_with(Arc::clone(&fake), discovery()).expect("discovery should pass");
        let flow = client.begin_authorization().expect("flow should begin");
        fake.responses
            .lock()
            .expect("responses lock poisoned")
            .push_back(response(serde_json::json!({
                "access_token": "",
                "token_type": "Bearer"
            })));
        let callback = Url::parse(&format!(
            "http://127.0.0.1:48123/callback?code=bad-code&state={}",
            flow.state
        ))
        .expect("callback URL");
        assert!(client.complete_authorization(&flow, &callback).is_err());

        fake.responses
            .lock()
            .expect("responses lock poisoned")
            .push_back(SessionHttpResponse {
                status: 200,
                body: vec![b'x'; MAX_SESSION_RESPONSE_BYTES + 1],
            });
        assert!(client.complete_authorization(&flow, &callback).is_err());
    }

    /// Insecure issuer and non-loopback plaintext redirects fail before discovery.
    #[test]
    fn rejects_insecure_client_configuration() {
        let fake: Arc<dyn SessionHttp> = Arc::new(FakeHttp {
            responses: Mutex::new(VecDeque::new()),
            forms: Mutex::new(Vec::new()),
        });
        let mut invalid = config();
        invalid.issuer = Url::parse("http://issuer.example").expect("issuer URL");
        assert!(SessionClient::discover_with_http(invalid, Arc::clone(&fake)).is_err());
        let mut invalid = config();
        invalid.redirect_uri = Url::parse("http://desktop.example/callback").expect("redirect URL");
        assert!(SessionClient::discover_with_http(invalid, fake).is_err());
    }
}
