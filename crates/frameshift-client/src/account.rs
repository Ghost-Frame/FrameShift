//! Account authentication, profile, and administrator control operations.
//!
//! Access tokens enter only through [`SecretString`] and are attached solely
//! to the registry request's `Authorization` header.

use std::fmt;
use std::net::IpAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use frameshift_catalog::{
    AccountInviteRecord, AccountInviteRequestRecord, AccountInviteStatus, AccountRecord,
    AccountStatus, PlatformRole, PlatformRoleRecord, PublisherMembershipRecord,
    PublisherProfileRecord,
};
use rand_core::{OsRng, RngCore as _};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ClientError;
use crate::session::AuthenticatedSession;

/// Public account-authentication bootstrap configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountAuthConfig {
    /// Whether authenticated account routes are enabled (OIDC or first-party).
    pub enabled: bool,
    /// Exact configured OIDC issuer when OIDC bearer auth is enabled.
    ///
    /// A registry running in first-party-only mode reports `enabled = true`
    /// with `issuer = None`; clients must consult [`Self::first_party_enabled`]
    /// before concluding that the registry misreported its OIDC issuer.
    pub issuer: Option<String>,
    /// Access-token audience expected by the registry when OIDC is enabled.
    pub audience: Option<String>,
    /// Whether the registry accepts invite-bound first-party password sessions.
    ///
    /// Defaults to `false` so responses from older registries that do not yet
    /// advertise the field deserialize unchanged.
    #[serde(default)]
    pub first_party_enabled: bool,
    /// First-party registration policy advertised by the registry.
    #[serde(default)]
    pub registration: Option<String>,
    /// Trusted browser portal used for first-party native authorization.
    #[serde(default)]
    pub native_authorization_url: Option<String>,
}

/// Native first-party client presentation requested from the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAuthClient {
    /// Desktop application session.
    Desktop,
    /// Command-line session.
    Cli,
}

/// Stable wire spellings for native client presentations.
impl NativeAuthClient {
    /// Return the exact query and JSON value bound into the authorization flow.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Cli => "cli",
        }
    }
}

/// Browser experience requested by one native authorization flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAuthorizationIntent {
    /// Authenticate an existing account before authorizing the native client.
    Login,
    /// Redeem an invitation in the browser before authorizing the native client.
    Register,
}

/// Stable browser intents understood by the first-party account portal.
impl NativeAuthorizationIntent {
    /// Return the exact portal query value for this browser experience.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "native_authorize",
            Self::Register => "native_register",
        }
    }
}

/// Pending first-party native browser authorization bound to S256 PKCE.
pub struct NativeAuthorizationFlow {
    /// Trusted HTTPS portal URL that the caller opens in the system browser.
    pub authorization_url: Url,
    /// Exact IP-literal loopback callback registered by the native client.
    redirect_uri: Url,
    /// Desktop or CLI presentation bound into the one-time code.
    client_kind: NativeAuthClient,
    /// Random callback state retained for exact constant-time comparison.
    state: SecretString,
    /// Random PKCE verifier retained only until one code exchange.
    code_verifier: SecretString,
}

/// Redact every random flow binding from diagnostics.
impl fmt::Debug for NativeAuthorizationFlow {
    /// Render only query-free portal and loopback URLs.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut portal = self.authorization_url.clone();
        portal.set_query(None);
        formatter
            .debug_struct("NativeAuthorizationFlow")
            .field("authorization_url", &portal)
            .field("redirect_uri", &self.redirect_uri)
            .field("client_kind", &self.client_kind)
            .field("state", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .finish()
    }
}

/// Native first-party authorization or token-lifecycle failure.
#[derive(Debug, thiserror::Error)]
pub enum NativeAuthError {
    /// Registry discovery or a token endpoint failed.
    #[error(transparent)]
    Registry(#[from] ClientError),
    /// Trusted portal or loopback callback configuration was unsafe.
    #[error("invalid native authorization configuration: {0}")]
    InvalidConfiguration(String),
    /// The browser callback did not match the pending flow.
    #[error("native authorization callback rejected: {0}")]
    InvalidCallback(String),
    /// A successful registry response violated the frozen token contract.
    #[error("native authorization response rejected: {0}")]
    InvalidResponse(String),
}

/// Successful first-party authentication with its secret-bearing session.
pub struct LocalAccountSession {
    /// Durable authenticated account returned by the registry.
    pub account: AccountRecord,
    /// Opaque native bearer session.
    pub session: AuthenticatedSession,
}

/// Redacted diagnostics for one local authentication result.
impl std::fmt::Debug for LocalAccountSession {
    /// Render public account metadata and the session's redacted representation.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalAccountSession")
            .field("account", &self.account)
            .field("session", &self.session)
            .finish()
    }
}

/// Native authorization-code exchange fields serialized at the HTTP boundary.
#[derive(Serialize)]
struct NativeAuthorizationCodeRequest<'a> {
    /// Frozen grant identifier for one-time native codes.
    grant_type: &'static str,
    /// One-time random authorization code exposed only to the serializer.
    code: &'a str,
    /// Secret S256 verifier exposed only to the serializer.
    code_verifier: &'a str,
    /// Exact IP-literal loopback URI bound into the code.
    redirect_uri: &'a str,
    /// Desktop or CLI presentation bound into the code.
    client_kind: NativeAuthClient,
}

/// Native refresh request serialized only at the HTTP boundary.
#[derive(Serialize)]
struct NativeRefreshRequest<'a> {
    /// Desktop or CLI presentation bound into the session family.
    client_kind: NativeAuthClient,
    /// Current rotating refresh credential exposed only to the serializer.
    refresh_token: &'a str,
}

/// Wire response carrying rotating native credentials that are wiped after conversion.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeTokenResponse {
    /// Durable authenticated account.
    account: AccountRecord,
    /// Current short-lived opaque access token.
    access_token: Option<String>,
    /// Current rotating opaque refresh token.
    refresh_token: Option<String>,
    /// Required HTTP authorization scheme.
    token_type: String,
    /// Exclusive access-token expiry.
    expires_at: DateTime<Utc>,
    /// Exclusive refresh-generation expiry.
    refresh_expires_at: DateTime<Utc>,
    /// Non-extendable session-family expiry.
    session_expires_at: DateTime<Utc>,
}

/// Wipe temporary raw native credentials when their wire value leaves scope.
impl Drop for NativeTokenResponse {
    /// Zero both optional token strings.
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        if let Some(token) = &mut self.access_token {
            token.zeroize();
        }
        if let Some(token) = &mut self.refresh_token {
            token.zeroize();
        }
    }
}

/// Stable local logout acknowledgement.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalLogoutResponse {
    /// Whether the registry accepted the revocation.
    logged_out: bool,
}

/// Caller-controlled field for one administrator platform-role grant.
#[derive(Serialize)]
struct AssignPlatformRoleRequest {
    /// Global authority being granted to the target account.
    role: PlatformRole,
}

/// Caller-controlled field for one administrator account status transition.
#[derive(Serialize)]
struct SetAccountStatusRequest {
    /// Status the target account must hold after the transition.
    status: AccountStatus,
}

/// Mutable authenticated-account profile fields serialized at the HTTP boundary.
#[derive(Serialize)]
struct UpdateAccountProfileRequest<'a> {
    /// Replacement email metadata when supplied.
    email: Option<&'a str>,
    /// Replacement display name when supplied.
    display_name: Option<&'a str>,
}

/// New publisher profile fields serialized at the HTTP boundary.
#[derive(Serialize)]
struct CreatePublisherProfileRequest<'a> {
    /// Unique public publisher handle.
    handle: &'a str,
    /// Public publisher display name.
    display_name: &'a str,
    /// Optional public biography.
    biography: Option<&'a str>,
}

/// Mutable publisher profile fields serialized at the HTTP boundary.
#[derive(Serialize)]
struct UpdatePublisherProfileRequest<'a> {
    /// Replacement public display name.
    display_name: &'a str,
    /// Replacement biography when supplied.
    biography: Option<&'a str>,
    /// Whether to remove an existing biography.
    clear_biography: bool,
}

/// Non-issued review states accepted by the administrator PATCH route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountInviteReviewStatus {
    /// Return an application to the initial review queue.
    Pending,
    /// Mark an application as actively under review.
    Reviewing,
    /// Decline an application while retaining its audit record.
    Declined,
}

/// Caller-controlled field for one administrator invite-request review.
#[derive(Serialize)]
struct ReviewAccountInviteRequest {
    /// Non-issued state the application must hold after the transition.
    status: AccountInviteReviewStatus,
}

/// Wire response containing an invitation token that is wiped after conversion.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuedAccountInviteResponse {
    /// Durable non-secret invitation metadata.
    invite: AccountInviteRecord,
    /// Raw one-time token returned only at issuance.
    token: Option<String>,
}

/// Wipe the raw invitation token when its temporary wire value leaves scope.
impl Drop for IssuedAccountInviteResponse {
    /// Zero the optional raw token string.
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        if let Some(token) = &mut self.token {
            token.zeroize();
        }
    }
}

/// One newly issued invitation with its secret-bearing one-time token.
pub struct IssuedAccountInvite {
    /// Durable invitation metadata safe for normal structured output.
    pub invite: AccountInviteRecord,
    /// Raw one-time token retained in secret memory.
    token: SecretString,
}

/// Redacted diagnostics for one newly issued account invitation.
impl std::fmt::Debug for IssuedAccountInvite {
    /// Render invitation metadata while withholding the raw token.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedAccountInvite")
            .field("invite", &self.invite)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Expose the one-time token only to callers that deliberately deliver it.
impl IssuedAccountInvite {
    /// Borrow the secret invitation token.
    #[must_use]
    pub fn token(&self) -> &SecretString {
        &self.token
    }
}

/// Authenticated account profile and its publisher memberships.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountView {
    /// Durable account record.
    pub account: AccountRecord,
    /// Publisher memberships held by the account.
    pub memberships: Vec<PublisherMembershipRecord>,
    /// Publisher profiles aligned with memberships when supplied by the registry.
    #[serde(default)]
    pub publishers: Vec<PublisherProfileRecord>,
}

/// Fetch the registry's non-secret account-authentication configuration.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, or JSON error.
pub fn get_auth_config(server_url: &str) -> Result<AccountAuthConfig, ClientError> {
    let url = crate::publisher::registry_endpoint_url(server_url, &["v1", "auth", "config"])?;
    let request = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .get(url.as_str());
    match request.call() {
        Ok(response) => crate::registry::response_json_bounded(response, url.as_str()),
        Err(ureq::Error::Status(status, response)) => Err(ClientError::RegistryRejected {
            url: url.to_string(),
            status,
            message: crate::registry::response_text_bounded(response, url.as_str()),
        }),
        Err(error) => Err(ClientError::RegistryHttp {
            url: url.to_string(),
            detail: error.to_string(),
        }),
    }
}

/// Begin a browser-owned first-party authorization bound to one loopback listener.
///
/// # Errors
///
/// Returns a configuration error when the registry does not advertise the exact
/// HTTPS account portal or the callback is not an exact IP-literal loopback URL.
pub fn begin_native_authorization(
    config: &AccountAuthConfig,
    client_kind: NativeAuthClient,
    redirect_uri: Url,
    intent: NativeAuthorizationIntent,
) -> Result<NativeAuthorizationFlow, NativeAuthError> {
    if !config.first_party_enabled {
        return Err(NativeAuthError::InvalidConfiguration(
            "registry does not advertise first-party authentication".to_string(),
        ));
    }
    let portal = config.native_authorization_url.as_deref().ok_or_else(|| {
        NativeAuthError::InvalidConfiguration(
            "registry omitted its native authorization portal".to_string(),
        )
    })?;
    let mut authorization_url = validate_native_portal(portal)?;
    validate_native_redirect(&redirect_uri)?;

    let state = random_native_binding();
    let code_verifier = random_native_binding();
    let challenge =
        URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.expose_secret().as_bytes()));
    authorization_url
        .query_pairs_mut()
        .append_pair("intent", intent.as_str())
        .append_pair("client_kind", client_kind.as_str())
        .append_pair("redirect_uri", redirect_uri.as_str())
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state.expose_secret());

    Ok(NativeAuthorizationFlow {
        authorization_url,
        redirect_uri,
        client_kind,
        state,
        code_verifier,
    })
}

/// Exchange an exact native browser callback for rotating first-party credentials.
///
/// # Errors
///
/// Returns a callback error before transport when the loopback URL or state does
/// not exactly match the pending flow. Registry and response failures never
/// include the code, verifier, state, access token, or refresh token.
pub fn complete_native_authorization(
    server_url: &str,
    flow: NativeAuthorizationFlow,
    callback_url: &Url,
) -> Result<LocalAccountSession, NativeAuthError> {
    let (code, _returned_state) = validate_native_callback(&flow, callback_url)?;
    let redirect_uri = flow.redirect_uri.as_str();
    let request = NativeAuthorizationCodeRequest {
        grant_type: "authorization_code",
        code: &code,
        code_verifier: flow.code_verifier.expose_secret(),
        redirect_uri,
        client_kind: flow.client_kind,
    };
    let response = post_native_token_json(server_url, &["native", "token"], &request)?;
    native_session_from_response(response)
}

/// Rotate a first-party native refresh credential and access token.
///
/// # Errors
///
/// Returns registry, JSON, response-contract, token-validation, or expiry errors
/// without including either rotating credential.
pub fn refresh_local_account(
    server_url: &str,
    refresh_token: &SecretString,
    client_kind: NativeAuthClient,
) -> Result<LocalAccountSession, NativeAuthError> {
    let request = NativeRefreshRequest {
        client_kind,
        refresh_token: refresh_token.expose_secret(),
    };
    let response = post_native_token_json(server_url, &["refresh"], &request)?;
    native_session_from_response(response)
}

/// Revoke one first-party bearer session at the registry.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, or JSON error without ever
/// including the bearer token in the diagnostic.
pub fn logout_local_account(
    server_url: &str,
    access_token: &SecretString,
) -> Result<(), ClientError> {
    let url = crate::publisher::registry_endpoint_url(server_url, &["v1", "auth", "logout"])?;
    let request = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .post(url.as_str());
    match crate::publisher::with_bearer(request, access_token).call() {
        Ok(response) => {
            let acknowledgement: LocalLogoutResponse =
                crate::registry::response_json_bounded(response, url.as_str())?;
            if acknowledgement.logged_out {
                Ok(())
            } else {
                Err(ClientError::RegistryRejected {
                    url: url.to_string(),
                    status: 502,
                    message: "registry did not acknowledge local logout".to_string(),
                })
            }
        }
        Err(ureq::Error::Status(status, response)) => Err(ClientError::RegistryRejected {
            url: url.to_string(),
            status,
            message: crate::registry::response_text_bounded(response, url.as_str()),
        }),
        Err(error) => Err(ClientError::RegistryHttp {
            url: url.to_string(),
            detail: error.to_string(),
        }),
    }
}

/// Submit one first-party credential request and validate its native session.
fn post_native_token_json(
    server_url: &str,
    operation: &[&str],
    request: &impl Serialize,
) -> Result<NativeTokenResponse, NativeAuthError> {
    let mut segments = vec!["v1", "auth"];
    segments.extend_from_slice(operation);
    let url = crate::publisher::registry_endpoint_url(server_url, &segments)?;
    let body = Zeroizing::new(
        serde_json::to_vec(request)
            .map_err(|error| ClientError::JsonSerialize(error.to_string()))?,
    );
    let response = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .post(url.as_str())
        .set("Content-Type", "application/json")
        .send_bytes(body.as_slice());
    match response {
        Ok(response) => crate::registry::response_json_bounded(response, url.as_str())
            .map_err(NativeAuthError::from),
        Err(ureq::Error::Status(status, response)) => Err(ClientError::RegistryRejected {
            url: url.to_string(),
            status,
            message: crate::registry::response_text_bounded(response, url.as_str()),
        }
        .into()),
        Err(error) => Err(ClientError::RegistryHttp {
            url: url.to_string(),
            detail: error.to_string(),
        }
        .into()),
    }
}

/// Convert and validate one frozen native token response.
fn native_session_from_response(
    mut response: NativeTokenResponse,
) -> Result<LocalAccountSession, NativeAuthError> {
    if response.token_type != "Bearer" {
        return Err(NativeAuthError::InvalidResponse(
            "registry returned an unsupported token type".to_string(),
        ));
    }
    let now = Utc::now();
    if response.expires_at <= now
        || response.refresh_expires_at < response.expires_at
        || response.session_expires_at < response.refresh_expires_at
    {
        return Err(NativeAuthError::InvalidResponse(
            "registry returned inconsistent native session expiries".to_string(),
        ));
    }
    let access_token = response.access_token.take().ok_or_else(|| {
        NativeAuthError::InvalidResponse("registry omitted the native access token".to_string())
    })?;
    let refresh_token = response.refresh_token.take().ok_or_else(|| {
        NativeAuthError::InvalidResponse("registry omitted the native refresh token".to_string())
    })?;
    let expires_at = u64::try_from(response.expires_at.timestamp()).map_err(|_| {
        NativeAuthError::InvalidResponse(
            "registry returned an invalid native access expiry".to_string(),
        )
    })?;
    let session = AuthenticatedSession::from_first_party_tokens(
        SecretString::new(access_token),
        SecretString::new(refresh_token),
        expires_at,
    )
    .map_err(|_| {
        NativeAuthError::InvalidResponse(
            "registry returned invalid native token material".to_string(),
        )
    })?;
    Ok(LocalAccountSession {
        account: response.account.clone(),
        session,
    })
}

/// Parse and validate the registry-advertised browser portal.
fn validate_native_portal(value: &str) -> Result<Url, NativeAuthError> {
    let url = Url::parse(value).map_err(|_| {
        NativeAuthError::InvalidConfiguration(
            "native authorization portal is not a valid URL".to_string(),
        )
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/account/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(NativeAuthError::InvalidConfiguration(
            "native authorization portal must be a credential-free HTTPS /account/ URL".to_string(),
        ));
    }
    Ok(url)
}

/// Require an exact HTTP callback on an IP-literal loopback address and explicit port.
fn validate_native_redirect(url: &Url) -> Result<(), NativeAuthError> {
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if url.scheme() != "http"
        || !loopback
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(NativeAuthError::InvalidConfiguration(
            "native callback must be an exact query-free HTTP IP-literal loopback URL with an explicit port"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validate one callback and return its one-time code and state without logging them.
fn validate_native_callback(
    flow: &NativeAuthorizationFlow,
    callback_url: &Url,
) -> Result<(String, String), NativeAuthError> {
    if callback_url.fragment().is_some() {
        return Err(NativeAuthError::InvalidCallback(
            "callback included a fragment".to_string(),
        ));
    }
    let mut callback_base = callback_url.clone();
    callback_base.set_query(None);
    if callback_base != flow.redirect_uri {
        return Err(NativeAuthError::InvalidCallback(
            "callback URL did not match the pending loopback listener".to_string(),
        ));
    }
    let mut code = None;
    let mut state = None;
    for (name, value) in callback_url.query_pairs() {
        let slot = match name.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            _ => {
                return Err(NativeAuthError::InvalidCallback(
                    "callback included an unsupported query field".to_string(),
                ));
            }
        };
        if value.is_empty() || slot.replace(value.into_owned()).is_some() {
            return Err(NativeAuthError::InvalidCallback(
                "callback included an empty or repeated query field".to_string(),
            ));
        }
    }
    let code = code.ok_or_else(|| {
        NativeAuthError::InvalidCallback("callback omitted the authorization code".to_string())
    })?;
    let state = state.ok_or_else(|| {
        NativeAuthError::InvalidCallback("callback omitted the authorization state".to_string())
    })?;
    if !constant_time_equal(flow.state.expose_secret().as_bytes(), state.as_bytes()) {
        return Err(NativeAuthError::InvalidCallback(
            "callback state did not match the pending authorization".to_string(),
        ));
    }
    Ok((code, state))
}

/// Generate one 256-bit URL-safe native authorization binding.
fn random_native_binding() -> SecretString {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    SecretString::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}

/// Compare two byte strings without data-dependent early exit.
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

/// Fetch the current account view from one FrameShift registry.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, or JSON error without ever
/// including the bearer token in the diagnostic.
pub fn get_account(
    server_url: &str,
    access_token: &SecretString,
) -> Result<AccountView, ClientError> {
    let url = crate::publisher::registry_endpoint_url(server_url, &["v1", "account"])?;
    let request = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .get(url.as_str());
    match crate::publisher::with_bearer(request, access_token).call() {
        Ok(response) => crate::registry::response_json_bounded(response, url.as_str()),
        Err(ureq::Error::Status(status, response)) => Err(ClientError::RegistryRejected {
            url: url.to_string(),
            status,
            message: crate::registry::response_text_bounded(response, url.as_str()),
        }),
        Err(error) => Err(ClientError::RegistryHttp {
            url: url.to_string(),
            detail: error.to_string(),
        }),
    }
}

/// Fetch one public publisher profile by handle.
///
/// This endpoint is intentionally unauthenticated because publisher profiles
/// are public registry metadata.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, or JSON error.
pub fn get_publisher_profile(
    server_url: &str,
    handle: &str,
) -> Result<PublisherProfileRecord, ClientError> {
    let url = crate::publisher::registry_endpoint_url(server_url, &["v1", "publishers", handle])?;
    let request = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .get(url.as_str());
    match request.call() {
        Ok(response) => crate::registry::response_json_bounded(response, url.as_str()),
        Err(ureq::Error::Status(status, response)) => Err(ClientError::RegistryRejected {
            url: url.to_string(),
            status,
            message: crate::registry::response_text_bounded(response, url.as_str()),
        }),
        Err(error) => Err(ClientError::RegistryHttp {
            url: url.to_string(),
            detail: error.to_string(),
        }),
    }
}

/// Update mutable metadata for the authenticated account.
///
/// Omitted fields retain their current values. Text validation remains owned
/// by the registry so its public bounds cannot drift from the client.
///
/// # Errors
///
/// Returns an input-shape, registry URL, transport, status, size, JSON
/// serialization, or JSON response error without including the bearer token.
pub fn update_account_profile(
    server_url: &str,
    access_token: &SecretString,
    email: Option<&str>,
    display_name: Option<&str>,
) -> Result<AccountRecord, ClientError> {
    if email.is_none() && display_name.is_none() {
        return Err(ClientError::InvalidAccountProfileInput {
            detail: "email or display_name must be supplied".to_string(),
        });
    }
    let url = crate::publisher::registry_endpoint_url(server_url, &["v1", "account"])?;
    send_account_json(
        crate::registry::http_agent().request("PATCH", url.as_str()),
        &url,
        access_token,
        &UpdateAccountProfileRequest {
            email,
            display_name,
        },
    )
}

/// Create a pending publisher profile owned by the authenticated account.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, JSON serialization, or JSON
/// response error without including the bearer token.
pub fn create_publisher_profile(
    server_url: &str,
    access_token: &SecretString,
    handle: &str,
    display_name: &str,
    biography: Option<&str>,
) -> Result<PublisherProfileRecord, ClientError> {
    let url = crate::publisher::registry_endpoint_url(server_url, &["v1", "publishers"])?;
    send_account_json(
        crate::registry::http_agent().post(url.as_str()),
        &url,
        access_token,
        &CreatePublisherProfileRequest {
            handle,
            display_name,
            biography,
        },
    )
}

/// Update a publisher profile under active-owner authority.
///
/// An omitted biography retains its current value. `clear_biography` removes
/// it, and cannot be combined with a replacement biography.
///
/// # Errors
///
/// Returns an input-shape, registry URL, transport, status, size, JSON
/// serialization, or JSON response error without including the bearer token.
pub fn update_publisher_profile(
    server_url: &str,
    access_token: &SecretString,
    handle: &str,
    display_name: &str,
    biography: Option<&str>,
    clear_biography: bool,
) -> Result<PublisherProfileRecord, ClientError> {
    if biography.is_some() && clear_biography {
        return Err(ClientError::InvalidAccountProfileInput {
            detail: "biography and clear_biography cannot be supplied together".to_string(),
        });
    }
    let url = crate::publisher::registry_endpoint_url(server_url, &["v1", "publishers", handle])?;
    send_account_json(
        crate::registry::http_agent().request("PATCH", url.as_str()),
        &url,
        access_token,
        &UpdatePublisherProfileRequest {
            display_name,
            biography,
            clear_biography,
        },
    )
}

/// Grant one global platform role under authenticated administrator authority.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, JSON serialization, or JSON
/// response error without including the bearer token in the diagnostic.
pub fn assign_account_platform_role(
    server_url: &str,
    access_token: &SecretString,
    account_id: Uuid,
    role: PlatformRole,
) -> Result<PlatformRoleRecord, ClientError> {
    let url = administrator_account_url(server_url, account_id, &["platform-roles"])?;
    send_account_json(
        crate::registry::http_agent().post(url.as_str()),
        &url,
        access_token,
        &AssignPlatformRoleRequest { role },
    )
}

/// Revoke one global platform role under authenticated administrator authority.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, or JSON response error
/// without including the bearer token in the diagnostic.
pub fn revoke_account_platform_role(
    server_url: &str,
    access_token: &SecretString,
    account_id: Uuid,
    role: PlatformRole,
) -> Result<PlatformRoleRecord, ClientError> {
    let role = match role {
        PlatformRole::Moderator => "moderator",
        PlatformRole::Administrator => "administrator",
    };
    let url = administrator_account_url(server_url, account_id, &["platform-roles", role])?;
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent().delete(url.as_str()),
        access_token,
    );
    crate::publisher::send_and_decode(request.call(), url.as_str())
}

/// Set one account lifecycle status under authenticated administrator authority.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, JSON serialization, or JSON
/// response error without including the bearer token in the diagnostic.
pub fn set_account_status(
    server_url: &str,
    access_token: &SecretString,
    account_id: Uuid,
    status: AccountStatus,
) -> Result<AccountRecord, ClientError> {
    let url = administrator_account_url(server_url, account_id, &["status"])?;
    send_account_json(
        crate::registry::http_agent().request("PATCH", url.as_str()),
        &url,
        access_token,
        &SetAccountStatusRequest { status },
    )
}

/// List administrator-visible account invitation requests.
///
/// # Errors
///
/// Returns an input-bound, registry URL, transport, status, size, or JSON
/// response error without including the bearer token in the diagnostic.
pub fn list_account_invite_requests(
    server_url: &str,
    access_token: &SecretString,
    status: Option<AccountInviteStatus>,
    limit: u32,
) -> Result<Vec<AccountInviteRequestRecord>, ClientError> {
    if !(1..=200).contains(&limit) {
        return Err(ClientError::InvalidAccountInviteInput {
            detail: "limit must be between 1 and 200".to_string(),
        });
    }
    let mut url = administrator_invite_url(server_url, &[])?;
    let mut query = url.query_pairs_mut();
    if let Some(status) = status {
        query.append_pair("status", account_invite_status_name(status));
    }
    query.append_pair("limit", &limit.to_string());
    drop(query);
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent().get(url.as_str()),
        access_token,
    );
    crate::publisher::send_and_decode(request.call(), url.as_str())
}

/// Transition one account invitation request to a non-issued review state.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, JSON serialization, or JSON
/// response error without including the bearer token in the diagnostic.
pub fn review_account_invite_request(
    server_url: &str,
    access_token: &SecretString,
    request_id: Uuid,
    status: AccountInviteReviewStatus,
) -> Result<AccountInviteRequestRecord, ClientError> {
    let request = request_id.to_string();
    let url = administrator_invite_url(server_url, &[&request])?;
    send_account_json(
        crate::registry::http_agent().request("PATCH", url.as_str()),
        &url,
        access_token,
        &ReviewAccountInviteRequest { status },
    )
}

/// Issue one account invitation and retain its raw token as a secret.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, JSON, or token-validation
/// error without including either bearer or invitation token in the diagnostic.
pub fn issue_account_invite(
    server_url: &str,
    access_token: &SecretString,
    request_id: Uuid,
) -> Result<IssuedAccountInvite, ClientError> {
    let request = request_id.to_string();
    let url = administrator_invite_url(server_url, &[&request, "invite"])?;
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent().post(url.as_str()),
        access_token,
    );
    let mut response: IssuedAccountInviteResponse =
        crate::publisher::send_and_decode(request.call(), url.as_str())?;
    let mut token = response
        .token
        .take()
        .ok_or_else(|| invalid_invitation_token(&url))?;
    let mut decoded = Zeroizing::new([0_u8; 32]);
    let valid_token = base64::Engine::decode_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        token.as_bytes(),
        decoded.as_mut(),
    )
    .is_ok_and(|length| length == decoded.len());
    if !valid_token {
        use zeroize::Zeroize as _;
        token.zeroize();
        return Err(invalid_invitation_token(&url));
    }
    Ok(IssuedAccountInvite {
        invite: response.invite.clone(),
        token: SecretString::new(token),
    })
}

/// Build one administrator account endpoint while preserving a registry base path.
fn administrator_account_url(
    server_url: &str,
    account_id: Uuid,
    suffix: &[&str],
) -> Result<url::Url, ClientError> {
    let account = account_id.to_string();
    let mut segments = vec!["v1", "admin", "accounts", account.as_str()];
    segments.extend_from_slice(suffix);
    crate::publisher::registry_endpoint_url(server_url, &segments)
}

/// Build one administrator invitation endpoint while preserving a registry base path.
fn administrator_invite_url(server_url: &str, suffix: &[&str]) -> Result<url::Url, ClientError> {
    let mut segments = vec!["v1", "admin", "invite-requests"];
    segments.extend_from_slice(suffix);
    crate::publisher::registry_endpoint_url(server_url, &segments)
}

/// Render one invitation status in its exact query-string spelling.
const fn account_invite_status_name(status: AccountInviteStatus) -> &'static str {
    match status {
        AccountInviteStatus::Pending => "pending",
        AccountInviteStatus::Reviewing => "reviewing",
        AccountInviteStatus::Invited => "invited",
        AccountInviteStatus::Declined => "declined",
    }
}

/// Build one bounded server-response error for a missing or malformed invitation token.
fn invalid_invitation_token(url: &url::Url) -> ClientError {
    ClientError::RegistryRejected {
        url: url.to_string(),
        status: 502,
        message: "registry returned an invalid one-time invitation token".to_string(),
    }
}

/// Send one bearer-authenticated administrator account JSON mutation.
fn send_account_json<T: Serialize, R: serde::de::DeserializeOwned>(
    request: ureq::Request,
    url: &url::Url,
    access_token: &SecretString,
    body: &T,
) -> Result<R, ClientError> {
    let bytes =
        serde_json::to_vec(body).map_err(|error| ClientError::JsonSerialize(error.to_string()))?;
    let request = crate::publisher::with_bearer(
        request.set("Content-Type", "application/json"),
        access_token,
    );
    crate::publisher::send_and_decode(request.send_bytes(&bytes), url.as_str())
}

#[cfg(test)]
/// Account HTTP client regression tests.
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use super::*;

    /// Read one complete bounded HTTP request including its declared body.
    fn read_request(stream: &mut std::net::TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let count = stream.read(&mut chunk).expect("read request");
            if count == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..count]);
            let Some(headers_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
            else {
                continue;
            };
            let headers_end = headers_end + 4;
            let headers = String::from_utf8_lossy(&request[..headers_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            if request.len() >= headers_end + content_length {
                break;
            }
        }
        String::from_utf8(request).expect("request UTF-8")
    }

    /// Serve one fixed JSON response and return the captured request.
    fn serve_json_response(body: impl Into<String>) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let body = body.into();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_request(&mut stream);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            request
        });
        (format!("http://{address}"), handle)
    }

    /// Return one stable account JSON object for native-auth responses.
    fn account_json() -> &'static str {
        r#"{"id":"00000000-0000-0000-0000-000000000001","issuer":"https://issuer.example","subject":"subject-1","email":"alice@example.com","display_name":"Alice","status":"active","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#
    }

    /// Return a first-party configuration advertising the exact browser portal.
    fn native_auth_config() -> AccountAuthConfig {
        AccountAuthConfig {
            enabled: true,
            issuer: None,
            audience: None,
            first_party_enabled: true,
            registration: Some("invite_only".to_string()),
            native_authorization_url: Some("https://market.example/account/".to_string()),
        }
    }

    /// Return one frozen rotating native token response with future expiries.
    fn native_token_json(access_token: &str, refresh_token: &str) -> String {
        format!(
            r#"{{"account":{},"access_token":"{access_token}","refresh_token":"{refresh_token}","token_type":"Bearer","expires_at":"2099-01-01T00:00:00Z","refresh_expires_at":"2099-02-01T00:00:00Z","session_expires_at":"2099-03-01T00:00:00Z"}}"#,
            account_json()
        )
    }

    /// Return one stable publisher profile JSON object for mutation responses.
    fn publisher_json() -> &'static str {
        r#"{"id":"00000000-0000-0000-0000-000000000002","handle":"gatekeeper","display_name":"Gatekeeper","biography":"Verifies releases.","moderation_status":"pending","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#
    }

    /// Account lookup sends the bearer only in the authorization header.
    #[test]
    fn fetches_account_with_bearer_header() {
        let body = format!(r#"{{"account":{},"memberships":[]}}"#, account_json());
        let (server, handle) = serve_json_response(body);
        let token = SecretString::new("test-access-token".to_string());
        let view = get_account(&server, &token).expect("account response");
        assert_eq!(view.account.display_name.as_deref(), Some("Alice"));
        assert!(view.publishers.is_empty());
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with("GET /v1/account HTTP/1.1\r\n"));
        assert!(request.contains("\r\nAuthorization: Bearer test-access-token\r\n"));
        assert_eq!(request.matches("test-access-token").count(), 1);
    }

    /// Public publisher lookup preserves base paths without adding authority.
    #[test]
    fn fetches_public_publisher_profile_without_authorization() {
        let (server, handle) = serve_json_response(publisher_json());
        let server = format!("{server}/registry");
        let publisher =
            get_publisher_profile(&server, "gatekeeper").expect("publisher profile response");
        assert_eq!(publisher.handle, "gatekeeper");
        let request = handle.join().expect("publisher request thread");
        assert!(request.starts_with("GET /registry/v1/publishers/gatekeeper HTTP/1.1\r\n"));
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
    }

    /// Profile mutations preserve base paths, bearer authority, and exact JSON fields.
    #[test]
    fn sends_account_and_publisher_profile_mutations() {
        let token = SecretString::new("profile-token".to_string());

        let (server, handle) = serve_json_response(account_json());
        let server = format!("{server}/registry");
        let account =
            update_account_profile(&server, &token, Some("new@example.test"), Some("New Name"))
                .expect("account profile response");
        assert_eq!(account.id, Uuid::from_u128(1));
        let request = handle.join().expect("account request thread");
        assert!(request.starts_with("PATCH /registry/v1/account HTTP/1.1\r\n"));
        assert!(request.contains("\r\nAuthorization: Bearer profile-token\r\n"));
        assert!(request.contains(r#"{"email":"new@example.test","display_name":"New Name"}"#));
        assert_eq!(request.matches("profile-token").count(), 1);

        let (server, handle) = serve_json_response(publisher_json());
        let server = format!("{server}/registry");
        let publisher = create_publisher_profile(
            &server,
            &token,
            "gatekeeper",
            "Gatekeeper",
            Some("Verifies releases."),
        )
        .expect("publisher creation response");
        assert_eq!(publisher.handle, "gatekeeper");
        let request = handle.join().expect("publisher creation thread");
        assert!(request.starts_with("POST /registry/v1/publishers HTTP/1.1\r\n"));
        assert!(request.contains(r#"{"handle":"gatekeeper","display_name":"Gatekeeper","biography":"Verifies releases."}"#));
        assert_eq!(request.matches("profile-token").count(), 1);

        let (server, handle) = serve_json_response(publisher_json());
        let server = format!("{server}/registry");
        update_publisher_profile(&server, &token, "gatekeeper", "Gatekeeper", None, true)
            .expect("publisher update response");
        let request = handle.join().expect("publisher update thread");
        assert!(request.starts_with("PATCH /registry/v1/publishers/gatekeeper HTTP/1.1\r\n"));
        assert!(request
            .contains(r#"{"display_name":"Gatekeeper","biography":null,"clear_biography":true}"#));
        assert_eq!(request.matches("profile-token").count(), 1);
    }

    /// Structurally ambiguous profile mutations fail before transport.
    #[test]
    fn rejects_ambiguous_profile_mutations() {
        let token = SecretString::new("profile-token".to_string());
        let empty = update_account_profile("https://registry.example", &token, None, None)
            .expect_err("empty account profile update");
        assert!(matches!(
            empty,
            ClientError::InvalidAccountProfileInput { .. }
        ));

        let conflicting = update_publisher_profile(
            "https://registry.example",
            &token,
            "gatekeeper",
            "Gatekeeper",
            Some("New biography"),
            true,
        )
        .expect_err("conflicting biography update");
        assert!(matches!(
            conflicting,
            ClientError::InvalidAccountProfileInput { .. }
        ));
    }

    /// Native browser authorization binds exact intent, client, callback, state, and S256 PKCE.
    #[test]
    fn begins_exact_native_browser_authorization_without_debug_disclosure() {
        let redirect = Url::parse("http://127.0.0.1:43119/callback").expect("redirect URL");
        let flow = begin_native_authorization(
            &native_auth_config(),
            NativeAuthClient::Cli,
            redirect.clone(),
            NativeAuthorizationIntent::Login,
        );
        let flow = flow.expect("native flow");
        let pairs: std::collections::HashMap<_, _> =
            flow.authorization_url.query_pairs().into_owned().collect();
        assert_eq!(flow.authorization_url.path(), "/account/");
        assert_eq!(
            pairs.get("intent").map(String::as_str),
            Some("native_authorize")
        );
        assert_eq!(pairs.get("client_kind").map(String::as_str), Some("cli"));
        assert_eq!(
            pairs.get("redirect_uri").map(String::as_str),
            Some(redirect.as_str())
        );
        assert_eq!(
            pairs.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(pairs.get("state").map(String::len), Some(43));
        assert_eq!(pairs.get("code_challenge").map(String::len), Some(43));

        let debug = format!("{flow:?}");
        assert!(!debug.contains(flow.state.expose_secret()));
        assert!(!debug.contains(pairs.get("code_challenge").expect("PKCE challenge")));
        assert!(!debug.contains(flow.code_verifier.expose_secret()));
    }

    /// Unsafe portal and loopback variants fail before a browser is opened.
    #[test]
    fn rejects_unsafe_native_authorization_configuration() {
        let redirect = Url::parse("http://127.0.0.1:43119/callback").expect("redirect URL");
        for portal in [
            "http://market.example/account/",
            "https://user@market.example/account/",
            "https://market.example/account",
            "https://market.example/account/?source=unsafe",
        ] {
            let mut config = native_auth_config();
            config.native_authorization_url = Some(portal.to_string());
            assert!(matches!(
                begin_native_authorization(
                    &config,
                    NativeAuthClient::Desktop,
                    redirect.clone(),
                    NativeAuthorizationIntent::Register,
                ),
                Err(NativeAuthError::InvalidConfiguration(_))
            ));
        }
        for callback in [
            "http://localhost:43119/callback",
            "http://192.0.2.1:43119/callback",
            "https://127.0.0.1:43119/callback",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:43119/callback?code=early",
        ] {
            assert!(matches!(
                begin_native_authorization(
                    &native_auth_config(),
                    NativeAuthClient::Desktop,
                    Url::parse(callback).expect("callback URL"),
                    NativeAuthorizationIntent::Register,
                ),
                Err(NativeAuthError::InvalidConfiguration(_))
            ));
        }
    }

    /// Exact callback exchange sends only the frozen one-time code contract.
    #[test]
    fn exchanges_exact_native_callback_for_rotating_tokens() {
        let redirect = Url::parse("http://127.0.0.1:43119/callback").expect("redirect URL");
        let flow = begin_native_authorization(
            &native_auth_config(),
            NativeAuthClient::Desktop,
            redirect.clone(),
            NativeAuthorizationIntent::Register,
        )
        .expect("native flow");
        let expected_state = flow.state.expose_secret().clone();
        let expected_verifier = flow.code_verifier.expose_secret().clone();
        let expected_challenge = flow
            .authorization_url
            .query_pairs()
            .find_map(|(name, value)| (name == "code_challenge").then(|| value.into_owned()))
            .expect("PKCE challenge");
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(expected_verifier.as_bytes())),
            expected_challenge
        );
        let mut callback = redirect;
        callback
            .query_pairs_mut()
            .append_pair("code", "one-time-code")
            .append_pair("state", &expected_state);

        let (server, handle) = serve_json_response(native_token_json(
            "native-access-token",
            "native-refresh-token",
        ));
        let authenticated = complete_native_authorization(&server, flow, &callback)
            .expect("native callback exchange");

        assert_eq!(
            authenticated.account.email.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            authenticated.session.access_token().expose_secret(),
            "native-access-token"
        );
        assert_eq!(
            authenticated
                .session
                .refresh_token()
                .expect("refresh token")
                .expose_secret(),
            "native-refresh-token"
        );
        let debug = format!("{authenticated:?}");
        assert!(!debug.contains("native-access-token"));
        assert!(!debug.contains("native-refresh-token"));
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with("POST /v1/auth/native/token HTTP/1.1\r\n"));
        assert!(request.contains("\"grant_type\":\"authorization_code\""));
        assert!(request.contains("\"code\":\"one-time-code\""));
        assert!(request.contains(&format!("\"code_verifier\":\"{expected_verifier}\"")));
        assert!(request.contains("\"redirect_uri\":\"http://127.0.0.1:43119/callback\""));
        assert!(request.contains("\"client_kind\":\"desktop\""));
        assert!(!request.contains("Authorization:"));
    }

    /// Callback mismatches and ambiguous query fields fail before token exchange.
    #[test]
    fn rejects_mismatched_native_callbacks_before_transport() {
        for query in [
            "code=one-time-code&state=wrong",
            "code=one-time-code&code=duplicate&state=wrong",
            "code=one-time-code&state=wrong&extra=value",
        ] {
            let redirect = Url::parse("http://127.0.0.1:43119/callback").expect("redirect URL");
            let flow = begin_native_authorization(
                &native_auth_config(),
                NativeAuthClient::Cli,
                redirect.clone(),
                NativeAuthorizationIntent::Login,
            )
            .expect("native flow");
            let callback = Url::parse(&format!("{redirect}?{query}")).expect("callback URL");
            assert!(matches!(
                complete_native_authorization("https://registry.example", flow, &callback),
                Err(NativeAuthError::InvalidCallback(_))
            ));
        }

        let redirect = Url::parse("http://127.0.0.1:43119/callback").expect("redirect URL");
        let flow = begin_native_authorization(
            &native_auth_config(),
            NativeAuthClient::Cli,
            redirect,
            NativeAuthorizationIntent::Login,
        )
        .expect("native flow");
        let state = flow.state.expose_secret().clone();
        let callback = Url::parse(&format!(
            "http://127.0.0.1:43119/wrong?code=one-time-code&state={state}"
        ))
        .expect("callback URL");
        assert!(matches!(
            complete_native_authorization("https://registry.example", flow, &callback),
            Err(NativeAuthError::InvalidCallback(_))
        ));
    }

    /// Native refresh rotates both credentials using the exact client-bound request.
    #[test]
    fn refreshes_native_session_with_rotating_credentials() {
        let (server, handle) = serve_json_response(native_token_json(
            "rotated-access-token",
            "rotated-refresh-token",
        ));
        let refresh = SecretString::new("current-refresh-token".to_string());
        let authenticated = refresh_local_account(&server, &refresh, NativeAuthClient::Cli)
            .expect("native refresh");
        assert_eq!(
            authenticated.session.access_token().expose_secret(),
            "rotated-access-token"
        );
        assert_eq!(
            authenticated
                .session
                .refresh_token()
                .expect("rotated refresh token")
                .expose_secret(),
            "rotated-refresh-token"
        );
        let request = handle.join().expect("refresh request thread");
        assert!(request.starts_with("POST /v1/auth/refresh HTTP/1.1\r\n"));
        assert!(request.contains("\"client_kind\":\"cli\""));
        assert!(request.contains("\"refresh_token\":\"current-refresh-token\""));
        assert!(!request.contains("Authorization:"));
    }

    /// Local logout uses the bearer header and requires an affirmative acknowledgement.
    #[test]
    fn logs_out_local_session_with_bearer_header() {
        let (server, handle) = serve_json_response(r#"{"logged_out":true}"#);
        let token = SecretString::new("native-session-token".to_string());
        logout_local_account(&server, &token).expect("local logout");
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with("POST /v1/auth/logout HTTP/1.1\r\n"));
        assert!(request.contains("\r\nAuthorization: Bearer native-session-token\r\n"));
        assert_eq!(request.matches("native-session-token").count(), 1);
    }

    /// Administrator account controls preserve exact paths, methods, bearer authority, and bodies.
    #[test]
    fn sends_administrator_account_controls() {
        let role_body = r#"{"account_id":"00000000-0000-0000-0000-000000000001","role":"administrator","state":"active","assigned_by_account_id":"00000000-0000-0000-0000-000000000002","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
        let (server, handle) = serve_json_response(role_body);
        let server = format!("{server}/registry");
        let token = SecretString::new("administrator-token".to_string());
        let role = assign_account_platform_role(
            &server,
            &token,
            uuid::Uuid::from_u128(1),
            frameshift_catalog::PlatformRole::Administrator,
        )
        .expect("role grant response");
        assert_eq!(role.role, frameshift_catalog::PlatformRole::Administrator);
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with(
            "POST /registry/v1/admin/accounts/00000000-0000-0000-0000-000000000001/platform-roles HTTP/1.1\r\n"
        ));
        assert!(request.contains("\r\nAuthorization: Bearer administrator-token\r\n"));
        let error = list_account_invite_requests(&server, &token, None, 201)
            .expect_err("oversized invite queue");
        assert!(matches!(
            error,
            ClientError::InvalidAccountInviteInput { .. }
        ));
        assert!(request.contains("\"role\":\"administrator\""));

        let (server, handle) = serve_json_response(role_body);
        let server = format!("{server}/registry");
        revoke_account_platform_role(
            &server,
            &token,
            uuid::Uuid::from_u128(1),
            frameshift_catalog::PlatformRole::Moderator,
        )
        .expect("role revocation response");
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with(
            "DELETE /registry/v1/admin/accounts/00000000-0000-0000-0000-000000000001/platform-roles/moderator HTTP/1.1\r\n"
        ));
        assert!(request.contains("\r\nAuthorization: Bearer administrator-token\r\n"));

        let (server, handle) = serve_json_response(account_json());
        let server = format!("{server}/registry");
        let account = set_account_status(
            &server,
            &token,
            uuid::Uuid::from_u128(1),
            frameshift_catalog::AccountStatus::Suspended,
        )
        .expect("account status response");
        assert_eq!(account.id, uuid::Uuid::from_u128(1));
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with(
            "PATCH /registry/v1/admin/accounts/00000000-0000-0000-0000-000000000001/status HTTP/1.1\r\n"
        ));
        assert!(request.contains("\r\nAuthorization: Bearer administrator-token\r\n"));
        assert!(request.contains("\"status\":\"suspended\""));
    }

    /// Administrator invitation controls preserve queue, review, issuance, and token boundaries.
    #[test]
    fn sends_administrator_invitation_controls() {
        let request_body = r#"{"id":"00000000-0000-0000-0000-000000000003","normalized_email":"invitee@example.test","display_name":null,"intent":"publish_personas","statement":"I want to publish personas.","status":"reviewing","consented_at":"2026-01-01T00:00:00Z","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
        let (server, handle) = serve_json_response(format!("[{request_body}]"));
        let server = format!("{server}/registry");
        let token = SecretString::new("administrator-token".to_string());
        let requests = list_account_invite_requests(
            &server,
            &token,
            Some(frameshift_catalog::AccountInviteStatus::Reviewing),
            25,
        )
        .expect("invite queue response");
        assert_eq!(requests.len(), 1);
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with(
            "GET /registry/v1/admin/invite-requests?status=reviewing&limit=25 HTTP/1.1\r\n"
        ));
        assert!(request.contains("\r\nAuthorization: Bearer administrator-token\r\n"));

        let declined_body = request_body.replace("\"reviewing\"", "\"declined\"");
        let (server, handle) = serve_json_response(declined_body);
        let server = format!("{server}/registry");
        let reviewed = review_account_invite_request(
            &server,
            &token,
            uuid::Uuid::from_u128(3),
            AccountInviteReviewStatus::Declined,
        )
        .expect("invite review response");
        assert_eq!(
            reviewed.status,
            frameshift_catalog::AccountInviteStatus::Declined
        );
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with(
            "PATCH /registry/v1/admin/invite-requests/00000000-0000-0000-0000-000000000003 HTTP/1.1\r\n"
        ));
        assert!(request.contains("\"status\":\"declined\""));

        let raw_invitation_token = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [7_u8; 32],
        );
        let issued_body = format!(
            r#"{{"invite":{{"id":"00000000-0000-0000-0000-000000000004","request_id":"00000000-0000-0000-0000-000000000003","normalized_email":"invitee@example.test","token_digest":"AQID","issued_by_account_id":"00000000-0000-0000-0000-000000000002","is_bootstrap":false,"expires_at":"2026-01-08T00:00:00Z","consumed_at":null,"revoked_at":null,"created_at":"2026-01-01T00:00:00Z"}},"token":"{raw_invitation_token}"}}"#
        );
        let (server, handle) = serve_json_response(issued_body.clone());
        let server = format!("{server}/registry");
        let issued = issue_account_invite(&server, &token, uuid::Uuid::from_u128(3))
            .expect("invite issuance response");
        assert_eq!(issued.token().expose_secret(), &raw_invitation_token);
        assert!(!format!("{issued:?}").contains(&raw_invitation_token));
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with(
            "POST /registry/v1/admin/invite-requests/00000000-0000-0000-0000-000000000003/invite HTTP/1.1\r\n"
        ));
        assert!(!request.contains(&raw_invitation_token));

        let malformed_body = issued_body.replace(&raw_invitation_token, "malformed-token");
        let (server, handle) = serve_json_response(malformed_body);
        let server = format!("{server}/registry");
        let error = issue_account_invite(&server, &token, uuid::Uuid::from_u128(3))
            .expect_err("malformed invitation token");
        assert!(!error.to_string().contains("malformed-token"));
        let _request = handle.join().expect("test server thread");
    }
}
