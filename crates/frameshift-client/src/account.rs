//! Account authentication, profile, and administrator control operations.
//!
//! Access tokens enter only through [`SecretString`] and are attached solely
//! to the registry request's `Authorization` header.

use chrono::{DateTime, Utc};
use frameshift_catalog::{
    AccountInviteRecord, AccountInviteRequestRecord, AccountInviteStatus, AccountRecord,
    AccountStatus, PlatformRole, PlatformRoleRecord, PublisherMembershipRecord,
    PublisherProfileRecord,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
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

/// Password login request serialized only at the HTTP boundary.
#[derive(Serialize)]
struct LoginLocalAccountRequest<'a> {
    /// Normalized sign-in email supplied by the caller.
    email: &'a str,
    /// Secret account password exposed only to the serializer.
    password: &'a str,
    /// Native session presentation.
    client_kind: NativeAuthClient,
}

/// Invitation registration request serialized only at the HTTP boundary.
#[derive(Serialize)]
struct RegisterLocalAccountRequest<'a> {
    /// Secret one-time invitation token exposed only to the serializer.
    invite_token: &'a str,
    /// Invitation-bound email address.
    email: &'a str,
    /// Optional account display name.
    display_name: Option<&'a str>,
    /// Secret account password exposed only to the serializer.
    password: &'a str,
    /// Native session presentation.
    client_kind: NativeAuthClient,
}

/// Wire response containing a bearer token that is wiped after conversion.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalAuthResponse {
    /// Durable authenticated account.
    account: AccountRecord,
    /// Opaque token required for native clients.
    token: Option<String>,
    /// Non-extendable session expiry.
    expires_at: DateTime<Utc>,
}

/// Wipe the raw response token when its temporary wire value leaves scope.
impl Drop for LocalAuthResponse {
    /// Zero the optional raw token string.
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        if let Some(token) = &mut self.token {
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

/// Register an invitation-bound first-party account and create a native session.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, JSON, token-validation, or
/// expiry error without including the invitation, password, or bearer token.
pub fn register_local_account(
    server_url: &str,
    invite_token: &SecretString,
    email: &str,
    display_name: Option<&str>,
    password: &SecretString,
    client_kind: NativeAuthClient,
) -> Result<LocalAccountSession, ClientError> {
    let request = RegisterLocalAccountRequest {
        invite_token: invite_token.expose_secret(),
        email,
        display_name,
        password: password.expose_secret(),
        client_kind,
    };
    post_local_auth(server_url, "register", request)
}

/// Verify first-party credentials and create a native bearer session.
///
/// # Errors
///
/// Returns a registry URL, transport, status, size, JSON, token-validation, or
/// expiry error without including the password or bearer token.
pub fn login_local_account(
    server_url: &str,
    email: &str,
    password: &SecretString,
    client_kind: NativeAuthClient,
) -> Result<LocalAccountSession, ClientError> {
    let request = LoginLocalAccountRequest {
        email,
        password: password.expose_secret(),
        client_kind,
    };
    post_local_auth(server_url, "login", request)
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
fn post_local_auth(
    server_url: &str,
    operation: &str,
    request: impl Serialize,
) -> Result<LocalAccountSession, ClientError> {
    let url = crate::publisher::registry_endpoint_url(server_url, &["v1", "auth", operation])?;
    let body = Zeroizing::new(
        serde_json::to_vec(&request)
            .map_err(|error| ClientError::JsonSerialize(error.to_string()))?,
    );
    let response = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .post(url.as_str())
        .set("Content-Type", "application/json")
        .send_bytes(body.as_slice());
    let mut response: LocalAuthResponse = match response {
        Ok(response) => crate::registry::response_json_bounded(response, url.as_str())?,
        Err(ureq::Error::Status(status, response)) => {
            return Err(ClientError::RegistryRejected {
                url: url.to_string(),
                status,
                message: crate::registry::response_text_bounded(response, url.as_str()),
            });
        }
        Err(error) => {
            return Err(ClientError::RegistryHttp {
                url: url.to_string(),
                detail: error.to_string(),
            });
        }
    };
    let token = response
        .token
        .take()
        .ok_or_else(|| ClientError::RegistryRejected {
            url: url.to_string(),
            status: 502,
            message: "registry omitted the native bearer token".to_string(),
        })?;
    let expires_at = u64::try_from(response.expires_at.timestamp()).map_err(|_| {
        ClientError::RegistryRejected {
            url: url.to_string(),
            status: 502,
            message: "registry returned an invalid native session expiry".to_string(),
        }
    })?;
    let session =
        AuthenticatedSession::from_first_party_bearer(SecretString::new(token), expires_at)
            .map_err(|_| ClientError::RegistryRejected {
                url: url.to_string(),
                status: 502,
                message: "registry returned an invalid native bearer session".to_string(),
            })?;
    Ok(LocalAccountSession {
        account: response.account.clone(),
        session,
    })
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

    /// First-party login sends credentials only in JSON and redacts its bearer result.
    #[test]
    fn logs_in_with_native_bearer_without_debug_disclosure() {
        let body = format!(
            r#"{{"account":{},"token":"native-session-token","expires_at":"2099-01-01T00:00:00Z"}}"#,
            account_json()
        );
        let (server, handle) = serve_json_response(body);
        let password = SecretString::new("correct horse battery staple".to_string());
        let authenticated = login_local_account(
            &server,
            "alice@example.com",
            &password,
            NativeAuthClient::Cli,
        )
        .expect("native login");

        assert_eq!(
            authenticated.account.email.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            authenticated.session.access_token().expose_secret(),
            "native-session-token"
        );
        let debug = format!("{authenticated:?}");
        assert!(!debug.contains("native-session-token"));
        assert!(!debug.contains("correct horse battery staple"));
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with("POST /v1/auth/login HTTP/1.1\r\n"));
        assert!(request.contains("\"client_kind\":\"cli\""));
        assert!(request.contains("\"password\":\"correct horse battery staple\""));
        assert!(!request.contains("Authorization:"));
    }

    /// Invitation registration preserves native client kind and optional profile data.
    #[test]
    fn registers_invited_native_account() {
        let body = format!(
            r#"{{"account":{},"token":"registered-session-token","expires_at":"2099-01-01T00:00:00Z"}}"#,
            account_json()
        );
        let (server, handle) = serve_json_response(body);
        let invite = SecretString::new("one-time-invite".to_string());
        let password = SecretString::new("a sufficiently long password".to_string());
        let authenticated = register_local_account(
            &server,
            &invite,
            "alice@example.com",
            Some("Alice"),
            &password,
            NativeAuthClient::Desktop,
        )
        .expect("native registration");

        assert_eq!(authenticated.account.display_name.as_deref(), Some("Alice"));
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with("POST /v1/auth/register HTTP/1.1\r\n"));
        assert!(request.contains("\"invite_token\":\"one-time-invite\""));
        assert!(request.contains("\"client_kind\":\"desktop\""));
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
