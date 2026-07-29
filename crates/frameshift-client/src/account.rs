//! Bearer-authenticated account profile operations.
//!
//! Access tokens enter only through [`SecretString`] and are attached solely
//! to the registry request's `Authorization` header.

use frameshift_catalog::{AccountRecord, PublisherMembershipRecord, PublisherProfileRecord};
use secrecy::SecretString;
use serde::Deserialize;

use crate::error::ClientError;

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

#[cfg(test)]
/// Account HTTP client regression tests.
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    /// Serve one fixed account response and return the captured request.
    fn serve_account_response() -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = vec![0_u8; 4096];
            let count = stream.read(&mut request).expect("read request");
            let body = r#"{"account":{"id":"00000000-0000-0000-0000-000000000001","issuer":"https://issuer.example","subject":"subject-1","email":null,"display_name":"Alice","status":"active","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},"memberships":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            String::from_utf8_lossy(&request[..count]).into_owned()
        });
        (format!("http://{address}"), handle)
    }

    /// Account lookup sends the bearer only in the authorization header.
    #[test]
    fn fetches_account_with_bearer_header() {
        let (server, handle) = serve_account_response();
        let token = SecretString::new("test-access-token".to_string());
        let view = get_account(&server, &token).expect("account response");
        assert_eq!(view.account.display_name.as_deref(), Some("Alice"));
        assert!(view.publishers.is_empty());
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with("GET /v1/account HTTP/1.1\r\n"));
        assert!(request.contains("\r\nAuthorization: Bearer test-access-token\r\n"));
        assert_eq!(request.matches("test-access-token").count(), 1);
    }
}
