//! Bearer-authenticated publisher-key registry operations.
//!
//! These calls keep account authorization separate from Ed25519 proof of
//! possession. Bearer tokens are accepted only as [`SecretString`] values and
//! are placed solely in the HTTP `Authorization` header.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::error::ClientError;
use crate::identity::public_key_b64;

/// Public lifecycle state returned for an enrolled publisher key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrolledPublisherKeyState {
    /// The key may authorize new publisher writes.
    Active,
    /// The key remains historical evidence but cannot authorize new writes.
    Revoked,
}

/// Public server record for one enrolled publisher key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EnrolledPublisherKey {
    /// Server-assigned key UUID.
    pub id: String,
    /// Server-assigned publisher UUID.
    pub publisher_id: String,
    /// Base64url-no-pad Ed25519 public key.
    pub public_key: String,
    /// User-visible device or purpose label.
    pub label: String,
    /// Current server lifecycle state.
    pub state: EnrolledPublisherKeyState,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 revocation timestamp, when revoked.
    pub revoked_at: Option<String>,
    /// RFC 3339 timestamp of the most recent successful use, when known.
    pub last_used_at: Option<String>,
}

/// Request body for a publisher-key enrollment challenge.
#[derive(Serialize)]
struct PublisherKeyChallengeRequest<'a> {
    /// Base64url-no-pad Ed25519 public key that will prove possession.
    public_key: &'a str,
}

/// Server-provided publisher-key enrollment challenge.
#[derive(Deserialize)]
struct PublisherKeyChallengeResponse {
    /// Exact UTF-8 string the proposed key must sign.
    challenge: String,
    /// Unix deadline associated with the account's fresh authentication.
    #[allow(dead_code)]
    expires_at: u64,
}

/// Request body carrying a publisher-key proof of possession.
#[derive(Serialize)]
struct EnrollPublisherKeyRequest<'a> {
    /// Base64url-no-pad Ed25519 public key.
    public_key: &'a str,
    /// User-visible device or purpose label.
    label: &'a str,
    /// Base64url-no-pad signature over the server challenge.
    proof_signature: String,
}

/// Enroll `key` under one account-owned publisher profile.
pub(crate) fn enroll_publisher_key(
    server_url: &str,
    publisher_handle: &str,
    access_token: &SecretString,
    key: &SigningKey,
    label: &str,
) -> Result<EnrolledPublisherKey, ClientError> {
    let public_key = public_key_b64(key);
    let challenge_url = publisher_key_url(server_url, publisher_handle, &["keys", "challenge"])?;
    let challenge_request = PublisherKeyChallengeRequest {
        public_key: &public_key,
    };
    let challenge: PublisherKeyChallengeResponse =
        post_json(&challenge_url, access_token, &challenge_request)?;
    let proof_signature =
        URL_SAFE_NO_PAD.encode(key.sign(challenge.challenge.as_bytes()).to_bytes());
    let enrollment_url = publisher_key_url(server_url, publisher_handle, &["keys"])?;
    let request = EnrollPublisherKeyRequest {
        public_key: &public_key,
        label,
        proof_signature,
    };
    post_json(&enrollment_url, access_token, &request)
}

/// List every active and revoked key for one account-owned publisher profile.
pub(crate) fn list_publisher_keys(
    server_url: &str,
    publisher_handle: &str,
    access_token: &SecretString,
) -> Result<Vec<EnrolledPublisherKey>, ClientError> {
    let url = publisher_key_url(server_url, publisher_handle, &["keys"])?;
    let request = with_bearer(
        crate::registry::http_agent().get(url.as_str()),
        access_token,
    );
    send_and_decode(request.call(), url.as_str())
}

/// Revoke one server-assigned publisher key without erasing its history.
pub(crate) fn revoke_publisher_key(
    server_url: &str,
    publisher_handle: &str,
    remote_key_id: &str,
    access_token: &SecretString,
) -> Result<EnrolledPublisherKey, ClientError> {
    let url = publisher_key_url(server_url, publisher_handle, &["keys", remote_key_id])?;
    let request = with_bearer(
        crate::registry::http_agent().delete(url.as_str()),
        access_token,
    );
    send_and_decode(request.call(), url.as_str())
}

/// Send one bearer-authenticated JSON POST and decode its bounded response.
fn post_json<T: Serialize, R: serde::de::DeserializeOwned>(
    url: &Url,
    access_token: &SecretString,
    body: &T,
) -> Result<R, ClientError> {
    let bytes =
        serde_json::to_vec(body).map_err(|error| ClientError::JsonSerialize(error.to_string()))?;
    let request = with_bearer(
        crate::registry::http_agent()
            .post(url.as_str())
            .set("Content-Type", "application/json"),
        access_token,
    );
    send_and_decode(request.send_bytes(&bytes), url.as_str())
}

/// Decode a successful response or map a bounded registry failure.
fn send_and_decode<T: serde::de::DeserializeOwned>(
    result: Result<ureq::Response, ureq::Error>,
    url: &str,
) -> Result<T, ClientError> {
    match result {
        Ok(response) => crate::registry::response_json_bounded(response, url),
        Err(ureq::Error::Status(status, response)) => Err(ClientError::RegistryRejected {
            url: url.to_string(),
            status,
            message: crate::registry::response_text_bounded(response, url),
        }),
        Err(error) => Err(ClientError::RegistryHttp {
            url: url.to_string(),
            detail: error.to_string(),
        }),
    }
}

/// Add a secret bearer credential to an HTTP request without logging it.
pub(crate) fn with_bearer(request: ureq::Request, access_token: &SecretString) -> ureq::Request {
    let header = Zeroizing::new(format!("Bearer {}", access_token.expose_secret()));
    request.set("Authorization", &header)
}

/// Build a percent-encoded publisher endpoint while preserving a base path.
fn publisher_key_url(
    server_url: &str,
    publisher_handle: &str,
    suffix: &[&str],
) -> Result<Url, ClientError> {
    let mut url = registry_base_url(server_url)?;
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| ClientError::RegistryHttp {
            url: "<invalid registry URL>".to_string(),
            detail: "registry URL cannot be a base URL".to_string(),
        })?;
    segments.pop_if_empty();
    segments.extend(["v1", "publishers", publisher_handle]);
    segments.extend(suffix.iter().copied());
    drop(segments);
    Ok(url)
}

/// Build one registry endpoint from a credential-free HTTP(S) base URL.
pub(crate) fn registry_endpoint_url(
    server_url: &str,
    endpoint_segments: &[&str],
) -> Result<Url, ClientError> {
    let mut url = registry_base_url(server_url)?;
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| ClientError::RegistryHttp {
            url: "<invalid registry URL>".to_string(),
            detail: "registry URL cannot be a base URL".to_string(),
        })?;
    segments.pop_if_empty();
    segments.extend(endpoint_segments.iter().copied());
    drop(segments);
    Ok(url)
}

/// Parse and sanitize a registry base URL before any request is constructed.
fn registry_base_url(server_url: &str) -> Result<Url, ClientError> {
    let url = Url::parse(server_url).map_err(|error| ClientError::RegistryHttp {
        url: "<invalid registry URL>".to_string(),
        detail: format!("invalid registry URL: {error}"),
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ClientError::RegistryHttp {
            url: "<invalid registry URL>".to_string(),
            detail: "registry URL must use http or https and include a host".to_string(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ClientError::RegistryHttp {
            url: "<credential-free registry URL required>".to_string(),
            detail: "registry URL must not contain userinfo credentials".to_string(),
        });
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ClientError::RegistryHttp {
            url: "<query-free registry URL required>".to_string(),
            detail: "registry URL must not contain a query or fragment".to_string(),
        });
    }
    Ok(url)
}

#[cfg(test)]
/// Publisher-key HTTP client regression tests.
mod tests {
    use ed25519_dalek::{Signature, Verifier as _};

    use super::*;

    /// Publisher path components are encoded rather than interpreted as paths.
    #[test]
    fn publisher_url_encodes_untrusted_segments() {
        let url =
            publisher_key_url("https://registry.example/base", "alice/admin", &["keys"]).unwrap();
        assert_eq!(
            url.as_str(),
            "https://registry.example/base/v1/publishers/alice%2Fadmin/keys"
        );
    }

    /// Registry URLs reject userinfo before it can enter request errors or logs.
    #[test]
    fn registry_url_rejects_embedded_credentials() {
        let error = registry_endpoint_url(
            "https://user:secret@registry.example/base",
            &["v1", "packs"],
        )
        .unwrap_err();
        let rendered = error.to_string();
        assert!(!rendered.contains("user:secret"));
        assert!(!rendered.contains("secret"));
    }

    /// Registry URLs reject query secrets instead of silently discarding or logging them.
    #[test]
    fn registry_url_rejects_query_components() {
        let error = registry_endpoint_url(
            "https://registry.example/base?token=secret",
            &["v1", "packs"],
        )
        .unwrap_err();
        assert!(!error.to_string().contains("secret"));
    }

    /// Enrollment proof bytes verify against the exact returned challenge.
    #[test]
    fn enrollment_proof_signs_exact_challenge() {
        let key = SigningKey::from_bytes(&[17_u8; 32]);
        let challenge = "frameshift-key-enrollment:v1:account:publisher:key";
        let encoded = URL_SAFE_NO_PAD.encode(key.sign(challenge.as_bytes()).to_bytes());
        let bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let signature = Signature::from_slice(&bytes).unwrap();
        key.verifying_key()
            .verify(challenge.as_bytes(), &signature)
            .unwrap();
    }
}
