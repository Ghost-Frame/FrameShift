//! Account-authenticated publication moderation and promotion transport.
//!
//! These operations expose the existing role-gated server boundary without
//! weakening it. The server remains authoritative for reviewer roles,
//! independent-review separation, lifecycle transitions, and promotion.

use frameshift_catalog::{
    PublicationModerationAction, PublicationModerationDecisionRecord, PublicationPromotionRecord,
    PublicationSubmissionRecord,
};
use secrecy::SecretString;
use serde::Serialize;
use uuid::Uuid;

use crate::error::ClientError;

/// Caller-controlled fields for one idempotent moderation decision.
#[derive(Serialize)]
struct ModeratePublicationRequest<'a> {
    /// Stable decision identifier.
    id: Uuid,
    /// Review action applied to the path-bound submission.
    action: PublicationModerationAction,
    /// Stable bounded private reason code.
    reason_code: &'a str,
    /// Optional bounded private explanation for the publisher.
    private_explanation: Option<&'a str>,
}

/// Caller-controlled identity for one idempotent promotion.
#[derive(Serialize)]
struct PromotePublicationRequest {
    /// Stable promotion identifier.
    id: Uuid,
}

/// Retrieve one role-gated publication submission for operator review.
pub fn get_moderation_submission(
    server_url: &str,
    access_token: &SecretString,
    submission_id: Uuid,
) -> Result<PublicationSubmissionRecord, ClientError> {
    let id = submission_id.to_string();
    let url = moderation_url(server_url, &[&id])?;
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent().get(url.as_str()),
        access_token,
    );
    crate::publisher::send_and_decode(request.call(), url.as_str())
}

/// Retrieve one exact quarantine archive under the shared compressed-body cap.
pub fn get_moderation_artifact(
    server_url: &str,
    access_token: &SecretString,
    submission_id: Uuid,
) -> Result<Vec<u8>, ClientError> {
    let id = submission_id.to_string();
    let url = moderation_url(server_url, &[&id, "artifact"])?;
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent().get(url.as_str()),
        access_token,
    );
    match request.call() {
        Ok(response) => crate::registry::response_archive_bytes_bounded(response, url.as_str()),
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

/// Record one idempotent role-gated moderation decision.
#[allow(clippy::too_many_arguments)]
pub fn moderate_publication_submission(
    server_url: &str,
    access_token: &SecretString,
    submission_id: Uuid,
    decision_id: Uuid,
    request_id: Uuid,
    action: PublicationModerationAction,
    reason_code: &str,
    private_explanation: Option<&str>,
) -> Result<PublicationModerationDecisionRecord, ClientError> {
    let id = submission_id.to_string();
    let url = moderation_url(server_url, &[&id, "decisions"])?;
    post_json_with_request_id(
        &url,
        access_token,
        request_id,
        &ModeratePublicationRequest {
            id: decision_id,
            action,
            reason_code,
            private_explanation,
        },
    )
}

/// Promote one approved submission using the server-verified quarantine bytes.
pub fn promote_publication_submission(
    server_url: &str,
    access_token: &SecretString,
    submission_id: Uuid,
    promotion_id: Uuid,
    request_id: Uuid,
) -> Result<PublicationPromotionRecord, ClientError> {
    let id = submission_id.to_string();
    let url = moderation_url(server_url, &[&id, "promotion"])?;
    post_json_with_request_id(
        &url,
        access_token,
        request_id,
        &PromotePublicationRequest { id: promotion_id },
    )
}

/// Build a moderation endpoint while preserving a registry base path.
fn moderation_url(server_url: &str, suffix: &[&str]) -> Result<url::Url, ClientError> {
    let mut segments = vec!["v1", "moderation", "publication-submissions"];
    segments.extend_from_slice(suffix);
    crate::publisher::registry_endpoint_url(server_url, &segments)
}

/// Send one bearer-authenticated idempotent JSON mutation.
fn post_json_with_request_id<T: Serialize, R: serde::de::DeserializeOwned>(
    url: &url::Url,
    access_token: &SecretString,
    request_id: Uuid,
    body: &T,
) -> Result<R, ClientError> {
    let bytes =
        serde_json::to_vec(body).map_err(|error| ClientError::JsonSerialize(error.to_string()))?;
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent()
            .post(url.as_str())
            .set("Content-Type", "application/json")
            .set("x-request-id", &request_id.to_string()),
        access_token,
    );
    crate::publisher::send_and_decode(request.send_bytes(&bytes), url.as_str())
}

#[cfg(test)]
/// Moderation HTTP client regression tests.
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use frameshift_catalog::PublicationSubmissionState;

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

    /// Serve one fixed response and return the captured request.
    fn serve_response(
        content_type: &'static str,
        body: Vec<u8>,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_request(&mut stream);
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).expect("write headers");
            stream.write_all(&body).expect("write response body");
            request
        });
        (format!("http://{address}/registry"), handle)
    }

    /// Return one complete quarantined-submission wire fixture.
    fn submission_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": Uuid::from_u128(1),
            "intent_id": Uuid::from_u128(2),
            "account_id": Uuid::from_u128(3),
            "publisher_id": Uuid::from_u128(4),
            "publisher_key_id": Uuid::from_u128(5),
            "archive_hash": "0101010101010101010101010101010101010101010101010101010101010101",
            "manifest_hash": "0202020202020202020202020202020202020202020202020202020202020202",
            "file_inventory_hash": "0303030303030303030303030303030303030303030303030303030303030303",
            "scan_schema_version": 1,
            "scan_report": {
                "schema_version": 1,
                "valid": true,
                "inventory_hash": "inventory",
                "inventory": [],
                "findings": []
            },
            "state": "quarantined",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        }))
        .expect("serialize submission fixture")
    }

    /// Submission retrieval preserves the registry base path and bearer boundary.
    #[test]
    fn retrieves_submission_with_bearer_header() {
        let (server, handle) = serve_response("application/json", submission_json());
        let token = SecretString::new("moderator-token".to_string());
        let submission = get_moderation_submission(&server, &token, Uuid::from_u128(1))
            .expect("submission response");
        assert_eq!(submission.state, PublicationSubmissionState::Quarantined);
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with(
            "GET /registry/v1/moderation/publication-submissions/00000000-0000-0000-0000-000000000001 HTTP/1.1\r\n"
        ));
        assert!(request.contains("\r\nAuthorization: Bearer moderator-token\r\n"));
        assert_eq!(request.matches("moderator-token").count(), 1);
    }

    /// Decision transport binds the path, stable IDs, action, and private reason fields.
    #[test]
    fn sends_idempotent_moderation_decision() {
        let decision_id = Uuid::from_u128(6);
        let request_id = Uuid::from_u128(7);
        let response = serde_json::to_vec(&serde_json::json!({
            "id": decision_id,
            "submission_id": Uuid::from_u128(1),
            "actor_account_id": Uuid::from_u128(3),
            "action": "request_changes",
            "from_state": "quarantined",
            "to_state": "needs_review",
            "reason_code": "metadata",
            "private_explanation": "clarify the description",
            "request_id": request_id,
            "created_at": "2026-01-01T00:00:00Z"
        }))
        .expect("serialize decision fixture");
        let (server, handle) = serve_response("application/json", response);
        let token = SecretString::new("moderator-token".to_string());
        let decision = moderate_publication_submission(
            &server,
            &token,
            Uuid::from_u128(1),
            decision_id,
            request_id,
            PublicationModerationAction::RequestChanges,
            "metadata",
            Some("clarify the description"),
        )
        .expect("decision response");
        assert_eq!(decision.id, decision_id);
        let request = handle.join().expect("test server thread");
        let lowercase_request = request.to_ascii_lowercase();
        assert!(request.starts_with(
            "POST /registry/v1/moderation/publication-submissions/00000000-0000-0000-0000-000000000001/decisions HTTP/1.1\r\n"
        ));
        assert!(lowercase_request.contains(&format!("\r\nx-request-id: {request_id}\r\n")));
        assert!(request.contains(&format!("\"id\":\"{decision_id}\"")));
        assert!(request.contains("\"action\":\"request_changes\""));
        assert!(request.contains("\"reason_code\":\"metadata\""));
    }

    /// Promotion transport binds a separate stable promotion and request identifier.
    #[test]
    fn sends_idempotent_promotion() {
        let promotion_id = Uuid::from_u128(8);
        let request_id = Uuid::from_u128(9);
        let response = serde_json::to_vec(&serde_json::json!({
            "id": promotion_id,
            "submission_id": Uuid::from_u128(1),
            "actor_account_id": Uuid::from_u128(3),
            "pack_name": "reviewed-pack",
            "version": "1.0.0",
            "content_hash": "0404040404040404040404040404040404040404040404040404040404040404",
            "request_id": request_id,
            "created_at": "2026-01-01T00:00:00Z"
        }))
        .expect("serialize promotion fixture");
        let (server, handle) = serve_response("application/json", response);
        let token = SecretString::new("moderator-token".to_string());
        let promotion = promote_publication_submission(
            &server,
            &token,
            Uuid::from_u128(1),
            promotion_id,
            request_id,
        )
        .expect("promotion response");
        assert_eq!(promotion.id, promotion_id);
        let request = handle.join().expect("test server thread");
        let lowercase_request = request.to_ascii_lowercase();
        assert!(lowercase_request.contains(&format!("\r\nx-request-id: {request_id}\r\n")));
        assert!(request.contains(&format!("\"id\":\"{promotion_id}\"")));
    }

    /// Artifact transport returns exact bytes under the shared archive cap.
    #[test]
    fn retrieves_exact_artifact_bytes() {
        let expected = b"reviewed archive bytes".to_vec();
        let (server, handle) = serve_response("application/gzip", expected.clone());
        let token = SecretString::new("moderator-token".to_string());
        let actual = get_moderation_artifact(&server, &token, Uuid::from_u128(1))
            .expect("artifact response");
        assert_eq!(actual, expected);
        let request = handle.join().expect("test server thread");
        assert!(request.contains("/artifact HTTP/1.1"));
    }

    /// Artifact transport rejects a response larger than the shared archive cap.
    #[test]
    fn rejects_oversized_artifact_response() {
        let oversized = vec![0_u8; 16 * 1024 * 1024 + 1];
        let (server, handle) = serve_response("application/gzip", oversized);
        let token = SecretString::new("moderator-token".to_string());
        let error = get_moderation_artifact(&server, &token, Uuid::from_u128(1))
            .expect_err("oversized artifact should fail");
        assert!(error
            .to_string()
            .contains("response exceeds maximum allowed size"));
        let request = handle.join().expect("test server thread");
        assert!(request.contains("/artifact HTTP/1.1"));
    }
}
