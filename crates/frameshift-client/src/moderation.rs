//! Account-authenticated publication moderation and promotion transport.
//!
//! These operations expose the existing role-gated server boundary without
//! weakening it. The server remains authoritative for reviewer roles,
//! independent-review separation, lifecycle transitions, and promotion.

use frameshift_catalog::{
    PublicationAppealCaseRecord, PublicationAppealCursor, PublicationAppealDisposition,
    PublicationAppealResolutionRecord, PublicationLifecycleCursor,
    PublicationLifecycleDecisionRecord, PublicationModerationAction,
    PublicationModerationDecisionRecord, PublicationPromotionRecord, PublicationSubmissionRecord,
    TombstoneReason,
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

/// Caller-controlled fields for one administrator publisher suspension.
#[derive(Serialize)]
struct SuspendPublicationPublisherRequest<'a> {
    /// Stable lifecycle decision identifier.
    id: Uuid,
    /// Stable bounded private reason code.
    reason_code: &'a str,
}

/// Caller-controlled fields for one administrator release tombstone.
#[derive(Serialize)]
struct TombstonePublicationReleaseRequest {
    /// Stable lifecycle decision identifier.
    id: Uuid,
    /// Closed public tombstone reason category.
    reason: TombstoneReason,
}

/// Caller-controlled fields for one administrator appeal resolution.
#[derive(Serialize)]
struct ResolvePublicationAppealRequest<'a> {
    /// Stable appeal-resolution identifier.
    id: Uuid,
    /// Final administrator disposition.
    disposition: PublicationAppealDisposition,
    /// Bounded private rationale for the disposition.
    rationale: &'a str,
    /// Bounded audited reason for an unavoidable self-resolution.
    separation_exception_reason: Option<&'a str>,
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

/// Suspend one publisher under authenticated administrator authority.
pub fn suspend_publication_publisher(
    server_url: &str,
    access_token: &SecretString,
    publisher_id: Uuid,
    decision_id: Uuid,
    request_id: Uuid,
    reason_code: &str,
) -> Result<PublicationLifecycleDecisionRecord, ClientError> {
    validate_lifecycle_reason_code(reason_code)?;
    let publisher = publisher_id.to_string();
    let url = admin_url(server_url, &["publishers", &publisher, "suspend"])?;
    post_json_with_request_id(
        &url,
        access_token,
        request_id,
        &SuspendPublicationPublisherRequest {
            id: decision_id,
            reason_code,
        },
    )
}

/// Tombstone one public release under authenticated administrator authority.
#[allow(clippy::too_many_arguments)]
pub fn tombstone_publication_release(
    server_url: &str,
    access_token: &SecretString,
    pack_name: &str,
    version: &str,
    decision_id: Uuid,
    request_id: Uuid,
    reason: TombstoneReason,
) -> Result<PublicationLifecycleDecisionRecord, ClientError> {
    let url = admin_url(server_url, &["packs", pack_name, version, "tombstone"])?;
    post_json_with_request_id(
        &url,
        access_token,
        request_id,
        &TombstonePublicationReleaseRequest {
            id: decision_id,
            reason,
        },
    )
}

/// List global immutable publication lifecycle decisions for an administrator.
pub fn list_administrator_publication_decisions(
    server_url: &str,
    access_token: &SecretString,
    before: Option<PublicationLifecycleCursor>,
    limit: u32,
) -> Result<Vec<PublicationLifecycleDecisionRecord>, ClientError> {
    let mut url = admin_url(server_url, &["publication-decisions"])?;
    append_admin_page_query(
        &mut url,
        before.map(|cursor| (cursor.created_at, cursor.id)),
        limit,
    )?;
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent().get(url.as_str()),
        access_token,
    );
    crate::publisher::send_and_decode(request.call(), url.as_str())
}

/// List global private publication appeal cases for an administrator.
pub fn list_administrator_publication_appeals(
    server_url: &str,
    access_token: &SecretString,
    before: Option<PublicationAppealCursor>,
    limit: u32,
) -> Result<Vec<PublicationAppealCaseRecord>, ClientError> {
    let mut url = admin_url(server_url, &["publication-appeals"])?;
    append_admin_page_query(
        &mut url,
        before.map(|cursor| (cursor.created_at, cursor.id)),
        limit,
    )?;
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent().get(url.as_str()),
        access_token,
    );
    crate::publisher::send_and_decode(request.call(), url.as_str())
}

/// Resolve one publication appeal under administrator separation enforcement.
#[allow(clippy::too_many_arguments)]
pub fn resolve_administrator_publication_appeal(
    server_url: &str,
    access_token: &SecretString,
    appeal_id: Uuid,
    resolution_id: Uuid,
    request_id: Uuid,
    disposition: PublicationAppealDisposition,
    rationale: &str,
    separation_exception_reason: Option<&str>,
) -> Result<PublicationAppealResolutionRecord, ClientError> {
    validate_appeal_text(rationale, "--rationale", 4_000)?;
    if let Some(reason) = separation_exception_reason {
        validate_appeal_text(reason, "--separation-exception-reason", 1_000)?;
    }
    let appeal = appeal_id.to_string();
    let url = admin_url(server_url, &["publication-appeals", &appeal, "resolution"])?;
    post_json_with_request_id(
        &url,
        access_token,
        request_id,
        &ResolvePublicationAppealRequest {
            id: resolution_id,
            disposition,
            rationale,
            separation_exception_reason,
        },
    )
}

/// Build a moderation endpoint while preserving a registry base path.
fn moderation_url(server_url: &str, suffix: &[&str]) -> Result<url::Url, ClientError> {
    let mut segments = vec!["v1", "moderation", "publication-submissions"];
    segments.extend_from_slice(suffix);
    crate::publisher::registry_endpoint_url(server_url, &segments)
}

/// Build an administrator endpoint while preserving a registry base path.
fn admin_url(server_url: &str, suffix: &[&str]) -> Result<url::Url, ClientError> {
    let mut segments = vec!["v1", "admin"];
    segments.extend_from_slice(suffix);
    crate::publisher::registry_endpoint_url(server_url, &segments)
}

/// Append a validated newest-first administrator page query.
fn append_admin_page_query(
    url: &mut url::Url,
    before: Option<(chrono::DateTime<chrono::Utc>, Uuid)>,
    limit: u32,
) -> Result<(), ClientError> {
    if !(1..=100).contains(&limit) {
        return Err(ClientError::InvalidPublicationLifecycleInput {
            detail: "--limit must be between 1 and 100".to_string(),
        });
    }
    let mut query = url.query_pairs_mut();
    if let Some((created_at, id)) = before {
        query.append_pair("before_created_at", &created_at.to_rfc3339());
        query.append_pair("before_id", &id.to_string());
    }
    query.append_pair("limit", &limit.to_string());
    drop(query);
    Ok(())
}

/// Validate the server's stable lifecycle reason-code grammar before transport.
fn validate_lifecycle_reason_code(reason_code: &str) -> Result<(), ClientError> {
    let reason = reason_code.as_bytes();
    let valid_head = !reason.is_empty()
        && reason.len() <= 64
        && reason
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    let valid_tail = reason.iter().skip(1).all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
    });
    if valid_head && valid_tail {
        return Ok(());
    }
    Err(ClientError::InvalidPublicationLifecycleInput {
        detail: "--reason-code must use 1-64 lowercase ASCII letters, digits, '.', '_', or '-'"
            .to_string(),
    })
}

/// Validate one bounded private administrator appeal field before transport.
fn validate_appeal_text(value: &str, flag: &str, maximum: usize) -> Result<(), ClientError> {
    if !value.trim().is_empty() && value.chars().count() <= maximum {
        return Ok(());
    }
    Err(ClientError::InvalidPublicationLifecycleInput {
        detail: format!("{flag} must be non-blank and at most {maximum} characters"),
    })
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

    /// Administrator lifecycle mutations preserve path targets and retry identifiers.
    #[test]
    fn sends_administrator_lifecycle_mutations() {
        let decision_id = Uuid::from_u128(20);
        let request_id = Uuid::from_u128(21);
        let response = serde_json::to_vec(&serde_json::json!({
            "id": decision_id,
            "action": "suspend_publisher",
            "actor_account_id": Uuid::from_u128(2),
            "publisher_id": Uuid::from_u128(3),
            "submission_id": null,
            "pack_name": null,
            "version": null,
            "from_state": "approved",
            "to_state": "suspended",
            "reason_code": "policy.abuse",
            "request_id": request_id,
            "created_at": "2026-01-01T00:00:00Z"
        }))
        .expect("serialize lifecycle fixture");
        let (server, handle) = serve_response("application/json", response);
        let token = SecretString::new("administrator-token".to_string());
        let record = suspend_publication_publisher(
            &server,
            &token,
            Uuid::from_u128(3),
            decision_id,
            request_id,
            "policy.abuse",
        )
        .expect("suspension response");
        assert_eq!(record.id, decision_id);
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with(
            "POST /registry/v1/admin/publishers/00000000-0000-0000-0000-000000000003/suspend HTTP/1.1\r\n"
        ));
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("\r\nx-request-id: {request_id}\r\n")));
        assert!(request.contains("\r\nAuthorization: Bearer administrator-token\r\n"));
        assert!(request.contains(&format!("\"id\":\"{decision_id}\"")));
        assert!(request.contains("\"reason_code\":\"policy.abuse\""));

        let response = serde_json::to_vec(&serde_json::json!({
            "id": decision_id,
            "action": "tombstone_release",
            "actor_account_id": Uuid::from_u128(2),
            "publisher_id": Uuid::from_u128(3),
            "submission_id": null,
            "pack_name": "pack/name",
            "version": "1.0.0+linux",
            "from_state": "active",
            "to_state": "tombstone",
            "reason_code": "tos-violation",
            "request_id": request_id,
            "created_at": "2026-01-01T00:00:00Z"
        }))
        .expect("serialize tombstone fixture");
        let (server, handle) = serve_response("application/json", response);
        tombstone_publication_release(
            &server,
            &token,
            "pack/name",
            "1.0.0+linux",
            decision_id,
            request_id,
            frameshift_catalog::TombstoneReason::TosViolation,
        )
        .expect("tombstone response");
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with(
            "POST /registry/v1/admin/packs/pack%2Fname/1.0.0+linux/tombstone HTTP/1.1\r\n"
        ));
        assert!(request.contains("\r\nAuthorization: Bearer administrator-token\r\n"));
        assert!(request.contains(&format!("\"id\":\"{decision_id}\"")));
        assert!(request.contains("\"reason\":\"tos-violation\""));
    }

    /// Administrator audit reads preserve bounded paired keyset cursors.
    #[test]
    fn lists_administrator_lifecycle_records() {
        use chrono::TimeZone as _;

        let cursor = frameshift_catalog::PublicationLifecycleCursor {
            created_at: chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
            id: Uuid::from_u128(22),
        };
        let token = SecretString::new("administrator-token".to_string());
        let (server, handle) = serve_response("application/json", b"[]".to_vec());
        let records = list_administrator_publication_decisions(&server, &token, Some(cursor), 25)
            .expect("decision list");
        assert!(records.is_empty());
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with("GET /registry/v1/admin/publication-decisions?"));
        assert!(request.contains("before_created_at=2026-01-02T03%3A04%3A05%2B00%3A00"));
        assert!(request.contains("before_id=00000000-0000-0000-0000-000000000016"));
        assert!(request.contains("limit=25"));
        assert!(request.contains("\r\nAuthorization: Bearer administrator-token\r\n"));

        let appeal_cursor = frameshift_catalog::PublicationAppealCursor {
            created_at: cursor.created_at,
            id: cursor.id,
        };
        let (server, handle) = serve_response("application/json", b"[]".to_vec());
        let records =
            list_administrator_publication_appeals(&server, &token, Some(appeal_cursor), 100)
                .expect("appeal list");
        assert!(records.is_empty());
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with("GET /registry/v1/admin/publication-appeals?"));
        assert!(request.contains("limit=100"));
    }

    /// Appeal resolution sends the exact private fields and stable retry identifiers.
    #[test]
    fn sends_administrator_appeal_resolution() {
        let resolution_id = Uuid::from_u128(30);
        let appeal_id = Uuid::from_u128(31);
        let request_id = Uuid::from_u128(32);
        let response = serde_json::to_vec(&serde_json::json!({
            "id": resolution_id,
            "appeal_id": appeal_id,
            "actor_account_id": Uuid::from_u128(2),
            "disposition": "overturn",
            "rationale": "Independent evidence supports reversal.",
            "separation_exception_reason": "Only one administrator is active.",
            "request_id": request_id,
            "created_at": "2026-01-01T00:00:00Z"
        }))
        .expect("serialize resolution fixture");
        let (server, handle) = serve_response("application/json", response);
        let token = SecretString::new("administrator-token".to_string());
        let record = resolve_administrator_publication_appeal(
            &server,
            &token,
            appeal_id,
            resolution_id,
            request_id,
            frameshift_catalog::PublicationAppealDisposition::Overturn,
            "Independent evidence supports reversal.",
            Some("Only one administrator is active."),
        )
        .expect("resolution response");
        assert_eq!(record.id, resolution_id);
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with(
            "POST /registry/v1/admin/publication-appeals/00000000-0000-0000-0000-00000000001f/resolution HTTP/1.1\r\n"
        ));
        assert!(request.contains("\r\nAuthorization: Bearer administrator-token\r\n"));
        assert!(request.contains(&format!("\"id\":\"{resolution_id}\"")));
        assert!(request.contains("\"disposition\":\"overturn\""));
        assert!(request
            .contains("\"separation_exception_reason\":\"Only one administrator is active.\""));
    }

    /// Administrator lifecycle validation rejects malformed input before transport.
    #[test]
    fn rejects_invalid_administrator_lifecycle_input() {
        let token = SecretString::new("administrator-token".to_string());
        let reason_error = suspend_publication_publisher(
            "https://registry.example",
            &token,
            Uuid::nil(),
            Uuid::nil(),
            Uuid::nil(),
            "Policy.Invalid",
        )
        .expect_err("uppercase reason must fail");
        assert!(reason_error.to_string().contains("reason-code"));

        let rationale_error = resolve_administrator_publication_appeal(
            "https://registry.example",
            &token,
            Uuid::nil(),
            Uuid::nil(),
            Uuid::nil(),
            frameshift_catalog::PublicationAppealDisposition::Uphold,
            "   ",
            None,
        )
        .expect_err("blank rationale must fail");
        assert!(rationale_error.to_string().contains("rationale"));

        let limit_error =
            list_administrator_publication_decisions("https://registry.example", &token, None, 101)
                .expect_err("oversized page must fail");
        assert!(limit_error.to_string().contains("limit"));
    }
}
