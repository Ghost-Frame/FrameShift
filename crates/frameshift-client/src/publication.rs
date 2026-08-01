//! Explicit Creator Studio publication preparation and quarantine transport.
//!
//! Preparation consumes an immutable [`frameshift_studio::DraftSnapshot`].
//! Network operations require caller-provided account authorization and, for
//! submission, the exact signing key. No operation in this module is exposed
//! through the MCP tool surface.

use std::fs;

use ed25519_dalek::{Signer as _, SigningKey};
use flate2::{Compression, GzBuilder};
use frameshift_catalog::{
    PublicationAppealCaseRecord, PublicationAppealCursor, PublicationAppealRecord,
    PublicationIntentRecord, PublicationLifecycleCursor, PublicationLifecycleDecisionRecord,
    PublicationSubmissionRecord,
};
use frameshift_pack::{ObjectHash, Pack};
use frameshift_studio::DraftSnapshot;
pub use frameshift_studio::{PublicationBinding, PublicationReviewBinding};
use secrecy::SecretString;
use serde::Serialize;
use uuid::Uuid;

use crate::error::ClientError;

/// Exact signed archive retained privately until explicit submission.
pub struct PreparedPublication {
    /// Public hashes safe to present for final human confirmation.
    binding: PublicationBinding,
    /// Exact archive bytes covered by `binding.archive_hash`.
    archive: Vec<u8>,
}

/// JSON body accepted by `POST /v1/publish-intents`.
#[derive(Serialize)]
struct CreatePublicationIntentRequest {
    /// Caller-generated idempotency identifier.
    id: Uuid,
    /// Server-assigned publisher identifier.
    publisher_id: Uuid,
    /// Server-assigned active publisher-key identifier.
    publisher_key_id: Uuid,
    /// SHA-256 digest of the exact archive.
    archive_hash: ObjectHash,
    /// SHA-256 digest of the exact manifest.
    manifest_hash: ObjectHash,
    /// SHA-256 digest of the normalized inventory.
    file_inventory_hash: ObjectHash,
    /// Positive shared scanner contract version.
    scan_schema_version: u32,
}

/// JSON body accepted by one owner submission withdrawal.
#[derive(Serialize)]
struct WithdrawPublicationSubmissionRequest<'a> {
    /// Stable lifecycle decision identifier and primary idempotency key.
    id: Uuid,
    /// Stable bounded private reason code.
    reason_code: &'a str,
}

/// JSON body accepted by one publisher-owner appeal filing.
#[derive(Serialize)]
struct FilePublicationAppealRequest<'a> {
    /// Stable appeal identifier and primary idempotency key.
    id: Uuid,
    /// Bounded private statement explaining the appeal.
    statement: &'a str,
}

/// Read-only accessors for a prepared publication.
impl PreparedPublication {
    /// Return the public exact-artifact binding for final review and intent creation.
    pub fn binding(&self) -> PublicationBinding {
        self.binding
    }
}

/// Deterministically sign and archive one immutable Creator Studio snapshot.
pub fn prepare_publication(
    snapshot: &DraftSnapshot,
    signing_key: &SigningKey,
) -> Result<PreparedPublication, ClientError> {
    let staged = tempfile::TempDir::new().map_err(|source| ClientError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    for file in snapshot.files() {
        let destination = staged.path().join(file.path());
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source| ClientError::Io {
                path: destination.clone(),
                source,
            })?;
        }
        fs::write(&destination, file.bytes()).map_err(|source| ClientError::Io {
            path: destination,
            source,
        })?;
    }

    let pack = Pack::from_dir(staged.path())?;
    if pack.manifest().is_local_unsigned() {
        return Err(ClientError::PublishLocalUnsigned {
            name: pack.manifest().name.clone(),
        });
    }
    if pack.manifest().author_pubkey != hex::encode(signing_key.verifying_key().to_bytes()) {
        return Err(ClientError::PublicationSignerMismatch);
    }

    let signature = signing_key.sign(&pack.canonical_hash()).to_bytes();
    let archive = deterministic_archive(snapshot, &signature)?;
    let report = snapshot.publication();
    let manifest = report
        .inventory
        .iter()
        .find(|entry| entry.path == "pack.toml")
        .expect("valid publication snapshots always contain pack.toml");
    let binding = PublicationBinding {
        archive_hash: ObjectHash::of(&archive),
        manifest_hash: ObjectHash::from_hex(&manifest.sha256)
            .expect("publication report hashes are valid lowercase SHA-256"),
        file_inventory_hash: ObjectHash::from_hex(&report.inventory_hash)
            .expect("publication inventory hashes are valid lowercase SHA-256"),
        scan_schema_version: report.schema_version,
    };
    Ok(PreparedPublication { binding, archive })
}

/// Create an authenticated idempotent intent for one exact prepared artifact.
pub fn create_publication_intent(
    server_url: &str,
    access_token: &SecretString,
    intent_id: Uuid,
    review_binding: PublicationReviewBinding,
    prepared: &PreparedPublication,
) -> Result<PublicationIntentRecord, ClientError> {
    if review_binding.artifact != prepared.binding {
        return Err(ClientError::PublicationReviewBindingMismatch);
    }
    let binding = prepared.binding;
    let body = serde_json::to_vec(&CreatePublicationIntentRequest {
        id: intent_id,
        publisher_id: review_binding.publisher_id,
        publisher_key_id: review_binding.publisher_key_id,
        archive_hash: binding.archive_hash,
        manifest_hash: binding.manifest_hash,
        file_inventory_hash: binding.file_inventory_hash,
        scan_schema_version: binding.scan_schema_version,
    })
    .map_err(|error| ClientError::JsonSerialize(error.to_string()))?;
    let url = crate::publisher::registry_endpoint_url(server_url, &["v1", "publish-intents"])?;
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent()
            .post(url.as_str())
            .set("Content-Type", "application/json"),
        access_token,
    );
    crate::publisher::send_and_decode(request.send_bytes(&body), url.as_str())
}

/// Retrieve one account-owned publication intent by its stable identifier.
pub fn get_publication_intent(
    server_url: &str,
    access_token: &SecretString,
    intent_id: Uuid,
) -> Result<PublicationIntentRecord, ClientError> {
    let id = intent_id.to_string();
    let url = crate::publisher::registry_endpoint_url(server_url, &["v1", "publish-intents", &id])?;
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent().get(url.as_str()),
        access_token,
    );
    crate::publisher::send_and_decode(request.call(), url.as_str())
}

/// Submit one exact prepared archive to quarantine under a durable intent.
pub fn submit_publication(
    server_url: &str,
    access_token: &SecretString,
    signing_key: &SigningKey,
    submission_id: Uuid,
    intent_id: Uuid,
    prepared: &PreparedPublication,
) -> Result<PublicationSubmissionRecord, ClientError> {
    let (boundary, body) = submission_multipart(submission_id, intent_id, &prepared.archive);
    let url =
        crate::publisher::registry_endpoint_url(server_url, &["v1", "publication-submissions"])?;
    let headers = crate::publish::signed_headers(signing_key, "POST", url.path(), &body);
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let mut request = crate::publisher::with_bearer(
        crate::registry::http_agent()
            .post(url.as_str())
            .set("Content-Type", &content_type),
        access_token,
    );
    for header in headers {
        request = request.set(header.name, &header.value);
    }
    let response = crate::publish::send_signed(request, url.as_str(), &body)?;
    crate::registry::response_json_bounded(response, url.as_str())
}

/// Retrieve one account-owned quarantined submission and its moderation state.
pub fn get_publication_submission(
    server_url: &str,
    access_token: &SecretString,
    submission_id: Uuid,
) -> Result<PublicationSubmissionRecord, ClientError> {
    let id = submission_id.to_string();
    let url = crate::publisher::registry_endpoint_url(
        server_url,
        &["v1", "publication-submissions", &id],
    )?;
    let request = crate::publisher::with_bearer(
        crate::registry::http_agent().get(url.as_str()),
        access_token,
    );
    crate::publisher::send_and_decode(request.call(), url.as_str())
}

/// Withdraw one eligible account-owned non-public submission idempotently.
pub fn withdraw_publication_submission(
    server_url: &str,
    access_token: &SecretString,
    submission_id: Uuid,
    decision_id: Uuid,
    request_id: Uuid,
    reason_code: &str,
) -> Result<PublicationLifecycleDecisionRecord, ClientError> {
    validate_lifecycle_reason_code(reason_code)?;
    let id = submission_id.to_string();
    let url = crate::publisher::registry_endpoint_url(
        server_url,
        &["v1", "publication-submissions", &id, "withdraw"],
    )?;
    let body = WithdrawPublicationSubmissionRequest {
        id: decision_id,
        reason_code,
    };
    post_publication_json(&url, access_token, request_id, &body)
}

/// List immutable lifecycle decisions scoped to one owned publisher profile.
pub fn list_publication_decisions(
    server_url: &str,
    access_token: &SecretString,
    publisher_handle: &str,
    before: Option<PublicationLifecycleCursor>,
    limit: u32,
) -> Result<Vec<PublicationLifecycleDecisionRecord>, ClientError> {
    let mut url = crate::publisher::registry_endpoint_url(
        server_url,
        &[
            "v1",
            "publishers",
            publisher_handle,
            "publication-decisions",
        ],
    )?;
    append_publication_page_query(
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

/// File one idempotent appeal against an adverse publisher moderation decision.
pub fn file_publication_appeal(
    server_url: &str,
    access_token: &SecretString,
    publisher_handle: &str,
    decision_id: Uuid,
    appeal_id: Uuid,
    request_id: Uuid,
    statement: &str,
) -> Result<PublicationAppealRecord, ClientError> {
    validate_appeal_statement(statement)?;
    let decision = decision_id.to_string();
    let url = crate::publisher::registry_endpoint_url(
        server_url,
        &[
            "v1",
            "publishers",
            publisher_handle,
            "publication-decisions",
            &decision,
            "appeal",
        ],
    )?;
    let body = FilePublicationAppealRequest {
        id: appeal_id,
        statement,
    };
    post_publication_json(&url, access_token, request_id, &body)
}

/// List private appeal cases scoped to one owned publisher profile.
pub fn list_publication_appeals(
    server_url: &str,
    access_token: &SecretString,
    publisher_handle: &str,
    before: Option<PublicationAppealCursor>,
    limit: u32,
) -> Result<Vec<PublicationAppealCaseRecord>, ClientError> {
    let mut url = crate::publisher::registry_endpoint_url(
        server_url,
        &["v1", "publishers", publisher_handle, "publication-appeals"],
    )?;
    append_publication_page_query(
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

/// Send one bearer-authenticated idempotent publication JSON mutation.
fn post_publication_json<T: Serialize, R: serde::de::DeserializeOwned>(
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

/// Append a validated newest-first publication page query to one endpoint.
fn append_publication_page_query(
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

/// Validate the server's stable private appeal statement bound before transport.
fn validate_appeal_statement(statement: &str) -> Result<(), ClientError> {
    if !statement.trim().is_empty() && statement.chars().count() <= 4_000 {
        return Ok(());
    }
    Err(ClientError::InvalidPublicationLifecycleInput {
        detail: "--statement must be non-blank and at most 4000 characters".to_string(),
    })
}

/// Build a reproducible gzip-tar from sorted snapshot files plus its signature.
fn deterministic_archive(
    snapshot: &DraftSnapshot,
    signature: &[u8; 64],
) -> Result<Vec<u8>, ClientError> {
    let mut entries = snapshot
        .files()
        .iter()
        .map(|file| (file.path().to_string(), file.bytes()))
        .collect::<Vec<_>>();
    entries.push(("signature.sig".to_string(), signature.as_slice()));
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    archive.mode(tar::HeaderMode::Deterministic);
    for (path, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, path, bytes)
            .map_err(|source| ClientError::Io {
                path: std::env::temp_dir(),
                source,
            })?;
    }
    let encoder = archive.into_inner().map_err(|source| ClientError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    encoder.finish().map_err(|source| ClientError::Io {
        path: std::env::temp_dir(),
        source,
    })
}

/// Build the exact multipart body signed for a quarantine submission.
fn submission_multipart(submission_id: Uuid, intent_id: Uuid, archive: &[u8]) -> (String, Vec<u8>) {
    let boundary = format!(
        "frameshiftSubmission{}",
        hex::encode(ObjectHash::of(archive).as_bytes())
    );
    let mut body = Vec::new();
    append_text_part(&mut body, &boundary, "id", &submission_id.to_string());
    append_text_part(&mut body, &boundary, "intent_id", &intent_id.to_string());
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"archive\"; filename=\"pack.tar.gz\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/gzip\r\n\r\n");
    body.extend_from_slice(archive);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

/// Append one UTF-8 text field to a multipart request body.
fn append_text_part(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(value.as_bytes());
    body.extend_from_slice(b"\r\n");
}

#[cfg(test)]
/// Tests for deterministic preparation and exact public request bindings.
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    use chrono::{TimeZone as _, Utc};
    use frameshift_catalog::{PublicationAppealCursor, PublicationLifecycleCursor};
    use frameshift_studio::Studio;

    use super::*;

    /// Return a deterministic signing key for publication fixtures.
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[17_u8; 32])
    }

    /// Build a valid exact pre-review snapshot using the fixture key.
    fn ready_snapshot(root: &std::path::Path) -> DraftSnapshot {
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(
            source.join("pack.toml"),
            format!(
                "schema_version = 1\nname = \"fixture\"\nauthor_handle = \"alice\"\n\
                 author_pubkey = \"{}\"\nversion = \"0.1.0\"\n",
                hex::encode(signing_key().verifying_key().to_bytes())
            ),
        )
        .unwrap();
        fs::write(source.join("AGENTS.md"), b"# Fixture\n").unwrap();
        let studio = Studio::open(root.join("studio")).unwrap();
        let status = studio.import("fixture", "Fixture", &source).unwrap();
        let inventory_hash = status.publication.inventory_hash;
        studio
            .snapshot_for_review("fixture", &inventory_hash)
            .unwrap()
    }

    /// Read one complete HTTP request from the blocking client under test.
    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let count = stream.read(&mut buffer).expect("read request");
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            let Some(headers_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
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
    fn serve_json_response(body: Vec<u8>) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_request(&mut stream);
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).expect("write headers");
            stream.write_all(&body).expect("write response");
            request
        });
        (format!("http://{address}/registry"), handle)
    }

    /// Return one complete owner lifecycle decision wire fixture.
    fn lifecycle_decision_json(decision_id: Uuid, request_id: Uuid) -> serde_json::Value {
        serde_json::json!({
            "id": decision_id,
            "action": "withdraw_submission",
            "actor_account_id": Uuid::from_u128(2),
            "publisher_id": Uuid::from_u128(3),
            "submission_id": Uuid::from_u128(1),
            "pack_name": null,
            "version": null,
            "from_state": "quarantined",
            "to_state": "withdrawn",
            "reason_code": "author_request",
            "request_id": request_id,
            "created_at": "2026-01-01T00:00:00Z"
        })
    }

    /// Repeated preparation produces byte-identical archives and valid pack signatures.
    #[test]
    fn preparation_is_reproducible_and_signed() {
        let temporary = tempfile::tempdir().unwrap();
        let snapshot = ready_snapshot(temporary.path());
        let first = prepare_publication(&snapshot, &signing_key()).unwrap();
        let second = prepare_publication(&snapshot, &signing_key()).unwrap();
        assert_eq!(first.binding, second.binding);
        assert_eq!(first.archive, second.archive);

        let unpacked = tempfile::tempdir().unwrap();
        let decoder = flate2::read::GzDecoder::new(first.archive.as_slice());
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(unpacked.path()).unwrap();
        let pack = Pack::from_dir(unpacked.path()).unwrap();
        pack.verify(&signing_key().verifying_key()).unwrap();
        let signature = fs::read(unpacked.path().join("signature.sig")).unwrap();
        assert_eq!(signature.len(), 64);
    }

    /// Preparation refuses a signer that differs from the manifest identity.
    #[test]
    fn preparation_rejects_manifest_signer_mismatch() {
        let temporary = tempfile::tempdir().unwrap();
        let snapshot = ready_snapshot(temporary.path());
        let different_key = SigningKey::from_bytes(&[18_u8; 32]);
        let error = match prepare_publication(&snapshot, &different_key) {
            Ok(_) => panic!("mismatched signer must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, ClientError::PublicationSignerMismatch));
    }

    /// Intent JSON carries every reviewed identity, exact hash, and idempotency identifier.
    #[test]
    fn intent_request_serializes_exact_binding() {
        let temporary = tempfile::tempdir().unwrap();
        let snapshot = ready_snapshot(temporary.path());
        let prepared = prepare_publication(&snapshot, &signing_key()).unwrap();
        let request = CreatePublicationIntentRequest {
            id: Uuid::from_u128(1),
            publisher_id: Uuid::from_u128(2),
            publisher_key_id: Uuid::from_u128(3),
            archive_hash: prepared.binding.archive_hash,
            manifest_hash: prepared.binding.manifest_hash,
            file_inventory_hash: prepared.binding.file_inventory_hash,
            scan_schema_version: prepared.binding.scan_schema_version,
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["id"], Uuid::from_u128(1).to_string());
        assert_eq!(value["publisher_id"], Uuid::from_u128(2).to_string());
        assert_eq!(value["publisher_key_id"], Uuid::from_u128(3).to_string());
        assert_eq!(
            value["archive_hash"],
            prepared.binding.archive_hash.to_hex()
        );
        assert_eq!(
            value["manifest_hash"],
            prepared.binding.manifest_hash.to_hex()
        );
        assert_eq!(
            value["file_inventory_hash"],
            prepared.binding.file_inventory_hash.to_hex()
        );
        assert_eq!(
            value["scan_schema_version"],
            prepared.binding.scan_schema_version
        );
    }

    /// Final review, intent confirmation, and submission snapshot share one exact binding.
    #[test]
    fn artifact_first_review_flow_preserves_one_binding() {
        let temporary = tempfile::tempdir().unwrap();
        let snapshot = ready_snapshot(temporary.path());
        let prepared = prepare_publication(&snapshot, &signing_key()).unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let binding = PublicationReviewBinding {
            artifact: prepared.binding(),
            publisher_id: Uuid::from_u128(2),
            publisher_key_id: Uuid::from_u128(3),
        };

        let review = studio.review_report("fixture", binding).unwrap();
        assert_eq!(review.binding, binding);
        studio.confirm_review("fixture", binding).unwrap();
        studio
            .confirm_submission_intent("fixture", binding)
            .unwrap();
        let submission = studio.snapshot_for_submission("fixture", binding).unwrap();
        assert_eq!(
            submission.publication().inventory_hash,
            snapshot.publication().inventory_hash
        );
    }

    /// Intent creation rejects a prepared archive substituted after final review.
    #[test]
    fn intent_creation_rejects_reviewed_artifact_substitution() {
        let temporary = tempfile::tempdir().unwrap();
        let snapshot = ready_snapshot(temporary.path());
        let prepared = prepare_publication(&snapshot, &signing_key()).unwrap();
        let mut binding = PublicationReviewBinding {
            artifact: prepared.binding(),
            publisher_id: Uuid::from_u128(2),
            publisher_key_id: Uuid::from_u128(3),
        };
        binding.artifact.archive_hash = ObjectHash::of(b"substituted archive");

        let error = create_publication_intent(
            "https://registry.example",
            &SecretString::from(String::from("token")),
            Uuid::from_u128(1),
            binding,
            &prepared,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ClientError::PublicationReviewBindingMismatch
        ));
    }

    /// Submission multipart includes both stable IDs and the exact archive bytes.
    #[test]
    fn submission_multipart_binds_exact_archive() {
        let archive = b"exact archive bytes";
        let submission_id = Uuid::from_u128(4);
        let intent_id = Uuid::from_u128(5);
        let (boundary, body) = submission_multipart(submission_id, intent_id, archive);
        assert!(body
            .windows(archive.len())
            .any(|window| window == archive.as_slice()));
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains(&submission_id.to_string()));
        assert!(text.contains(&intent_id.to_string()));
        assert!(text.contains("name=\"archive\""));
        assert!(text.contains(&format!("--{boundary}--")));
    }

    /// Withdrawal transport binds the submission path and both retry identifiers.
    #[test]
    fn sends_idempotent_owner_withdrawal() {
        let decision_id = Uuid::from_u128(6);
        let request_id = Uuid::from_u128(7);
        let response = serde_json::to_vec(&lifecycle_decision_json(decision_id, request_id))
            .expect("serialize decision fixture");
        let (server, handle) = serve_json_response(response);
        let token = SecretString::new("owner-token".to_string());

        let decision = withdraw_publication_submission(
            &server,
            &token,
            Uuid::from_u128(1),
            decision_id,
            request_id,
            "author_request",
        )
        .expect("withdrawal response");

        assert_eq!(decision.id, decision_id);
        let request = handle.join().expect("test server thread");
        let lowercase_request = request.to_ascii_lowercase();
        assert!(request.starts_with(
            "POST /registry/v1/publication-submissions/00000000-0000-0000-0000-000000000001/withdraw HTTP/1.1\r\n"
        ));
        assert!(lowercase_request.contains(&format!("\r\nx-request-id: {request_id}\r\n")));
        assert!(request.contains(&format!("\"id\":\"{decision_id}\"")));
        assert!(request.contains("\"reason_code\":\"author_request\""));
        assert!(request.contains("\r\nAuthorization: Bearer owner-token\r\n"));
    }

    /// Lifecycle decision reads encode both keyset cursor components and the page bound.
    #[test]
    fn lists_owner_decisions_with_keyset_cursor() {
        let response = serde_json::to_vec(&vec![lifecycle_decision_json(
            Uuid::from_u128(6),
            Uuid::from_u128(7),
        )])
        .expect("serialize decision page");
        let (server, handle) = serve_json_response(response);
        let token = SecretString::new("owner-token".to_string());
        let cursor = PublicationLifecycleCursor {
            created_at: Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
            id: Uuid::from_u128(9),
        };

        let decisions =
            list_publication_decisions(&server, &token, "alice/admin", Some(cursor), 25)
                .expect("decision page");

        assert_eq!(decisions.len(), 1);
        let request = handle.join().expect("test server thread");
        assert!(
            request.starts_with("GET /registry/v1/publishers/alice%2Fadmin/publication-decisions?")
        );
        assert!(request.contains("before_created_at=2026-01-02T03%3A04%3A05%2B00%3A00"));
        assert!(request.contains("before_id=00000000-0000-0000-0000-000000000009"));
        assert!(request.contains("limit=25"));
    }

    /// Appeal filing binds the publisher path, adverse decision, and stable retry IDs.
    #[test]
    fn files_idempotent_owner_appeal() {
        let appeal_id = Uuid::from_u128(10);
        let decision_id = Uuid::from_u128(11);
        let request_id = Uuid::from_u128(12);
        let response = serde_json::to_vec(&serde_json::json!({
            "id": appeal_id,
            "decision_id": decision_id,
            "submission_id": Uuid::from_u128(1),
            "publisher_id": Uuid::from_u128(3),
            "actor_account_id": Uuid::from_u128(2),
            "statement": "The unchanged artifact meets policy.",
            "request_id": request_id,
            "created_at": "2026-01-01T00:00:00Z"
        }))
        .expect("serialize appeal fixture");
        let (server, handle) = serve_json_response(response);
        let token = SecretString::new("owner-token".to_string());

        let appeal = file_publication_appeal(
            &server,
            &token,
            "alice",
            decision_id,
            appeal_id,
            request_id,
            "The unchanged artifact meets policy.",
        )
        .expect("appeal response");

        assert_eq!(appeal.id, appeal_id);
        let request = handle.join().expect("test server thread");
        let lowercase_request = request.to_ascii_lowercase();
        assert!(request.starts_with(&format!(
            "POST /registry/v1/publishers/alice/publication-decisions/{decision_id}/appeal HTTP/1.1\r\n"
        )));
        assert!(lowercase_request.contains(&format!("\r\nx-request-id: {request_id}\r\n")));
        assert!(request.contains(&format!("\"id\":\"{appeal_id}\"")));
        assert!(request.contains("\"statement\":\"The unchanged artifact meets policy.\""));
    }

    /// Appeal case reads preserve the publisher path and bounded page query.
    #[test]
    fn lists_owner_appeals_with_keyset_cursor() {
        let response =
            serde_json::to_vec(&serde_json::json!([])).expect("serialize empty appeal page");
        let (server, handle) = serve_json_response(response);
        let token = SecretString::new("owner-token".to_string());
        let cursor = PublicationAppealCursor {
            created_at: Utc.with_ymd_and_hms(2026, 2, 3, 4, 5, 6).unwrap(),
            id: Uuid::from_u128(13),
        };

        let appeals = list_publication_appeals(&server, &token, "alice", Some(cursor), 100)
            .expect("appeal page");

        assert!(appeals.is_empty());
        let request = handle.join().expect("test server thread");
        assert!(request.starts_with("GET /registry/v1/publishers/alice/publication-appeals?"));
        assert!(request.contains("before_created_at=2026-02-03T04%3A05%3A06%2B00%3A00"));
        assert!(request.contains("before_id=00000000-0000-0000-0000-00000000000d"));
        assert!(request.contains("limit=100"));
    }

    /// Invalid lifecycle mutation fields fail before opening an HTTP connection.
    #[test]
    fn rejects_invalid_owner_mutation_fields_locally() {
        let token = SecretString::new("owner-token".to_string());
        let reason_error = withdraw_publication_submission(
            "https://registry.example",
            &token,
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            "Invalid Reason",
        )
        .expect_err("invalid reason code should fail");
        assert!(reason_error.to_string().contains("--reason-code"));

        let statement_error = file_publication_appeal(
            "https://registry.example",
            &token,
            "alice",
            Uuid::from_u128(4),
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            "   ",
        )
        .expect_err("blank statement should fail");
        assert!(statement_error.to_string().contains("--statement"));
    }

    /// Invalid page bounds fail locally with the accepted range.
    #[test]
    fn rejects_invalid_owner_page_limit_locally() {
        let token = SecretString::new("owner-token".to_string());
        let error =
            list_publication_decisions("https://registry.example", &token, "alice", None, 101)
                .expect_err("oversized page should fail");
        assert!(error.to_string().contains("between 1 and 100"));
    }
}
