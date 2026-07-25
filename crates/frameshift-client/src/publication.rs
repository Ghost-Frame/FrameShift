//! Explicit Creator Studio publication preparation and quarantine transport.
//!
//! Preparation consumes an immutable [`frameshift_studio::DraftSnapshot`].
//! Network operations require caller-provided account authorization and, for
//! submission, the exact signing key. No operation in this module is exposed
//! through the MCP tool surface.

use std::fs;

use ed25519_dalek::{Signer as _, SigningKey};
use flate2::{Compression, GzBuilder};
use frameshift_catalog::{PublicationIntentRecord, PublicationSubmissionRecord};
use frameshift_pack::{ObjectHash, Pack};
use frameshift_studio::DraftSnapshot;
use secrecy::SecretString;
use serde::Serialize;
use uuid::Uuid;

use crate::error::ClientError;

/// Public non-secret hashes that bind one exact prepared publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PublicationBinding {
    /// SHA-256 digest of the exact deterministic gzip-tar bytes.
    pub archive_hash: ObjectHash,
    /// SHA-256 digest of the exact `pack.toml` bytes.
    pub manifest_hash: ObjectHash,
    /// SHA-256 digest of the normalized public file inventory.
    pub file_inventory_hash: ObjectHash,
    /// Version of the shared publication scanner contract.
    pub scan_schema_version: u32,
}

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
    publisher_id: Uuid,
    publisher_key_id: Uuid,
    prepared: &PreparedPublication,
) -> Result<PublicationIntentRecord, ClientError> {
    let binding = prepared.binding;
    let body = serde_json::to_vec(&CreatePublicationIntentRequest {
        id: intent_id,
        publisher_id,
        publisher_key_id,
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
    use frameshift_studio::Studio;

    use super::*;

    /// Return a deterministic signing key for publication fixtures.
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[17_u8; 32])
    }

    /// Build a reviewed and intent-confirmed snapshot using the fixture key.
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
        studio.confirm_review("fixture", &inventory_hash).unwrap();
        studio
            .confirm_submission_intent("fixture", &inventory_hash)
            .unwrap();
        studio
            .snapshot_for_submission("fixture", &inventory_hash)
            .unwrap()
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

    /// Intent JSON carries every exact hash and caller-selected idempotency identifier.
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
}
