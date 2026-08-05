//! Integration tests for route-free publication quarantine admission.
//!
//! These tests prove that all deterministic archive and intent checks precede
//! storage, and that catalog failures cannot make quarantine bytes public.

mod mocks;

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use flate2::write::GzEncoder;
use flate2::Compression;
use frameshift_catalog::{
    Ed25519PublicKey, PublicationIntentClaim, PublicationSubmissionState, PublisherKeyRecord,
    PublisherKeyState,
};
use frameshift_objects::ObjectHash;
use frameshift_pack::Pack;
use frameshift_server::publication::{PublicationAdmissionError, PublicationAdmissionService};
use tar::Builder;
use uuid::Uuid;

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Exact bytes, report-derived claim, and archive hash for one valid submission.
struct AdmissionFixture {
    /// Temporary directory retaining the source pack files.
    _source: tempfile::TempDir,
    /// Exact gzip-tar bytes authorized by the intent.
    archive: Vec<u8>,
    /// Exact intent bindings derived from a fresh server report.
    intent: PublicationIntentClaim,
}

/// Write a minimal valid public pack into `directory`.
fn write_valid_pack(directory: &Path) {
    let signing = SigningKey::from_bytes(&[41_u8; 32]);
    let author_pubkey = hex::encode(signing.verifying_key().to_bytes());
    let manifest = format!(
        "schema_version = 1\nname = \"quarantine-fixture\"\n\
         author_handle = \"alice\"\nauthor_pubkey = \"{author_pubkey}\"\n\
         version = \"1.0.0\"\nlicense = \"MIT\"\n"
    );
    std::fs::write(directory.join("pack.toml"), manifest).unwrap();
    std::fs::write(directory.join("README.md"), b"# quarantine fixture\n").unwrap();
    let mut pack = Pack::from_dir(directory).unwrap();
    pack.sign(&signing).unwrap();
}

/// Encode all files in `directory` as a flat gzip-tar archive.
fn make_targz(directory: &Path) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    archive.append_dir_all(".", directory).unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

/// Encode all files below one top-level directory in a gzip-tar archive.
fn make_nested_targz(directory: &Path) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    archive
        .append_dir_all("quarantine-fixture", directory)
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

/// Encode an archive containing two entries with the same normalized manifest path.
fn make_duplicate_manifest_targz(directory: &Path) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    archive
        .append_path_with_name(directory.join("pack.toml"), "pack.toml")
        .unwrap();
    archive
        .append_path_with_name(directory.join("README.md"), "README.md")
        .unwrap();
    archive
        .append_path_with_name(directory.join("pack.toml"), "pack.toml")
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

/// Build a valid archive and derive every intent hash from its fresh report.
fn admission_fixture() -> AdmissionFixture {
    let source = tempfile::TempDir::new().unwrap();
    write_valid_pack(source.path());
    let report = frameshift_publication::validate_directory(source.path()).unwrap();
    assert!(report.valid);
    let archive = make_targz(source.path());
    let manifest_hash = report
        .inventory
        .iter()
        .find(|entry| entry.path == "pack.toml")
        .and_then(|entry| ObjectHash::from_hex(&entry.sha256).ok())
        .unwrap();
    let file_inventory_hash = ObjectHash::from_hex(&report.inventory_hash).unwrap();
    let intent = PublicationIntentClaim {
        id: Uuid::new_v4(),
        account_id: Uuid::new_v4(),
        publisher_id: Uuid::new_v4(),
        publisher_key_id: Uuid::new_v4(),
        archive_hash: ObjectHash::of(&archive),
        manifest_hash,
        file_inventory_hash,
        scan_schema_version: report.schema_version,
    };
    AdmissionFixture {
        _source: source,
        archive,
        intent,
    }
}

/// Rebuild fixture evidence after mutating source files.
fn refresh_fixture(fixture: &mut AdmissionFixture) {
    let report = frameshift_publication::validate_directory(fixture._source.path()).unwrap();
    fixture.archive = make_targz(fixture._source.path());
    fixture.intent.archive_hash = ObjectHash::of(&fixture.archive);
    fixture.intent.manifest_hash = report
        .inventory
        .iter()
        .find(|entry| entry.path == "pack.toml")
        .and_then(|entry| ObjectHash::from_hex(&entry.sha256).ok())
        .unwrap();
    fixture.intent.file_inventory_hash = ObjectHash::from_hex(&report.inventory_hash).unwrap();
    fixture.intent.scan_schema_version = report.schema_version;
}

/// Build an admission service with observable in-memory boundaries.
fn admission_service(
    catalog: &MockCatalog,
    quarantine: &MockPackStore,
) -> PublicationAdmissionService {
    PublicationAdmissionService::new(Arc::new(catalog.clone()), Arc::new(quarantine.clone()))
}

/// Build a mock catalog containing the exact enrolled key bound by a fixture.
fn catalog_for(fixture: &AdmissionFixture) -> MockCatalog {
    let catalog = MockCatalog::new();
    catalog.state.write().unwrap().publisher_keys.insert(
        fixture.intent.publisher_key_id,
        PublisherKeyRecord {
            id: fixture.intent.publisher_key_id,
            publisher_id: fixture.intent.publisher_id,
            public_key: Ed25519PublicKey(
                SigningKey::from_bytes(&[41_u8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            label: "admission fixture".to_string(),
            state: PublisherKeyState::Active,
            created_at: Utc::now(),
            revoked_at: None,
            last_used_at: None,
        },
    );
    catalog
}

/// A valid exact submission enters quarantine once and retries idempotently.
#[tokio::test]
async fn admits_exact_archive_to_quarantine_idempotently() {
    let fixture = admission_fixture();
    let catalog = catalog_for(&fixture);
    let quarantine = MockPackStore::new();
    let service = admission_service(&catalog, &quarantine);
    let submission_id = Uuid::new_v4();

    let first = service
        .admit(
            submission_id,
            fixture.intent.clone(),
            fixture.archive.clone(),
        )
        .await
        .unwrap();
    let retry = service
        .admit(
            submission_id,
            fixture.intent.clone(),
            fixture.archive.clone(),
        )
        .await
        .unwrap();

    assert_eq!(retry, first);
    assert_eq!(first.state, PublicationSubmissionState::Quarantined);
    assert_eq!(first.archive_hash, fixture.intent.archive_hash);
    assert_eq!(quarantine.blobs.read().unwrap().len(), 1);
    assert_eq!(
        quarantine
            .blobs
            .read()
            .unwrap()
            .get(&fixture.intent.archive_hash),
        Some(&fixture.archive)
    );
    assert_eq!(
        catalog.state.read().unwrap().publication_submissions.len(),
        1
    );
}

/// A valid archive below one top-level directory is admitted to quarantine.
#[tokio::test]
async fn admits_single_directory_archive_layout() {
    let mut fixture = admission_fixture();
    fixture.archive = make_nested_targz(fixture._source.path());
    fixture.intent.archive_hash = ObjectHash::of(&fixture.archive);
    let catalog = catalog_for(&fixture);
    let quarantine = MockPackStore::new();
    let service = admission_service(&catalog, &quarantine);

    let record = service
        .admit(Uuid::new_v4(), fixture.intent, fixture.archive)
        .await
        .unwrap();

    assert_eq!(record.state, PublicationSubmissionState::Quarantined);
    assert_eq!(quarantine.blobs.read().unwrap().len(), 1);
    assert_eq!(
        catalog.state.read().unwrap().publication_submissions.len(),
        1
    );
}

/// An archive hash mismatch fails before quarantine or catalog mutation.
#[tokio::test]
async fn rejects_archive_hash_mismatch_before_writes() {
    let mut fixture = admission_fixture();
    fixture.intent.archive_hash = ObjectHash::of(b"different archive");
    let catalog = catalog_for(&fixture);
    let quarantine = MockPackStore::new();
    let service = admission_service(&catalog, &quarantine);

    let error = service
        .admit(Uuid::new_v4(), fixture.intent, fixture.archive)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        PublicationAdmissionError::ArchiveHashMismatch
    ));
    assert!(quarantine.blobs.read().unwrap().is_empty());
    assert!(catalog
        .state
        .read()
        .unwrap()
        .publication_submissions
        .is_empty());
}

/// Manifest, inventory, and scanner schema mismatches all fail before writes.
#[tokio::test]
async fn rejects_report_binding_mismatches_before_writes() {
    for field in ["manifest", "file inventory", "scan schema"] {
        let mut fixture = admission_fixture();
        match field {
            "manifest" => fixture.intent.manifest_hash = ObjectHash::of(b"other manifest"),
            "file inventory" => {
                fixture.intent.file_inventory_hash = ObjectHash::of(b"other inventory")
            }
            "scan schema" => {
                assert_eq!(frameshift_publication::REPORT_SCHEMA_VERSION, 2);
                fixture.intent.scan_schema_version = 1;
            }
            _ => unreachable!("all mismatch fixtures are enumerated"),
        }
        let catalog = catalog_for(&fixture);
        let quarantine = MockPackStore::new();
        let service = admission_service(&catalog, &quarantine);

        let error = service
            .admit(Uuid::new_v4(), fixture.intent, fixture.archive)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            PublicationAdmissionError::IntentMismatch {
                field: observed
            } if observed == field
        ));
        assert!(quarantine.blobs.read().unwrap().is_empty());
        assert!(catalog
            .state
            .read()
            .unwrap()
            .publication_submissions
            .is_empty());
    }
}

/// Missing, malformed, wrong-key, and manifest-substituted signatures fail closed.
#[tokio::test]
async fn rejects_unauthorized_archive_signatures_before_writes() {
    for case in ["unsigned", "malformed", "wrong-key", "manifest-key"] {
        let mut fixture = admission_fixture();
        match case {
            "unsigned" => {
                std::fs::remove_file(fixture._source.path().join("signature.sig")).unwrap()
            }
            "malformed" => {
                std::fs::write(fixture._source.path().join("signature.sig"), [7_u8; 63]).unwrap()
            }
            "wrong-key" => {
                let mut pack = Pack::from_dir(fixture._source.path()).unwrap();
                pack.sign(&SigningKey::from_bytes(&[42_u8; 32])).unwrap();
            }
            "manifest-key" => {
                let signing = SigningKey::from_bytes(&[42_u8; 32]);
                let manifest = format!(
                    "schema_version = 1\nname = \"quarantine-fixture\"\n\
                     author_handle = \"alice\"\nauthor_pubkey = \"{}\"\n\
                     version = \"1.0.0\"\nlicense = \"MIT\"\n",
                    hex::encode(signing.verifying_key().to_bytes())
                );
                std::fs::write(fixture._source.path().join("pack.toml"), manifest).unwrap();
                let mut pack = Pack::from_dir(fixture._source.path()).unwrap();
                pack.sign(&signing).unwrap();
            }
            _ => unreachable!("signature cases are enumerated"),
        }
        refresh_fixture(&mut fixture);
        let catalog = catalog_for(&fixture);
        let quarantine = MockPackStore::new();
        let service = admission_service(&catalog, &quarantine);

        let error = service
            .admit(Uuid::new_v4(), fixture.intent, fixture.archive)
            .await
            .unwrap_err();

        assert!(
            matches!(error, PublicationAdmissionError::Signature),
            "unexpected {case} error: {error}"
        );
        assert!(quarantine.blobs.read().unwrap().is_empty());
        assert!(catalog
            .state
            .read()
            .unwrap()
            .publication_submissions
            .is_empty());
    }
}

/// Unsafe duplicate paths are rejected before either durable boundary changes.
#[tokio::test]
async fn rejects_duplicate_archive_paths_before_writes() {
    let mut fixture = admission_fixture();
    fixture.archive = make_duplicate_manifest_targz(fixture._source.path());
    fixture.intent.archive_hash = ObjectHash::of(&fixture.archive);
    let catalog = catalog_for(&fixture);
    let quarantine = MockPackStore::new();
    let service = admission_service(&catalog, &quarantine);

    let error = service
        .admit(Uuid::new_v4(), fixture.intent, fixture.archive)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        PublicationAdmissionError::InvalidArchive("duplicate archive path")
    ));
    assert!(quarantine.blobs.read().unwrap().is_empty());
    assert!(catalog
        .state
        .read()
        .unwrap()
        .publication_submissions
        .is_empty());
}

/// A deterministic blocking publication finding fails before durable writes.
#[tokio::test]
async fn rejects_invalid_publication_report_before_writes() {
    let mut fixture = admission_fixture();
    std::fs::write(
        fixture._source.path().join("notes.txt"),
        b"not public pack content",
    )
    .unwrap();
    fixture.archive = make_targz(fixture._source.path());
    fixture.intent.archive_hash = ObjectHash::of(&fixture.archive);
    let catalog = catalog_for(&fixture);
    let quarantine = MockPackStore::new();
    let service = admission_service(&catalog, &quarantine);

    let error = service
        .admit(Uuid::new_v4(), fixture.intent, fixture.archive)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        PublicationAdmissionError::Validation { ref codes }
            if codes == "path.not_allowed"
    ));
    assert!(quarantine.blobs.read().unwrap().is_empty());
    assert!(catalog
        .state
        .read()
        .unwrap()
        .publication_submissions
        .is_empty());
}

/// A quarantine write failure prevents catalog persistence.
#[tokio::test]
async fn quarantine_failure_prevents_catalog_write() {
    let fixture = admission_fixture();
    let catalog = catalog_for(&fixture);
    let quarantine = MockPackStore::new();
    quarantine.fail_put_with("injected quarantine failure");
    let service = admission_service(&catalog, &quarantine);

    let error = service
        .admit(Uuid::new_v4(), fixture.intent, fixture.archive)
        .await
        .unwrap_err();

    assert!(matches!(error, PublicationAdmissionError::Quarantine(_)));
    assert!(quarantine.blobs.read().unwrap().is_empty());
    assert!(catalog
        .state
        .read()
        .unwrap()
        .publication_submissions
        .is_empty());
}

/// A catalog failure leaves only a content-addressed, unreachable quarantine blob.
#[tokio::test]
async fn catalog_failure_leaves_only_quarantine_blob() {
    let fixture = admission_fixture();
    let catalog = catalog_for(&fixture);
    catalog.state.write().unwrap().publication_submission_error =
        Some("injected catalog failure".to_string());
    let quarantine = MockPackStore::new();
    let unrelated_public_store = MockPackStore::new();
    let service = admission_service(&catalog, &quarantine);

    let error = service
        .admit(
            Uuid::new_v4(),
            fixture.intent.clone(),
            fixture.archive.clone(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, PublicationAdmissionError::Catalog(_)));
    assert_eq!(quarantine.blobs.read().unwrap().len(), 1);
    assert_eq!(
        quarantine
            .blobs
            .read()
            .unwrap()
            .get(&fixture.intent.archive_hash),
        Some(&fixture.archive)
    );
    assert!(unrelated_public_store.blobs.read().unwrap().is_empty());
    assert!(catalog
        .state
        .read()
        .unwrap()
        .publication_submissions
        .is_empty());
}
