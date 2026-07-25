//! Integration tests for route-free approved-submission promotion.

mod mocks;

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use flate2::write::GzEncoder;
use flate2::Compression;
use frameshift_catalog::{
    AccountRecord, AccountStatus, CatalogError, Ed25519PublicKey, PackRecord, PlatformRole,
    PlatformRoleRecord, PlatformRoleState, PublicationSubmissionRecord, PublicationSubmissionState,
    PublishQuota, PublisherKeyRecord, PublisherKeyState, PublisherModerationStatus,
    PublisherProfileRecord,
};
use frameshift_objects::ObjectHash;
use frameshift_pack::Pack;
use frameshift_server::publication::{PublicationPromotionError, PublicationPromotionService};
use tar::Builder;
use uuid::Uuid;

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Complete promotion fixture with isolated quarantine and public stores.
struct PromotionFixture {
    /// Shared catalog containing approved submission state and authority.
    catalog: MockCatalog,
    /// Isolated quarantine store containing the exact approved archive.
    quarantine: MockPackStore,
    /// Public object store initially containing no archive.
    public: MockPackStore,
    /// Promotion service under test.
    service: PublicationPromotionService,
    /// Approved submission selected for promotion.
    submission: PublicationSubmissionRecord,
    /// Account holding active global moderation authority.
    moderator_id: Uuid,
}

/// Write and sign one minimal valid public pack.
fn write_signed_pack(directory: &Path, signing: &SigningKey) {
    let manifest = format!(
        "schema_version = 1\nname = \"promoted-fixture\"\n\
         author_handle = \"alice\"\nauthor_pubkey = \"{}\"\n\
         version = \"1.2.3\"\nlicense = \"MIT\"\n\
         description = \"Verified promotion fixture\"\ntags = [\"test\", \"promotion\"]\n",
        hex::encode(signing.verifying_key().to_bytes())
    );
    std::fs::write(directory.join("pack.toml"), manifest).unwrap();
    std::fs::write(directory.join("README.md"), b"# promoted fixture\n").unwrap();
    let mut pack = Pack::from_dir(directory).unwrap();
    pack.sign(signing).unwrap();
}

/// Encode every source file into one flat gzip-tar archive.
fn make_targz(directory: &Path) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    archive.append_dir_all(".", directory).unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

/// Build an approved submission and all current promotion authority.
fn fixture() -> PromotionFixture {
    let source = tempfile::TempDir::new().unwrap();
    let signing = SigningKey::from_bytes(&[71_u8; 32]);
    write_signed_pack(source.path(), &signing);
    let report = frameshift_publication::validate_directory(source.path()).unwrap();
    let archive = make_targz(source.path());
    let archive_hash = ObjectHash::of(&archive);
    let manifest_hash = report
        .inventory
        .iter()
        .find(|entry| entry.path == "pack.toml")
        .and_then(|entry| ObjectHash::from_hex(&entry.sha256).ok())
        .unwrap();
    let now = Utc::now();
    let moderator_id = Uuid::new_v4();
    let publisher_id = Uuid::new_v4();
    let publisher_key_id = Uuid::new_v4();
    let submission = PublicationSubmissionRecord {
        id: Uuid::new_v4(),
        intent_id: Uuid::new_v4(),
        account_id: Uuid::new_v4(),
        publisher_id,
        publisher_key_id,
        archive_hash,
        manifest_hash,
        file_inventory_hash: ObjectHash::from_hex(&report.inventory_hash).unwrap(),
        scan_schema_version: report.schema_version,
        scan_report: report,
        state: PublicationSubmissionState::Approved,
        created_at: now,
        updated_at: now,
    };
    let catalog = MockCatalog::new();
    {
        let mut state = catalog.state.write().unwrap();
        state.accounts.insert(
            moderator_id,
            AccountRecord {
                id: moderator_id,
                issuer: "https://issuer.frameshift.test".to_string(),
                subject: "moderator".to_string(),
                email: None,
                display_name: Some("Moderator".to_string()),
                status: AccountStatus::Active,
                created_at: now,
                updated_at: now,
            },
        );
        state.platform_roles.push(PlatformRoleRecord {
            account_id: moderator_id,
            role: PlatformRole::Moderator,
            state: PlatformRoleState::Active,
            assigned_by_account_id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
        });
        state.publishers.insert(
            publisher_id,
            PublisherProfileRecord {
                id: publisher_id,
                handle: "promoted-publisher".to_string(),
                display_name: "Promoted Publisher".to_string(),
                biography: None,
                moderation_status: PublisherModerationStatus::Approved,
                created_at: now,
                updated_at: now,
            },
        );
        state.publisher_keys.insert(
            publisher_key_id,
            PublisherKeyRecord {
                id: publisher_key_id,
                publisher_id,
                public_key: Ed25519PublicKey(signing.verifying_key().to_bytes()),
                label: "promotion fixture".to_string(),
                state: PublisherKeyState::Active,
                created_at: now,
                revoked_at: None,
                last_used_at: None,
            },
        );
        state
            .publication_submissions
            .insert(submission.id, submission.clone());
    }
    let quarantine = MockPackStore::new();
    quarantine.insert(archive_hash, archive);
    let public = MockPackStore::new();
    let service = PublicationPromotionService::new(
        Arc::new(catalog.clone()),
        Arc::new(quarantine.clone()),
        Arc::new(public.clone()),
        1_048_576,
        PublishQuota::unlimited(),
    );
    PromotionFixture {
        catalog,
        quarantine,
        public,
        service,
        submission,
        moderator_id,
    }
}

/// A verified approved archive becomes one active version and exact retry evidence.
#[tokio::test]
async fn promotes_approved_archive_and_replays_exactly() {
    let fixture = fixture();
    let promotion_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();

    let first = fixture
        .service
        .promote(
            promotion_id,
            fixture.submission.id,
            fixture.moderator_id,
            request_id,
        )
        .await
        .unwrap();
    let retry = fixture
        .service
        .promote(
            promotion_id,
            fixture.submission.id,
            fixture.moderator_id,
            request_id,
        )
        .await
        .unwrap();

    assert_eq!(retry, first);
    assert_eq!(first.content_hash, fixture.submission.archive_hash);
    assert_eq!(fixture.public.blobs.read().unwrap().len(), 1);
    let state = fixture.catalog.state.read().unwrap();
    assert_eq!(state.publication_promotions.len(), 1);
    assert_eq!(state.versions.len(), 1);
    assert_eq!(
        state
            .publication_submissions
            .get(&fixture.submission.id)
            .unwrap()
            .state,
        PublicationSubmissionState::Promoted
    );
}

/// A public-store failure leaves the approved submission and catalog untouched.
#[tokio::test]
async fn public_store_failure_prevents_catalog_activation() {
    let fixture = fixture();
    fixture.public.fail_put_with("injected public failure");

    let error = fixture
        .service
        .promote(
            Uuid::new_v4(),
            fixture.submission.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, PublicationPromotionError::PublicStore(_)));
    let state = fixture.catalog.state.read().unwrap();
    assert!(state.publication_promotions.is_empty());
    assert!(state.versions.is_empty());
    assert_eq!(
        state
            .publication_submissions
            .get(&fixture.submission.id)
            .unwrap()
            .state,
        PublicationSubmissionState::Approved
    );
}

/// Revoked signing authority fails closed without creating an active version.
#[tokio::test]
async fn revoked_key_prevents_activation() {
    let fixture = fixture();
    fixture
        .catalog
        .state
        .write()
        .unwrap()
        .publisher_keys
        .get_mut(&fixture.submission.publisher_key_id)
        .unwrap()
        .state = PublisherKeyState::Revoked;

    let error = fixture
        .service
        .promote(
            Uuid::new_v4(),
            fixture.submission.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, PublicationPromotionError::Verification(_)));
    assert!(fixture.public.blobs.read().unwrap().is_empty());
    assert!(fixture.catalog.state.read().unwrap().versions.is_empty());
}

/// Substituted quarantine bytes fail integrity before public storage is touched.
#[tokio::test]
async fn substituted_quarantine_bytes_fail_before_public_write() {
    let fixture = fixture();
    fixture
        .quarantine
        .blobs
        .write()
        .unwrap()
        .insert(fixture.submission.archive_hash, b"substituted".to_vec());

    let error = fixture
        .service
        .promote(
            Uuid::new_v4(),
            fixture.submission.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, PublicationPromotionError::Integrity));
    assert!(fixture.public.blobs.read().unwrap().is_empty());
    assert!(fixture.catalog.state.read().unwrap().versions.is_empty());
}

/// A missing quarantine object fails without touching public or catalog state.
#[tokio::test]
async fn missing_quarantine_bytes_fail_before_public_write() {
    let fixture = fixture();
    fixture
        .quarantine
        .blobs
        .write()
        .unwrap()
        .remove(&fixture.submission.archive_hash);

    let error = fixture
        .service
        .promote(
            Uuid::new_v4(),
            fixture.submission.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, PublicationPromotionError::Quarantine(_)));
    assert!(fixture.public.blobs.read().unwrap().is_empty());
    assert!(fixture.catalog.state.read().unwrap().versions.is_empty());
}

/// An archive above the configured compressed-byte ceiling fails closed.
#[tokio::test]
async fn oversized_quarantine_bytes_fail_before_public_write() {
    let fixture = fixture();
    let service = PublicationPromotionService::new(
        Arc::new(fixture.catalog.clone()),
        Arc::new(fixture.quarantine.clone()),
        Arc::new(fixture.public.clone()),
        1,
        PublishQuota::unlimited(),
    );

    let error = service
        .promote(
            Uuid::new_v4(),
            fixture.submission.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, PublicationPromotionError::Integrity));
    assert!(fixture.public.blobs.read().unwrap().is_empty());
    assert!(fixture.catalog.state.read().unwrap().versions.is_empty());
}

/// Human approval is mandatory before quarantine bytes can reach public storage.
#[tokio::test]
async fn non_approved_submission_fails_before_public_write() {
    let fixture = fixture();
    fixture
        .catalog
        .state
        .write()
        .unwrap()
        .publication_submissions
        .get_mut(&fixture.submission.id)
        .unwrap()
        .state = PublicationSubmissionState::Quarantined;

    let error = fixture
        .service
        .promote(
            Uuid::new_v4(),
            fixture.submission.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, PublicationPromotionError::NotApproved));
    assert!(fixture.public.blobs.read().unwrap().is_empty());
    assert!(fixture.catalog.state.read().unwrap().versions.is_empty());
}

/// Publisher suspension is rechecked transactionally and leaves approval retryable.
#[tokio::test]
async fn suspended_publisher_prevents_catalog_activation() {
    let fixture = fixture();
    fixture
        .catalog
        .state
        .write()
        .unwrap()
        .publishers
        .get_mut(&fixture.submission.publisher_id)
        .unwrap()
        .moderation_status = PublisherModerationStatus::Suspended;

    let error = fixture
        .service
        .promote(
            Uuid::new_v4(),
            fixture.submission.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        PublicationPromotionError::Catalog(CatalogError::Unauthorized { .. })
    ));
    assert_eq!(fixture.public.blobs.read().unwrap().len(), 1);
    let state = fixture.catalog.state.read().unwrap();
    assert!(state.versions.is_empty());
    assert_eq!(
        state
            .publication_submissions
            .get(&fixture.submission.id)
            .unwrap()
            .state,
        PublicationSubmissionState::Approved
    );
}

/// A catalog failure can leave only an unreachable blob and retryable approval.
#[tokio::test]
async fn catalog_failure_leaves_no_active_version_and_preserves_approval() {
    let fixture = fixture();
    fixture
        .catalog
        .state
        .write()
        .unwrap()
        .publication_promotion_error = Some("injected promotion failure".to_string());

    let error = fixture
        .service
        .promote(
            Uuid::new_v4(),
            fixture.submission.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        PublicationPromotionError::Catalog(CatalogError::BackendError(_))
    ));
    assert_eq!(fixture.public.blobs.read().unwrap().len(), 1);
    let state = fixture.catalog.state.read().unwrap();
    assert!(state.publication_promotions.is_empty());
    assert!(state.versions.is_empty());
    assert_eq!(
        state
            .publication_submissions
            .get(&fixture.submission.id)
            .unwrap()
            .state,
        PublicationSubmissionState::Approved
    );
}

/// A pack already bound to another publisher cannot be taken over by promotion.
#[tokio::test]
async fn existing_pack_ownership_prevents_catalog_activation() {
    let fixture = fixture();
    let now = Utc::now();
    fixture.catalog.state.write().unwrap().packs.insert(
        "promoted-fixture".to_string(),
        PackRecord {
            name: "promoted-fixture".to_string(),
            current_author: Ed25519PublicKey([99_u8; 32]),
            publisher_id: Some(Uuid::new_v4()),
            tags: Vec::new(),
            description: String::new(),
            created_at: now,
            latest_version: None,
            total_downloads: 0,
            extends: None,
        },
    );

    let error = fixture
        .service
        .promote(
            Uuid::new_v4(),
            fixture.submission.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        PublicationPromotionError::Catalog(CatalogError::Unauthorized { kind: "pack", .. })
    ));
    assert_eq!(fixture.public.blobs.read().unwrap().len(), 1);
    let state = fixture.catalog.state.read().unwrap();
    assert!(state.versions.is_empty());
    assert!(state.publication_promotions.is_empty());
}

/// A second approved submission cannot overwrite an already active pack version.
#[tokio::test]
async fn duplicate_pack_version_prevents_second_activation() {
    let fixture = fixture();
    let mut duplicate = fixture.submission.clone();
    duplicate.id = Uuid::new_v4();
    duplicate.intent_id = Uuid::new_v4();
    fixture
        .catalog
        .state
        .write()
        .unwrap()
        .publication_submissions
        .insert(duplicate.id, duplicate.clone());

    fixture
        .service
        .promote(
            Uuid::new_v4(),
            fixture.submission.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let error = fixture
        .service
        .promote(
            Uuid::new_v4(),
            duplicate.id,
            fixture.moderator_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        PublicationPromotionError::Catalog(CatalogError::Conflict {
            kind: "pack_version",
            ..
        })
    ));
    let state = fixture.catalog.state.read().unwrap();
    assert_eq!(state.versions.len(), 1);
    assert_eq!(state.publication_promotions.len(), 1);
    assert_eq!(
        state
            .publication_submissions
            .get(&duplicate.id)
            .unwrap()
            .state,
        PublicationSubmissionState::Approved
    );
}
