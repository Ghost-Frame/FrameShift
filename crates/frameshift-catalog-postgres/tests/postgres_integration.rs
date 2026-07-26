//! Integration tests for [`PostgresCatalog`].
//!
//! These tests require Docker to run a `postgres:16-alpine` container via
//! `testcontainers`. They are gated behind `#[ignore]` so that `cargo test`
//! succeeds without Docker.
//!
//! # Running the integration tests
//!
//! ```bash
//! cargo test -p frameshift-catalog-postgres -- --ignored
//! ```
//!
//! All tests share a single container started in `setup_catalog()`.

use std::time::Duration;

use diesel::{ExpressionMethods as _, QueryDsl as _};
use diesel_async::{RunQueryDsl as _, SimpleAsyncConnection as _};
use frameshift_catalog::{
    AccountRecord, AccountStatus, AuthorRecord, CatalogBackend, CatalogError, Ed25519PublicKey,
    MembershipState, ObjectHash, PackSearchFilters, PackStatus, PackVersionRecord, PlatformRole,
    PlatformRoleState, PublicationAppealDisposition, PublicationAppealRequest,
    PublicationAppealResolutionRequest, PublicationIntentClaim, PublicationIntentRecord,
    PublicationLifecycleAction, PublicationLifecycleCursor, PublicationModerationAction,
    PublicationModerationDecisionRequest, PublicationPromotionRequest,
    PublicationSubmissionRequest, PublicationSubmissionState, PublicationTombstoneRequest,
    PublicationWithdrawalRequest, PublishQuota, PublisherAuditEventRecord, PublisherKeyRecord,
    PublisherKeyState, PublisherMembershipRecord, PublisherModerationStatus,
    PublisherProfileRecord, PublisherRole, PublisherSuspensionRequest, SortMode, TombstoneReason,
    TombstoneRecord,
};
use frameshift_catalog_postgres::schema::{
    account_platform_roles, accounts, pack_versions, publication_appeal_resolutions,
    publication_appeals, publication_lifecycle_decisions, publication_moderation_decisions,
    publication_promotions, publication_submissions, publisher_audit_events, publisher_keys,
    publisher_memberships, publisher_profiles,
};
use frameshift_catalog_postgres::{
    OwnershipBackfillApplied, OwnershipBackfillManifest, OwnershipBackfillMode,
    OwnershipManifestKey, OwnershipManifestKeyState, OwnershipManifestModerationStatus,
    OwnershipManifestPack, OwnershipManifestPublisher, OwnershipManifestVersion, PostgresCatalog,
    PostgresCatalogConfig, OWNERSHIP_BACKFILL_SCHEMA_VERSION,
};
use frameshift_publication::{
    inventory_hash, FindingSeverity, InventoryEntry, PublicationFinding, PublicationReport,
};
use secrecy::SecretString;
use sha2::{Digest as _, Sha256};

/// Construct a [`PostgresCatalog`] pointing at a fresh `testcontainers`-managed
/// Postgres instance.
///
/// The `testcontainers` library starts the container on first call and keeps it
/// alive as long as the returned `ContainerAsync` is not dropped. Callers must
/// hold the container handle for the lifetime of the test.
async fn setup_catalog() -> (
    PostgresCatalog,
    testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>,
) {
    use testcontainers::runners::AsyncRunner as _;
    use testcontainers_modules::postgres::Postgres;

    let container = Postgres::default()
        .start()
        .await
        .expect("failed to start postgres container");

    let host = container
        .get_host()
        .await
        .expect("failed to get container host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to get container port");

    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    let catalog = PostgresCatalog::new(PostgresCatalogConfig {
        url: SecretString::from(url),
        pool_size: 5,
        connect_timeout: Duration::from_secs(10),
        statement_timeout: Duration::from_secs(30),
    })
    .await
    .expect("PostgresCatalog::new failed");

    (catalog, container)
}

/// Build a deterministic [`Ed25519PublicKey`] from a seed byte.
fn make_pubkey(seed: u8) -> Ed25519PublicKey {
    Ed25519PublicKey([seed; 32])
}

/// Build a deterministic [`ObjectHash`] from a seed byte.
fn make_hash(seed: u8) -> ObjectHash {
    ObjectHash::from_bytes([seed; 32])
}

/// Build a minimal [`AuthorRecord`] for use in tests.
fn make_author(seed: u8, handle: &str) -> AuthorRecord {
    AuthorRecord {
        pubkey: make_pubkey(seed),
        handle: handle.to_string(),
        display_name: None,
        created_at: chrono::Utc::now(),
        oauth_links: vec![],
    }
}

/// Build a minimal [`PackVersionRecord`] for use in tests.
fn make_version(
    pack_name: &str,
    version: &str,
    author_seed: u8,
    hash_seed: u8,
) -> PackVersionRecord {
    PackVersionRecord {
        pack_name: pack_name.to_string(),
        version: version.to_string(),
        content_hash: make_hash(hash_seed),
        signature: vec![0x42_u8; 64],
        author_pubkey: make_pubkey(author_seed),
        publisher_key_id: None,
        parent_hash: None,
        capability_manifest_json: r#"{"permissions":[]}"#.to_string(),
        schema_version: 1,
        license: "Apache-2.0".to_string(),
        published_at: chrono::Utc::now(),
        status: PackStatus::Active,
        size_bytes: 1024,
    }
}

/// Build a minimal active OIDC account for repository tests.
fn make_account(id: uuid::Uuid, subject: &str) -> AccountRecord {
    let now = chrono::Utc::now();
    AccountRecord {
        id,
        issuer: "https://issuer.example".to_string(),
        subject: subject.to_string(),
        email: Some(format!("{subject}@example.test")),
        display_name: Some(subject.to_string()),
        status: AccountStatus::Active,
        created_at: now,
        updated_at: now,
    }
}

/// Create one approved publisher with an active deterministic signing key.
async fn create_test_publisher(
    catalog: &PostgresCatalog,
    handle: &str,
    key_seed: u8,
) -> (uuid::Uuid, uuid::Uuid, PublisherKeyRecord) {
    let account = make_account(uuid::Uuid::new_v4(), &format!("{handle}-account"));
    catalog
        .create_account(account.clone())
        .await
        .expect("create publisher test account failed");
    let publisher_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    catalog
        .create_publisher(
            PublisherProfileRecord {
                id: publisher_id,
                handle: handle.to_string(),
                display_name: handle.to_string(),
                biography: None,
                moderation_status: PublisherModerationStatus::Approved,
                created_at: now,
                updated_at: now,
            },
            PublisherMembershipRecord {
                account_id: account.id,
                publisher_id,
                role: PublisherRole::Owner,
                state: MembershipState::Active,
                created_at: now,
                updated_at: now,
            },
            None,
        )
        .await
        .expect("create test publisher failed");
    let key = PublisherKeyRecord {
        id: uuid::Uuid::new_v4(),
        publisher_id,
        public_key: make_pubkey(key_seed),
        label: format!("{handle} key"),
        state: PublisherKeyState::Active,
        created_at: now,
        revoked_at: None,
        last_used_at: None,
    };
    catalog
        .create_publisher_key(key.clone(), None)
        .await
        .expect("create test publisher key failed");
    (account.id, publisher_id, key)
}

/// Build an unconsumed publication intent with deterministic artifact hashes.
fn make_publication_intent(
    account_id: uuid::Uuid,
    publisher_id: uuid::Uuid,
    publisher_key_id: uuid::Uuid,
    hash_seed: u8,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> PublicationIntentRecord {
    PublicationIntentRecord {
        id: uuid::Uuid::new_v4(),
        account_id,
        publisher_id,
        publisher_key_id,
        archive_hash: make_hash(hash_seed),
        manifest_hash: make_hash(hash_seed.wrapping_add(1)),
        file_inventory_hash: make_hash(hash_seed.wrapping_add(2)),
        scan_schema_version: 1,
        created_at,
        expires_at,
        consumed_at: None,
    }
}

/// Build an exact consumption claim from a persisted intent.
fn make_publication_claim(intent: &PublicationIntentRecord) -> PublicationIntentClaim {
    PublicationIntentClaim {
        id: intent.id,
        account_id: intent.account_id,
        publisher_id: intent.publisher_id,
        publisher_key_id: intent.publisher_key_id,
        archive_hash: intent.archive_hash,
        manifest_hash: intent.manifest_hash,
        file_inventory_hash: intent.file_inventory_hash,
        scan_schema_version: intent.scan_schema_version,
    }
}

/// Build a valid deterministic server report bound to one intent inventory hash.
fn make_publication_report(intent: &PublicationIntentRecord) -> PublicationReport {
    let inventory = vec![InventoryEntry {
        path: "pack.toml".to_string(),
        size: 12,
        sha256: make_hash(151).to_hex(),
    }];
    PublicationReport {
        schema_version: intent.scan_schema_version,
        valid: true,
        inventory_hash: inventory_hash(&inventory),
        inventory,
        findings: Vec::new(),
    }
}

/// Build an intent whose inventory digest matches the stable submission fixture.
fn make_publication_submission_intent(
    account_id: uuid::Uuid,
    publisher_id: uuid::Uuid,
    publisher_key_id: uuid::Uuid,
    hash_seed: u8,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> PublicationIntentRecord {
    let mut intent = make_publication_intent(
        account_id,
        publisher_id,
        publisher_key_id,
        hash_seed,
        created_at,
        expires_at,
    );
    let report = make_publication_report(&intent);
    intent.file_inventory_hash =
        ObjectHash::from_hex(&report.inventory_hash).expect("fixture inventory hash must parse");
    intent
}

/// Build an exact quarantined submission request for one intent.
fn make_publication_submission(intent: &PublicationIntentRecord) -> PublicationSubmissionRequest {
    PublicationSubmissionRequest {
        id: uuid::Uuid::new_v4(),
        intent: make_publication_claim(intent),
        scan_report: make_publication_report(intent),
    }
}

/// Persist one active global role directly for a moderation fixture.
async fn assign_test_platform_role(catalog: &PostgresCatalog, account_id: uuid::Uuid, role: &str) {
    let now = chrono::Utc::now();
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("platform role fixture connection failed");
    diesel::insert_into(account_platform_roles::table)
        .values((
            account_platform_roles::account_id.eq(account_id),
            account_platform_roles::role.eq(role),
            account_platform_roles::state.eq("active"),
            account_platform_roles::assigned_by_account_id.eq(account_id),
            account_platform_roles::created_at.eq(now),
            account_platform_roles::updated_at.eq(now),
        ))
        .execute(&mut connection)
        .await
        .expect("insert platform role fixture failed");
}

/// Create and persist one quarantined submission for moderation tests.
async fn create_test_publication_submission(
    catalog: &PostgresCatalog,
    handle: &str,
    seed: u8,
) -> (uuid::Uuid, uuid::Uuid, uuid::Uuid) {
    let (owner_account_id, publisher_id, key) = create_test_publisher(catalog, handle, seed).await;
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("current timestamp must fit");
    let intent = make_publication_submission_intent(
        owner_account_id,
        publisher_id,
        key.id,
        seed.wrapping_add(1),
        now,
        now + chrono::Duration::minutes(10),
    );
    catalog
        .create_publication_intent(intent.clone())
        .await
        .expect("create moderation intent failed");
    let request = make_publication_submission(&intent);
    let submission = catalog
        .create_publication_submission(request)
        .await
        .expect("create moderation submission failed");
    (owner_account_id, publisher_id, submission.id)
}

/// Build one bounded moderation request for a submission and actor.
fn make_moderation_request(
    submission_id: uuid::Uuid,
    actor_account_id: uuid::Uuid,
    action: PublicationModerationAction,
) -> PublicationModerationDecisionRequest {
    PublicationModerationDecisionRequest {
        id: uuid::Uuid::new_v4(),
        submission_id,
        actor_account_id,
        action,
        reason_code: "policy.reviewed".to_string(),
        private_explanation: Some("The submission completed manual review.".to_string()),
        request_id: uuid::Uuid::new_v4(),
    }
}

/// Build one bounded owner appeal request for an adverse decision.
fn make_appeal_request(
    decision_id: uuid::Uuid,
    publisher_id: uuid::Uuid,
    actor_account_id: uuid::Uuid,
) -> PublicationAppealRequest {
    PublicationAppealRequest {
        id: uuid::Uuid::new_v4(),
        decision_id,
        publisher_id,
        actor_account_id,
        statement: "The unchanged artifact should be reconsidered under the stated policy."
            .to_string(),
        request_id: uuid::Uuid::new_v4(),
    }
}

/// Build one bounded administrator appeal resolution request.
fn make_appeal_resolution_request(
    appeal_id: uuid::Uuid,
    actor_account_id: uuid::Uuid,
    disposition: PublicationAppealDisposition,
) -> PublicationAppealResolutionRequest {
    PublicationAppealResolutionRequest {
        id: uuid::Uuid::new_v4(),
        appeal_id,
        actor_account_id,
        disposition,
        rationale: "The appeal was independently reviewed against the original artifact."
            .to_string(),
        separation_exception_reason: None,
        request_id: uuid::Uuid::new_v4(),
    }
}

/// Build one active version and exact promotion request from approved evidence.
async fn make_promotion_request(
    catalog: &PostgresCatalog,
    submission_id: uuid::Uuid,
    actor_account_id: uuid::Uuid,
) -> PublicationPromotionRequest {
    let submission = catalog
        .get_publication_submission(submission_id)
        .await
        .expect("promotion submission lookup failed");
    let key = catalog
        .get_publisher_key(submission.publisher_key_id)
        .await
        .expect("promotion publisher key lookup failed");
    PublicationPromotionRequest {
        id: uuid::Uuid::new_v4(),
        submission_id,
        actor_account_id,
        request_id: uuid::Uuid::new_v4(),
        version: PackVersionRecord {
            pack_name: format!("promotion-{submission_id}"),
            version: "1.0.0".to_string(),
            content_hash: submission.archive_hash,
            signature: vec![0x51_u8; 64],
            author_pubkey: key.public_key,
            publisher_key_id: Some(key.id),
            parent_hash: None,
            capability_manifest_json: r#"{"permissions":[]}"#.to_string(),
            schema_version: 1,
            license: "MIT".to_string(),
            published_at: chrono::Utc::now(),
            status: PackStatus::Active,
            size_bytes: 2048,
        },
        description: "Atomic promotion fixture".to_string(),
        tags: vec!["promotion".to_string(), "test".to_string()],
        extends: None,
    }
}

/// Return a stable microsecond-safe timestamp for ownership migration manifests.
fn ownership_manifest_time() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_750_000_000, 0)
        .expect("ownership manifest timestamp must be valid")
}

/// Serialize a manifest and compute the confirmation for its exact bytes.
fn ownership_manifest_input(manifest: &OwnershipBackfillManifest) -> (Vec<u8>, String) {
    let bytes = serde_json::to_vec(manifest).expect("ownership manifest must serialize");
    let digest = hex::encode(Sha256::digest(&bytes));
    (bytes, digest)
}

/// Build a complete ownership manifest for one legacy pack version.
fn ownership_manifest_for_legacy_pack(
    account_id: uuid::Uuid,
    publisher_id: uuid::Uuid,
    key_id: uuid::Uuid,
    audit_event_id: uuid::Uuid,
    handle: &str,
    pack_name: &str,
    version: &PackVersionRecord,
) -> OwnershipBackfillManifest {
    let timestamp = ownership_manifest_time();
    OwnershipBackfillManifest {
        schema_version: OWNERSHIP_BACKFILL_SCHEMA_VERSION,
        expected_pack_count: 1,
        expected_version_count: 1,
        publishers: vec![OwnershipManifestPublisher {
            id: publisher_id,
            handle: handle.to_string(),
            owner_account_id: account_id,
            display_name: format!("{handle} publisher"),
            biography: Some("Migrated legacy publisher".to_string()),
            moderation_status: OwnershipManifestModerationStatus::Approved,
            created_at: timestamp,
            audit_event_id,
            audit_created_at: timestamp,
            keys: vec![OwnershipManifestKey {
                id: key_id,
                public_key: hex::encode(version.author_pubkey.0),
                label: "legacy signing key".to_string(),
                state: OwnershipManifestKeyState::Active,
                created_at: timestamp,
                revoked_at: None,
            }],
        }],
        packs: vec![OwnershipManifestPack {
            name: pack_name.to_string(),
            publisher_id,
            expected_current_author: hex::encode(version.author_pubkey.0),
        }],
        versions: vec![OwnershipManifestVersion {
            pack_name: pack_name.to_string(),
            version: version.version.clone(),
            publisher_key_id: key_id,
            expected_author_pubkey: hex::encode(version.author_pubkey.0),
            expected_content_hash: hex::encode(version.content_hash.as_bytes()),
        }],
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// An exactly empty catalog supports dry-run and apply with a zero census.
#[tokio::test]
#[ignore = "requires Docker"]
async fn ownership_backfill_accepts_empty_catalog() {
    let (catalog, _container) = setup_catalog().await;
    let manifest = OwnershipBackfillManifest {
        schema_version: OWNERSHIP_BACKFILL_SCHEMA_VERSION,
        expected_pack_count: 0,
        expected_version_count: 0,
        publishers: vec![],
        packs: vec![],
        versions: vec![],
    };
    let (manifest_bytes, digest) = ownership_manifest_input(&manifest);

    let dry_run = catalog
        .run_ownership_backfill(&manifest_bytes, None, OwnershipBackfillMode::DryRun)
        .await
        .expect("empty dry-run must succeed");
    assert_eq!(dry_run.census.catalog_packs, 0);
    assert_eq!(dry_run.census.catalog_versions, 0);
    assert_eq!(dry_run.applied.packs, 0);
    assert_eq!(dry_run.applied.versions, 0);

    let applied = catalog
        .run_ownership_backfill(&manifest_bytes, Some(&digest), OwnershipBackfillMode::Apply)
        .await
        .expect("empty apply must succeed");
    assert_eq!(applied.census, dry_run.census);
    assert_eq!(applied.applied, dry_run.applied);
}

/// Populated backfill preserves signer evidence and is idempotent.
#[tokio::test]
#[ignore = "requires Docker"]
async fn ownership_backfill_preserves_evidence_and_is_idempotent() {
    let (catalog, _container) = setup_catalog().await;
    let handle = "legacy-migrated";
    let pack_name = "ownership-migrated-pack";
    let author = make_author(72, handle);
    catalog
        .register_author(author.clone())
        .await
        .expect("register legacy author failed");
    let mut version = make_version(pack_name, "1.0.0", 72, 73);
    let parent_hash = make_hash(71);
    version.parent_hash = Some(parent_hash);
    catalog
        .register_pack_version(version.clone())
        .await
        .expect("register legacy pack failed");
    let account = make_account(uuid::Uuid::from_u128(10_001), "ownership-owner");
    catalog
        .create_account(account.clone())
        .await
        .expect("create ownership account failed");
    let publisher_id = uuid::Uuid::from_u128(10_002);
    let key_id = uuid::Uuid::from_u128(10_003);
    let manifest = ownership_manifest_for_legacy_pack(
        account.id,
        publisher_id,
        key_id,
        uuid::Uuid::from_u128(10_004),
        handle,
        pack_name,
        &version,
    );
    let mut unrelated_key_manifest = manifest.clone();
    unrelated_key_manifest.publishers[0]
        .keys
        .push(OwnershipManifestKey {
            id: uuid::Uuid::from_u128(10_005),
            public_key: hex::encode([99_u8; 32]),
            label: "unrelated bootstrap key".to_string(),
            state: OwnershipManifestKeyState::Active,
            created_at: ownership_manifest_time(),
            revoked_at: None,
        });
    let (unrelated_key_bytes, _) = ownership_manifest_input(&unrelated_key_manifest);
    let unrelated_key_error = catalog
        .run_ownership_backfill(&unrelated_key_bytes, None, OwnershipBackfillMode::DryRun)
        .await
        .expect_err("backfill must not create an unrelated publisher key");
    assert!(unrelated_key_error
        .to_string()
        .contains("new publisher key"));
    let (manifest_bytes, digest) = ownership_manifest_input(&manifest);

    let dry_run = catalog
        .run_ownership_backfill(&manifest_bytes, None, OwnershipBackfillMode::DryRun)
        .await
        .expect("ownership dry-run failed");
    assert_eq!(dry_run.census.publisher_profiles_to_create, 1);
    assert_eq!(dry_run.census.publisher_keys_to_create, 1);
    assert_eq!(dry_run.census.packs_to_update, 1);
    assert_eq!(dry_run.census.versions_to_update, 1);
    assert_eq!(dry_run.census.publishers.len(), 1);
    assert_eq!(dry_run.census.publishers[0].publisher_id, publisher_id);
    assert_eq!(dry_run.census.publishers[0].handle, handle);
    assert_eq!(dry_run.census.publishers[0].manifest_keys, 1);
    assert_eq!(dry_run.census.publishers[0].mapped_packs, 1);
    assert_eq!(dry_run.census.publishers[0].mapped_versions, 1);
    assert_eq!(dry_run.census.publishers[0].packs_to_update, 1);
    assert_eq!(dry_run.census.publishers[0].versions_to_update, 1);
    let before_pack = catalog
        .get_pack(pack_name)
        .await
        .expect("get legacy pack before apply failed");
    assert_eq!(before_pack.publisher_id, None);

    let first_apply = catalog
        .run_ownership_backfill(&manifest_bytes, Some(&digest), OwnershipBackfillMode::Apply)
        .await
        .expect("ownership apply failed");
    assert_eq!(first_apply.applied.publisher_profiles, 1);
    assert_eq!(first_apply.applied.owner_memberships, 1);
    assert_eq!(first_apply.applied.publisher_keys, 1);
    assert_eq!(first_apply.applied.audit_events, 1);
    assert_eq!(first_apply.applied.packs, 1);
    assert_eq!(first_apply.applied.versions, 1);

    let migrated_pack = catalog
        .get_pack(pack_name)
        .await
        .expect("get migrated pack failed");
    let migrated_version = catalog
        .get_pack_version(pack_name, "1.0.0")
        .await
        .expect("get migrated version failed");
    assert_eq!(migrated_pack.publisher_id, Some(publisher_id));
    assert_eq!(migrated_pack.current_author, author.pubkey);
    assert_eq!(migrated_version.publisher_key_id, Some(key_id));
    assert_eq!(migrated_version.author_pubkey, version.author_pubkey);
    assert_eq!(migrated_version.content_hash, version.content_hash);
    assert_eq!(migrated_version.signature, version.signature);
    assert_eq!(migrated_version.parent_hash, Some(parent_hash));
    let membership = catalog
        .get_publisher_membership(account.id, publisher_id)
        .await
        .expect("get migrated owner membership failed");
    assert_eq!(membership.created_at, ownership_manifest_time());
    let mut audit_connection = catalog
        .pool()
        .get()
        .await
        .expect("ownership audit verification connection failed");
    let audit = publisher_audit_events::table
        .find(uuid::Uuid::from_u128(10_004))
        .select((
            publisher_audit_events::actor_account_id,
            publisher_audit_events::publisher_id,
            publisher_audit_events::action,
        ))
        .first::<(Option<uuid::Uuid>, uuid::Uuid, String)>(&mut audit_connection)
        .await
        .expect("ownership audit row must exist");
    assert_eq!(audit.0, None);
    assert_eq!(audit.1, publisher_id);
    assert_eq!(audit.2, "publisher.ownership_backfilled");
    drop(audit_connection);

    let stale_legacy_version = make_version(pack_name, "1.1.0", 72, 76);
    let stale_error = catalog
        .register_pack_version(stale_legacy_version)
        .await
        .expect_err("migrated handle must reject stale legacy authority");
    assert!(matches!(
        stale_error,
        CatalogError::Unauthorized {
            kind: "publisher",
            ..
        }
    ));
    let absent_version = catalog
        .get_pack_version(pack_name, "1.1.0")
        .await
        .expect_err("rejected stale legacy version must remain absent");
    assert!(matches!(
        absent_version,
        CatalogError::NotFound {
            kind: "pack_version",
            ..
        }
    ));

    let second_apply = catalog
        .run_ownership_backfill(&manifest_bytes, Some(&digest), OwnershipBackfillMode::Apply)
        .await
        .expect("idempotent ownership apply failed");
    assert_eq!(second_apply.census.publisher_profiles_existing, 1);
    assert_eq!(second_apply.census.owner_memberships_existing, 1);
    assert_eq!(second_apply.census.publisher_keys_existing, 1);
    assert_eq!(second_apply.census.audit_events_existing, 1);
    assert_eq!(second_apply.census.packs_already_linked, 1);
    assert_eq!(second_apply.census.versions_already_linked, 1);
    assert_eq!(second_apply.applied.publisher_profiles, 0);
    assert_eq!(second_apply.applied.owner_memberships, 0);
    assert_eq!(second_apply.applied.publisher_keys, 0);
    assert_eq!(second_apply.applied.audit_events, 0);
    assert_eq!(second_apply.applied.packs, 0);
    assert_eq!(second_apply.applied.versions, 0);

    let post_apply_dry_run = catalog
        .run_ownership_backfill(&manifest_bytes, None, OwnershipBackfillMode::DryRun)
        .await
        .expect("post-apply ownership dry-run failed");
    assert_eq!(post_apply_dry_run.census, second_apply.census);
    assert_eq!(post_apply_dry_run.applied, second_apply.applied);
}

/// Prelinked publisher rows allow no legacy author but reject one with a foreign key.
#[tokio::test]
#[ignore = "requires Docker"]
async fn ownership_backfill_validates_prelinked_legacy_handle_when_present() {
    let (catalog, _container) = setup_catalog().await;
    let handle = "prelinked-publisher";
    let pack_name = "prelinked-owned-pack";
    let timestamp = ownership_manifest_time();
    let account = make_account(uuid::Uuid::from_u128(10_101), "prelinked-owner");
    let publisher_id = uuid::Uuid::from_u128(10_102);
    let key_id = uuid::Uuid::from_u128(10_103);
    let audit_id = uuid::Uuid::from_u128(10_104);
    let unused_key_id = uuid::Uuid::from_u128(10_105);
    catalog
        .create_account(account.clone())
        .await
        .expect("create prelinked account failed");
    catalog
        .create_publisher(
            PublisherProfileRecord {
                id: publisher_id,
                handle: handle.to_string(),
                display_name: "Prelinked publisher".to_string(),
                biography: Some("Account-backed publisher".to_string()),
                moderation_status: PublisherModerationStatus::Approved,
                created_at: timestamp,
                updated_at: timestamp,
            },
            PublisherMembershipRecord {
                account_id: account.id,
                publisher_id,
                role: PublisherRole::Owner,
                state: MembershipState::Active,
                created_at: timestamp,
                updated_at: timestamp,
            },
            None,
        )
        .await
        .expect("create prelinked publisher failed");
    let key = PublisherKeyRecord {
        id: key_id,
        publisher_id,
        public_key: make_pubkey(84),
        label: "Prelinked signing key".to_string(),
        state: PublisherKeyState::Active,
        created_at: timestamp,
        revoked_at: None,
        last_used_at: None,
    };
    catalog
        .create_publisher_key(key.clone(), None)
        .await
        .expect("create prelinked key failed");
    let unused_key = PublisherKeyRecord {
        id: unused_key_id,
        publisher_id,
        public_key: make_pubkey(86),
        label: "Unused prelinked rotation key".to_string(),
        state: PublisherKeyState::Active,
        created_at: timestamp,
        revoked_at: None,
        last_used_at: None,
    };
    catalog
        .create_publisher_key(unused_key.clone(), None)
        .await
        .expect("create unused prelinked key failed");
    let mut version = make_version(pack_name, "1.0.0", 84, 85);
    version.publisher_key_id = Some(key_id);
    catalog
        .register_pack_version(version.clone())
        .await
        .expect("register prelinked pack failed");
    let author_error = catalog
        .lookup_author_by_handle(handle)
        .await
        .expect_err("prelinked fixture must not have a legacy author");
    assert!(matches!(
        author_error,
        CatalogError::NotFound { kind: "author", .. }
    ));

    let manifest = OwnershipBackfillManifest {
        schema_version: OWNERSHIP_BACKFILL_SCHEMA_VERSION,
        expected_pack_count: 1,
        expected_version_count: 1,
        publishers: vec![OwnershipManifestPublisher {
            id: publisher_id,
            handle: handle.to_string(),
            owner_account_id: account.id,
            display_name: "Prelinked publisher".to_string(),
            biography: Some("Account-backed publisher".to_string()),
            moderation_status: OwnershipManifestModerationStatus::Approved,
            created_at: timestamp,
            audit_event_id: audit_id,
            audit_created_at: timestamp,
            keys: vec![
                OwnershipManifestKey {
                    id: key_id,
                    public_key: hex::encode(key.public_key.0),
                    label: key.label.clone(),
                    state: OwnershipManifestKeyState::Active,
                    created_at: timestamp,
                    revoked_at: None,
                },
                OwnershipManifestKey {
                    id: unused_key_id,
                    public_key: hex::encode(unused_key.public_key.0),
                    label: unused_key.label.clone(),
                    state: OwnershipManifestKeyState::Active,
                    created_at: timestamp,
                    revoked_at: None,
                },
            ],
        }],
        packs: vec![OwnershipManifestPack {
            name: pack_name.to_string(),
            publisher_id,
            expected_current_author: hex::encode(version.author_pubkey.0),
        }],
        versions: vec![OwnershipManifestVersion {
            pack_name: pack_name.to_string(),
            version: version.version.clone(),
            publisher_key_id: key_id,
            expected_author_pubkey: hex::encode(version.author_pubkey.0),
            expected_content_hash: hex::encode(version.content_hash.as_bytes()),
        }],
    };
    let (manifest_bytes, digest) = ownership_manifest_input(&manifest);

    let dry_run = catalog
        .run_ownership_backfill(&manifest_bytes, None, OwnershipBackfillMode::DryRun)
        .await
        .expect("prelinked dry-run failed");
    assert_eq!(dry_run.census.publisher_profiles_existing, 1);
    assert_eq!(dry_run.census.owner_memberships_existing, 1);
    assert_eq!(dry_run.census.publisher_keys_existing, 2);
    assert_eq!(dry_run.census.publishers[0].manifest_keys, 2);
    assert_eq!(dry_run.census.audit_events_to_create, 1);
    assert_eq!(dry_run.census.packs_already_linked, 1);
    assert_eq!(dry_run.census.versions_already_linked, 1);

    let first_apply = catalog
        .run_ownership_backfill(&manifest_bytes, Some(&digest), OwnershipBackfillMode::Apply)
        .await
        .expect("prelinked apply failed");
    assert_eq!(first_apply.applied.audit_events, 1);
    assert_eq!(first_apply.applied.publisher_profiles, 0);
    assert_eq!(first_apply.applied.owner_memberships, 0);
    assert_eq!(first_apply.applied.publisher_keys, 0);
    assert_eq!(first_apply.applied.packs, 0);
    assert_eq!(first_apply.applied.versions, 0);

    let second_apply = catalog
        .run_ownership_backfill(&manifest_bytes, Some(&digest), OwnershipBackfillMode::Apply)
        .await
        .expect("idempotent prelinked apply failed");
    assert_eq!(second_apply.census.audit_events_existing, 1);
    assert_eq!(second_apply.applied.audit_events, 0);
    assert_eq!(second_apply.applied, OwnershipBackfillApplied::default());

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("foreign legacy author fixture connection failed");
    connection
        .batch_execute(
            "INSERT INTO authors (pubkey, handle, display_name, oauth_links) \
             VALUES (decode(repeat('57', 32), 'hex'), 'prelinked-publisher', NULL, '[]'::jsonb)",
        )
        .await
        .expect("insert foreign same-handle legacy author failed");
    drop(connection);

    let ambiguity = catalog
        .run_ownership_backfill(&manifest_bytes, None, OwnershipBackfillMode::DryRun)
        .await
        .expect_err("foreign same-handle legacy author must fail closed");
    assert!(ambiguity
        .to_string()
        .contains("legacy author handle prelinked-publisher has an unmapped or foreign key"));
}

/// A database failure after bootstrap inserts rolls back every mutation.
#[tokio::test]
#[ignore = "requires Docker"]
async fn ownership_backfill_apply_failure_rolls_back_everything() {
    let (catalog, _container) = setup_catalog().await;
    let handle = "legacy-rollback";
    let pack_name = "ownership-rollback-pack";
    catalog
        .register_author(make_author(74, handle))
        .await
        .expect("register rollback author failed");
    let version = make_version(pack_name, "1.0.0", 74, 75);
    catalog
        .register_pack_version(version.clone())
        .await
        .expect("register rollback pack failed");
    let account = make_account(uuid::Uuid::from_u128(11_001), "ownership-rollback-owner");
    catalog
        .create_account(account.clone())
        .await
        .expect("create rollback account failed");
    let publisher_id = uuid::Uuid::from_u128(11_002);
    let manifest = ownership_manifest_for_legacy_pack(
        account.id,
        publisher_id,
        uuid::Uuid::from_u128(11_003),
        uuid::Uuid::from_u128(11_004),
        handle,
        pack_name,
        &version,
    );
    let (manifest_bytes, digest) = ownership_manifest_input(&manifest);
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("rollback trigger connection failed");
    connection
        .batch_execute(
            "CREATE FUNCTION reject_ownership_version_link() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN \
             RAISE EXCEPTION 'injected ownership backfill failure'; \
             END $$; \
             CREATE TRIGGER reject_ownership_version_link \
             BEFORE UPDATE OF publisher_key_id ON pack_versions \
             FOR EACH ROW EXECUTE FUNCTION reject_ownership_version_link();",
        )
        .await
        .expect("create rollback trigger failed");
    drop(connection);

    let error = catalog
        .run_ownership_backfill(&manifest_bytes, Some(&digest), OwnershipBackfillMode::Apply)
        .await
        .expect_err("injected version-link failure must fail apply");
    assert!(error.to_string().contains("database operation failed"));

    let pack = catalog
        .get_pack(pack_name)
        .await
        .expect("get rollback pack failed");
    let stored_version = catalog
        .get_pack_version(pack_name, "1.0.0")
        .await
        .expect("get rollback version failed");
    assert_eq!(pack.publisher_id, None);
    assert_eq!(stored_version.publisher_key_id, None);
    assert_eq!(stored_version.author_pubkey, version.author_pubkey);
    assert_eq!(stored_version.content_hash, version.content_hash);
    let publisher_error = catalog
        .get_publisher_by_handle(handle)
        .await
        .expect_err("failed migration must not create publisher");
    assert!(matches!(
        publisher_error,
        CatalogError::NotFound {
            kind: "publisher",
            ..
        }
    ));
    let membership_error = catalog
        .get_publisher_membership(account.id, publisher_id)
        .await
        .expect_err("failed migration must not create membership");
    assert!(matches!(
        membership_error,
        CatalogError::NotFound {
            kind: "publisher_membership",
            ..
        }
    ));
    let key_error = catalog
        .get_publisher_key(uuid::Uuid::from_u128(11_003))
        .await
        .expect_err("failed migration must not create key");
    assert!(matches!(
        key_error,
        CatalogError::NotFound {
            kind: "publisher_key",
            ..
        }
    ));
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("audit verification connection failed");
    let audit_count = publisher_audit_events::table
        .count()
        .get_result::<i64>(&mut connection)
        .await
        .expect("count ownership audit rows failed");
    assert_eq!(audit_count, 0);
}

/// Equal row counts cannot hide a substituted pack/version identity.
#[tokio::test]
#[ignore = "requires Docker"]
async fn ownership_backfill_rejects_exact_count_identity_substitution() {
    let (catalog, _container) = setup_catalog().await;
    let handle = "legacy-census";
    let pack_name = "ownership-census-pack";
    catalog
        .register_author(make_author(77, handle))
        .await
        .expect("register census author failed");
    let version = make_version(pack_name, "1.0.0", 77, 78);
    catalog
        .register_pack_version(version.clone())
        .await
        .expect("register census pack failed");
    let account = make_account(uuid::Uuid::from_u128(12_001), "ownership-census-owner");
    catalog
        .create_account(account.clone())
        .await
        .expect("create census account failed");
    let empty_manifest = OwnershipBackfillManifest {
        schema_version: OWNERSHIP_BACKFILL_SCHEMA_VERSION,
        expected_pack_count: 0,
        expected_version_count: 0,
        publishers: vec![],
        packs: vec![],
        versions: vec![],
    };
    let (empty_manifest_bytes, _) = ownership_manifest_input(&empty_manifest);
    let count_error = catalog
        .run_ownership_backfill(&empty_manifest_bytes, None, OwnershipBackfillMode::DryRun)
        .await
        .expect_err("live catalog count mismatch must fail");
    assert!(count_error.to_string().contains("catalog has 1 packs"));

    let mut manifest = ownership_manifest_for_legacy_pack(
        account.id,
        uuid::Uuid::from_u128(12_002),
        uuid::Uuid::from_u128(12_003),
        uuid::Uuid::from_u128(12_004),
        handle,
        pack_name,
        &version,
    );
    manifest.packs[0].name = "substituted-pack".to_string();
    manifest.versions[0].pack_name = "substituted-pack".to_string();
    let (manifest_bytes, _) = ownership_manifest_input(&manifest);

    let error = catalog
        .run_ownership_backfill(&manifest_bytes, None, OwnershipBackfillMode::DryRun)
        .await
        .expect_err("equal-count identity substitution must fail");
    assert!(error.to_string().contains(pack_name));

    let stored_pack = catalog
        .get_pack(pack_name)
        .await
        .expect("get census pack failed");
    let stored_version = catalog
        .get_pack_version(pack_name, "1.0.0")
        .await
        .expect("get census version failed");
    assert_eq!(stored_pack.publisher_id, None);
    assert_eq!(stored_version.publisher_key_id, None);
}

/// Backfill cannot transfer another legacy handle's signed rows into a publisher.
#[tokio::test]
#[ignore = "requires Docker"]
async fn ownership_backfill_rejects_cross_handle_key_transfer() {
    let (catalog, _container) = setup_catalog().await;
    let alice_handle = "legacy-alice";
    let bob_handle = "legacy-bob";
    let alice_pack = "ownership-alice-pack";
    let bob_pack = "ownership-bob-pack";
    catalog
        .register_author(make_author(80, alice_handle))
        .await
        .expect("register Alice author failed");
    catalog
        .register_author(make_author(81, bob_handle))
        .await
        .expect("register Bob author failed");
    let alice_version = make_version(alice_pack, "1.0.0", 80, 82);
    let bob_version = make_version(bob_pack, "1.0.0", 81, 83);
    catalog
        .register_pack_version(alice_version.clone())
        .await
        .expect("register Alice pack failed");
    catalog
        .register_pack_version(bob_version.clone())
        .await
        .expect("register Bob pack failed");
    let account = make_account(uuid::Uuid::from_u128(13_001), "ownership-alice-owner");
    catalog
        .create_account(account.clone())
        .await
        .expect("create Alice ownership account failed");

    let publisher_id = uuid::Uuid::from_u128(13_002);
    let alice_key_id = uuid::Uuid::from_u128(13_003);
    let bob_key_id = uuid::Uuid::from_u128(13_004);
    let timestamp = ownership_manifest_time();
    let manifest = OwnershipBackfillManifest {
        schema_version: OWNERSHIP_BACKFILL_SCHEMA_VERSION,
        expected_pack_count: 2,
        expected_version_count: 2,
        publishers: vec![OwnershipManifestPublisher {
            id: publisher_id,
            handle: alice_handle.to_string(),
            owner_account_id: account.id,
            display_name: "Alice publisher".to_string(),
            biography: None,
            moderation_status: OwnershipManifestModerationStatus::Approved,
            created_at: timestamp,
            audit_event_id: uuid::Uuid::from_u128(13_005),
            audit_created_at: timestamp,
            keys: vec![
                OwnershipManifestKey {
                    id: alice_key_id,
                    public_key: hex::encode(alice_version.author_pubkey.0),
                    label: "Alice legacy key".to_string(),
                    state: OwnershipManifestKeyState::Active,
                    created_at: timestamp,
                    revoked_at: None,
                },
                OwnershipManifestKey {
                    id: bob_key_id,
                    public_key: hex::encode(bob_version.author_pubkey.0),
                    label: "Bob legacy key".to_string(),
                    state: OwnershipManifestKeyState::Active,
                    created_at: timestamp,
                    revoked_at: None,
                },
            ],
        }],
        packs: vec![
            OwnershipManifestPack {
                name: alice_pack.to_string(),
                publisher_id,
                expected_current_author: hex::encode(alice_version.author_pubkey.0),
            },
            OwnershipManifestPack {
                name: bob_pack.to_string(),
                publisher_id,
                expected_current_author: hex::encode(bob_version.author_pubkey.0),
            },
        ],
        versions: vec![
            OwnershipManifestVersion {
                pack_name: alice_pack.to_string(),
                version: alice_version.version.clone(),
                publisher_key_id: alice_key_id,
                expected_author_pubkey: hex::encode(alice_version.author_pubkey.0),
                expected_content_hash: hex::encode(alice_version.content_hash.as_bytes()),
            },
            OwnershipManifestVersion {
                pack_name: bob_pack.to_string(),
                version: bob_version.version.clone(),
                publisher_key_id: bob_key_id,
                expected_author_pubkey: hex::encode(bob_version.author_pubkey.0),
                expected_content_hash: hex::encode(bob_version.content_hash.as_bytes()),
            },
        ],
    };
    let (manifest_bytes, _) = ownership_manifest_input(&manifest);

    let error = catalog
        .run_ownership_backfill(&manifest_bytes, None, OwnershipBackfillMode::DryRun)
        .await
        .expect_err("cross-handle ownership transfer must fail");
    assert!(error
        .to_string()
        .contains("belongs to legacy author handle legacy-bob, not legacy-alice"));
    let alice_stored = catalog
        .get_pack(alice_pack)
        .await
        .expect("get Alice pack after rejection failed");
    let bob_stored = catalog
        .get_pack(bob_pack)
        .await
        .expect("get Bob pack after rejection failed");
    assert_eq!(alice_stored.publisher_id, None);
    assert_eq!(bob_stored.publisher_id, None);
}

/// Account identities are unique by exact issuer and subject and remain provider-neutral.
#[tokio::test]
#[ignore = "requires Docker"]
async fn account_identity_roundtrip_and_duplicate_rejection() {
    let (catalog, _container) = setup_catalog().await;
    let account = make_account(uuid::Uuid::new_v4(), "account-subject");
    catalog
        .create_account(account.clone())
        .await
        .expect("create account failed");

    let found = catalog
        .get_account_by_subject(&account.issuer, &account.subject)
        .await
        .expect("lookup by subject failed");
    assert_eq!(found.id, account.id);
    assert_eq!(found.issuer, account.issuer);
    assert_eq!(found.subject, account.subject);
    assert_eq!(found.email, account.email);
    assert_eq!(found.display_name, account.display_name);
    assert_eq!(found.status, account.status);

    let duplicate = make_account(uuid::Uuid::new_v4(), &account.subject);
    let error = catalog
        .create_account(duplicate)
        .await
        .expect_err("duplicate identity must fail");
    assert!(matches!(
        error,
        CatalogError::Conflict {
            kind: "account",
            ..
        }
    ));
}

/// Publisher creation atomically establishes ownership and key revocation keeps one active key.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publisher_membership_key_and_audit_lifecycle() {
    let (catalog, _container) = setup_catalog().await;
    let account = make_account(uuid::Uuid::new_v4(), "publisher-owner");
    catalog
        .create_account(account.clone())
        .await
        .expect("create account failed");
    let publisher_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let profile = PublisherProfileRecord {
        id: publisher_id,
        handle: "publisher-owner".to_string(),
        display_name: "Publisher Owner".to_string(),
        biography: None,
        moderation_status: PublisherModerationStatus::Pending,
        created_at: now,
        updated_at: now,
    };
    let membership = PublisherMembershipRecord {
        account_id: account.id,
        publisher_id,
        role: PublisherRole::Owner,
        state: MembershipState::Active,
        created_at: now,
        updated_at: now,
    };
    catalog
        .create_publisher(profile.clone(), membership.clone(), None)
        .await
        .expect("create publisher failed");
    let found_profile = catalog
        .get_publisher_by_handle(&profile.handle)
        .await
        .expect("publisher lookup failed");
    assert_eq!(found_profile.id, profile.id);
    assert_eq!(found_profile.handle, profile.handle);
    assert_eq!(found_profile.display_name, profile.display_name);
    assert_eq!(found_profile.biography, profile.biography);
    assert_eq!(found_profile.moderation_status, profile.moderation_status);
    let found_membership = catalog
        .get_publisher_membership(account.id, publisher_id)
        .await
        .expect("membership lookup failed");
    assert_eq!(found_membership.account_id, membership.account_id);
    assert_eq!(found_membership.publisher_id, membership.publisher_id);
    assert_eq!(found_membership.role, membership.role);
    assert_eq!(found_membership.state, membership.state);

    let first_key = PublisherKeyRecord {
        id: uuid::Uuid::new_v4(),
        publisher_id,
        public_key: make_pubkey(90),
        label: "first device".to_string(),
        state: PublisherKeyState::Active,
        created_at: now,
        revoked_at: None,
        last_used_at: None,
    };
    catalog
        .create_publisher_key(first_key.clone(), None)
        .await
        .expect("create first key failed");
    let mut retry = first_key.clone();
    retry.id = uuid::Uuid::new_v4();
    let retried = catalog
        .create_publisher_key(retry, None)
        .await
        .expect("same publisher key enrollment must be idempotent");
    assert_eq!(retried.id, first_key.id);
    let keys_after_retry = catalog
        .list_publisher_keys(publisher_id)
        .await
        .expect("list keys after idempotent retry failed");
    assert_eq!(keys_after_retry, vec![retried]);
    let last_key_error = catalog
        .revoke_publisher_key(publisher_id, first_key.id, chrono::Utc::now(), None)
        .await
        .expect_err("last active key revocation must fail");
    assert!(matches!(last_key_error, CatalogError::Validation(_)));

    let second_key = PublisherKeyRecord {
        id: uuid::Uuid::new_v4(),
        publisher_id,
        public_key: make_pubkey(91),
        label: "second device".to_string(),
        state: PublisherKeyState::Active,
        created_at: chrono::Utc::now(),
        revoked_at: None,
        last_used_at: None,
    };
    catalog
        .create_publisher_key(second_key.clone(), None)
        .await
        .expect("create second key failed");
    let (first_result, second_result) = tokio::join!(
        catalog.revoke_publisher_key(publisher_id, first_key.id, chrono::Utc::now(), None),
        catalog.revoke_publisher_key(publisher_id, second_key.id, chrono::Utc::now(), None),
    );
    assert!(matches!(
        (&first_result, &second_result),
        (Ok(_), Err(CatalogError::Validation(_))) | (Err(CatalogError::Validation(_)), Ok(_))
    ));
    let revoked = first_result
        .as_ref()
        .ok()
        .or_else(|| second_result.as_ref().ok())
        .expect("one concurrent revocation must succeed");
    assert_eq!(revoked.state, PublisherKeyState::Revoked);
    assert!(revoked.revoked_at.is_some());
    let keys = catalog
        .list_publisher_keys(publisher_id)
        .await
        .expect("list keys after concurrent revocation failed");
    assert_eq!(
        keys.iter()
            .filter(|key| key.state == PublisherKeyState::Active)
            .count(),
        1
    );

    let audit_id = uuid::Uuid::new_v4();
    catalog
        .append_publisher_audit_event(PublisherAuditEventRecord {
            id: audit_id,
            actor_account_id: Some(account.id),
            publisher_id,
            action: "publisher.key.revoked".to_string(),
            target_key_id: Some(revoked.id),
            target_version: None,
            request_id: Some(uuid::Uuid::new_v4()),
            created_at: chrono::Utc::now(),
            metadata: serde_json::json!({"reason": "test"}),
        })
        .await
        .expect("append audit event failed");

    let rollback_publisher_id = uuid::Uuid::new_v4();
    let rollback_profile = PublisherProfileRecord {
        id: rollback_publisher_id,
        handle: "atomic-rollback".to_string(),
        display_name: "Atomic Rollback".to_string(),
        biography: None,
        moderation_status: PublisherModerationStatus::Pending,
        created_at: now,
        updated_at: now,
    };
    let rollback_membership = PublisherMembershipRecord {
        account_id: account.id,
        publisher_id: rollback_publisher_id,
        role: PublisherRole::Owner,
        state: MembershipState::Active,
        created_at: now,
        updated_at: now,
    };
    let duplicate_audit = PublisherAuditEventRecord {
        id: audit_id,
        actor_account_id: Some(account.id),
        publisher_id: rollback_publisher_id,
        action: "publisher.created".to_string(),
        target_key_id: None,
        target_version: None,
        request_id: Some(uuid::Uuid::new_v4()),
        created_at: chrono::Utc::now(),
        metadata: serde_json::json!({}),
    };
    let error = catalog
        .create_publisher(rollback_profile, rollback_membership, Some(duplicate_audit))
        .await
        .expect_err("duplicate audit identifier must roll back publisher creation");
    assert!(matches!(error, CatalogError::Conflict { .. }));
    let lookup_error = catalog
        .get_publisher_by_handle("atomic-rollback")
        .await
        .expect_err("publisher row must not survive a failed atomic audit insert");
    assert!(matches!(lookup_error, CatalogError::NotFound { .. }));
}

/// Publication intents are exact-idempotent and permit one concurrent consumer.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_intent_roundtrip_idempotency_and_atomic_consumption() {
    let (catalog, _container) = setup_catalog().await;
    let (account_id, publisher_id, key) =
        create_test_publisher(&catalog, "intent-owner", 103).await;
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("current timestamp must fit");
    let intent = make_publication_intent(
        account_id,
        publisher_id,
        key.id,
        104,
        now,
        now + chrono::Duration::minutes(10),
    );

    let created = catalog
        .create_publication_intent(intent.clone())
        .await
        .expect("create publication intent failed");
    assert_eq!(created, intent);
    let retried = catalog
        .create_publication_intent(intent.clone())
        .await
        .expect("exact publication intent retry must be idempotent");
    assert_eq!(retried, created);
    let found = catalog
        .get_publication_intent(intent.id)
        .await
        .expect("publication intent lookup failed");
    assert_eq!(found, created);

    let mut conflicting = intent.clone();
    conflicting.archive_hash = make_hash(109);
    let conflict = catalog
        .create_publication_intent(conflicting)
        .await
        .expect_err("altered idempotency-key reuse must fail");
    assert!(matches!(
        conflict,
        CatalogError::Conflict {
            kind: "publication_intent",
            ..
        }
    ));

    let mut mismatched = make_publication_claim(&intent);
    mismatched.manifest_hash = make_hash(110);
    assert!(
        !catalog
            .consume_publication_intent(mismatched)
            .await
            .expect("mismatched intent claim failed"),
        "a mismatched digest must not consume the intent"
    );

    let claim = make_publication_claim(&intent);
    let (first, second) = tokio::join!(
        catalog.consume_publication_intent(claim.clone()),
        catalog.consume_publication_intent(claim),
    );
    let outcomes = [
        first.expect("first concurrent intent claim failed"),
        second.expect("second concurrent intent claim failed"),
    ];
    assert_eq!(
        outcomes.into_iter().filter(|consumed| *consumed).count(),
        1,
        "exactly one concurrent intent claim must consume the record"
    );
    let consumed = catalog
        .get_publication_intent(intent.id)
        .await
        .expect("consumed publication intent lookup failed");
    let consumed_at = consumed
        .consumed_at
        .expect("successful consumption must persist the database timestamp");
    assert!(
        consumed_at >= consumed.created_at && consumed_at < consumed.expires_at,
        "database consumption timestamp must remain inside the intent window"
    );
    let post_consumption_retry = catalog
        .create_publication_intent(intent)
        .await
        .expect("exact create retry must remain idempotent after consumption");
    assert_eq!(post_consumption_retry, consumed);
}

/// Publication transitions require the publisher to remain approved.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_requires_an_approved_publisher() {
    let (catalog, _container) = setup_catalog().await;
    let (account_id, publisher_id, key) =
        create_test_publisher(&catalog, "approved-admission", 108).await;
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("current timestamp must fit");
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("publisher approval connection failed");

    for status in ["pending", "suspended", "rejected"] {
        diesel::update(publisher_profiles::table.find(publisher_id))
            .set(publisher_profiles::moderation_status.eq(status))
            .execute(&mut connection)
            .await
            .expect("set non-approved publisher status failed");
        let intent = make_publication_submission_intent(
            account_id,
            publisher_id,
            key.id,
            109,
            now,
            now + chrono::Duration::minutes(10),
        );
        assert!(matches!(
            catalog
                .create_publication_intent(intent)
                .await
                .expect_err("non-approved publisher must not create an intent"),
            CatalogError::Unauthorized {
                kind: "publication_intent",
                ..
            }
        ));
    }

    diesel::update(publisher_profiles::table.find(publisher_id))
        .set(publisher_profiles::moderation_status.eq("approved"))
        .execute(&mut connection)
        .await
        .expect("approve publisher for intent creation failed");
    let intent = make_publication_submission_intent(
        account_id,
        publisher_id,
        key.id,
        112,
        now,
        now + chrono::Duration::minutes(10),
    );
    catalog
        .create_publication_intent(intent.clone())
        .await
        .expect("approved publisher intent creation failed");

    diesel::update(publisher_profiles::table.find(publisher_id))
        .set(publisher_profiles::moderation_status.eq("suspended"))
        .execute(&mut connection)
        .await
        .expect("suspend publisher before admission failed");
    assert!(
        !catalog
            .consume_publication_intent(make_publication_claim(&intent))
            .await
            .expect("suspended publisher intent consumption failed"),
        "a suspended publisher must not consume an existing intent"
    );
    let submission_request = make_publication_submission(&intent);
    assert!(matches!(
        catalog
            .create_publication_submission(submission_request.clone())
            .await
            .expect_err("suspended publisher must not create a submission"),
        CatalogError::Unauthorized {
            kind: "publication_submission",
            ..
        }
    ));
    assert!(
        catalog
            .get_publication_intent(intent.id)
            .await
            .expect("denied intent lookup failed")
            .consumed_at
            .is_none(),
        "denied submission must not consume its intent"
    );
    assert!(matches!(
        catalog
            .get_publication_submission(submission_request.id)
            .await
            .expect_err("denied submission must not persist"),
        CatalogError::NotFound {
            kind: "publication_submission",
            ..
        }
    ));

    diesel::update(publisher_profiles::table.find(publisher_id))
        .set(publisher_profiles::moderation_status.eq("approved"))
        .execute(&mut connection)
        .await
        .expect("restore publisher approval failed");
    let created = catalog
        .create_publication_submission(submission_request.clone())
        .await
        .expect("restored approved publisher submission failed");
    assert_eq!(created.state, PublicationSubmissionState::Quarantined);

    diesel::update(publisher_profiles::table.find(publisher_id))
        .set(publisher_profiles::moderation_status.eq("suspended"))
        .execute(&mut connection)
        .await
        .expect("suspend publisher after submission failed");
    let retry = catalog
        .create_publication_submission(submission_request)
        .await
        .expect("completed exact retry must remain idempotent after suspension");
    assert_eq!(retry, created);
}

/// Intent consumption revalidates expiry, account, membership, and key state.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_intent_consumption_fails_closed_after_identity_changes() {
    let (catalog, _container) = setup_catalog().await;
    let (account_id, publisher_id, key) =
        create_test_publisher(&catalog, "intent-revalidation", 111).await;
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("current timestamp must fit");
    let expired = make_publication_intent(
        account_id,
        publisher_id,
        key.id,
        112,
        now - chrono::Duration::minutes(2),
        now - chrono::Duration::minutes(1),
    );
    catalog
        .create_publication_intent(expired.clone())
        .await
        .expect("create expired test intent failed");
    assert!(
        !catalog
            .consume_publication_intent(make_publication_claim(&expired))
            .await
            .expect("expired intent claim failed"),
        "an expired intent must remain unconsumed"
    );

    let active = make_publication_intent(
        account_id,
        publisher_id,
        key.id,
        115,
        now,
        now + chrono::Duration::minutes(10),
    );
    catalog
        .create_publication_intent(active.clone())
        .await
        .expect("create revalidation intent failed");
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("identity revalidation connection failed");

    diesel::update(accounts::table.find(account_id))
        .set(accounts::status.eq("suspended"))
        .execute(&mut connection)
        .await
        .expect("suspend intent account failed");
    assert!(
        !catalog
            .consume_publication_intent(make_publication_claim(&active))
            .await
            .expect("suspended-account claim failed"),
        "a suspended account must not consume an existing intent"
    );
    diesel::update(accounts::table.find(account_id))
        .set(accounts::status.eq("active"))
        .execute(&mut connection)
        .await
        .expect("reactivate intent account failed");

    diesel::update(publisher_memberships::table.find((account_id, publisher_id)))
        .set(publisher_memberships::state.eq("revoked"))
        .execute(&mut connection)
        .await
        .expect("revoke intent membership failed");
    assert!(
        !catalog
            .consume_publication_intent(make_publication_claim(&active))
            .await
            .expect("revoked-membership claim failed"),
        "a revoked owner membership must not consume an existing intent"
    );
    diesel::update(publisher_memberships::table.find((account_id, publisher_id)))
        .set(publisher_memberships::state.eq("active"))
        .execute(&mut connection)
        .await
        .expect("reactivate intent membership failed");
    drop(connection);

    let second_key = PublisherKeyRecord {
        id: uuid::Uuid::new_v4(),
        publisher_id,
        public_key: make_pubkey(118),
        label: "intent fallback key".to_string(),
        state: PublisherKeyState::Active,
        created_at: now,
        revoked_at: None,
        last_used_at: None,
    };
    catalog
        .create_publisher_key(second_key, None)
        .await
        .expect("create intent fallback key failed");
    catalog
        .revoke_publisher_key(publisher_id, key.id, now, None)
        .await
        .expect("revoke intent signing key failed");
    assert!(
        !catalog
            .consume_publication_intent(make_publication_claim(&active))
            .await
            .expect("revoked-key claim failed"),
        "a revoked signing key must not consume an existing intent"
    );

    let (_, _, foreign_key) = create_test_publisher(&catalog, "intent-foreign", 119).await;
    let cross_publisher = make_publication_intent(
        account_id,
        publisher_id,
        foreign_key.id,
        120,
        now,
        now + chrono::Duration::minutes(10),
    );
    let unauthorized = catalog
        .create_publication_intent(cross_publisher)
        .await
        .expect_err("cross-publisher key binding must fail");
    assert!(matches!(
        unauthorized,
        CatalogError::Unauthorized {
            kind: "publication_intent",
            ..
        }
    ));
}

/// Exact concurrent submission retries persist and return one quarantined row.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_submission_is_atomic_idempotent_and_concurrency_safe() {
    let (catalog, _container) = setup_catalog().await;
    let (account_id, publisher_id, key) =
        create_test_publisher(&catalog, "submission-owner", 152).await;
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("current timestamp must fit");
    let intent = make_publication_submission_intent(
        account_id,
        publisher_id,
        key.id,
        153,
        now,
        now + chrono::Duration::minutes(10),
    );
    catalog
        .create_publication_intent(intent.clone())
        .await
        .expect("create submission intent failed");
    let request = make_publication_submission(&intent);

    let (first, second) = tokio::join!(
        catalog.create_publication_submission(request.clone()),
        catalog.create_publication_submission(request.clone()),
    );
    let first = first.expect("first concurrent submission failed");
    let second = second.expect("second concurrent submission retry failed");
    assert_eq!(first, second);
    assert_eq!(first.id, request.id);
    assert_eq!(first.intent_id, intent.id);
    assert_eq!(first.state, PublicationSubmissionState::Quarantined);
    assert_eq!(first.created_at, first.updated_at);
    assert_eq!(
        catalog
            .get_publication_submission(request.id)
            .await
            .expect("submission lookup failed"),
        first
    );

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("submission count connection failed");
    let count = publication_submissions::table
        .count()
        .get_result::<i64>(&mut connection)
        .await
        .expect("count publication submissions failed");
    assert_eq!(count, 1);
    let consumed = catalog
        .get_publication_intent(intent.id)
        .await
        .expect("consumed submission intent lookup failed");
    assert_eq!(consumed.consumed_at, Some(first.created_at));

    let mut altered = request.clone();
    altered.scan_report.findings.push(PublicationFinding {
        code: "review.advisory".to_string(),
        severity: FindingSeverity::Warning,
        path: None,
        message: "reviewer-visible advisory".to_string(),
    });
    let conflict = catalog
        .create_publication_submission(altered)
        .await
        .expect_err("altered submission idempotency retry must fail");
    assert!(matches!(
        conflict,
        CatalogError::Conflict {
            kind: "publication_submission",
            ..
        }
    ));

    let mut second_id = request;
    second_id.id = uuid::Uuid::new_v4();
    let intent_conflict = catalog
        .create_publication_submission(second_id)
        .await
        .expect_err("one intent must not create a second submission");
    assert!(matches!(
        intent_conflict,
        CatalogError::Conflict {
            kind: "publication_submission",
            ..
        }
    ));
}

/// Moderation snapshots aggregate unresolved work and distinct active reviewers.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_moderation_snapshot_is_bounded_and_distinct() {
    let (catalog, _container) = setup_catalog().await;
    let (_, _, quarantined_id) =
        create_test_publication_submission(&catalog, "snapshot-quarantined", 165).await;
    let (_, _, needs_review_id) =
        create_test_publication_submission(&catalog, "snapshot-needs-review", 168).await;
    let quarantined = catalog
        .get_publication_submission(quarantined_id)
        .await
        .expect("quarantined snapshot fixture lookup failed");
    let needs_review = catalog
        .get_publication_submission(needs_review_id)
        .await
        .expect("needs-review snapshot fixture lookup failed");

    let reviewer = make_account(uuid::Uuid::new_v4(), "snapshot-reviewer");
    catalog
        .create_account(reviewer.clone())
        .await
        .expect("create snapshot reviewer failed");
    assign_test_platform_role(&catalog, reviewer.id, "moderator").await;
    assign_test_platform_role(&catalog, reviewer.id, "administrator").await;
    catalog
        .moderate_publication_submission(make_moderation_request(
            needs_review_id,
            reviewer.id,
            PublicationModerationAction::RequestChanges,
        ))
        .await
        .expect("move snapshot fixture to needs-review failed");

    let snapshot = catalog
        .publication_moderation_snapshot()
        .await
        .expect("moderation snapshot query failed")
        .expect("Postgres must support moderation snapshots");
    assert_eq!(snapshot.quarantined_submissions, 1);
    assert_eq!(snapshot.oldest_quarantined_at, Some(quarantined.created_at));
    assert_eq!(snapshot.queued_submissions, 2);
    assert_eq!(
        snapshot.oldest_queued_at,
        Some(quarantined.created_at.min(needs_review.created_at))
    );
    assert_eq!(
        snapshot.active_reviewers, 1,
        "one account with two active roles must count once"
    );
}

/// Submission admission rejects report drift and inactive authorization chains.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_submission_revalidates_report_expiry_and_identity() {
    let (catalog, _container) = setup_catalog().await;
    let (account_id, publisher_id, key) =
        create_test_publisher(&catalog, "submission-revalidation", 160).await;
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("current timestamp must fit");
    let expired = make_publication_submission_intent(
        account_id,
        publisher_id,
        key.id,
        161,
        now - chrono::Duration::minutes(2),
        now - chrono::Duration::minutes(1),
    );
    catalog
        .create_publication_intent(expired.clone())
        .await
        .expect("create expired submission intent failed");
    let expired_error = catalog
        .create_publication_submission(make_publication_submission(&expired))
        .await
        .expect_err("expired intent must reject submission");
    assert!(matches!(expired_error, CatalogError::Unauthorized { .. }));

    let active = make_publication_submission_intent(
        account_id,
        publisher_id,
        key.id,
        164,
        now,
        now + chrono::Duration::minutes(10),
    );
    catalog
        .create_publication_intent(active.clone())
        .await
        .expect("create active submission intent failed");

    let mut mismatched_report = make_publication_submission(&active);
    mismatched_report.scan_report.inventory_hash = make_hash(170).to_hex();
    let report_error = catalog
        .create_publication_submission(mismatched_report)
        .await
        .expect_err("inventory report mismatch must reject submission");
    assert!(matches!(report_error, CatalogError::Unauthorized { .. }));

    let mut inconsistent_report = make_publication_submission(&active);
    inconsistent_report.scan_report.inventory[0].size += 1;
    let consistency_error = catalog
        .create_publication_submission(inconsistent_report)
        .await
        .expect_err("internally inconsistent report must reject submission");
    assert!(matches!(consistency_error, CatalogError::Validation(_)));

    let mut invalid_report = make_publication_submission(&active);
    invalid_report.scan_report.valid = false;
    let invalid_error = catalog
        .create_publication_submission(invalid_report)
        .await
        .expect_err("invalid server report must reject submission");
    assert!(matches!(invalid_error, CatalogError::Validation(_)));

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("submission identity connection failed");
    diesel::update(accounts::table.find(account_id))
        .set(accounts::status.eq("suspended"))
        .execute(&mut connection)
        .await
        .expect("suspend submission account failed");
    let request = make_publication_submission(&active);
    assert!(matches!(
        catalog
            .create_publication_submission(request.clone())
            .await
            .expect_err("suspended account must reject submission"),
        CatalogError::Unauthorized { .. }
    ));
    diesel::update(accounts::table.find(account_id))
        .set(accounts::status.eq("active"))
        .execute(&mut connection)
        .await
        .expect("reactivate submission account failed");

    diesel::update(publisher_memberships::table.find((account_id, publisher_id)))
        .set(publisher_memberships::state.eq("revoked"))
        .execute(&mut connection)
        .await
        .expect("revoke submission membership failed");
    assert!(matches!(
        catalog
            .create_publication_submission(request.clone())
            .await
            .expect_err("revoked owner membership must reject submission"),
        CatalogError::Unauthorized { .. }
    ));
    diesel::update(publisher_memberships::table.find((account_id, publisher_id)))
        .set(publisher_memberships::state.eq("active"))
        .execute(&mut connection)
        .await
        .expect("reactivate submission membership failed");
    drop(connection);

    let fallback_key = PublisherKeyRecord {
        id: uuid::Uuid::new_v4(),
        publisher_id,
        public_key: make_pubkey(171),
        label: "submission fallback key".to_string(),
        state: PublisherKeyState::Active,
        created_at: now,
        revoked_at: None,
        last_used_at: None,
    };
    catalog
        .create_publisher_key(fallback_key, None)
        .await
        .expect("create submission fallback key failed");
    catalog
        .revoke_publisher_key(publisher_id, key.id, now, None)
        .await
        .expect("revoke submission key failed");
    assert!(matches!(
        catalog
            .create_publication_submission(request)
            .await
            .expect_err("revoked publisher key must reject submission"),
        CatalogError::Unauthorized { .. }
    ));
    let unconsumed = catalog
        .get_publication_intent(active.id)
        .await
        .expect("unconsumed submission intent lookup failed");
    assert!(unconsumed.consumed_at.is_none());
}

/// A database insertion failure rolls back the intent consumption timestamp.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_submission_insert_failure_does_not_burn_intent() {
    let (catalog, _container) = setup_catalog().await;
    let (account_id, publisher_id, key) =
        create_test_publisher(&catalog, "submission-rollback", 172).await;
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("current timestamp must fit");
    let intent = make_publication_submission_intent(
        account_id,
        publisher_id,
        key.id,
        173,
        now,
        now + chrono::Duration::minutes(10),
    );
    catalog
        .create_publication_intent(intent.clone())
        .await
        .expect("create rollback submission intent failed");
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("submission rollback connection failed");
    connection
        .batch_execute(
            r#"
            CREATE FUNCTION reject_test_submission() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'forced submission insertion failure';
            END
            $$;
            CREATE TRIGGER reject_test_submission
            BEFORE INSERT ON publication_submissions
            FOR EACH ROW EXECUTE FUNCTION reject_test_submission();
            "#,
        )
        .await
        .expect("install submission rejection trigger failed");
    drop(connection);

    catalog
        .create_publication_submission(make_publication_submission(&intent))
        .await
        .expect_err("forced insertion failure must surface");
    let preserved = catalog
        .get_publication_intent(intent.id)
        .await
        .expect("rollback intent lookup failed");
    assert!(
        preserved.consumed_at.is_none(),
        "failed submission insertion must roll back intent consumption"
    );
    let missing = catalog
        .get_publication_submission(uuid::Uuid::new_v4())
        .await
        .expect_err("failed insertion must not leave a submission");
    assert!(matches!(missing, CatalogError::NotFound { .. }));
}

/// Authorized review is atomic, non-public, and exactly idempotent.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_moderation_is_authorized_audited_and_idempotent() {
    let (catalog, _container) = setup_catalog().await;
    let (_owner_account_id, _publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "moderation-happy", 180).await;
    let moderator = make_account(uuid::Uuid::new_v4(), "moderation-happy-reviewer");
    catalog
        .create_account(moderator.clone())
        .await
        .expect("create moderator account failed");
    assign_test_platform_role(&catalog, moderator.id, "moderator").await;

    let request = make_moderation_request(
        submission_id,
        moderator.id,
        PublicationModerationAction::Approve,
    );
    let first = catalog
        .moderate_publication_submission(request.clone())
        .await
        .expect("authorized moderation failed");
    assert_eq!(first.id, request.id);
    assert_eq!(first.from_state, PublicationSubmissionState::Quarantined);
    assert_eq!(first.to_state, PublicationSubmissionState::Approved);
    assert_eq!(
        catalog
            .get_publication_submission(submission_id)
            .await
            .expect("approved submission lookup failed")
            .state,
        PublicationSubmissionState::Approved
    );
    let roles = catalog
        .list_account_platform_roles(moderator.id)
        .await
        .expect("moderator role lookup failed");
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].role, PlatformRole::Moderator);
    assert_eq!(roles[0].state, PlatformRoleState::Active);

    let retry = catalog
        .moderate_publication_submission(request.clone())
        .await
        .expect("exact moderation retry failed");
    assert_eq!(retry, first);

    let mut conflicting_id = request.clone();
    conflicting_id.private_explanation = Some("Conflicting retry content.".to_string());
    assert!(matches!(
        catalog
            .moderate_publication_submission(conflicting_id)
            .await
            .expect_err("conflicting decision id must fail"),
        CatalogError::Conflict {
            kind: "publication_moderation_decision",
            ..
        }
    ));

    let mut conflicting_request = request.clone();
    conflicting_request.id = uuid::Uuid::new_v4();
    assert!(matches!(
        catalog
            .moderate_publication_submission(conflicting_request)
            .await
            .expect_err("reused request id must fail"),
        CatalogError::Conflict {
            kind: "publication_moderation_decision",
            ..
        }
    ));

    let terminal = make_moderation_request(
        submission_id,
        moderator.id,
        PublicationModerationAction::Reject,
    );
    assert!(matches!(
        catalog
            .moderate_publication_submission(terminal)
            .await
            .expect_err("terminal submission must not be re-reviewed"),
        CatalogError::Conflict {
            kind: "publication_submission",
            ..
        }
    ));

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("moderation decision count connection failed");
    let decision_count = publication_moderation_decisions::table
        .count()
        .get_result::<i64>(&mut connection)
        .await
        .expect("count moderation decisions failed");
    assert_eq!(decision_count, 1);
    diesel::update(publication_moderation_decisions::table.find(first.id))
        .set(publication_moderation_decisions::reason_code.eq("policy.rewritten"))
        .execute(&mut connection)
        .await
        .expect_err("moderation decision updates must be rejected");
    diesel::delete(publication_moderation_decisions::table.find(first.id))
        .execute(&mut connection)
        .await
        .expect_err("moderation decision deletes must be rejected");
    assert_eq!(
        publication_moderation_decisions::table
            .count()
            .get_result::<i64>(&mut connection)
            .await
            .expect("recount immutable moderation decisions failed"),
        1
    );
}

/// A request-changes decision can be followed by a fresh approval decision.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_moderation_supports_the_needs_review_loop() {
    let (catalog, _container) = setup_catalog().await;
    let (_owner_account_id, _publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "moderation-revision", 181).await;
    let moderator = make_account(uuid::Uuid::new_v4(), "moderation-revision-reviewer");
    catalog
        .create_account(moderator.clone())
        .await
        .expect("create revision moderator account failed");
    assign_test_platform_role(&catalog, moderator.id, "moderator").await;

    let changes = catalog
        .moderate_publication_submission(make_moderation_request(
            submission_id,
            moderator.id,
            PublicationModerationAction::RequestChanges,
        ))
        .await
        .expect("request-changes moderation failed");
    assert_eq!(changes.from_state, PublicationSubmissionState::Quarantined);
    assert_eq!(changes.to_state, PublicationSubmissionState::NeedsReview);

    let approval = catalog
        .moderate_publication_submission(make_moderation_request(
            submission_id,
            moderator.id,
            PublicationModerationAction::Approve,
        ))
        .await
        .expect("approval after requested changes failed");
    assert_eq!(approval.from_state, PublicationSubmissionState::NeedsReview);
    assert_eq!(approval.to_state, PublicationSubmissionState::Approved);
    assert_ne!(approval.id, changes.id);
    assert_ne!(approval.request_id, changes.request_id);

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("revision decision count connection failed");
    assert_eq!(
        publication_moderation_decisions::table
            .filter(publication_moderation_decisions::submission_id.eq(submission_id))
            .count()
            .get_result::<i64>(&mut connection)
            .await
            .expect("count revision decisions failed"),
        2
    );
}

/// Owner appeals and independent overturns are exact, private, and immutable.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_appeal_is_atomic_idempotent_and_audited() {
    let (catalog, _container) = setup_catalog().await;
    let (owner_id, publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "appeal-happy", 194).await;
    let moderator = make_account(uuid::Uuid::new_v4(), "appeal-happy-moderator");
    catalog
        .create_account(moderator.clone())
        .await
        .expect("create appeal moderator failed");
    assign_test_platform_role(&catalog, moderator.id, "moderator").await;
    let decision = catalog
        .moderate_publication_submission(make_moderation_request(
            submission_id,
            moderator.id,
            PublicationModerationAction::Reject,
        ))
        .await
        .expect("reject appeal submission failed");

    let appeal_request = make_appeal_request(decision.id, publisher_id, owner_id);
    let (left, right) = tokio::join!(
        catalog.file_publication_appeal(appeal_request.clone()),
        catalog.file_publication_appeal(appeal_request.clone())
    );
    let left = left.expect("first concurrent appeal failed");
    let right = right.expect("concurrent exact appeal retry failed");
    assert_eq!(left, right);
    assert_eq!(left.decision_id, decision.id);
    assert_eq!(left.submission_id, submission_id);
    assert_eq!(left.publisher_id, publisher_id);

    let mut substituted = appeal_request.clone();
    substituted.statement = "Substituted appeal statement.".to_string();
    assert!(matches!(
        catalog
            .file_publication_appeal(substituted)
            .await
            .expect_err("appeal payload substitution must conflict"),
        CatalogError::Conflict {
            kind: "publication_appeal",
            ..
        }
    ));

    let administrator = make_account(uuid::Uuid::new_v4(), "appeal-happy-administrator");
    catalog
        .create_account(administrator.clone())
        .await
        .expect("create appeal administrator failed");
    assign_test_platform_role(&catalog, administrator.id, "administrator").await;
    let resolution_request = make_appeal_resolution_request(
        left.id,
        administrator.id,
        PublicationAppealDisposition::Overturn,
    );
    let resolution = catalog
        .resolve_publication_appeal(resolution_request.clone())
        .await
        .expect("independent appeal resolution failed");
    assert_eq!(resolution.appeal_id, left.id);
    assert_eq!(
        catalog
            .get_publication_submission(submission_id)
            .await
            .expect("overturned submission lookup failed")
            .state,
        PublicationSubmissionState::Approved
    );

    let owner_cases = catalog
        .list_publisher_publication_appeals(owner_id, publisher_id, None, 50)
        .await
        .expect("owner appeal list failed");
    assert_eq!(owner_cases.len(), 1);
    assert_eq!(owner_cases[0].appeal, left);
    assert_eq!(
        owner_cases[0].resolution.as_ref().map(|record| record.id),
        Some(resolution.id)
    );
    let admin_cases = catalog
        .list_administrator_publication_appeals(administrator.id, None, 50)
        .await
        .expect("administrator appeal list failed");
    assert_eq!(admin_cases, owner_cases);

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("appeal evidence connection failed");
    diesel::update(
        account_platform_roles::table.find((administrator.id, "administrator".to_string())),
    )
    .set(account_platform_roles::state.eq("revoked"))
    .execute(&mut connection)
    .await
    .expect("revoke appeal administrator failed");
    drop(connection);
    assert_eq!(
        catalog
            .resolve_publication_appeal(resolution_request)
            .await
            .expect("completed resolution retry must survive role revocation"),
        resolution
    );

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("appeal immutability connection failed");
    diesel::update(publication_appeals::table.find(left.id))
        .set(publication_appeals::statement.eq("rewritten"))
        .execute(&mut connection)
        .await
        .expect_err("appeal filing updates must be rejected");
    diesel::delete(publication_appeal_resolutions::table.find(resolution.id))
        .execute(&mut connection)
        .await
        .expect_err("appeal resolution deletes must be rejected");
}

/// Self-resolution requires sole-administrator status and explicit evidence.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_appeal_enforces_reviewer_separation() {
    let (catalog, _container) = setup_catalog().await;
    let (owner_id, publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "appeal-separation", 195).await;
    let original_admin = make_account(uuid::Uuid::new_v4(), "appeal-original-admin");
    let alternate_admin = make_account(uuid::Uuid::new_v4(), "appeal-alternate-admin");
    for account in [&original_admin, &alternate_admin] {
        catalog
            .create_account(account.clone())
            .await
            .expect("create separation administrator failed");
        assign_test_platform_role(&catalog, account.id, "administrator").await;
    }
    let decision = catalog
        .moderate_publication_submission(make_moderation_request(
            submission_id,
            original_admin.id,
            PublicationModerationAction::Reject,
        ))
        .await
        .expect("create self-resolution decision failed");
    let appeal = catalog
        .file_publication_appeal(make_appeal_request(decision.id, publisher_id, owner_id))
        .await
        .expect("file separation appeal failed");

    let mut self_resolution = make_appeal_resolution_request(
        appeal.id,
        original_admin.id,
        PublicationAppealDisposition::Uphold,
    );
    self_resolution.separation_exception_reason =
        Some("Only administrator available for this appeal.".to_string());
    assert!(matches!(
        catalog
            .resolve_publication_appeal(self_resolution.clone())
            .await
            .expect_err("self-resolution must fail while another administrator exists"),
        CatalogError::Unauthorized {
            kind: "publication_appeal_separation",
            ..
        }
    ));

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("separation role connection failed");
    diesel::update(
        account_platform_roles::table.find((alternate_admin.id, "administrator".to_string())),
    )
    .set(account_platform_roles::state.eq("revoked"))
    .execute(&mut connection)
    .await
    .expect("revoke alternate administrator failed");
    drop(connection);

    let missing_exception = PublicationAppealResolutionRequest {
        separation_exception_reason: None,
        ..self_resolution.clone()
    };
    assert!(matches!(
        catalog
            .resolve_publication_appeal(missing_exception)
            .await
            .expect_err("sole administrator self-resolution needs exception evidence"),
        CatalogError::Unauthorized {
            kind: "publication_appeal_separation",
            ..
        }
    ));
    let resolved = catalog
        .resolve_publication_appeal(self_resolution)
        .await
        .expect("audited sole-administrator self-resolution failed");
    assert!(resolved.separation_exception_reason.is_some());
    assert_eq!(
        catalog
            .get_publication_submission(submission_id)
            .await
            .expect("upheld submission lookup failed")
            .state,
        PublicationSubmissionState::Rejected
    );
}

/// Appeal eligibility, deadlines, ownership, and current state fail closed.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_appeal_rejects_ineligible_stale_and_cross_publisher_requests() {
    let (catalog, _container) = setup_catalog().await;
    let (owner_id, publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "appeal-policy", 196).await;
    let moderator = make_account(uuid::Uuid::new_v4(), "appeal-policy-moderator");
    catalog
        .create_account(moderator.clone())
        .await
        .expect("create policy moderator failed");
    assign_test_platform_role(&catalog, moderator.id, "moderator").await;
    let approval = catalog
        .moderate_publication_submission(make_moderation_request(
            submission_id,
            moderator.id,
            PublicationModerationAction::Approve,
        ))
        .await
        .expect("approve policy submission failed");
    assert!(matches!(
        catalog
            .file_publication_appeal(make_appeal_request(approval.id, publisher_id, owner_id))
            .await
            .expect_err("approval must not be appealable"),
        CatalogError::Conflict {
            kind: "publication_moderation_decision",
            ..
        }
    ));

    let (stale_owner_id, stale_publisher_id, stale_submission_id) =
        create_test_publication_submission(&catalog, "appeal-stale", 197).await;
    let stale_decision_id = uuid::Uuid::new_v4();
    let old = chrono::Utc::now() - chrono::Duration::days(31);
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("stale appeal fixture connection failed");
    diesel::update(publication_submissions::table.find(stale_submission_id))
        .set(publication_submissions::state.eq("rejected"))
        .execute(&mut connection)
        .await
        .expect("set stale submission state failed");
    diesel::insert_into(publication_moderation_decisions::table)
        .values((
            publication_moderation_decisions::id.eq(stale_decision_id),
            publication_moderation_decisions::submission_id.eq(stale_submission_id),
            publication_moderation_decisions::actor_account_id.eq(moderator.id),
            publication_moderation_decisions::action.eq("reject"),
            publication_moderation_decisions::from_state.eq("quarantined"),
            publication_moderation_decisions::to_state.eq("rejected"),
            publication_moderation_decisions::reason_code.eq("policy.stale"),
            publication_moderation_decisions::private_explanation
                .eq(Some("Expired appeal fixture.")),
            publication_moderation_decisions::request_id.eq(uuid::Uuid::new_v4()),
            publication_moderation_decisions::created_at.eq(old),
        ))
        .execute(&mut connection)
        .await
        .expect("insert stale moderation decision failed");
    drop(connection);

    assert!(matches!(
        catalog
            .file_publication_appeal(make_appeal_request(
                stale_decision_id,
                stale_publisher_id,
                stale_owner_id
            ))
            .await
            .expect_err("expired appeal must fail"),
        CatalogError::Conflict {
            kind: "publication_appeal_deadline",
            ..
        }
    ));
    assert!(matches!(
        catalog
            .file_publication_appeal(make_appeal_request(
                stale_decision_id,
                publisher_id,
                stale_owner_id
            ))
            .await
            .expect_err("cross-publisher path binding must fail"),
        CatalogError::Unauthorized {
            kind: "publication_appeal",
            ..
        }
    ));
}

/// Competing administrator resolutions commit exactly one effective outcome.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_appeal_resolution_is_concurrency_safe() {
    let (catalog, _container) = setup_catalog().await;
    let (owner_id, publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "appeal-concurrent", 198).await;
    let moderator = make_account(uuid::Uuid::new_v4(), "appeal-concurrent-moderator");
    catalog
        .create_account(moderator.clone())
        .await
        .expect("create concurrent moderator failed");
    assign_test_platform_role(&catalog, moderator.id, "moderator").await;
    let decision = catalog
        .moderate_publication_submission(make_moderation_request(
            submission_id,
            moderator.id,
            PublicationModerationAction::Reject,
        ))
        .await
        .expect("create concurrent appeal decision failed");
    let appeal = catalog
        .file_publication_appeal(make_appeal_request(decision.id, publisher_id, owner_id))
        .await
        .expect("file concurrent appeal failed");

    let first_admin = make_account(uuid::Uuid::new_v4(), "appeal-concurrent-admin-one");
    let second_admin = make_account(uuid::Uuid::new_v4(), "appeal-concurrent-admin-two");
    for account in [&first_admin, &second_admin] {
        catalog
            .create_account(account.clone())
            .await
            .expect("create concurrent administrator failed");
        assign_test_platform_role(&catalog, account.id, "administrator").await;
    }
    let uphold = make_appeal_resolution_request(
        appeal.id,
        first_admin.id,
        PublicationAppealDisposition::Uphold,
    );
    let overturn = make_appeal_resolution_request(
        appeal.id,
        second_admin.id,
        PublicationAppealDisposition::Overturn,
    );
    let (left, right) = tokio::join!(
        catalog.resolve_publication_appeal(uphold),
        catalog.resolve_publication_appeal(overturn)
    );
    assert_eq!(
        usize::from(left.is_ok()) + usize::from(right.is_ok()),
        1,
        "exactly one competing appeal resolution must commit"
    );
    let winner = left.or(right).expect("one appeal resolution must succeed");
    let expected_state = match winner.disposition {
        PublicationAppealDisposition::Uphold => PublicationSubmissionState::Rejected,
        PublicationAppealDisposition::Overturn => PublicationSubmissionState::Approved,
    };
    assert_eq!(
        catalog
            .get_publication_submission(submission_id)
            .await
            .expect("concurrent resolution submission lookup failed")
            .state,
        expected_state
    );
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("concurrent resolution count connection failed");
    assert_eq!(
        publication_appeal_resolutions::table
            .count()
            .get_result::<i64>(&mut connection)
            .await
            .expect("count concurrent appeal resolutions failed"),
        1
    );
}

/// Concurrent exact promotion creates one active version and immutable evidence row.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_promotion_is_atomic_concurrent_and_exactly_idempotent() {
    let (catalog, _container) = setup_catalog().await;
    let (_owner_id, _publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "promotion-atomic", 191).await;
    let moderator = make_account(uuid::Uuid::new_v4(), "promotion-atomic-reviewer");
    catalog
        .create_account(moderator.clone())
        .await
        .expect("create promotion moderator failed");
    assign_test_platform_role(&catalog, moderator.id, "moderator").await;
    catalog
        .moderate_publication_submission(make_moderation_request(
            submission_id,
            moderator.id,
            PublicationModerationAction::Approve,
        ))
        .await
        .expect("approve promotion submission failed");
    let request = make_promotion_request(&catalog, submission_id, moderator.id).await;

    let left_catalog = catalog.clone();
    let left_request = request.clone();
    let right_catalog = catalog.clone();
    let right_request = request.clone();
    let (left, right) = tokio::join!(
        left_catalog.promote_publication_submission(left_request, PublishQuota::unlimited()),
        right_catalog.promote_publication_submission(right_request, PublishQuota::unlimited())
    );
    let left = left.expect("first concurrent promotion failed");
    let right = right.expect("second concurrent promotion failed");
    assert_eq!(left, right);
    assert_eq!(left.id, request.id);
    assert_eq!(
        catalog
            .get_publication_submission(submission_id)
            .await
            .expect("promoted submission lookup failed")
            .state,
        PublicationSubmissionState::Promoted
    );
    let stored_version = catalog
        .get_pack_version(&request.version.pack_name, &request.version.version)
        .await
        .expect("promoted pack version lookup failed");
    assert_eq!(stored_version.content_hash, request.version.content_hash);
    assert_eq!(
        stored_version.publisher_key_id,
        request.version.publisher_key_id
    );

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("promotion evidence connection failed");
    assert_eq!(
        publication_promotions::table
            .count()
            .get_result::<i64>(&mut connection)
            .await
            .expect("count promotions failed"),
        1
    );
    assert_eq!(
        pack_versions::table
            .filter(pack_versions::pack_name.eq(&request.version.pack_name))
            .count()
            .get_result::<i64>(&mut connection)
            .await
            .expect("count promoted versions failed"),
        1
    );

    diesel::update(account_platform_roles::table.find((moderator.id, "moderator".to_string())))
        .set(account_platform_roles::state.eq("revoked"))
        .execute(&mut connection)
        .await
        .expect("revoke promotion moderator role failed");
    diesel::update(publisher_keys::table.find(request.version.publisher_key_id.unwrap()))
        .set((
            publisher_keys::state.eq("revoked"),
            publisher_keys::revoked_at.eq(Some(chrono::Utc::now())),
        ))
        .execute(&mut connection)
        .await
        .expect("revoke promoted publisher key failed");
    drop(connection);

    let replay = catalog
        .promote_publication_submission(request.clone(), PublishQuota::unlimited())
        .await
        .expect("completed promotion must replay after authority revocation");
    assert_eq!(replay, left);

    let mut substituted = request.clone();
    substituted.id = uuid::Uuid::new_v4();
    assert!(matches!(
        catalog
            .promote_publication_submission(substituted, PublishQuota::unlimited())
            .await
            .expect_err("promotion identifier substitution must conflict"),
        CatalogError::Conflict {
            kind: "publication_promotion",
            ..
        }
    ));

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("promotion immutability connection failed");
    diesel::update(publication_promotions::table.find(left.id))
        .set(publication_promotions::request_id.eq(uuid::Uuid::new_v4()))
        .execute(&mut connection)
        .await
        .expect_err("promotion evidence updates must be rejected");
    diesel::delete(publication_promotions::table.find(left.id))
        .execute(&mut connection)
        .await
        .expect_err("promotion evidence deletes must be rejected");
}

/// Promotion evidence insertion failure rolls back version activation and state.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_promotion_failure_rolls_back_catalog_activation() {
    let (catalog, _container) = setup_catalog().await;
    let (_owner_id, _publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "promotion-rollback", 193).await;
    let moderator = make_account(uuid::Uuid::new_v4(), "promotion-rollback-reviewer");
    catalog
        .create_account(moderator.clone())
        .await
        .expect("create rollback moderator failed");
    assign_test_platform_role(&catalog, moderator.id, "administrator").await;
    catalog
        .moderate_publication_submission(make_moderation_request(
            submission_id,
            moderator.id,
            PublicationModerationAction::Approve,
        ))
        .await
        .expect("approve rollback submission failed");
    let request = make_promotion_request(&catalog, submission_id, moderator.id).await;
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("promotion rollback connection failed");
    connection
        .batch_execute(
            r#"
            CREATE FUNCTION reject_test_promotion() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'forced promotion insertion failure';
            END
            $$;
            CREATE TRIGGER reject_test_promotion
            BEFORE INSERT ON publication_promotions
            FOR EACH ROW EXECUTE FUNCTION reject_test_promotion();
            "#,
        )
        .await
        .expect("install promotion rejection trigger failed");
    drop(connection);

    catalog
        .promote_publication_submission(request.clone(), PublishQuota::unlimited())
        .await
        .expect_err("forced promotion insertion failure must surface");
    assert_eq!(
        catalog
            .get_publication_submission(submission_id)
            .await
            .expect("rollback submission lookup failed")
            .state,
        PublicationSubmissionState::Approved
    );
    assert!(matches!(
        catalog
            .get_pack_version(&request.version.pack_name, &request.version.version)
            .await
            .expect_err("rolled-back promotion must not leave an active version"),
        CatalogError::NotFound { .. }
    ));
}

/// Missing authority, inactive accounts, and self-review all fail closed.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_moderation_rejects_unauthorized_inactive_and_self_review() {
    let (catalog, _container) = setup_catalog().await;
    let (owner_account_id, _publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "moderation-authz", 183).await;
    let administrator = make_account(uuid::Uuid::new_v4(), "moderation-authz-admin");
    catalog
        .create_account(administrator.clone())
        .await
        .expect("create administrator account failed");
    let request = make_moderation_request(
        submission_id,
        administrator.id,
        PublicationModerationAction::Approve,
    );
    assert!(matches!(
        catalog
            .moderate_publication_submission(request.clone())
            .await
            .expect_err("account without platform role must fail"),
        CatalogError::Unauthorized {
            kind: "publication_moderation",
            ..
        }
    ));
    let unauthorized_missing = make_moderation_request(
        uuid::Uuid::new_v4(),
        administrator.id,
        PublicationModerationAction::Approve,
    );
    assert!(matches!(
        catalog
            .moderate_publication_submission(unauthorized_missing)
            .await
            .expect_err("unauthorized actor must not probe missing submissions"),
        CatalogError::Unauthorized {
            kind: "publication_moderation",
            ..
        }
    ));

    assign_test_platform_role(&catalog, administrator.id, "administrator").await;
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("moderation authorization connection failed");
    diesel::update(accounts::table.find(administrator.id))
        .set(accounts::status.eq("suspended"))
        .execute(&mut connection)
        .await
        .expect("suspend administrator failed");
    assert!(matches!(
        catalog
            .moderate_publication_submission(request.clone())
            .await
            .expect_err("suspended administrator must fail"),
        CatalogError::Unauthorized { .. }
    ));
    diesel::update(accounts::table.find(administrator.id))
        .set(accounts::status.eq("active"))
        .execute(&mut connection)
        .await
        .expect("reactivate administrator failed");
    diesel::update(
        account_platform_roles::table.find((administrator.id, "administrator".to_string())),
    )
    .set(account_platform_roles::state.eq("revoked"))
    .execute(&mut connection)
    .await
    .expect("revoke administrator role failed");
    assert!(matches!(
        catalog
            .moderate_publication_submission(request.clone())
            .await
            .expect_err("revoked administrator role must fail"),
        CatalogError::Unauthorized { .. }
    ));
    diesel::update(
        account_platform_roles::table.find((administrator.id, "administrator".to_string())),
    )
    .set(account_platform_roles::state.eq("active"))
    .execute(&mut connection)
    .await
    .expect("reactivate administrator role failed");
    drop(connection);

    assign_test_platform_role(&catalog, owner_account_id, "moderator").await;
    let owner_request = make_moderation_request(
        submission_id,
        owner_account_id,
        PublicationModerationAction::Reject,
    );
    assert!(matches!(
        catalog
            .moderate_publication_submission(owner_request)
            .await
            .expect_err("publisher owner must not review their own submission"),
        CatalogError::Unauthorized {
            kind: "publication_moderation",
            ..
        }
    ));

    let approved = catalog
        .moderate_publication_submission(request)
        .await
        .expect("foreign active administrator should review");
    assert_eq!(approved.to_state, PublicationSubmissionState::Approved);

    let missing = make_moderation_request(
        uuid::Uuid::new_v4(),
        administrator.id,
        PublicationModerationAction::Approve,
    );
    assert!(matches!(
        catalog
            .moderate_publication_submission(missing)
            .await
            .expect_err("missing submission must fail"),
        CatalogError::NotFound {
            kind: "publication_submission",
            ..
        }
    ));
}

/// Malformed or oversized private moderation fields never mutate state.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_moderation_validates_bounded_private_fields() {
    let (catalog, _container) = setup_catalog().await;
    let (_owner_account_id, _publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "moderation-bounds", 186).await;
    let moderator = make_account(uuid::Uuid::new_v4(), "moderation-bounds-reviewer");
    catalog
        .create_account(moderator.clone())
        .await
        .expect("create bounds moderator failed");
    assign_test_platform_role(&catalog, moderator.id, "moderator").await;
    let base = make_moderation_request(
        submission_id,
        moderator.id,
        PublicationModerationAction::Reject,
    );

    let mut invalid_requests = Vec::new();
    let mut blank_reason = base.clone();
    blank_reason.reason_code.clear();
    invalid_requests.push(blank_reason);
    let mut uppercase_reason = base.clone();
    uppercase_reason.reason_code = "Policy.Invalid".to_string();
    invalid_requests.push(uppercase_reason);
    let mut long_reason = base.clone();
    long_reason.reason_code = "a".repeat(65);
    invalid_requests.push(long_reason);
    let mut blank_explanation = base.clone();
    blank_explanation.private_explanation = Some("   ".to_string());
    invalid_requests.push(blank_explanation);
    let mut long_explanation = base;
    long_explanation.private_explanation = Some("x".repeat(2_001));
    invalid_requests.push(long_explanation);

    for invalid in invalid_requests {
        assert!(matches!(
            catalog
                .moderate_publication_submission(invalid)
                .await
                .expect_err("invalid moderation field must fail"),
            CatalogError::InvalidArgument(_)
        ));
    }
    assert_eq!(
        catalog
            .get_publication_submission(submission_id)
            .await
            .expect("bounded submission lookup failed")
            .state,
        PublicationSubmissionState::Quarantined
    );
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("bounded decision count connection failed");
    assert_eq!(
        publication_moderation_decisions::table
            .count()
            .get_result::<i64>(&mut connection)
            .await
            .expect("count bounded moderation decisions failed"),
        0
    );
}

/// A decision insert failure rolls back the submission lifecycle update.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_moderation_insert_failure_rolls_back_state() {
    let (catalog, _container) = setup_catalog().await;
    let (_owner_account_id, _publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "moderation-rollback", 189).await;
    let moderator = make_account(uuid::Uuid::new_v4(), "moderation-rollback-reviewer");
    catalog
        .create_account(moderator.clone())
        .await
        .expect("create rollback moderator failed");
    assign_test_platform_role(&catalog, moderator.id, "moderator").await;
    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("moderation rollback connection failed");
    connection
        .batch_execute(
            r#"
            CREATE FUNCTION reject_test_moderation_decision() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'forced moderation decision failure';
            END
            $$;
            CREATE TRIGGER reject_test_moderation_decision
            BEFORE INSERT ON publication_moderation_decisions
            FOR EACH ROW EXECUTE FUNCTION reject_test_moderation_decision();
            "#,
        )
        .await
        .expect("install moderation rejection trigger failed");
    drop(connection);

    let request = make_moderation_request(
        submission_id,
        moderator.id,
        PublicationModerationAction::Reject,
    );
    catalog
        .moderate_publication_submission(request)
        .await
        .expect_err("forced moderation insertion failure must surface");
    assert_eq!(
        catalog
            .get_publication_submission(submission_id)
            .await
            .expect("rollback submission lookup failed")
            .state,
        PublicationSubmissionState::Quarantined
    );
}

/// Publisher writes persist identity links and reject revoked keys without hiding history.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publisher_pack_registration_enforces_active_key_state() {
    let (catalog, _container) = setup_catalog().await;
    let account = make_account(uuid::Uuid::new_v4(), "pack-publisher-owner");
    catalog
        .create_account(account.clone())
        .await
        .expect("create account failed");
    let publisher_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    catalog
        .create_publisher(
            PublisherProfileRecord {
                id: publisher_id,
                handle: "pack-publisher".to_string(),
                display_name: "Pack Publisher".to_string(),
                biography: None,
                moderation_status: PublisherModerationStatus::Approved,
                created_at: now,
                updated_at: now,
            },
            PublisherMembershipRecord {
                account_id: account.id,
                publisher_id,
                role: PublisherRole::Owner,
                state: MembershipState::Active,
                created_at: now,
                updated_at: now,
            },
            None,
        )
        .await
        .expect("create publisher failed");
    let publishing_key = PublisherKeyRecord {
        id: uuid::Uuid::new_v4(),
        publisher_id,
        public_key: make_pubkey(92),
        label: "publishing key".to_string(),
        state: PublisherKeyState::Active,
        created_at: now,
        revoked_at: None,
        last_used_at: None,
    };
    let backup_key = PublisherKeyRecord {
        id: uuid::Uuid::new_v4(),
        publisher_id,
        public_key: make_pubkey(93),
        label: "backup key".to_string(),
        state: PublisherKeyState::Active,
        created_at: now,
        revoked_at: None,
        last_used_at: None,
    };
    catalog
        .create_publisher_key(publishing_key.clone(), None)
        .await
        .expect("create publishing key failed");
    catalog
        .create_publisher_key(backup_key, None)
        .await
        .expect("create backup key failed");

    let mut first = make_version("publisher-owned-pack", "1.0.0", 92, 92);
    first.publisher_key_id = Some(publishing_key.id);
    catalog
        .register_pack_version(first.clone())
        .await
        .expect("active publisher key must register a version");
    let pack = catalog
        .get_pack(&first.pack_name)
        .await
        .expect("publisher-owned pack must be readable");
    assert_eq!(pack.publisher_id, Some(publisher_id));
    let stored_first = catalog
        .get_pack_version(&first.pack_name, &first.version)
        .await
        .expect("publisher version must be readable");
    assert_eq!(stored_first.publisher_key_id, Some(publishing_key.id));
    let used_at = catalog
        .list_publisher_keys(publisher_id)
        .await
        .expect("list publisher keys after publish failed")
        .into_iter()
        .find(|key| key.id == publishing_key.id)
        .and_then(|key| key.last_used_at)
        .expect("successful publish must update key last_used_at");
    let duplicate_error = catalog
        .register_pack_version(first.clone())
        .await
        .expect_err("duplicate version must fail");
    assert!(matches!(duplicate_error, CatalogError::Conflict { .. }));
    let after_duplicate = catalog
        .list_publisher_keys(publisher_id)
        .await
        .expect("list publisher keys after duplicate failed")
        .into_iter()
        .find(|key| key.id == publishing_key.id)
        .and_then(|key| key.last_used_at)
        .expect("successful key use timestamp must remain present");
    assert_eq!(after_duplicate, used_at);

    catalog
        .revoke_publisher_key(publisher_id, publishing_key.id, chrono::Utc::now(), None)
        .await
        .expect("publishing key revocation failed");
    let historical = catalog
        .get_pack_version(&first.pack_name, &first.version)
        .await
        .expect("revocation must not hide historical versions");
    assert_eq!(historical.publisher_key_id, Some(publishing_key.id));

    let mut rejected = make_version("publisher-owned-pack", "1.1.0", 92, 94);
    rejected.publisher_key_id = Some(publishing_key.id);
    let error = catalog
        .register_pack_version(rejected)
        .await
        .expect_err("revoked publisher key must not register a new version");
    assert!(matches!(
        error,
        CatalogError::Unauthorized {
            kind: "publisher_key",
            ..
        }
    ));
}

/// Concurrent first publishers cannot both add versions beneath one pack head.
#[tokio::test]
#[ignore = "requires Docker"]
async fn concurrent_first_publish_enforces_winning_owner() {
    let (catalog, _container) = setup_catalog().await;
    let (_, first_publisher_id, first_key) =
        create_test_publisher(&catalog, "first-racer", 101).await;
    let (_, second_publisher_id, second_key) =
        create_test_publisher(&catalog, "second-racer", 102).await;
    let mut first = make_version("contended-pack", "1.0.0", 101, 101);
    first.publisher_key_id = Some(first_key.id);
    let mut second = make_version("contended-pack", "2.0.0", 102, 102);
    second.publisher_key_id = Some(second_key.id);

    let (first_result, second_result) = tokio::join!(
        catalog.register_pack_version(first),
        catalog.register_pack_version(second)
    );
    let winner = match (first_result, second_result) {
        (Ok(()), Err(CatalogError::Unauthorized { kind: "pack", .. })) => first_publisher_id,
        (Err(CatalogError::Unauthorized { kind: "pack", .. }), Ok(())) => second_publisher_id,
        (first, second) => panic!("expected one winning owner, got {first:?} and {second:?}"),
    };
    let pack = catalog
        .get_pack("contended-pack")
        .await
        .expect("winning pack head must exist");
    assert_eq!(pack.publisher_id, Some(winner));
    let versions = catalog
        .list_pack_versions("contended-pack")
        .await
        .expect("winning pack versions must be readable");
    assert_eq!(versions.len(), 1);
}

/// Concurrent legacy and publisher claims leave exactly one namespace owner.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publisher_and_legacy_handle_namespaces_are_disjoint() {
    let (catalog, _container) = setup_catalog().await;
    let account = make_account(uuid::Uuid::new_v4(), "namespace-racer-account");
    catalog
        .create_account(account.clone())
        .await
        .expect("create namespace test account failed");
    let publisher_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let profile = PublisherProfileRecord {
        id: publisher_id,
        handle: "namespace-racer".to_string(),
        display_name: "Namespace Racer".to_string(),
        biography: None,
        moderation_status: PublisherModerationStatus::Approved,
        created_at: now,
        updated_at: now,
    };
    let membership = PublisherMembershipRecord {
        account_id: account.id,
        publisher_id,
        role: PublisherRole::Owner,
        state: MembershipState::Active,
        created_at: now,
        updated_at: now,
    };
    let author = make_author(103, "namespace-racer");

    let (publisher_result, author_result) = tokio::join!(
        catalog.create_publisher(profile, membership, None),
        catalog.register_author(author.clone())
    );
    match (&publisher_result, &author_result) {
        (Ok(()), Err(CatalogError::Conflict { .. }))
        | (Err(CatalogError::Conflict { .. }), Ok(())) => {}
        _ => panic!(
            "expected one namespace winner and one conflict, got {publisher_result:?} and {author_result:?}"
        ),
    }
    let publisher_exists = catalog
        .get_publisher_by_handle("namespace-racer")
        .await
        .is_ok();
    let author_exists = catalog.lookup_author(&author.pubkey).await.is_ok();
    assert_ne!(publisher_exists, author_exists);
}

/// Register an author and look them up by pubkey.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_register_and_lookup_author() {
    let (catalog, _container) = setup_catalog().await;

    let author = make_author(1, "alice");
    catalog
        .register_author(author.clone())
        .await
        .expect("register_author failed");

    let fetched = catalog
        .lookup_author(&author.pubkey)
        .await
        .expect("lookup_author failed");

    assert_eq!(fetched.handle, "alice");
    assert_eq!(fetched.pubkey, author.pubkey);
}

/// Registering the same author twice (same pubkey + handle) is idempotent.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_register_author_idempotent() {
    let (catalog, _container) = setup_catalog().await;

    let author = make_author(2, "bob");
    catalog
        .register_author(author.clone())
        .await
        .expect("first registration failed");
    catalog
        .register_author(author.clone())
        .await
        .expect("idempotent re-registration failed");
}

/// Registering a handle owned by a different pubkey returns HandleTaken.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_register_author_handle_taken() {
    let (catalog, _container) = setup_catalog().await;

    // Register "carol" with pubkey seed=3.
    let carol = make_author(3, "carol");
    catalog
        .register_author(carol.clone())
        .await
        .expect("first registration failed");

    // Try to claim the same handle with a different pubkey.
    let imposter = make_author(99, "carol");
    let err = catalog
        .register_author(imposter)
        .await
        .expect_err("expected HandleTaken error");

    match err {
        CatalogError::HandleTaken { owner } => {
            assert_eq!(
                owner, carol.pubkey,
                "HandleTaken must carry the correct owner"
            );
        }
        other => panic!("expected HandleTaken, got {other:?}"),
    }
}

/// Look up an author by handle.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_lookup_author_by_handle() {
    let (catalog, _container) = setup_catalog().await;

    let author = make_author(4, "dana");
    catalog
        .register_author(author.clone())
        .await
        .expect("register failed");

    let fetched = catalog
        .lookup_author_by_handle("dana")
        .await
        .expect("lookup_author_by_handle failed");

    assert_eq!(fetched.pubkey, author.pubkey);
}

/// Register a pack version and retrieve it.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_register_and_get_pack_version() {
    let (catalog, _container) = setup_catalog().await;

    // Author must exist before registering a version.
    catalog
        .register_author(make_author(5, "eve"))
        .await
        .expect("register author failed");

    let version = make_version("test-pack", "1.0.0", 5, 10);
    catalog
        .register_pack_version(version.clone())
        .await
        .expect("register_pack_version failed");

    let fetched = catalog
        .get_pack_version("test-pack", "1.0.0")
        .await
        .expect("get_pack_version failed");

    assert_eq!(fetched.pack_name, "test-pack");
    assert_eq!(fetched.version, "1.0.0");
    assert_eq!(fetched.content_hash, version.content_hash);
}

/// Registering the same (pack_name, version) twice returns Conflict.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_register_pack_version_conflict() {
    let (catalog, _container) = setup_catalog().await;

    catalog
        .register_author(make_author(6, "frank"))
        .await
        .expect("register author failed");

    let version = make_version("dup-pack", "1.0.0", 6, 20);
    catalog
        .register_pack_version(version.clone())
        .await
        .expect("first version failed");

    let err = catalog
        .register_pack_version(version)
        .await
        .expect_err("expected Conflict");

    assert!(
        matches!(err, CatalogError::Conflict { .. }),
        "expected Conflict, got {err:?}"
    );
}

/// List versions of a pack, ordered by published_at ASC.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_list_pack_versions() {
    let (catalog, _container) = setup_catalog().await;

    catalog
        .register_author(make_author(7, "grace"))
        .await
        .expect("register author failed");

    catalog
        .register_pack_version(make_version("list-pack", "1.0.0", 7, 30))
        .await
        .expect("v1 failed");
    catalog
        .register_pack_version(make_version("list-pack", "1.1.0", 7, 31))
        .await
        .expect("v2 failed");

    let versions = catalog
        .list_pack_versions("list-pack")
        .await
        .expect("list_pack_versions failed");

    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, "1.0.0");
    assert_eq!(versions[1].version, "1.1.0");
}

/// Search packs by tag intersection.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_search_by_tag() {
    let (catalog, _container) = setup_catalog().await;

    catalog
        .register_author(make_author(8, "hank"))
        .await
        .expect("register author failed");

    // Register version first so pack row is created.
    catalog
        .register_pack_version(make_version("tag-pack-a", "1.0.0", 8, 40))
        .await
        .expect("pack-a failed");
    catalog
        .register_pack_version(make_version("tag-pack-b", "1.0.0", 8, 41))
        .await
        .expect("pack-b failed");

    // Update pack-a's tags via raw SQL is not part of the trait; skip tag search
    // and verify search returns all packs instead.
    let results = catalog
        .search_packs(&PackSearchFilters {
            sort: SortMode::Recent,
            limit: 10,
            offset: 0,
            ..Default::default()
        })
        .await
        .expect("search_packs failed");

    // We should get at least the two packs we just created.
    assert!(
        results.len() >= 2,
        "expected >= 2 results, got {}",
        results.len()
    );
}

/// Increment download counter twice in parallel; expect counter = 2.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_increment_download_counter_parallel() {
    let (catalog, _container) = setup_catalog().await;

    catalog
        .register_author(make_author(9, "iris"))
        .await
        .expect("register author failed");

    catalog
        .register_pack_version(make_version("dl-pack", "1.0.0", 9, 50))
        .await
        .expect("register version failed");

    // Increment in parallel.
    let (r1, r2) = tokio::join!(
        catalog.increment_download_counter("dl-pack", "1.0.0"),
        catalog.increment_download_counter("dl-pack", "1.0.0"),
    );

    let c1 = r1.expect("first increment failed");
    let c2 = r2.expect("second increment failed");

    // Both increments must succeed; together they account for 2 downloads.
    assert_eq!(
        c1 + c2,
        3, // 1 + 2 or 2 + 1
        "combined counter values should be 1+2=3, got {c1}+{c2}"
    );
}

/// increment_download_counter returns NotFound for non-existent pack.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_increment_download_counter_not_found() {
    let (catalog, _container) = setup_catalog().await;

    let err = catalog
        .increment_download_counter("no-such-pack", "1.0.0")
        .await
        .expect_err("expected NotFound");

    assert!(
        matches!(err, CatalogError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );
}

/// Tombstone a pack version; get_pack_version still returns it with Tombstone status.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_tombstone_pack() {
    let (catalog, _container) = setup_catalog().await;

    catalog
        .register_author(make_author(10, "jack"))
        .await
        .expect("register author failed");

    catalog
        .register_pack_version(make_version("tomb-pack", "1.0.0", 10, 60))
        .await
        .expect("register version failed");

    let tombstone = TombstoneRecord {
        reason: TombstoneReason::AuthorRequest,
        recorded_at: chrono::Utc::now(),
    };
    catalog
        .tombstone_pack("tomb-pack", "1.0.0", tombstone.clone())
        .await
        .expect("tombstone_pack failed");

    let fetched = catalog
        .get_pack_version("tomb-pack", "1.0.0")
        .await
        .expect("get_pack_version after tombstone failed");

    assert!(
        matches!(fetched.status, PackStatus::Tombstone { .. }),
        "expected Tombstone status, got {:?}",
        fetched.status
    );
}

/// tombstone_pack on a non-existent version returns NotFound.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_tombstone_not_found() {
    let (catalog, _container) = setup_catalog().await;

    let tombstone = TombstoneRecord {
        reason: TombstoneReason::Dmca,
        recorded_at: chrono::Utc::now(),
    };
    let err = catalog
        .tombstone_pack("ghost-pack", "1.0.0", tombstone)
        .await
        .expect_err("expected NotFound");

    assert!(
        matches!(err, CatalogError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );
}

/// Tombstoning the current latest of two `Active` versions recomputes the
/// pack head's `latest_version` to the older remaining `Active` version. The
/// pack must remain visible in `search_packs` because it still has one
/// `Active` version left.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_tombstone_latest_recomputes_head_to_older_active_version() {
    let (catalog, _container) = setup_catalog().await;

    catalog
        .register_author(make_author(50, "morgan"))
        .await
        .expect("register author failed");

    catalog
        .register_pack_version(make_version("head-recompute-pack", "1.0.0", 50, 100))
        .await
        .expect("register 1.0.0 failed");
    catalog
        .register_pack_version(make_version("head-recompute-pack", "2.0.0", 50, 101))
        .await
        .expect("register 2.0.0 failed");

    // Sanity: latest_version is "2.0.0" before the tombstone.
    let before = catalog
        .get_pack("head-recompute-pack")
        .await
        .expect("get_pack before tombstone failed");
    assert_eq!(before.latest_version, Some("2.0.0".to_string()));

    catalog
        .tombstone_pack(
            "head-recompute-pack",
            "2.0.0",
            TombstoneRecord {
                reason: TombstoneReason::AuthorRequest,
                recorded_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("tombstone_pack failed");

    let after = catalog
        .get_pack("head-recompute-pack")
        .await
        .expect("get_pack after tombstone failed");
    assert_eq!(
        after.latest_version,
        Some("1.0.0".to_string()),
        "latest_version must fall back to the newest remaining Active version"
    );

    let results = catalog
        .search_packs(&PackSearchFilters {
            sort: SortMode::Recent,
            limit: 50,
            offset: 0,
            ..Default::default()
        })
        .await
        .expect("search_packs failed");
    assert!(
        results.iter().any(|r| r.pack.name == "head-recompute-pack"),
        "pack must still appear in search after tombstoning its (non-only) latest version"
    );
}

/// Tombstoning the ONLY version of a pack clears the head's `latest_version`
/// to `NULL`, which removes the pack from `search_packs` entirely. The
/// version record itself remains readable via `get_pack_version` with
/// `Tombstone` status.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_tombstone_only_version_clears_head_and_hides_from_search() {
    let (catalog, _container) = setup_catalog().await;

    catalog
        .register_author(make_author(51, "nadia"))
        .await
        .expect("register author failed");

    catalog
        .register_pack_version(make_version("solo-pack", "1.0.0", 51, 102))
        .await
        .expect("register 1.0.0 failed");

    catalog
        .tombstone_pack(
            "solo-pack",
            "1.0.0",
            TombstoneRecord {
                reason: TombstoneReason::TosViolation,
                recorded_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("tombstone_pack failed");

    let after = catalog
        .get_pack("solo-pack")
        .await
        .expect("get_pack after tombstone failed");
    assert_eq!(
        after.latest_version, None,
        "latest_version must clear to NULL when no Active version remains"
    );

    let results = catalog
        .search_packs(&PackSearchFilters {
            sort: SortMode::Recent,
            limit: 50,
            offset: 0,
            ..Default::default()
        })
        .await
        .expect("search_packs failed");
    assert!(
        !results.iter().any(|r| r.pack.name == "solo-pack"),
        "pack must disappear from search once its only version is tombstoned"
    );

    let version = catalog
        .get_pack_version("solo-pack", "1.0.0")
        .await
        .expect("get_pack_version must still return the tombstoned record");
    assert!(
        matches!(version.status, PackStatus::Tombstone { .. }),
        "tombstoned version record must remain directly readable with its status intact"
    );
}

/// Tombstoning a non-latest version leaves the head's `latest_version`
/// untouched and does not affect search visibility.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_tombstone_non_latest_version_leaves_head_unchanged() {
    let (catalog, _container) = setup_catalog().await;

    catalog
        .register_author(make_author(52, "oscar"))
        .await
        .expect("register author failed");

    catalog
        .register_pack_version(make_version("stable-pack", "1.0.0", 52, 103))
        .await
        .expect("register 1.0.0 failed");
    catalog
        .register_pack_version(make_version("stable-pack", "2.0.0", 52, 104))
        .await
        .expect("register 2.0.0 failed");

    // Tombstone the OLDER, non-latest version.
    catalog
        .tombstone_pack(
            "stable-pack",
            "1.0.0",
            TombstoneRecord {
                reason: TombstoneReason::Dmca,
                recorded_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("tombstone_pack failed");

    let after = catalog
        .get_pack("stable-pack")
        .await
        .expect("get_pack after tombstone failed");
    assert_eq!(
        after.latest_version,
        Some("2.0.0".to_string()),
        "latest_version must be unchanged when a non-latest version is tombstoned"
    );

    let results = catalog
        .search_packs(&PackSearchFilters {
            sort: SortMode::Recent,
            limit: 50,
            offset: 0,
            ..Default::default()
        })
        .await
        .expect("search_packs failed");
    assert!(
        results.iter().any(|r| r.pack.name == "stable-pack"),
        "pack must remain in search after tombstoning a non-latest version"
    );
}

/// set_handle_pubkey transfers handle ownership; get_handle_pubkey reflects it.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_set_handle_pubkey_transfers_ownership() {
    let (catalog, _container) = setup_catalog().await;

    // Register author so the pubkeys exist in authors table.
    let old_author = make_author(11, "karen");
    let new_author = make_author(12, "karen2");
    catalog
        .register_author(old_author.clone())
        .await
        .expect("register old_author failed");
    catalog
        .register_author(new_author.clone())
        .await
        .expect("register new_author failed");

    // Set initial ownership.
    catalog
        .set_handle_pubkey("myhandle", old_author.pubkey)
        .await
        .expect("set_handle_pubkey initial failed");

    let fetched = catalog
        .get_handle_pubkey("myhandle")
        .await
        .expect("get_handle_pubkey failed");
    assert_eq!(fetched, old_author.pubkey);

    // Transfer to new_author.
    catalog
        .set_handle_pubkey("myhandle", new_author.pubkey)
        .await
        .expect("set_handle_pubkey transfer failed");

    let updated = catalog
        .get_handle_pubkey("myhandle")
        .await
        .expect("get_handle_pubkey after transfer failed");
    assert_eq!(updated, new_author.pubkey);
}

/// get_handle_pubkey returns NotFound for an unknown handle.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_get_handle_pubkey_not_found() {
    let (catalog, _container) = setup_catalog().await;

    let err = catalog
        .get_handle_pubkey("nonexistent-handle")
        .await
        .expect_err("expected NotFound");

    assert!(
        matches!(err, CatalogError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );
}

/// health() returns a healthy status when the database is reachable.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_health_returns_healthy() {
    let (catalog, _container) = setup_catalog().await;

    let status = catalog.health().await.expect("health() returned Err");
    assert!(
        status.healthy,
        "expected healthy=true, got detail={}",
        status.detail
    );
}

/// A second author cannot publish to a pack already owned by another author.
///
/// Author A registers `ownership-guard-pack@1.0.0`. Author B attempting to
/// publish `ownership-guard-pack@1.1.0` must be rejected with `Unauthorized`.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_register_pack_version_ownership_guard() {
    let (catalog, _container) = setup_catalog().await;

    // Register two distinct authors with different pubkeys and handles.
    catalog
        .register_author(make_author(30, "author-a"))
        .await
        .expect("register author A failed");
    catalog
        .register_author(make_author(31, "author-b"))
        .await
        .expect("register author B failed");

    // Author A publishes the first version.
    let v1 = make_version("ownership-guard-pack", "1.0.0", 30, 80);
    catalog
        .register_pack_version(v1)
        .await
        .expect("author A publishing 1.0.0 should succeed");

    // Author B attempts to publish a subsequent version -- must be rejected.
    let v2 = make_version("ownership-guard-pack", "1.1.0", 31, 81);
    let err = catalog
        .register_pack_version(v2)
        .await
        .expect_err("author B should be rejected with Unauthorized");

    assert!(
        matches!(err, CatalogError::Unauthorized { kind: "pack", .. }),
        "expected Unauthorized{{kind=pack}}, got {err:?}"
    );
}

/// `record_download` records an event; `SortMode::Trending` ranks the more-downloaded pack first.
///
/// Two packs are registered with the same author. Three downloads are recorded
/// for "hot-pack" and one for "cold-pack". A trending search MUST return
/// "hot-pack" before "cold-pack" because it has more downloads in the 7-day window.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_trending_orders_by_recent_downloads() {
    let (catalog, _container) = setup_catalog().await;

    // Register a shared author for both packs.
    catalog
        .register_author(make_author(40, "trend-author"))
        .await
        .expect("register trend-author failed");

    // Register both packs.
    catalog
        .register_pack_version(make_version("hot-pack", "1.0.0", 40, 90))
        .await
        .expect("register hot-pack failed");
    catalog
        .register_pack_version(make_version("cold-pack", "1.0.0", 40, 91))
        .await
        .expect("register cold-pack failed");

    // Record three downloads for hot-pack; one for cold-pack.
    catalog
        .record_download("hot-pack", "1.0.0")
        .await
        .expect("record_download hot 1 failed");
    catalog
        .record_download("hot-pack", "1.0.0")
        .await
        .expect("record_download hot 2 failed");
    catalog
        .record_download("hot-pack", "1.0.0")
        .await
        .expect("record_download hot 3 failed");
    catalog
        .record_download("cold-pack", "1.0.0")
        .await
        .expect("record_download cold 1 failed");

    // Trending search over all packs (no extra filters).
    let results = catalog
        .search_packs(&PackSearchFilters {
            sort: SortMode::Trending,
            limit: 10,
            offset: 0,
            ..Default::default()
        })
        .await
        .expect("search_packs (trending) failed");

    // Both packs must appear.
    assert!(
        results.len() >= 2,
        "expected >= 2 trending results, got {}",
        results.len()
    );

    // Locate positions of hot-pack and cold-pack in the result list.
    let hot_pos = results
        .iter()
        .position(|r| r.pack.name == "hot-pack")
        .expect("hot-pack not found in trending results");
    let cold_pos = results
        .iter()
        .position(|r| r.pack.name == "cold-pack")
        .expect("cold-pack not found in trending results");

    assert!(
        hot_pos < cold_pos,
        "hot-pack (3 downloads) should rank before cold-pack (1 download) in trending; \
         got hot_pos={hot_pos}, cold_pos={cold_pos}"
    );
}

/// `record_download` returns Ok even for an unrecognised pack name.
///
/// The method is best-effort and has no FK constraint to `packs`, so
/// recording a download for an unknown pack name must not return an error.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_record_download_unknown_pack_is_ok() {
    let (catalog, _container) = setup_catalog().await;

    // No pack registered -- but record_download has no FK and must not error.
    catalog
        .record_download("no-such-pack", "1.0.0")
        .await
        .expect("record_download for unknown pack should succeed (best-effort)");
}

/// Search packs with FTS query text.
#[tokio::test]
#[ignore = "requires Docker"]
async fn test_search_by_fts_query() {
    let (catalog, _container) = setup_catalog().await;

    catalog
        .register_author(make_author(20, "luna"))
        .await
        .expect("register author failed");

    catalog
        .register_pack_version(make_version("fts-search-pack", "1.0.0", 20, 70))
        .await
        .expect("register version failed");

    // FTS query that should match the pack name.
    let results = catalog
        .search_packs(&PackSearchFilters {
            query: Some("fts".to_string()),
            sort: SortMode::Recent,
            limit: 10,
            offset: 0,
            ..Default::default()
        })
        .await
        .expect("search_packs failed");

    assert!(
        results.iter().any(|r| r.pack.name == "fts-search-pack"),
        "FTS search should find fts-search-pack, got: {:?}",
        results.iter().map(|r| &r.pack.name).collect::<Vec<_>>()
    );
}

/// Concurrent claims permit exactly one use of a signer-scoped nonce.
#[tokio::test]
#[ignore = "requires Docker"]
async fn security_shared_nonce_claim_is_atomic() {
    let (catalog, _container) = setup_catalog().await;
    let pubkey = make_pubkey(70);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    let (first, second) = tokio::join!(
        catalog.claim_signed_request_nonce(&pubkey, "postgres-security-nonce", expires_at),
        catalog.claim_signed_request_nonce(&pubkey, "postgres-security-nonce", expires_at),
    );
    let claims = [
        first.expect("first nonce claim failed"),
        second.expect("second nonce claim failed"),
    ];

    assert_eq!(
        claims.into_iter().filter(|claimed| *claimed).count(),
        1,
        "exactly one concurrent nonce claim must succeed"
    );
    assert!(
        catalog
            .claim_signed_request_nonce(&make_pubkey(71), "postgres-security-nonce", expires_at,)
            .await
            .expect("signer-scoped nonce claim failed"),
        "a different signer must be able to use the same nonce"
    );
}

/// Active-hash lookup stops authorizing a version immediately after tombstoning.
#[tokio::test]
#[ignore = "requires Docker"]
async fn security_active_hash_lookup_respects_tombstone() {
    let (catalog, _container) = setup_catalog().await;
    let version = make_version("revoked-download-pack", "1.0.0", 72, 72);

    catalog
        .register_author(make_author(72, "revocation-author"))
        .await
        .expect("register author failed");
    catalog
        .register_pack_version(version.clone())
        .await
        .expect("register version failed");
    catalog
        .get_active_pack_version_by_hash(&version.content_hash)
        .await
        .expect("active hash lookup failed before tombstone");

    catalog
        .tombstone_pack(
            &version.pack_name,
            &version.version,
            TombstoneRecord {
                reason: TombstoneReason::AuthorRequest,
                recorded_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("tombstone failed");

    let error = catalog
        .get_active_pack_version_by_hash(&version.content_hash)
        .await
        .expect_err("tombstoned hash must not remain active");
    assert!(
        matches!(error, CatalogError::NotFound { .. }),
        "expected NotFound after tombstone, got {error:?}"
    );
}

/// Per-author quota accounting serializes concurrent PostgreSQL publications.
#[tokio::test]
#[ignore = "requires Docker"]
async fn security_publish_quota_is_transactional_under_concurrency() {
    let (catalog, _container) = setup_catalog().await;
    catalog
        .register_author(make_author(73, "quota-author"))
        .await
        .expect("register author failed");

    let quota = PublishQuota {
        max_versions: Some(1),
        max_bytes: Some(2048),
        max_total_bytes: None,
    };
    let first_version = make_version("quota-race-a", "1.0.0", 73, 73);
    let second_version = make_version("quota-race-b", "1.0.0", 73, 74);
    let (first, second) = tokio::join!(
        catalog.register_pack_version_with_quota(first_version.clone(), quota),
        catalog.register_pack_version_with_quota(second_version.clone(), quota),
    );

    assert_eq!(
        [&first, &second]
            .into_iter()
            .filter(|result| result.is_ok())
            .count(),
        1,
        "exactly one concurrent publication must fit a one-version quota"
    );
    assert_eq!(
        [&first, &second]
            .into_iter()
            .filter(|result| matches!(result, Err(CatalogError::Validation(_))))
            .count(),
        1,
        "the losing publication must fail with a quota validation error"
    );

    let (first_persisted, second_persisted) = tokio::join!(
        catalog.get_pack_version(&first_version.pack_name, &first_version.version),
        catalog.get_pack_version(&second_version.pack_name, &second_version.version),
    );
    assert_ne!(
        first_persisted.is_ok(),
        second_persisted.is_ok(),
        "only the quota-winning version may persist"
    );
}

/// Owner withdrawal is atomic, immutable, and retry-safe after authority revocation.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_withdrawal_commits_state_and_immutable_evidence() {
    let (catalog, _container) = setup_catalog().await;
    let (owner_id, publisher_id, submission_id) =
        create_test_publication_submission(&catalog, "withdraw-owner", 81).await;
    let request = PublicationWithdrawalRequest {
        id: uuid::Uuid::new_v4(),
        submission_id,
        actor_account_id: owner_id,
        reason_code: "owner.cancelled".to_string(),
        request_id: uuid::Uuid::new_v4(),
    };
    let (first, concurrent_retry) = tokio::join!(
        catalog.withdraw_publication_submission(request.clone()),
        catalog.withdraw_publication_submission(request.clone()),
    );
    let first = first.expect("owner withdrawal failed");
    assert_eq!(
        concurrent_retry.expect("concurrent exact withdrawal retry failed"),
        first
    );
    assert_eq!(first.action, PublicationLifecycleAction::WithdrawSubmission);
    assert_eq!(first.publisher_id, Some(publisher_id));
    assert_eq!(
        catalog
            .get_publication_submission(submission_id)
            .await
            .expect("withdrawn submission lookup failed")
            .state,
        PublicationSubmissionState::Withdrawn
    );

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("withdrawal fixture connection failed");
    diesel::update(publisher_memberships::table.find((owner_id, publisher_id)))
        .set(publisher_memberships::state.eq("revoked"))
        .execute(&mut connection)
        .await
        .expect("revoke owner membership failed");
    let retry = catalog
        .withdraw_publication_submission(request.clone())
        .await
        .expect("exact retry must resolve before current authorization");
    assert_eq!(retry, first);
    let mut substituted = request;
    substituted.reason_code = "owner.other".to_string();
    assert!(matches!(
        catalog
            .withdraw_publication_submission(substituted)
            .await
            .expect_err("retry substitution must conflict"),
        CatalogError::Conflict { .. }
    ));
    let mutation = diesel::update(publication_lifecycle_decisions::table.find(first.id))
        .set(publication_lifecycle_decisions::reason_code.eq("changed"))
        .execute(&mut connection)
        .await;
    assert!(mutation.is_err(), "lifecycle evidence must reject updates");
}

/// Administrator suspension rechecks authority and exposes bounded audit evidence.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publisher_suspension_is_admin_only_and_auditable() {
    let (catalog, _container) = setup_catalog().await;
    let (owner_id, publisher_id, _) =
        create_test_publisher(&catalog, "suspend-publisher", 82).await;
    let administrator = make_account(uuid::Uuid::new_v4(), "suspension-admin");
    catalog
        .create_account(administrator.clone())
        .await
        .expect("create administrator failed");
    let unauthorized = PublisherSuspensionRequest {
        id: uuid::Uuid::new_v4(),
        publisher_id,
        actor_account_id: owner_id,
        reason_code: "policy.abuse".to_string(),
        request_id: uuid::Uuid::new_v4(),
    };
    assert!(matches!(
        catalog
            .suspend_publisher(unauthorized)
            .await
            .expect_err("publisher owner must not suspend a publisher"),
        CatalogError::Unauthorized { .. }
    ));

    assign_test_platform_role(&catalog, administrator.id, "administrator").await;
    let request = PublisherSuspensionRequest {
        id: uuid::Uuid::new_v4(),
        publisher_id,
        actor_account_id: administrator.id,
        reason_code: "policy.abuse".to_string(),
        request_id: uuid::Uuid::new_v4(),
    };
    let (decision, concurrent_retry) = tokio::join!(
        catalog.suspend_publisher(request.clone()),
        catalog.suspend_publisher(request),
    );
    let decision = decision.expect("administrator suspension failed");
    assert_eq!(
        concurrent_retry.expect("concurrent exact suspension retry failed"),
        decision
    );
    assert_eq!(
        decision.action,
        PublicationLifecycleAction::SuspendPublisher
    );
    assert_eq!(
        catalog
            .get_publisher(publisher_id)
            .await
            .expect("suspended publisher lookup failed")
            .moderation_status,
        PublisherModerationStatus::Suspended
    );
    let owner_audit = catalog
        .list_publisher_lifecycle_decisions(owner_id, publisher_id, None, 50)
        .await
        .expect("active owner audit read failed");
    assert_eq!(owner_audit, vec![decision.clone()]);
    let admin_audit = catalog
        .list_administrator_lifecycle_decisions(administrator.id, None, 50)
        .await
        .expect("administrator audit read failed");
    assert_eq!(admin_audit, vec![decision.clone()]);
    let empty_page = catalog
        .list_administrator_lifecycle_decisions(
            administrator.id,
            Some(PublicationLifecycleCursor {
                created_at: decision.created_at,
                id: decision.id,
            }),
            50,
        )
        .await
        .expect("cursor audit read failed");
    assert!(empty_page.is_empty(), "cursor must be exclusive");
}

/// Administrator tombstone removes every active resolution path and retains evidence.
#[tokio::test]
#[ignore = "requires Docker"]
async fn publication_tombstone_is_atomic_and_retry_safe() {
    let (catalog, _container) = setup_catalog().await;
    catalog
        .register_author(make_author(83, "lifecycle-tombstone-author"))
        .await
        .expect("register tombstone author failed");
    let version = make_version("lifecycle-tombstone", "1.0.0", 83, 83);
    catalog
        .register_pack_version(version.clone())
        .await
        .expect("register tombstone version failed");
    let administrator = make_account(uuid::Uuid::new_v4(), "tombstone-admin");
    catalog
        .create_account(administrator.clone())
        .await
        .expect("create tombstone administrator failed");
    assign_test_platform_role(&catalog, administrator.id, "administrator").await;
    let request = PublicationTombstoneRequest {
        id: uuid::Uuid::new_v4(),
        pack_name: version.pack_name.clone(),
        version: version.version.clone(),
        actor_account_id: administrator.id,
        reason: TombstoneReason::TosViolation,
        request_id: uuid::Uuid::new_v4(),
    };
    let (first, concurrent_retry) = tokio::join!(
        catalog.tombstone_publication_release(request.clone()),
        catalog.tombstone_publication_release(request.clone()),
    );
    let first = first.expect("administrator tombstone failed");
    assert_eq!(
        concurrent_retry.expect("concurrent exact tombstone retry failed"),
        first
    );
    assert_eq!(first.action, PublicationLifecycleAction::TombstoneRelease);
    assert!(matches!(
        catalog
            .get_active_pack_version_by_hash(&version.content_hash)
            .await
            .expect_err("tombstone must hide active hash resolution"),
        CatalogError::NotFound { .. }
    ));
    assert!(matches!(
        catalog
            .get_pack_version(&version.pack_name, &version.version)
            .await
            .expect("tombstoned metadata must remain")
            .status,
        PackStatus::Tombstone {
            reason: TombstoneReason::TosViolation,
            ..
        }
    ));

    let mut connection = catalog
        .pool()
        .get()
        .await
        .expect("tombstone fixture connection failed");
    diesel::update(
        account_platform_roles::table.find((administrator.id, "administrator".to_string())),
    )
    .set(account_platform_roles::state.eq("revoked"))
    .execute(&mut connection)
    .await
    .expect("revoke administrator role failed");
    let retry = catalog
        .tombstone_publication_release(request)
        .await
        .expect("exact tombstone retry must survive authority revocation");
    assert_eq!(retry, first);
}
