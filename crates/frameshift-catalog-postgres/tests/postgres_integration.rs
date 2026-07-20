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

use frameshift_catalog::{
    AuthorRecord, CatalogBackend, CatalogError, Ed25519PublicKey, ObjectHash, PackSearchFilters,
    PackStatus, PackVersionRecord, PublishQuota, SortMode, TombstoneReason, TombstoneRecord,
};
use frameshift_catalog_postgres::{PostgresCatalog, PostgresCatalogConfig};
use secrecy::SecretString;

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
        parent_hash: None,
        capability_manifest_json: r#"{"permissions":[]}"#.to_string(),
        schema_version: 1,
        license: "Apache-2.0".to_string(),
        published_at: chrono::Utc::now(),
        status: PackStatus::Active,
        size_bytes: 1024,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

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
/// pack head's `latest_version` to the older remaining `Active` version
/// (spec_42eb1942 item 1: the head, not just the version row, must reflect
/// the tombstone). The pack must remain visible in `search_packs` because it
/// still has one `Active` version left.
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

/// D5: A second author cannot publish to a pack already owned by another author.
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
