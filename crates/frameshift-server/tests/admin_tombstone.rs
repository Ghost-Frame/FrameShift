//! Integration tests for the signed-request, allowlist-gated admin route
//! `POST /v1/admin/packs/{name}/{version}/tombstone`.
//!
//! Every request is driven through the real router
//! ([`frameshift_server::app`]) via `tower::ServiceExt::oneshot`, exactly like
//! the other integration test files. All catalog interaction goes through the
//! in-memory [`MockCatalog`], whose `tombstone_pack` mirrors the Postgres
//! adapter's documented idempotent (last-writer-wins) semantics.
//!
//! # Coverage
//!
//! - unsigned request -> `401` (signed-request middleware rejects before the
//!   handler's allowlist check ever runs)
//! - signed by a key NOT on the allowlist -> `403`
//! - signed by a key ON the allowlist -> `200`, catalog state updated
//! - unknown pack/version -> `404`
//! - empty allowlist (feature disabled) -> `404` even with a valid signature
//! - repeat tombstone of an already-tombstoned version -> `200` (idempotent,
//!   matching the Postgres adapter's documented last-writer-wins choice)

mod mocks;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use secrecy::SecretString;
use tower::ServiceExt as _;

use frameshift_catalog::identity::Ed25519PublicKey;
use frameshift_catalog::records::PackVersionRecord;
use frameshift_catalog::status::PackStatus;
use frameshift_objects::ObjectHash;

use frameshift_server::metrics::Metrics;
use frameshift_server::{app, AppState, LogFormat, ServerConfig};

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Build a minimal [`ServerConfig`] for these tests, with `admin_pubkeys` set
/// to `admins`. Pass an empty `Vec` to exercise the disabled-endpoint path.
fn test_config(admins: Vec<String>) -> Arc<ServerConfig> {
    Arc::new(ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        postgres_url: SecretString::new("postgres://test".into()),
        object_store_root: PathBuf::from("/tmp"),
        log_level: "off".into(),
        log_format: LogFormat::Text,
        max_request_bytes: 1_048_576,
        max_search_limit: 100,
        trust_forwarded_for: false,
        signed_request_max_skew: Duration::from_secs(300),
        admin_pubkeys: admins,
        shutdown_grace: Duration::from_secs(1),
        cors_allowed_origins: String::new(),
        download_secret: SecretString::new(String::new()),
        download_token_ttl: Duration::from_secs(300),
        download_max_token_ttl: Duration::from_secs(1800),
        download_rate_per_min: 0,
        object_store_backend: "fs".to_string(),
        r2_endpoint: String::new(),
        r2_bucket: String::new(),
        r2_prefix: "objects".to_string(),
        r2_region: "auto".to_string(),
        r2_access_key_id: String::new(),
        r2_secret_access_key: SecretString::new(String::new()),
        memory_backend: "none".to_string(),
        memory_http_endpoint: String::new(),
        memory_http_auth: "none".to_string(),
        memory_http_timeout_secs: 30,
        memory_sqlite_path: String::new(),
    })
}

/// Build an [`AppState`] backed by `catalog`, with the admin allowlist set to
/// `admins`.
fn mk_state(catalog: MockCatalog, admins: Vec<String>) -> AppState {
    AppState {
        catalog: Arc::new(catalog),
        objects: Arc::new(MockPackStore::new()),
        runtime: None,
        memory: None,
        config: test_config(admins),
        metrics: Arc::new(Metrics::new()),
        auth_nonces: Arc::new(frameshift_server::auth::NonceCache::new(
            Duration::from_secs(600),
        )),
    }
}

/// base64url-no-pad encoding of a signing key's public key -- the same
/// representation `admin_pubkeys` entries and `VerifiedSigner::pubkey`'s
/// `Display` impl use.
fn pubkey_b64(key: &SigningKey) -> String {
    Ed25519PublicKey(key.verifying_key().to_bytes()).to_string()
}

/// Insert a minimal, `Active` [`PackVersionRecord`] for `(name, version)`
/// directly into `catalog`'s in-memory state, bypassing the publish flow.
fn seed_active_version(catalog: &MockCatalog, name: &str, version: &str) {
    let mut state = catalog.state.write().unwrap();
    let record = PackVersionRecord {
        pack_name: name.to_string(),
        version: version.to_string(),
        content_hash: ObjectHash::of(b"test-pack-bytes"),
        signature: vec![0u8; 64],
        author_pubkey: Ed25519PublicKey([7u8; 32]),
        parent_hash: None,
        capability_manifest_json: "{}".to_string(),
        schema_version: 1,
        license: "MIT".to_string(),
        published_at: Utc::now(),
        status: PackStatus::Active,
        size_bytes: 16,
    };
    state
        .versions
        .insert((name.to_string(), version.to_string()), record);
}

/// Issue a signed (or unsigned, when `key` is `None`) JSON POST against the
/// real router and return the response.
async fn post_signed_json(
    state: AppState,
    path: &str,
    json: serde_json::Value,
    key: Option<&SigningKey>,
) -> axum::http::Response<Body> {
    let body = serde_json::to_vec(&json).unwrap();
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(k) = key {
        for h in mocks::signing::signed_headers(k, "POST", path, &body) {
            req = req.header(h.name, h.value);
        }
    }
    let req = req.body(Body::from(body)).unwrap();
    app(state).oneshot(req).await.unwrap()
}

/// The standard tombstone request body used across these tests.
fn tombstone_body() -> serde_json::Value {
    serde_json::json!({ "reason": "author-request" })
}

/// An unsigned request is rejected by the signed-request middleware before
/// the handler's allowlist check ever runs.
#[tokio::test]
async fn unsigned_request_returns_401() {
    let admin = SigningKey::from_bytes(&[50u8; 32]);
    let catalog = MockCatalog::new();
    seed_active_version(&catalog, "my-pack", "1.0.0");
    let state = mk_state(catalog, vec![pubkey_b64(&admin)]);

    let resp = post_signed_json(
        state,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        tombstone_body(),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A correctly signed request from a key that is NOT on the allowlist -> 403.
#[tokio::test]
async fn non_admin_signer_returns_403() {
    let admin = SigningKey::from_bytes(&[51u8; 32]);
    let non_admin = SigningKey::from_bytes(&[52u8; 32]);
    let catalog = MockCatalog::new();
    seed_active_version(&catalog, "my-pack", "1.0.0");
    let state = mk_state(catalog, vec![pubkey_b64(&admin)]);

    let resp = post_signed_json(
        state,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        tombstone_body(),
        Some(&non_admin),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A correctly signed request from an admin key tombstones the version and
/// returns 200 with the expected body shape.
#[tokio::test]
async fn admin_signer_returns_200_and_tombstones() {
    let admin = SigningKey::from_bytes(&[53u8; 32]);
    let catalog = MockCatalog::new();
    seed_active_version(&catalog, "my-pack", "1.0.0");
    let state = mk_state(catalog.clone(), vec![pubkey_b64(&admin)]);

    let resp = post_signed_json(
        state,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        tombstone_body(),
        Some(&admin),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "admin tombstone should 200");

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["name"], "my-pack");
    assert_eq!(json["version"], "1.0.0");
    assert_eq!(json["status"], "tombstoned");

    let s = catalog.state.read().unwrap();
    let record = s
        .versions
        .get(&("my-pack".to_string(), "1.0.0".to_string()))
        .expect("version must still exist");
    assert!(
        matches!(record.status, PackStatus::Tombstone { .. }),
        "version status must transition to Tombstone"
    );
}

/// Tombstoning an unknown pack/version -> 404.
#[tokio::test]
async fn unknown_version_returns_404() {
    let admin = SigningKey::from_bytes(&[54u8; 32]);
    let catalog = MockCatalog::new();
    let state = mk_state(catalog, vec![pubkey_b64(&admin)]);

    let resp = post_signed_json(
        state,
        "/v1/admin/packs/no-such-pack/9.9.9/tombstone",
        tombstone_body(),
        Some(&admin),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// An empty admin allowlist disables the endpoint entirely -> 404, even for a
/// validly signed request and an existing version. This must NOT be 403: an
/// empty allowlist means the feature is off, indistinguishable from an
/// unmapped route.
#[tokio::test]
async fn empty_allowlist_returns_404_even_with_valid_signature() {
    let signer = SigningKey::from_bytes(&[55u8; 32]);
    let catalog = MockCatalog::new();
    seed_active_version(&catalog, "my-pack", "1.0.0");
    let state = mk_state(catalog, vec![]);

    let resp = post_signed_json(
        state,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        tombstone_body(),
        Some(&signer),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Repeat-tombstoning an already-tombstoned version is idempotent (200), not
/// a conflict -- matching the Postgres adapter's documented last-writer-wins
/// choice (`crates/frameshift-catalog-postgres/src/backend.rs`).
#[tokio::test]
async fn repeat_tombstone_is_idempotent_200() {
    let admin = SigningKey::from_bytes(&[56u8; 32]);
    let catalog = MockCatalog::new();
    seed_active_version(&catalog, "my-pack", "1.0.0");
    let state = mk_state(catalog.clone(), vec![pubkey_b64(&admin)]);

    let r1 = post_signed_json(
        state,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        tombstone_body(),
        Some(&admin),
    )
    .await;
    assert_eq!(r1.status(), StatusCode::OK);

    let state2 = mk_state(catalog, vec![pubkey_b64(&admin)]);
    let r2 = post_signed_json(
        state2,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        serde_json::json!({ "reason": "tos-violation" }),
        Some(&admin),
    )
    .await;
    assert_eq!(
        r2.status(),
        StatusCode::OK,
        "re-tombstoning must be idempotent, not a conflict"
    );
}
