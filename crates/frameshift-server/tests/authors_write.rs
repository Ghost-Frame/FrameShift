//! Integration tests for the signed-request registration route on `/v1/authors`.
//!
//! Each request is signed with the Ed25519 signed-request envelope (the only
//! accepted auth). All catalog interaction goes through the in-memory
//! `MockCatalog`, whose `handles` map is the publish authority.

mod mocks;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use secrecy::SecretString;
use tower::ServiceExt as _;

use frameshift_catalog::identity::Ed25519PublicKey;

use frameshift_server::metrics::Metrics;
use frameshift_server::{app, AppState, LogFormat, ServerConfig};

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Minimal [`ServerConfig`] for these tests.
fn test_config() -> Arc<ServerConfig> {
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
        admin_pubkeys: Vec::new(),
        oidc: frameshift_server::OidcConfig::disabled(),
        shutdown_grace: Duration::from_secs(1),
        cors_allowed_origins: String::new(),
        download_secret: SecretString::new(String::new()),
        download_token_ttl: Duration::from_secs(300),
        download_max_token_ttl: Duration::from_secs(1800),
        download_rate_per_min: 0,
        abuse_rate_per_min: 0,
        metrics_bearer_token: SecretString::new(String::new()),
        publisher_pubkeys: vec!["*".to_string()],
        max_versions_per_author: 0,
        max_bytes_per_author: 0,
        max_total_bytes: 0,
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

/// Build an [`AppState`] backed by the given mock catalog.
fn mk_state(catalog: MockCatalog) -> AppState {
    AppState {
        catalog: Arc::new(catalog),
        objects: Arc::new(MockPackStore::new()),
        runtime: None,
        memory: None,
        config: test_config(),
        metrics: Arc::new(Metrics::new()),
        auth_nonces: Arc::new(frameshift_server::auth::NonceCache::new(
            Duration::from_secs(600),
        )),
        account_auth: None,
    }
}

/// Issue a signed (or unsigned, when `key` is `None`) JSON POST and return the
/// response.
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

// ---------------------------------------------------------------------------
// registration
// ---------------------------------------------------------------------------

/// A signed `POST /v1/authors` registers the signer's key under the handle and
/// populates both the authors and handles maps.
#[tokio::test]
async fn register_creates_author_and_handle() {
    let key = SigningKey::from_bytes(&[30u8; 32]);
    let catalog = MockCatalog::new();
    let state = mk_state(catalog.clone());

    let resp = post_signed_json(
        state,
        "/v1/authors",
        serde_json::json!({ "handle": "alice", "display_name": "Alice" }),
        Some(&key),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "register should 201");

    let s = catalog.state.read().unwrap();
    let pubkey = Ed25519PublicKey(key.verifying_key().to_bytes());
    assert_eq!(
        s.handles.get("alice").copied(),
        Some(pubkey),
        "handles map must point at the signer key"
    );
    assert!(
        s.authors.values().any(|a| a.handle == "alice"),
        "authors map must contain the new handle"
    );
}

/// Registration with no auth headers is rejected by the middleware.
#[tokio::test]
async fn register_without_auth_returns_401() {
    let catalog = MockCatalog::new();
    let state = mk_state(catalog);
    let resp = post_signed_json(
        state,
        "/v1/authors",
        serde_json::json!({ "handle": "alice" }),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A handle already owned by another key cannot be re-registered -> 409.
#[tokio::test]
async fn register_duplicate_handle_returns_409() {
    let key_a = SigningKey::from_bytes(&[31u8; 32]);
    let key_b = SigningKey::from_bytes(&[32u8; 32]);
    let catalog = MockCatalog::new();

    let r1 = post_signed_json(
        mk_state(catalog.clone()),
        "/v1/authors",
        serde_json::json!({ "handle": "bob" }),
        Some(&key_a),
    )
    .await;
    assert_eq!(r1.status(), StatusCode::CREATED);

    let r2 = post_signed_json(
        mk_state(catalog),
        "/v1/authors",
        serde_json::json!({ "handle": "bob" }),
        Some(&key_b),
    )
    .await;
    assert_eq!(
        r2.status(),
        StatusCode::CONFLICT,
        "a taken handle must 409 for a different key"
    );
}

/// Regression: a handle present only in the `handles` table (e.g. seeded
/// directly via set_handle_pubkey, with no matching `authors` row) cannot be
/// hijacked by registering it under a different key. Without the register-route
/// ownership check, register_author's authors-table guard would miss this and
/// the follow-up set_handle_pubkey would overwrite the owner.
#[tokio::test]
async fn register_handle_owned_only_in_handles_table_returns_409() {
    let owner = SigningKey::from_bytes(&[40u8; 32]);
    let attacker = SigningKey::from_bytes(&[41u8; 32]);
    let owner_pubkey = Ed25519PublicKey(owner.verifying_key().to_bytes());
    let catalog = MockCatalog::new();

    // Seed the handle into the handles map only, with no authors row.
    {
        let mut s = catalog.state.write().unwrap();
        s.handles.insert("carol".to_string(), owner_pubkey);
    }

    let resp = post_signed_json(
        mk_state(catalog.clone()),
        "/v1/authors",
        serde_json::json!({ "handle": "carol" }),
        Some(&attacker),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "registering a handle owned only in the handles table must 409"
    );

    // The owner mapping must be untouched by the rejected registration.
    let s = catalog.state.read().unwrap();
    assert_eq!(
        s.handles.get("carol").copied(),
        Some(owner_pubkey),
        "attacker must not overwrite the existing handle owner"
    );
}

// ---------------------------------------------------------------------------
// unsupported key rotation
// ---------------------------------------------------------------------------

/// Key rotation is not exposed until a verifiable continuity protocol exists.
#[tokio::test]
async fn rotate_route_is_not_exposed() {
    let old = SigningKey::from_bytes(&[33u8; 32]);
    let new = SigningKey::from_bytes(&[34u8; 32]);
    let catalog = MockCatalog::new();

    let r1 = post_signed_json(
        mk_state(catalog.clone()),
        "/v1/authors",
        serde_json::json!({ "handle": "carol" }),
        Some(&old),
    )
    .await;
    assert_eq!(r1.status(), StatusCode::CREATED);

    let r2 = post_signed_json(
        mk_state(catalog.clone()),
        "/v1/authors/carol/rotate",
        serde_json::json!({
            "new_pubkey": Ed25519PublicKey(new.verifying_key().to_bytes()).to_string()
        }),
        Some(&old),
    )
    .await;
    assert_eq!(r2.status(), StatusCode::NOT_FOUND);

    let s = catalog.state.read().unwrap();
    assert_eq!(
        s.handles.get("carol").copied(),
        Some(Ed25519PublicKey(old.verifying_key().to_bytes())),
        "an unavailable route must not alter handle ownership"
    );
}
