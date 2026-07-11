//! Integration tests for `POST /v1/telemetry/selection`.
//!
//! Verifies the wire contract matches `frameshift_client::selection::SelectionTelemetry`
//! and that the route-level body size limit rejects oversized payloads.

mod mocks;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use tower::ServiceExt as _;

use frameshift_server::metrics::Metrics;
use frameshift_server::{app, AppState, LogFormat, ServerConfig};

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Build a minimal [`ServerConfig`] suitable for tests. Mirrors `test_config`
/// in `tests/integration.rs`.
fn test_config() -> Arc<ServerConfig> {
    Arc::new(ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        postgres_url: SecretString::new("postgres://test".into()),
        object_store_root: PathBuf::from("/tmp"),
        log_level: "off".into(),
        log_format: LogFormat::Text,
        max_request_bytes: 1_048_576,
        max_search_limit: 100,
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
        trust_forwarded_for: false,
        signed_request_max_skew: Duration::from_secs(300),
        admin_pubkeys: Vec::new(),
        memory_backend: "none".to_string(),
        memory_http_endpoint: String::new(),
        memory_http_auth: "none".to_string(),
        memory_http_timeout_secs: 30,
        memory_sqlite_path: String::new(),
    })
}

/// Build an [`AppState`] with fresh mocks and a fresh metrics registry.
fn make_state() -> AppState {
    AppState {
        catalog: Arc::new(MockCatalog::new()),
        objects: Arc::new(MockPackStore::new()),
        runtime: None,
        memory: None,
        config: test_config(),
        metrics: Arc::new(Metrics::new()),
        auth_nonces: Arc::new(frameshift_server::auth::NonceCache::new(
            Duration::from_secs(600),
        )),
    }
}

/// A representative telemetry payload matching the client's
/// `SelectionTelemetry` wire shape exactly (persona, session, project_id,
/// recorded_at_unix).
const VALID_PAYLOAD: &str = r#"{"persona":"rust","session":"sess-1","project_id":"proj-abc123","recorded_at_unix":1750000000}"#;

/// `POST /v1/telemetry/selection` with a well-formed, client-shaped payload
/// returns a 2xx status.
#[tokio::test]
async fn selection_telemetry_valid_payload_returns_2xx() {
    let state = make_state();
    let router = app(state);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/telemetry/selection")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(VALID_PAYLOAD))
        .unwrap();
    let resp = router.oneshot(request).await.unwrap();
    assert!(
        resp.status().is_success(),
        "expected 2xx, got {}",
        resp.status()
    );
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// An oversized body is rejected before deserialization, via the route-level
/// `DefaultBodyLimit`.
#[tokio::test]
async fn selection_telemetry_oversized_body_is_rejected() {
    let state = make_state();
    let router = app(state);
    // Well over the route's 4 KiB cap, wrapped as a JSON string value so it
    // would otherwise be syntactically valid if size were not enforced.
    let oversized = format!(
        r#"{{"persona":"{}","session":"s","project_id":"p","recorded_at_unix":1}}"#,
        "a".repeat(8192)
    );
    let request = Request::builder()
        .method("POST")
        .uri("/v1/telemetry/selection")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(oversized))
        .unwrap();
    let resp = router.oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
