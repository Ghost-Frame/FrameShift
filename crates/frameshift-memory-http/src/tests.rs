//! Integration tests for [`HttpAdapter`] using wiremock.
//!
//! Each test stands up a local mock server, configures an [`HttpAdapter`]
//! pointing at it, calls the adapter method, and asserts both the result and
//! the number of HTTP requests received by the mock.

#![cfg(test)]

use std::time::Duration;

use frameshift_memory::{Filters, MemoryAdapter, MemoryError, MemoryId, Metadata};
use secrecy::SecretString;
use uuid::Uuid;
use wiremock::matchers::{method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::{HttpAdapter, HttpAdapterConfig, HttpAuth};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an [`HttpAdapter`] pointed at `server`'s base URL.
fn make_adapter(server: &MockServer) -> HttpAdapter {
    let config = HttpAdapterConfig {
        endpoint: server.uri().parse().expect("valid URL"),
        auth: HttpAuth::Bearer(SecretString::new("test-token".into())),
        timeout: Duration::from_secs(5),
        user_agent: "frameshift-test/1.0".into(),
    };
    HttpAdapter::new(config).expect("adapter construction must succeed")
}

/// A minimal Memory JSON object for use in mock responses.
///
/// The UUID is fixed so tests can assert on the returned `MemoryId`.
fn memory_json(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "text": "hello memory",
        "tags": ["a", "b"],
        "created_at": "2026-05-13T00:00:00Z",
        "updated_at": null
    })
}

/// Fixed UUID string used across tests.
const FIXED_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

// ---------------------------------------------------------------------------
// store -- happy path
// ---------------------------------------------------------------------------

/// `store` on a 201 response must return the assigned `MemoryId`.
#[tokio::test]
async fn store_happy_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/store"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": FIXED_UUID,
            "created_at": "2026-05-13T00:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let id = adapter
        .store("hello memory", &["tag1".into()], Metadata::new())
        .await
        .expect("store must succeed");

    let expected = MemoryId::from_uuid(Uuid::parse_str(FIXED_UUID).unwrap());
    assert_eq!(id, expected);
}

// ---------------------------------------------------------------------------
// search -- happy path
// ---------------------------------------------------------------------------

/// `search` on a 200 response must return the list of matching memories.
#[tokio::test]
async fn search_happy_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [memory_json(FIXED_UUID)]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let results = adapter
        .search("hello", 5, &Filters::default())
        .await
        .expect("search must succeed");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].text, "hello memory");
}

// ---------------------------------------------------------------------------
// search -- k=0 short-circuit (no HTTP request made)
// ---------------------------------------------------------------------------

/// `search` with `k=0` must return an empty `Vec` without making any HTTP request.
#[tokio::test]
async fn search_k_zero_short_circuits() {
    let server = MockServer::start().await;

    // Register a mock but expect ZERO calls.
    Mock::given(method("POST"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": []
        })))
        .expect(0)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let results = adapter
        .search("anything", 0, &Filters::default())
        .await
        .expect("search k=0 must not error");

    assert!(results.is_empty(), "k=0 must return empty Vec");
    // wiremock will assert the expect(0) on drop.
}

// ---------------------------------------------------------------------------
// recall -- happy path
// ---------------------------------------------------------------------------

/// `recall` on a 200 response must return the memory with matching fields.
#[tokio::test]
async fn recall_happy_path() {
    let server = MockServer::start().await;
    let id = MemoryId::from_uuid(Uuid::parse_str(FIXED_UUID).unwrap());

    Mock::given(method("GET"))
        .and(path(format!("/memories/{FIXED_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(memory_json(FIXED_UUID)))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let mem = adapter.recall(&id).await.expect("recall must succeed");

    assert_eq!(mem.text, "hello memory");
    assert_eq!(mem.id, id);
}

// ---------------------------------------------------------------------------
// recall -- 404 -> NotFound
// ---------------------------------------------------------------------------

/// `recall` on a 404 response must return `MemoryError::NotFound`.
#[tokio::test]
async fn recall_not_found() {
    let server = MockServer::start().await;
    let id = MemoryId::from_uuid(Uuid::parse_str(FIXED_UUID).unwrap());

    Mock::given(method("GET"))
        .and(path_regex(r"^/memories/.*"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let err = adapter.recall(&id).await.expect_err("must be NotFound");

    assert!(
        matches!(err, MemoryError::NotFound(_)),
        "expected NotFound, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// list -- happy path
// ---------------------------------------------------------------------------

/// `list` on a 200 response must return the paginated items.
#[tokio::test]
async fn list_happy_path() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/memories"))
        .and(query_param("limit", "10"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [memory_json(FIXED_UUID)]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let items = adapter.list(10, 0).await.expect("list must succeed");

    assert_eq!(items.len(), 1);
    assert_eq!(items[0].text, "hello memory");
}

// ---------------------------------------------------------------------------
// forget -- happy path
// ---------------------------------------------------------------------------

/// `forget` on a 204 response must return `Ok(())`.
#[tokio::test]
async fn forget_happy_path() {
    let server = MockServer::start().await;
    let id = MemoryId::from_uuid(Uuid::parse_str(FIXED_UUID).unwrap());

    Mock::given(method("DELETE"))
        .and(path(format!("/memories/{FIXED_UUID}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    adapter.forget(&id).await.expect("forget must succeed");
}

// ---------------------------------------------------------------------------
// forget -- 404 -> NotFound
// ---------------------------------------------------------------------------

/// `forget` on a 404 response must return `MemoryError::NotFound`.
#[tokio::test]
async fn forget_not_found() {
    let server = MockServer::start().await;
    let id = MemoryId::from_uuid(Uuid::parse_str(FIXED_UUID).unwrap());

    Mock::given(method("DELETE"))
        .and(path_regex(r"^/memories/.*"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let err = adapter.forget(&id).await.expect_err("must be NotFound");

    assert!(
        matches!(err, MemoryError::NotFound(_)),
        "expected NotFound, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// health -- happy path
// ---------------------------------------------------------------------------

/// `health` on a 200 response must return `HealthStatus { healthy: true, .. }`.
#[tokio::test]
async fn health_happy_path() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "healthy": true,
            "message": "all systems operational"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let status = adapter.health().await.expect("health must succeed");

    assert!(status.healthy);
    assert_eq!(status.message, "all systems operational");
    assert!(status.latency_ms.is_some());
}

// ---------------------------------------------------------------------------
// store -- 401 -> Unauthorized
// ---------------------------------------------------------------------------

/// `store` on a 401 response must return `MemoryError::Unauthorized`.
#[tokio::test]
async fn store_unauthorized() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/store"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let err = adapter
        .store("text", &[], Metadata::new())
        .await
        .expect_err("must be Unauthorized");

    assert!(
        matches!(err, MemoryError::Unauthorized(_)),
        "expected Unauthorized, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// search -- 401 -> Unauthorized
// ---------------------------------------------------------------------------

/// `search` on a 401 response must return `MemoryError::Unauthorized`.
#[tokio::test]
async fn search_unauthorized() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let err = adapter
        .search("query", 5, &Filters::default())
        .await
        .expect_err("must be Unauthorized");

    assert!(
        matches!(err, MemoryError::Unauthorized(_)),
        "expected Unauthorized, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// store -- 503 with Retry-After: honored
// ---------------------------------------------------------------------------

/// `store` against a 503 that includes `Retry-After: 1` must retry and succeed
/// on the next attempt within a reasonable time window.
#[tokio::test]
async fn store_retries_on_503_with_retry_after() {
    let server = MockServer::start().await;

    // First response: 503 with Retry-After: 1 second.
    Mock::given(method("POST"))
        .and(path("/store"))
        .respond_with(ResponseTemplate::new(503).append_header("Retry-After", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Second response: 201 success.
    Mock::given(method("POST"))
        .and(path("/store"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": FIXED_UUID,
            "created_at": "2026-05-13T00:00:00Z"
        })))
        .mount(&server)
        .await;

    let adapter = make_adapter(&server);
    let id = adapter
        .store("retry test", &[], Metadata::new())
        .await
        .expect("store must succeed after retry");

    let expected = MemoryId::from_uuid(Uuid::parse_str(FIXED_UUID).unwrap());
    assert_eq!(id, expected);
    // Verify that at least 2 requests were made (the 503 + the success).
    assert!(server.received_requests().await.unwrap().len() >= 2);
}
