//! Integration tests for `POST /v1/packs` (the publish endpoint).
//!
//! These tests build a multipart upload in memory, drive the router via
//! `tower::ServiceExt::oneshot`, and assert on the resulting status code and
//! JSON body. All catalog and object store interaction goes through the
//! in-memory mocks in `tests/mocks/`.
//!
//! # Coverage
//!
//! - **happy path** -- register an author, sign a real pack with their key,
//!   POST it, assert `200 OK` and the response shape, then verify that the
//!   bytes are fetchable via `GET /v1/packs/{name}/versions/{version}/pack`.
//! - **bad signature** -- POST a pack with a tampered signature, assert `401`.
//! - **unregistered author** -- POST with an unknown `author_handle`, assert `401`.
//! - **duplicate** -- POST the same pack twice, assert second call is `409`.
//! - **malformed archive/manifest** -- POST a corrupt tar.gz or invalid
//!   `pack.toml`, assert `400` with a fixed, generic error message that never
//!   echoes the server's temp-directory path or raw `io::Error`/tar text.

mod mocks;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use flate2::write::GzEncoder;
use flate2::Compression;
use http_body_util::BodyExt as _;
use secrecy::SecretString;
use tower::ServiceExt as _;

use frameshift_catalog::identity::Ed25519PublicKey;
use frameshift_catalog::records::{AuthorRecord, PackRecord};
use frameshift_pack::Pack;

use frameshift_server::metrics::Metrics;
use frameshift_server::{app, AppState, LogFormat, ServerConfig};

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Minimal [`ServerConfig`] for tests. Body limit is large enough to fit a
/// realistic pack upload.
fn test_config() -> Arc<ServerConfig> {
    Arc::new(ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        postgres_url: SecretString::new("postgres://test".into()),
        object_store_root: PathBuf::from("/tmp"),
        log_level: "off".into(),
        log_format: LogFormat::Text,
        max_request_bytes: 4 * 1024 * 1024,
        max_search_limit: 100,
        trust_forwarded_for: false,
        signed_request_max_skew: Duration::from_secs(300),
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

/// Build an [`AppState`] from the given catalog and object store mocks.
fn make_state(catalog: MockCatalog, objects: MockPackStore) -> AppState {
    AppState {
        catalog: Arc::new(catalog),
        objects: Arc::new(objects),
        runtime: None,
        memory: None,
        config: test_config(),
        // Each test gets its own registry for counter isolation.
        metrics: Arc::new(Metrics::new()),
        // Fresh replay-nonce cache per state.
        auth_nonces: Arc::new(frameshift_server::auth::NonceCache::new(
            Duration::from_secs(600),
        )),
    }
}

/// Write a minimal valid pack directory at `dir` with the given name/version
/// and author handle.
fn write_pack(dir: &Path, name: &str, version: &str, handle: &str) {
    let manifest = format!(
        "schema_version = 1\nname = \"{name}\"\nauthor_handle = \"{handle}\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"{version}\"\nlicense = \"MIT\"\n"
    );
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("pack.toml"), manifest).unwrap();
    std::fs::write(dir.join("README.md"), b"# test pack\n").unwrap();
}

/// Like [`write_pack`], but also sets `description` and `tags` in the
/// manifest so publish-time metadata propagation can be exercised.
fn write_pack_with_metadata(
    dir: &Path,
    name: &str,
    version: &str,
    handle: &str,
    description: &str,
    tags: &[&str],
) {
    let tags_toml = tags
        .iter()
        .map(|t| format!("\"{t}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let manifest = format!(
        "schema_version = 1\nname = \"{name}\"\nauthor_handle = \"{handle}\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"{version}\"\nlicense = \"MIT\"\ndescription = \"{description}\"\ntags = [{tags_toml}]\n"
    );
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("pack.toml"), manifest).unwrap();
    std::fs::write(dir.join("README.md"), b"# test pack\n").unwrap();
}

/// Pack a directory tree into a gzipped tar archive and return the bytes.
///
/// The archive entries are placed at the root (no top-level directory) so the
/// publish handler's flat-layout extractor finds `pack.toml` directly.
fn make_targz(dir: &Path) -> Vec<u8> {
    let buf: Vec<u8> = Vec::new();
    let enc = GzEncoder::new(buf, Compression::default());
    let mut tar = tar::Builder::new(enc);
    tar.append_dir_all(".", dir).unwrap();
    let enc = tar.into_inner().unwrap();
    enc.finish().unwrap()
}

/// Build a multipart body manually with a fixed boundary.
///
/// We avoid an extra crate dependency by hand-rolling the wire format. axum
/// 0.8's `Multipart` extractor parses any RFC 7578-shaped body, so a minimal
/// boundary string is enough.
fn build_multipart(
    boundary: &str,
    pack_bytes: &[u8],
    signature: &[u8],
    author_handle: &str,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    let push_str = |b: &mut Vec<u8>, s: &str| b.extend_from_slice(s.as_bytes());

    push_str(&mut body, &format!("--{boundary}\r\n"));
    push_str(
        &mut body,
        "Content-Disposition: form-data; name=\"pack\"; filename=\"pack.tar.gz\"\r\n",
    );
    push_str(&mut body, "Content-Type: application/gzip\r\n\r\n");
    body.extend_from_slice(pack_bytes);
    push_str(&mut body, "\r\n");

    push_str(&mut body, &format!("--{boundary}\r\n"));
    push_str(
        &mut body,
        "Content-Disposition: form-data; name=\"signature\"; filename=\"sig\"\r\n",
    );
    push_str(&mut body, "Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(signature);
    push_str(&mut body, "\r\n");

    push_str(&mut body, &format!("--{boundary}\r\n"));
    push_str(
        &mut body,
        "Content-Disposition: form-data; name=\"author_handle\"\r\n\r\n",
    );
    push_str(&mut body, author_handle);
    push_str(&mut body, "\r\n");

    push_str(&mut body, &format!("--{boundary}--\r\n"));
    body
}

/// Issue a `POST /v1/packs` multipart request and return the response.
///
/// When `request_key` is `Some`, the request is signed with that Ed25519 key
/// using the signed-request envelope (the only accepted auth). When `None`, no
/// auth headers are sent -- used to assert the unauthenticated rejection.
async fn post_publish(
    state: AppState,
    pack_bytes: &[u8],
    signature: &[u8],
    author_handle: &str,
    request_key: Option<&SigningKey>,
) -> axum::http::Response<Body> {
    let boundary = "frameshifttestboundary";
    let body = build_multipart(boundary, pack_bytes, signature, author_handle);
    let mut req = Request::builder().method("POST").uri("/v1/packs").header(
        "content-type",
        format!("multipart/form-data; boundary={boundary}"),
    );
    if let Some(key) = request_key {
        for h in mocks::signing::signed_headers(key, "POST", "/v1/packs", &body) {
            req = req.header(h.name, h.value);
        }
    }
    let req = req.body(Body::from(body)).unwrap();
    app(state).oneshot(req).await.unwrap()
}

/// Read a response body as JSON.
async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Set up an in-memory catalog with the given author registered, returning
/// the catalog plus the registered pubkey.
fn catalog_with_author(signing: &SigningKey, handle: &str) -> (MockCatalog, Ed25519PublicKey) {
    let pubkey_bytes: [u8; 32] = signing.verifying_key().to_bytes();
    let pubkey = Ed25519PublicKey(pubkey_bytes);
    let catalog = MockCatalog::new();
    {
        let mut s = catalog.state.write().unwrap();
        s.authors.insert(
            pubkey.to_string(),
            AuthorRecord {
                pubkey,
                handle: handle.to_string(),
                display_name: None,
                created_at: Utc::now(),
                oauth_links: vec![],
            },
        );
        // Pre-populate the parent pack record so downstream `GET /v1/packs/{name}`
        // succeeds after publish. The MockCatalog does not auto-create parent
        // records on `register_pack_version`, but the catalog trait requires
        // real backends to. We seed it manually here so the test exercises the
        // happy-path GET path.
        s.packs.insert(
            "demo-pack".to_string(),
            PackRecord {
                name: "demo-pack".to_string(),
                current_author: pubkey,
                tags: vec![],
                description: "test".to_string(),
                created_at: Utc::now(),
                latest_version: Some("0.1.0".to_string()),
                total_downloads: 0,
                extends: None,
            },
        );
    }
    (catalog, pubkey)
}

/// Build a fully prepared pack: extract dir, tar.gz bytes, canonical hash,
/// and signature. The caller drives the test from there.
struct PreparedPack {
    /// The gzipped tar archive of the pack contents.
    targz: Vec<u8>,
    /// The 64-byte signature over the canonical pack hash.
    signature: Vec<u8>,
}

/// Build a signed pack with the given name/version/handle/key.
fn prepare_pack(name: &str, version: &str, handle: &str, signing: &SigningKey) -> PreparedPack {
    let tmp = tempfile::TempDir::new().unwrap();
    write_pack(tmp.path(), name, version, handle);
    let pack = Pack::from_dir(tmp.path()).unwrap();
    let canonical_hash = pack.canonical_hash();
    let sig = signing.sign(&canonical_hash);
    let targz = make_targz(tmp.path());
    PreparedPack {
        targz,
        signature: sig.to_bytes().to_vec(),
    }
}

/// Like [`prepare_pack`], but the manifest also declares `description` and
/// `tags`, exercising the publish-time metadata propagation path.
fn prepare_pack_with_metadata(
    name: &str,
    version: &str,
    handle: &str,
    signing: &SigningKey,
    description: &str,
    tags: &[&str],
) -> PreparedPack {
    let tmp = tempfile::TempDir::new().unwrap();
    write_pack_with_metadata(tmp.path(), name, version, handle, description, tags);
    let pack = Pack::from_dir(tmp.path()).unwrap();
    let canonical_hash = pack.canonical_hash();
    let sig = signing.sign(&canonical_hash);
    let targz = make_targz(tmp.path());
    PreparedPack {
        targz,
        signature: sig.to_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// happy path
// ---------------------------------------------------------------------------

/// Register an author, sign a real pack with their key, POST it, expect 200
/// with the correct response shape, and then verify the pack archive bytes
/// are fetchable via `GET /v1/packs/{name}/versions/{version}/pack`.
#[tokio::test]
async fn publish_happy_path_returns_200_and_pack_is_fetchable() {
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let (catalog, _pubkey) = catalog_with_author(&signing, "alice");
    let objects = MockPackStore::new();
    let prepared = prepare_pack("demo-pack", "0.1.0", "alice", &signing);

    let state = make_state(catalog.clone(), objects.clone());
    let resp = post_publish(
        state,
        &prepared.targz,
        &prepared.signature,
        "alice",
        Some(&signing),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200, got {}",
        resp.status()
    );

    let body = body_json(resp).await;
    assert_eq!(body["name"], "demo-pack");
    assert_eq!(body["version"], "0.1.0");
    assert_eq!(body["author_handle"], "alice");
    assert!(
        body["pack_hash"]
            .as_str()
            .map(|s| s.len() == 64)
            .unwrap_or(false),
        "pack_hash must be a 64-char hex string"
    );

    // The pack must be fetchable via the download endpoint.
    let state2 = make_state(catalog, objects);
    let resp2 = app(state2)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/packs/demo-pack/versions/0.1.0/pack")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let archive_bytes = resp2.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(archive_bytes.as_ref(), prepared.targz.as_slice());
}

// ---------------------------------------------------------------------------
// description / tags propagation (P0-2 regression test)
// ---------------------------------------------------------------------------

/// Publish a pack whose manifest declares `description` and `tags`, then
/// assert the pack head record returned by `GET /v1/packs` (the search/list
/// path) carries the same description and tags rather than being blank. This
/// is the regression test for the bug where `publish_pack` registered the
/// version but never wrote manifest metadata onto the pack head row.
#[tokio::test]
async fn publish_pack_description_and_tags_are_searchable() {
    let signing = SigningKey::from_bytes(&[40u8; 32]);
    let (catalog, _pubkey) = catalog_with_author(&signing, "grace");
    let objects = MockPackStore::new();
    let description = "A helpful pack for testing marketplace search.";
    let tags = ["rust", "testing"];
    let prepared =
        prepare_pack_with_metadata("demo-pack", "0.1.0", "grace", &signing, description, &tags);

    let state = make_state(catalog.clone(), objects.clone());
    let resp = post_publish(
        state,
        &prepared.targz,
        &prepared.signature,
        "grace",
        Some(&signing),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200, got {}",
        resp.status()
    );

    // Search/list path: the mock's `search_packs` returns every stored pack
    // head record, so the description/tags update from `set_pack_metadata`
    // must be visible here for the search index to be non-blind.
    let state2 = make_state(catalog, objects);
    let search_resp = app(state2)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/packs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(search_resp.status(), StatusCode::OK);
    let body = body_json(search_resp).await;
    let results = body["results"]
        .as_array()
        .expect("results must be an array");
    let demo_pack = results
        .iter()
        .find(|r| r["pack"]["name"] == "demo-pack")
        .expect("demo-pack must be present in search results");
    assert_eq!(demo_pack["pack"]["description"], description);
    assert_eq!(demo_pack["pack"]["tags"][0], "rust");
    assert_eq!(demo_pack["pack"]["tags"][1], "testing");
}

// ---------------------------------------------------------------------------
// bad signature
// ---------------------------------------------------------------------------

/// POST a pack with a structurally-valid-length but cryptographically-wrong
/// signature -> 401 Unauthorized.
#[tokio::test]
async fn publish_bad_signature_returns_401() {
    let signing = SigningKey::from_bytes(&[8u8; 32]);
    let (catalog, _pubkey) = catalog_with_author(&signing, "bob");
    let prepared = prepare_pack("demo-pack", "0.1.0", "bob", &signing);

    // Wrong signature: signed with a different key entirely.
    let wrong_key = SigningKey::from_bytes(&[9u8; 32]);
    let wrong_sig = wrong_key.sign(&[0u8; 32]); // signs the wrong message too
    let wrong_sig_bytes = wrong_sig.to_bytes().to_vec();

    let state = make_state(catalog, MockPackStore::new());
    let resp = post_publish(
        state,
        &prepared.targz,
        &wrong_sig_bytes,
        "bob",
        Some(&signing),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// unregistered author
// ---------------------------------------------------------------------------

/// POST with an `author_handle` that doesn't exist in the catalog -> 401.
#[tokio::test]
async fn publish_unregistered_author_returns_401() {
    let signing = SigningKey::from_bytes(&[10u8; 32]);
    // The catalog has NO author registered.
    let catalog = MockCatalog::new();
    let prepared = prepare_pack("demo-pack", "0.1.0", "ghost", &signing);

    let state = make_state(catalog, MockPackStore::new());
    let resp = post_publish(
        state,
        &prepared.targz,
        &prepared.signature,
        "ghost",
        Some(&signing),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// duplicate
// ---------------------------------------------------------------------------

/// POST the same pack twice -> second call returns 409 Conflict.
#[tokio::test]
async fn publish_duplicate_returns_409() {
    let signing = SigningKey::from_bytes(&[11u8; 32]);
    let (catalog, _pubkey) = catalog_with_author(&signing, "carol");
    let objects = MockPackStore::new();
    let prepared = prepare_pack("demo-pack", "0.1.0", "carol", &signing);

    let state1 = make_state(catalog.clone(), objects.clone());
    let resp1 = post_publish(
        state1,
        &prepared.targz,
        &prepared.signature,
        "carol",
        Some(&signing),
    )
    .await;
    assert_eq!(resp1.status(), StatusCode::OK);

    let state2 = make_state(catalog, objects);
    let resp2 = post_publish(
        state2,
        &prepared.targz,
        &prepared.signature,
        "carol",
        Some(&signing),
    )
    .await;
    assert_eq!(resp2.status(), StatusCode::CONFLICT);
}

// ---------------------------------------------------------------------------
// missing signed-request auth
// ---------------------------------------------------------------------------

/// POST without any signed-request auth headers -> 401 (the middleware rejects
/// it before the handler runs).
#[tokio::test]
async fn publish_missing_auth_returns_401() {
    let signing = SigningKey::from_bytes(&[12u8; 32]);
    let (catalog, _pubkey) = catalog_with_author(&signing, "dave");
    let prepared = prepare_pack("demo-pack", "0.1.0", "dave", &signing);

    let state = make_state(catalog, MockPackStore::new());
    let resp = post_publish(state, &prepared.targz, &prepared.signature, "dave", None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// request signed by a non-owner key
// ---------------------------------------------------------------------------

/// The pack is correctly signed by the handle owner, but the *live request* is
/// signed by a different key. The handler's authorization check (signer must be
/// the handle owner) rejects it -> 401. This is the core property the old
/// "any non-empty session token" stub could not enforce.
#[tokio::test]
async fn publish_request_signed_by_non_owner_returns_401() {
    let owner = SigningKey::from_bytes(&[20u8; 32]);
    let (catalog, _pubkey) = catalog_with_author(&owner, "erin");
    // The pack itself is validly signed by the owner key.
    let prepared = prepare_pack("demo-pack", "0.1.0", "erin", &owner);

    // But the HTTP request is signed by an unrelated key.
    let attacker = SigningKey::from_bytes(&[21u8; 32]);

    let state = make_state(catalog, MockPackStore::new());
    let resp = post_publish(
        state,
        &prepared.targz,
        &prepared.signature,
        "erin",
        Some(&attacker),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// replayed request
// ---------------------------------------------------------------------------

/// Replaying the exact same signed publish request (identical nonce) against
/// the same server instance is rejected by the nonce cache -> 401.
#[tokio::test]
async fn publish_replayed_request_returns_401() {
    let signing = SigningKey::from_bytes(&[22u8; 32]);
    let (catalog, _pubkey) = catalog_with_author(&signing, "frank");
    let objects = MockPackStore::new();
    let prepared = prepare_pack("demo-pack", "0.1.0", "frank", &signing);

    // One shared state so the nonce cache persists across both requests.
    let state = make_state(catalog, objects);

    let boundary = "frameshifttestboundary";
    let body = build_multipart(boundary, &prepared.targz, &prepared.signature, "frank");
    // Build a single set of signed headers and replay it verbatim.
    let headers = mocks::signing::signed_headers(&signing, "POST", "/v1/packs", &body);
    let build_req = || {
        let mut req = Request::builder().method("POST").uri("/v1/packs").header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        );
        for h in &headers {
            req = req.header(h.name, h.value.clone());
        }
        req.body(Body::from(body.clone())).unwrap()
    };

    let resp1 = app(state.clone()).oneshot(build_req()).await.unwrap();
    assert_eq!(
        resp1.status(),
        StatusCode::OK,
        "first publish should succeed"
    );

    let resp2 = app(state).oneshot(build_req()).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::UNAUTHORIZED,
        "replay with the same nonce must be rejected"
    );
}

// ---------------------------------------------------------------------------
// malformed archive / manifest (temp-directory path leak regression)
// ---------------------------------------------------------------------------

/// POST a `pack` field that is not a valid gzip/tar stream at all -> `400`
/// with a fixed, generic `"invalid archive: ..."` message. Regression test
/// for the leak where the raw tar/io error text (which can embed the
/// server's absolute temp-directory path) was echoed straight into the
/// response body.
#[tokio::test]
async fn publish_malformed_tar_returns_400_generic_message_without_path_leak() {
    let signing = SigningKey::from_bytes(&[50u8; 32]);
    let (catalog, _pubkey) = catalog_with_author(&signing, "mallory");
    // Not a valid gzip stream: decompression fails while the tar reader
    // pulls the first header block, well before any pack.toml is touched.
    let garbage_archive = b"not a valid gzip stream at all".to_vec();
    // The signature field only needs to be 64 bytes; extraction fails before
    // the signature is ever verified.
    let fake_signature = vec![0u8; 64];

    let state = make_state(catalog, MockPackStore::new());
    let resp = post_publish(
        state,
        &garbage_archive,
        &fake_signature,
        "mallory",
        Some(&signing),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = body_json(resp).await;
    let msg = body["error"]
        .as_str()
        .expect("error message must be a string");
    assert!(
        msg.starts_with("invalid archive"),
        "expected a generic 'invalid archive' message, got: {msg}"
    );
    assert!(
        !msg.contains("/tmp") && !msg.to_lowercase().contains("os error"),
        "error message must not leak server filesystem details: {msg}"
    );
}

/// POST a well-formed tar.gz whose `pack.toml` is not valid TOML -> `400`
/// with the fixed message `"invalid pack"`, never the underlying
/// `PackError` text (which can embed the server's absolute
/// temp-directory path via `PackError::Io`/`NonUtf8Path`).
#[tokio::test]
async fn publish_malformed_manifest_returns_400_generic_message_without_path_leak() {
    let signing = SigningKey::from_bytes(&[51u8; 32]);
    let (catalog, _pubkey) = catalog_with_author(&signing, "trent");

    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join("pack.toml"), b"this is not valid toml {{{").unwrap();
    let archive_bytes = make_targz(tmp.path());
    let fake_signature = vec![0u8; 64];

    let state = make_state(catalog, MockPackStore::new());
    let resp = post_publish(
        state,
        &archive_bytes,
        &fake_signature,
        "trent",
        Some(&signing),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = body_json(resp).await;
    assert_eq!(
        body["error"], "invalid pack",
        "publish must return the fixed generic message, not the underlying PackError text"
    );
}
