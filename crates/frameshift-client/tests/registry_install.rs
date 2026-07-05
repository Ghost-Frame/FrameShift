//! End-to-end tests for the HTTP registry install path.
//!
//! Unlike `tests/install_flow.rs` (local-path installs) and the unit tests in
//! `src/registry.rs` (URL parsing, hash-mismatch *detection logic*, HTTP-error
//! mapping for `search`/`resolve_latest_version`), this file drives
//! `Client::install` with `InstallSource::Registry` against a real HTTP mock
//! server, exercising the full `fetch_and_install` pipeline: version-record
//! fetch, archive fetch, content-hash check, `.tar.gz` extraction, Ed25519
//! signature verification, and content-addressed caching.
//!
//! The mock server is a hand-rolled `std::net::TcpListener` responder (the
//! same pattern as `src/publish.rs`'s test module), not `wiremock` (which
//! requires a tokio runtime the blocking `ureq` client does not have) and not
//! the server crate's `tower::ServiceExt::oneshot` (which drives the router
//! in-process rather than over a real socket). Server threads spawned here
//! are intentionally detached: the process exits at the end of the test
//! binary, so no join is required.

use std::collections::HashMap;
use std::io::{BufRead as _, Write as _};
use std::net::TcpListener;
use std::sync::Mutex;

use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use flate2::write::GzEncoder;
use flate2::Compression;
use frameshift_catalog::identity::Ed25519PublicKey;
use frameshift_catalog::records::PackVersionRecord;
use frameshift_catalog::status::PackStatus;
use frameshift_client::{Client, ClientOptions, InstallRequest, InstallSource, PersonaSpec};
use frameshift_pack::{ObjectHash, Pack};

/// A single canned HTTP response: status code, `Content-Type` header value,
/// and raw body bytes.
#[derive(Clone)]
struct MockResponse {
    /// The HTTP status code to send (only 200 and 404 are used by these tests).
    status: u16,
    /// The `Content-Type` header value.
    content_type: &'static str,
    /// The raw response body bytes.
    body: Vec<u8>,
}

/// Spawn a detached background HTTP server bound to an ephemeral port that
/// answers every request by looking up the request path in `routes`. Paths
/// not present in `routes` get a 404. Every response is sent with
/// `Connection: close`, and the server loop runs for the lifetime of the test
/// process (it is never joined) so it can answer both of `fetch_and_install`'s
/// sequential requests -- the version record, then the archive -- on a fresh
/// connection each time.
///
/// Returns the `http://127.0.0.1:<port>` base URL.
fn spawn_registry(routes: HashMap<String, MockResponse>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(cloned) = stream.try_clone() else {
                continue;
            };
            let mut reader = std::io::BufReader::new(cloned);

            let mut request_line = String::new();
            if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                continue;
            }
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_string();

            // Drain the remaining request headers (we don't need them).
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) if line == "\r\n" => break,
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }

            let default = MockResponse {
                status: 404,
                content_type: "text/plain",
                body: b"not found".to_vec(),
            };
            let response = routes.get(&path).cloned().unwrap_or(default);
            let status_line = match response.status {
                200 => "200 OK",
                404 => "404 Not Found",
                other => panic!("unsupported mock status {other}"),
            };
            let head = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.content_type,
                response.body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&response.body);
            let _ = stream.flush();
        }
    });

    format!("http://127.0.0.1:{port}")
}

/// Write a minimal valid pack directory at `dir` with the given name/version
/// and author handle. Ported from `frameshift-server/tests/publish.rs`.
fn write_pack(dir: &std::path::Path, name: &str, version: &str, handle: &str) {
    let manifest = format!(
        "schema_version = 1\nname = \"{name}\"\nauthor_handle = \"{handle}\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"{version}\"\nlicense = \"MIT\"\n"
    );
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("pack.toml"), manifest).unwrap();
    std::fs::write(dir.join("README.md"), b"# test pack\n").unwrap();
}

/// Pack a directory tree into a gzipped tar archive, root-flat (no top-level
/// directory entry), matching the layout `fetch_and_install`'s
/// `find_pack_root` expects. Ported from `frameshift-server/tests/publish.rs`.
fn make_targz(dir: &std::path::Path) -> Vec<u8> {
    let buf: Vec<u8> = Vec::new();
    let enc = GzEncoder::new(buf, Compression::default());
    let mut tar = tar::Builder::new(enc);
    tar.append_dir_all(".", dir).unwrap();
    let enc = tar.into_inner().unwrap();
    enc.finish().unwrap()
}

/// A fully prepared signed-pack fixture for registry-install tests.
///
/// Bundles the gzipped tar bytes served at the `/pack` endpoint together with
/// the real server-canonical `PackVersionRecord` describing them, so tests
/// can tamper with individual record fields (`content_hash`, `signature`)
/// before serializing to JSON for the mock server.
struct Fixture {
    /// The gzipped tar archive bytes (served at the `.../pack` endpoint).
    targz: Vec<u8>,
    /// The real `frameshift_catalog::PackVersionRecord` describing `targz`,
    /// signed by the fixture's `signing` key over the pack's canonical hash.
    record: PackVersionRecord,
    /// Hex canonical hash of the pack contents (matches `LockedPersona.hash`).
    canonical_hash: String,
}

/// Build a real, signed pack fixture: writes a minimal pack directory, signs
/// its canonical hash with `signing`, packs it into a `.tar.gz`, and builds
/// the real server-side `PackVersionRecord` (Active status) describing it.
///
/// Using the actual `frameshift_catalog::PackVersionRecord` type (rather than
/// a hand-rolled JSON string) means a future rename/reshape of the server's
/// wire type breaks this test at compile time.
fn prepare_signed_fixture(name: &str, version: &str, signing: &SigningKey) -> Fixture {
    let tmp = tempfile::TempDir::new().unwrap();
    write_pack(tmp.path(), name, version, "alice");

    let pack = Pack::from_dir(tmp.path()).unwrap();
    let canonical_hash_bytes = pack.canonical_hash();
    let signature = signing.sign(&canonical_hash_bytes).to_bytes().to_vec();

    let targz = make_targz(tmp.path());
    let content_hash = ObjectHash::of(&targz);

    let record = PackVersionRecord {
        pack_name: name.to_string(),
        version: version.to_string(),
        content_hash,
        signature,
        author_pubkey: Ed25519PublicKey(signing.verifying_key().to_bytes()),
        parent_hash: None,
        capability_manifest_json: "{}".to_string(),
        schema_version: 1,
        license: "MIT".to_string(),
        published_at: Utc::now(),
        status: PackStatus::Active,
        size_bytes: targz.len() as u64,
    };

    Fixture {
        targz,
        record,
        canonical_hash: pack.canonical_hash_hex(),
    }
}

/// The env var `registry_base_url()` reads to override the registry base URL.
/// Mirrors `frameshift_client::registry::REGISTRY_URL_ENV`, which is private
/// to the crate and not re-exported, so the literal is duplicated here.
const REGISTRY_URL_ENV: &str = "FRAMESHIFT_REGISTRY_URL";

/// Serializes all environment-variable mutation across tests in this binary.
/// Cargo runs tests on multiple threads but the process environment is
/// global, so two tests that set and read `FRAMESHIFT_REGISTRY_URL`
/// concurrently would race. Every `EnvGuard` holds this lock for its
/// lifetime, ensuring only one env-mutating test runs at a time. Ported from
/// `src/registry.rs`'s test module (private there, so duplicated here).
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard that sets `FRAMESHIFT_REGISTRY_URL` and restores/removes it on
/// drop, holding [`ENV_LOCK`] for the guard's lifetime.
struct EnvGuard {
    /// Original value, or `None` if the var was not set.
    original: Option<String>,
    /// Held for the guard's lifetime to serialize env access across threads.
    /// Declared last so it is released only after `Drop` restores the variable.
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    /// Set `FRAMESHIFT_REGISTRY_URL` to `value`, remembering the original
    /// value (if any) for restoration on drop.
    fn set(value: &str) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let original = std::env::var(REGISTRY_URL_ENV).ok();
        // SAFETY: ENV_LOCK serializes all env mutation in this test binary.
        unsafe { std::env::set_var(REGISTRY_URL_ENV, value) };
        Self {
            original,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    /// Restore `FRAMESHIFT_REGISTRY_URL` to its pre-guard state.
    fn drop(&mut self) {
        // SAFETY: ENV_LOCK (held by this guard) serializes env mutation.
        unsafe {
            match &self.original {
                Some(v) => std::env::set_var(REGISTRY_URL_ENV, v),
                None => std::env::remove_var(REGISTRY_URL_ENV),
            }
        }
    }
}

/// Build a `Client` rooted at a fresh temp data directory, and a project root
/// directory under the same temp dir (created, since `install` requires it to
/// exist).
fn test_client_and_project(temp: &tempfile::TempDir) -> (Client, std::path::PathBuf) {
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    std::fs::create_dir_all(&project_root).unwrap();
    let client = Client::new(ClientOptions {
        data_root,
        config_root: None,
    });
    (client, project_root)
}

/// 200 JSON response wrapping a serialized `PackVersionRecord`.
fn record_response(record: &PackVersionRecord) -> MockResponse {
    MockResponse {
        status: 200,
        content_type: "application/json",
        body: serde_json::to_vec(record).unwrap(),
    }
}

/// 200 raw-bytes response for the pack archive endpoint.
fn pack_response(bytes: Vec<u8>) -> MockResponse {
    MockResponse {
        status: 200,
        content_type: "application/gzip",
        body: bytes,
    }
}

/// 404 response for an unknown path.
fn not_found_response() -> MockResponse {
    MockResponse {
        status: 404,
        content_type: "text/plain",
        body: b"not found".to_vec(),
    }
}

/// Happy path: `Client::install` with `InstallSource::Registry` against a
/// mock server that serves a valid, correctly signed pack succeeds end to
/// end -- the report's persona fields match the fixture, the cache entry is
/// materialized on disk, the lockfile records the persona, and the persona's
/// source directory is materialized under the project's central store.
#[test]
fn registry_install_happy_path() {
    let signing = SigningKey::from_bytes(&[3u8; 32]);
    let fixture = prepare_signed_fixture("demo-pack", "1.0.0", &signing);

    let mut routes = HashMap::new();
    routes.insert(
        "/v1/packs/demo-pack/versions/1.0.0".to_string(),
        record_response(&fixture.record),
    );
    routes.insert(
        "/v1/packs/demo-pack/versions/1.0.0/pack".to_string(),
        pack_response(fixture.targz.clone()),
    );
    let base = spawn_registry(routes);
    let _env = EnvGuard::set(&base);

    let temp = tempfile::tempdir().unwrap();
    let (client, project_root) = test_client_and_project(&temp);

    let report = client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "demo-pack".to_string(),
                version: "1.0.0".to_string(),
            },
            source: InstallSource::Registry,
        })
        .expect("registry install should succeed");

    assert_eq!(report.persona.name, "demo-pack");
    assert_eq!(report.persona.version, "1.0.0");
    assert_eq!(report.persona.hash, fixture.canonical_hash);

    // The pack must be materialized in the content-addressed cache.
    assert!(
        report.cache_path.join("pack.toml").is_file(),
        "cache_path/pack.toml must exist after install"
    );

    // The lockfile must record the persona.
    let paths = client.project_paths(&project_root).unwrap();
    let lock_raw = std::fs::read_to_string(&paths.lock_path).unwrap();
    assert!(
        lock_raw.contains("demo-pack"),
        "lock.toml must reference the installed persona: {lock_raw}"
    );

    // The persona source must be materialized into the project's central store.
    let source_manifest = paths
        .personas_dir
        .join("demo-pack")
        .join("source/pack.toml");
    assert!(
        source_manifest.is_file(),
        "personas/demo-pack/source/pack.toml must be materialized"
    );
}

/// A content-hash mismatch (advertised `content_hash` in the version record
/// does not match `SHA-256` of the actual downloaded archive bytes) is
/// rejected with `ClientError::ContentHashMismatch`, and nothing is cached.
#[test]
fn registry_install_rejects_content_hash_mismatch() {
    let signing = SigningKey::from_bytes(&[4u8; 32]);
    let mut fixture = prepare_signed_fixture("demo-pack", "1.0.0", &signing);
    // Advertise a hash that does not match the served archive bytes.
    fixture.record.content_hash = ObjectHash::of(b"totally different bytes");

    let mut routes = HashMap::new();
    routes.insert(
        "/v1/packs/demo-pack/versions/1.0.0".to_string(),
        record_response(&fixture.record),
    );
    routes.insert(
        "/v1/packs/demo-pack/versions/1.0.0/pack".to_string(),
        pack_response(fixture.targz.clone()),
    );
    let base = spawn_registry(routes);
    let _env = EnvGuard::set(&base);

    let temp = tempfile::tempdir().unwrap();
    let (client, project_root) = test_client_and_project(&temp);

    let err = client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "demo-pack".to_string(),
                version: "1.0.0".to_string(),
            },
            source: InstallSource::Registry,
        })
        .expect_err("hash-mismatched archive must be rejected");

    assert!(
        matches!(
            err,
            frameshift_client::ClientError::ContentHashMismatch { .. }
        ),
        "expected ContentHashMismatch, got {err:?}"
    );

    // Nothing should have been cached.
    let paths = client.project_paths(&project_root).unwrap();
    assert!(
        !paths.cache_dir.join(&fixture.canonical_hash).exists(),
        "no cache entry should exist after a hash-mismatch rejection"
    );
}

/// A version record whose `signature` does not verify against
/// `author_pubkey` (signed by a different key) is rejected with
/// `ClientError::SignatureVerification`, and nothing is cached.
#[test]
fn registry_install_rejects_bad_signature() {
    let signing = SigningKey::from_bytes(&[5u8; 32]);
    let mut fixture = prepare_signed_fixture("demo-pack", "1.0.0", &signing);

    // Replace the signature with one from a different key entirely -- the
    // record's `author_pubkey` still belongs to `signing`, so verification
    // against the mismatched signature must fail.
    let wrong_key = SigningKey::from_bytes(&[6u8; 32]);
    fixture.record.signature = wrong_key.sign(b"not the real message").to_bytes().to_vec();

    let mut routes = HashMap::new();
    routes.insert(
        "/v1/packs/demo-pack/versions/1.0.0".to_string(),
        record_response(&fixture.record),
    );
    routes.insert(
        "/v1/packs/demo-pack/versions/1.0.0/pack".to_string(),
        pack_response(fixture.targz.clone()),
    );
    let base = spawn_registry(routes);
    let _env = EnvGuard::set(&base);

    let temp = tempfile::tempdir().unwrap();
    let (client, project_root) = test_client_and_project(&temp);

    let err = client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "demo-pack".to_string(),
                version: "1.0.0".to_string(),
            },
            source: InstallSource::Registry,
        })
        .expect_err("bad signature must be rejected");

    assert!(
        matches!(err, frameshift_client::ClientError::SignatureVerification),
        "expected SignatureVerification, got {err:?}"
    );

    let paths = client.project_paths(&project_root).unwrap();
    assert!(
        !paths.cache_dir.join(&fixture.canonical_hash).exists(),
        "no cache entry should exist after a bad-signature rejection"
    );
}

/// Two 404 sub-cases against the registry:
///
/// 1. The version record resolves (200), but the pack archive endpoint 404s
///    (e.g. a tombstoned or since-deleted object) -> `ClientError::RegistryHttp`
///    whose `url` ends in `/pack`.
/// 2. The version record endpoint itself 404s (an unknown/unpublished
///    version) -> `ClientError::RegistryHttp` whose `url` is the record URL.
#[test]
fn registry_install_tombstoned_pack_404() {
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let fixture = prepare_signed_fixture("demo-pack", "1.0.0", &signing);

    // Sub-case 1: record resolves, archive endpoint 404s.
    let mut routes = HashMap::new();
    routes.insert(
        "/v1/packs/demo-pack/versions/1.0.0".to_string(),
        record_response(&fixture.record),
    );
    routes.insert(
        "/v1/packs/demo-pack/versions/1.0.0/pack".to_string(),
        not_found_response(),
    );
    let base = spawn_registry(routes);
    let _env = EnvGuard::set(&base);

    let temp = tempfile::tempdir().unwrap();
    let (client, project_root) = test_client_and_project(&temp);

    let err = client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "demo-pack".to_string(),
                version: "1.0.0".to_string(),
            },
            source: InstallSource::Registry,
        })
        .expect_err("404 on the pack archive endpoint must be rejected");

    match err {
        frameshift_client::ClientError::RegistryHttp { url, .. } => {
            assert!(url.ends_with("/pack"), "expected .../pack URL, got {url}");
        }
        other => panic!("expected RegistryHttp, got {other:?}"),
    }
    drop(_env);

    // Sub-case 2: an unpublished version -- the record endpoint itself 404s.
    let base2 = spawn_registry(HashMap::new());
    let _env2 = EnvGuard::set(&base2);

    let temp2 = tempfile::tempdir().unwrap();
    let (client2, project_root2) = test_client_and_project(&temp2);

    let err2 = client2
        .install(InstallRequest {
            project_root: project_root2,
            spec: PersonaSpec {
                name: "demo-pack".to_string(),
                version: "9.9.9".to_string(),
            },
            source: InstallSource::Registry,
        })
        .expect_err("404 on the version-record endpoint must be rejected");

    match err2 {
        frameshift_client::ClientError::RegistryHttp { url, .. } => {
            assert!(
                url.ends_with("/v1/packs/demo-pack/versions/9.9.9"),
                "expected the record URL, got {url}"
            );
        }
        other => panic!("expected RegistryHttp, got {other:?}"),
    }
}
