//! HTTP registry publish: pack, sign, and upload.
//!
//! Provides [`publish_pack_dir`] and [`register_author`], the client-side
//! counterparts to the server's `POST /v1/packs` and `POST /v1/authors`
//! endpoints. Both construct the Ed25519 signed-request envelope verified by
//! `frameshift_server::auth`, and both are fully synchronous (blocking `ureq`)
//! so this crate stays free of a tokio runtime -- matching [`crate::registry`].
//!
//! # Author key
//!
//! The author's Ed25519 signing key is a managed file in the central data root
//! ([`load_or_create_signing_key`]): a raw 32-byte seed at
//! `identity/ed25519-signing-key.bin`, `0o600`, created on first use. This
//! mirrors the proven `frameshift-seed` key handling; the age vault schema
//! cannot hold a private signing key, so a dedicated file is used instead.
//!
//! # Publish flow
//!
//! 1. Load the [`Pack`] from `pack_dir` (must contain `pack.toml`).
//! 2. Sign the pack's canonical hash -> the 64-byte `signature` field.
//! 3. Pack the directory into a gzipped tar (excluding `signature.sig`).
//! 4. Build a `multipart/form-data` body (`pack`, `signature`, `author_handle`).
//! 5. Sign the request envelope over `POST /v1/packs` + the body hash.
//! 6. `POST` and parse the [`PublishOutcome`].

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use frameshift_pack::Pack;
use rand_core::{OsRng, RngCore as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::ClientError;

/// Domain-separation prefix for the signed-request envelope.
///
/// MUST match `frameshift_server::auth::SIGNING_DOMAIN`. The pack-content
/// signature (over the canonical hash) carries no such prefix, so a captured
/// pack signature can never be replayed as a request signature and vice versa.
const SIGNING_DOMAIN: &str = "frameshift-signed-request/v1";

/// Relative path of the managed author signing key within the central data root.
const SIGNING_KEY_REL: &str = "identity/ed25519-signing-key.bin";

/// Outcome of a successful publish, deserialized from the server's
/// `PublishResponse` JSON body.
#[derive(Debug, Clone, Deserialize)]
pub struct PublishOutcome {
    /// Canonical SHA-256 hash of the published pack (hex), independent of archive encoding.
    pub pack_hash: String,
    /// The pack name, echoed from the manifest.
    pub name: String,
    /// The pack version string, echoed from the manifest.
    pub version: String,
    /// The handle of the author the pack was published under.
    pub author_handle: String,
}

/// Load the author's Ed25519 signing key from the central data root, creating
/// and persisting a fresh key (`0o600`) on first use.
///
/// The key is a raw 32-byte seed. A file of any other length is a hard error
/// rather than a silently regenerated key, so a corrupt or truncated key never
/// masquerades as a new identity.
pub fn load_or_create_signing_key(data_root: &Path) -> Result<SigningKey, ClientError> {
    let path = data_root.join(SIGNING_KEY_REL);
    match fs::symlink_metadata(&path) {
        Ok(_) => return load_existing_signing_key(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ClientError::Io {
                path: path.clone(),
                source,
            });
        }
    }

    // First use: generate and persist atomically. `create_new` fails if the
    // file already exists, which closes the check-then-write race -- two
    // concurrent first-use callers can no longer each write a different key and
    // let "last write win" (which would silently change the author identity).
    // On Unix the 0o600 mode is applied at open() time, so the secret seed is
    // never world-readable even for an instant. If another process wins the
    // race (AlreadyExists), we load and use the key it persisted.
    let key = SigningKey::generate(&mut OsRng);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ClientError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let mut open_opts = fs::OpenOptions::new();
    open_opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        open_opts.mode(0o600);
    }

    match open_opts.open(&path) {
        Ok(mut file) => {
            use std::io::Write as _;
            file.write_all(&key.to_bytes())
                .map_err(|source| ClientError::Io {
                    path: path.clone(),
                    source,
                })?;
            Ok(key)
        }
        // Another process created the key between our `exists` check and here;
        // adopt the winner's key so the author identity stays stable.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => load_existing_signing_key(&path),
        Err(source) => Err(ClientError::Io {
            path: path.clone(),
            source,
        }),
    }
}

/// Load a regular signing-key file without following symlinks.
fn load_existing_signing_key(path: &Path) -> Result<SigningKey, ClientError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClientError::InvalidSigningKey {
            path: path.to_path_buf(),
            detail: "key path is not a regular file".to_string(),
        });
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| ClientError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }
    use std::io::Read as _;
    let mut bytes = Vec::with_capacity(33);
    file.take(33)
        .read_to_end(&mut bytes)
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let seed: [u8; 32] =
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| ClientError::InvalidSigningKey {
                path: path.to_path_buf(),
                detail: format!("expected 32-byte seed, found {} bytes", bytes.len()),
            })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The base64url-no-pad public key string for a signing key, matching the
/// `Ed25519PublicKey` wire encoding the server registers and looks up.
pub fn public_key_b64(key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
}

/// The lowercase-hex public key string used in synthesized `pack.toml`
/// manifests (informational; the catalog binds handles to typed keys).
pub fn public_key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

/// Register the managed author key under `handle` at the registry.
///
/// Sends a signed `POST /v1/authors` with a JSON body `{handle, display_name?}`.
/// The server takes the public key from the verified request signer, so this
/// claims `handle` for the local managed key. A `409` means the handle is taken
/// by another key (or this key already owns a different handle).
pub fn register_author(
    server_url: &str,
    key: &SigningKey,
    handle: &str,
    display_name: Option<&str>,
) -> Result<(), ClientError> {
    let body_value = serde_json::json!({
        "handle": handle,
        "display_name": display_name,
    });
    let body =
        serde_json::to_vec(&body_value).map_err(|e| ClientError::JsonSerialize(e.to_string()))?;

    let base = server_url.trim_end_matches('/');
    let url = format!("{base}/v1/authors");
    let headers = signed_headers(key, "POST", "/v1/authors", &body);

    let mut req = crate::registry::http_agent()
        .post(&url)
        .set("Content-Type", "application/json");
    for header in &headers {
        req = req.set(header.name, &header.value);
    }
    send_signed(req, &url, &body).map(|_| ())
}

/// Pack, sign, and upload `pack_dir` to the registry under `author_handle`.
///
/// `pack_dir` must contain a `pack.toml` manifest. `key` produces both the
/// pack-content signature (over the canonical hash) and the request envelope.
pub fn publish_pack_dir(
    server_url: &str,
    key: &SigningKey,
    pack_dir: &Path,
    author_handle: &str,
) -> Result<PublishOutcome, ClientError> {
    // Load the pack and sign its canonical hash. We sign the hash directly
    // rather than via Pack::sign so the on-disk pack directory is not mutated
    // (no signature.sig is written into the source the caller owns).
    let pack = Pack::from_dir(pack_dir)?;

    // Unsigned local packs (author_pubkey sentinel) must never reach the
    // registry: refuse before signing or any network activity so the caller
    // gets a typed, actionable error instead of a server rejection.
    if pack.manifest().is_local_unsigned() {
        return Err(ClientError::PublishLocalUnsigned {
            name: pack.manifest().name.clone(),
        });
    }

    let signature = key.sign(&pack.canonical_hash()).to_bytes();

    // Build the gzipped tar archive of the pack contents.
    let pack_targz = targz_dir(pack_dir)?;

    // Assemble the multipart body and sign the request over it.
    let (boundary, body) = build_publish_multipart(&pack_targz, &signature, author_handle);
    let base = server_url.trim_end_matches('/');
    let url = format!("{base}/v1/packs");
    let headers = signed_headers(key, "POST", "/v1/packs", &body);
    let content_type = format!("multipart/form-data; boundary={boundary}");

    let mut req = crate::registry::http_agent()
        .post(&url)
        .set("Content-Type", &content_type);
    for header in &headers {
        req = req.set(header.name, &header.value);
    }
    let response = send_signed(req, &url, &body)?;

    crate::registry::response_json_bounded::<PublishOutcome>(response, &url)
}

/// Send a prepared signed request body, mapping non-2xx statuses to
/// [`ClientError::RegistryRejected`] (with the status code preserved) and
/// transport errors to [`ClientError::RegistryHttp`].
fn send_signed(req: ureq::Request, url: &str, body: &[u8]) -> Result<ureq::Response, ClientError> {
    match req.send_bytes(body) {
        Ok(response) => Ok(response),
        Err(ureq::Error::Status(status, response)) => {
            let message = crate::registry::response_text_bounded(response, url);
            Err(ClientError::RegistryRejected {
                url: url.to_string(),
                status,
                message,
            })
        }
        Err(err) => Err(ClientError::RegistryHttp {
            url: url.to_string(),
            detail: err.to_string(),
        }),
    }
}

/// One signed-request header: a static name plus the computed value.
struct SignedHeader {
    /// Lowercase header name (e.g. `x-frameshift-pubkey`).
    name: &'static str,
    /// The header value.
    value: String,
}

/// Build the four `X-Frameshift-*` signed-request headers for `key` over
/// `(method, path, body)`, using the current wall clock and a fresh nonce.
///
/// The signature covers `<DOMAIN>\n<METHOD>\n<PATH>\n<hex(sha256(body))>\n
/// <TIMESTAMP>\n<NONCE>`, exactly the string `frameshift_server::auth` rebuilds
/// and verifies.
fn signed_headers(key: &SigningKey, method: &str, path: &str, body: &[u8]) -> Vec<SignedHeader> {
    let timestamp = unix_now();
    let nonce = fresh_nonce();
    let body_hex = hex::encode(Sha256::digest(body));
    let message = format!("{SIGNING_DOMAIN}\n{method}\n{path}\n{body_hex}\n{timestamp}\n{nonce}");
    let signature = key.sign(message.as_bytes());

    vec![
        SignedHeader {
            name: "x-frameshift-pubkey",
            value: public_key_b64(key),
        },
        SignedHeader {
            name: "x-frameshift-timestamp",
            value: timestamp.to_string(),
        },
        SignedHeader {
            name: "x-frameshift-nonce",
            value: nonce,
        },
        SignedHeader {
            name: "x-frameshift-signature",
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    ]
}

/// Current Unix time in whole seconds (matching the server's timestamp units).
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A fresh per-request nonce: 16 random bytes as base64url-no-pad (~22 chars,
/// within the server's 8..=128 length bound).
fn fresh_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Build a `multipart/form-data` body (and its boundary) for the publish upload.
///
/// Fields, in order: `pack` (the gzipped tar), `signature` (the raw 64-byte
/// Ed25519 signature), and `author_handle` (UTF-8 text). The boundary is
/// randomized so it cannot collide with the binary field contents.
fn build_publish_multipart(
    pack_targz: &[u8],
    signature: &[u8; 64],
    author_handle: &str,
) -> (String, Vec<u8>) {
    let mut boundary_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut boundary_bytes);
    let boundary = format!("frameshiftBoundary{}", hex::encode(boundary_bytes));

    let mut body = Vec::new();
    // pack field.
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"pack\"; filename=\"pack.tar.gz\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/gzip\r\n\r\n");
    body.extend_from_slice(pack_targz);
    body.extend_from_slice(b"\r\n");
    // signature field.
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"signature\"; filename=\"signature.bin\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(signature);
    body.extend_from_slice(b"\r\n");
    // author_handle field.
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"author_handle\"\r\n\r\n");
    body.extend_from_slice(author_handle.as_bytes());
    body.extend_from_slice(b"\r\n");
    // Closing boundary.
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    (boundary, body)
}

/// Pack a directory into a gzipped tar archive held in memory.
///
/// Files are added at the archive root so the server's `find_pack_root` locates
/// `pack.toml` at the top level. `signature.sig` is never included (the
/// signature travels in its own multipart field), and non-regular files
/// (symlinks, devices) are skipped.
fn targz_dir(dir: &Path) -> Result<Vec<u8>, ClientError> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append_dir_files(&mut builder, dir, dir)?;

    let encoder = builder.into_inner().map_err(|source| ClientError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    encoder.finish().map_err(|source| ClientError::Io {
        path: dir.to_path_buf(),
        source,
    })
}

/// Recursively append regular files under `current` to `builder`, keyed by
/// their path relative to `base`. Skips `signature.sig` and non-files.
fn append_dir_files<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    base: &Path,
    current: &Path,
) -> Result<(), ClientError> {
    let entries = fs::read_dir(current).map_err(|source| ClientError::Io {
        path: current.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ClientError::Io {
            path: current.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| ClientError::Io {
            path: path.clone(),
            source,
        })?;

        if file_type.is_dir() {
            append_dir_files(builder, base, &path)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let rel = path.strip_prefix(base).unwrap_or(&path);
        if rel.to_string_lossy() == "signature.sig" {
            continue;
        }
        builder
            .append_path_with_name(&path, rel)
            .map_err(|source| ClientError::Io {
                path: path.clone(),
                source,
            })?;
    }
    Ok(())
}

#[cfg(test)]
/// Unit and transport tests for signing and publishing.
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier as _, VerifyingKey};
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::net::TcpListener;

    /// A deterministic signing key for tests.
    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// load_or_create persists a 32-byte key and reloads it identically.
    #[test]
    fn signing_key_load_or_create_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_signing_key(dir.path()).unwrap();
        let key_path = dir.path().join(SIGNING_KEY_REL);
        assert!(key_path.is_file(), "key file must be created");
        assert_eq!(fs::read(&key_path).unwrap().len(), 32, "raw 32-byte seed");

        let second = load_or_create_signing_key(dir.path()).unwrap();
        assert_eq!(
            first.to_bytes(),
            second.to_bytes(),
            "reload must return the same key"
        );
    }

    /// A pack still carrying the local-unsigned author_pubkey sentinel must be
    /// refused before signing or any network activity, with a typed error.
    #[test]
    fn publish_rejects_local_unsigned_pack() {
        let dir = tempfile::tempdir().unwrap();
        let pack_dir = dir.path().join("pack");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(
            pack_dir.join("pack.toml"),
            b"schema_version = 1\nname = \"legacy\"\nauthor_handle = \"local\"\nauthor_pubkey = \"local-unsigned\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(pack_dir.join("AGENTS.md"), b"# legacy\n").unwrap();

        // Unroutable URL: if the guard is missing, the failure mode would be a
        // network error instead of the typed rejection this asserts on.
        let err = publish_pack_dir("http://127.0.0.1:1", &test_key(), &pack_dir, "local")
            .expect_err("sentinel pack must not publish");
        assert!(
            matches!(err, ClientError::PublishLocalUnsigned { ref name } if name == "legacy"),
            "expected PublishLocalUnsigned, got: {err:?}"
        );
    }

    /// A corrupt (wrong-length) key file is an error, not a silent regeneration.
    #[test]
    fn signing_key_wrong_length_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(SIGNING_KEY_REL);
        fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        fs::write(&key_path, b"too short").unwrap();

        let err = load_or_create_signing_key(dir.path()).unwrap_err();
        assert!(matches!(err, ClientError::InvalidSigningKey { .. }));
    }

    /// Existing signing-key symlinks are rejected rather than followed.
    #[cfg(unix)]
    #[test]
    fn signing_key_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target-key");
        fs::write(&target, [9u8; 32]).unwrap();
        let key_path = dir.path().join(SIGNING_KEY_REL);
        fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        symlink(&target, &key_path).unwrap();

        assert!(matches!(
            load_or_create_signing_key(dir.path()),
            Err(ClientError::InvalidSigningKey { .. })
        ));
    }

    /// The signed-request envelope reproduces the exact server signing string and
    /// verifies against the signer's public key -- the real wire-compat check.
    #[test]
    fn signed_headers_match_server_signing_string() {
        let key = test_key();
        let body = b"hello body bytes";
        let headers = signed_headers(&key, "POST", "/v1/packs", body);

        // Pull the four header values back out.
        let get = |name: &str| {
            headers
                .iter()
                .find(|h| h.name == name)
                .map(|h| h.value.clone())
                .unwrap()
        };
        let pubkey_b64 = get("x-frameshift-pubkey");
        let timestamp = get("x-frameshift-timestamp");
        let nonce = get("x-frameshift-nonce");
        let sig_b64 = get("x-frameshift-signature");

        // Reconstruct the signing string exactly as the server does.
        let body_hex = hex::encode(Sha256::digest(body));
        let message =
            format!("{SIGNING_DOMAIN}\nPOST\n/v1/packs\n{body_hex}\n{timestamp}\n{nonce}");

        // Decode pubkey + signature and verify.
        let pk_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&pubkey_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(pk_bytes, key.verifying_key().to_bytes());
        let verifying = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&sig_b64)
            .unwrap()
            .try_into()
            .unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying
            .verify(message.as_bytes(), &signature)
            .expect("server-format signature must verify");

        // Nonce length is within the server's 8..=128 bound.
        assert!((8..=128).contains(&nonce.len()));
    }

    /// The multipart body contains all three required field names and the
    /// boundary delimiters.
    #[test]
    fn multipart_contains_all_fields() {
        let (boundary, body) = build_publish_multipart(b"PACKBYTES", &[9u8; 64], "alice");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains(&format!("--{boundary}")));
        assert!(text.contains("name=\"pack\""));
        assert!(text.contains("name=\"signature\""));
        assert!(text.contains("name=\"author_handle\""));
        assert!(text.contains("alice"));
        assert!(text.contains(&format!("--{boundary}--")));
    }

    /// End-to-end: publish_pack_dir performs a real HTTP round-trip whose signed
    /// envelope verifies against the exact bytes on the wire, and whose response
    /// parses into a PublishOutcome.
    ///
    /// A throwaway TCP server captures the request, reconstructs the server's
    /// signing string from the actual body, verifies the Ed25519 signature, and
    /// replies with a PublishResponse JSON.
    #[test]
    fn publish_pack_dir_sends_server_verifiable_request() {
        // A pack directory with a manifest and one content file.
        let pack = tempfile::tempdir().unwrap();
        fs::write(
            pack.path().join("pack.toml"),
            b"schema_version = 1\nname = \"demo\"\nauthor_handle = \"alice\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(pack.path().join("README.md"), b"hello").unwrap();

        let key = test_key();

        // Bind an ephemeral port and hand the handler thread everything it needs.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());

            // Read the request line + headers.
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut content_length = 0usize;
            let mut hdr = std::collections::HashMap::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    let name = name.trim().to_ascii_lowercase();
                    let value = value.trim().to_string();
                    if name == "content-length" {
                        content_length = value.parse().unwrap();
                    }
                    hdr.insert(name, value);
                }
            }

            // Read exactly Content-Length body bytes.
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();

            // Reconstruct the signing string and verify the envelope signature.
            let timestamp = hdr.get("x-frameshift-timestamp").unwrap();
            let nonce = hdr.get("x-frameshift-nonce").unwrap();
            let body_hex = hex::encode(Sha256::digest(&body));
            let message =
                format!("{SIGNING_DOMAIN}\nPOST\n/v1/packs\n{body_hex}\n{timestamp}\n{nonce}");
            let pk_bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(hdr.get("x-frameshift-pubkey").unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let verifying = VerifyingKey::from_bytes(&pk_bytes).unwrap();
            let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
                .decode(hdr.get("x-frameshift-signature").unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            let envelope_ok = verifying.verify(message.as_bytes(), &sig).is_ok();

            // Confirm the multipart fields are present in the body.
            let body_text = String::from_utf8_lossy(&body);
            let fields_ok = body_text.contains("name=\"pack\"")
                && body_text.contains("name=\"signature\"")
                && body_text.contains("name=\"author_handle\"");

            // Respond with a PublishResponse JSON.
            let json =
                r#"{"pack_hash":"abc123","name":"demo","version":"0.1.0","author_handle":"alice"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json.len(),
                json
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();

            (envelope_ok, fields_ok)
        });

        let url = format!("http://127.0.0.1:{port}");
        let outcome = publish_pack_dir(&url, &key, pack.path(), "alice").unwrap();
        assert_eq!(outcome.name, "demo");
        assert_eq!(outcome.version, "0.1.0");
        assert_eq!(outcome.author_handle, "alice");
        assert_eq!(outcome.pack_hash, "abc123");

        let (envelope_ok, fields_ok) = handle.join().unwrap();
        assert!(
            envelope_ok,
            "signed-request envelope must verify on the server side"
        );
        assert!(
            fields_ok,
            "all three multipart fields must reach the server"
        );
    }
}
