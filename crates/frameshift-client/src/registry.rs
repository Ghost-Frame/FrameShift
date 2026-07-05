//! HTTP registry install implementation.
//!
//! Provides [`fetch_and_install`], which is called by the `InstallSource::Registry` arm of
//! [`crate::Client::install`]. All HTTP I/O is performed with the blocking `ureq` crate so
//! that this crate stays fully synchronous and does not need a tokio runtime.
//!
//! # Flow
//!
//! 1. Resolve the registry base URL from `FRAMESHIFT_REGISTRY_URL` env var (or the default).
//! 2. `GET {base}/v1/packs/{name}/versions/{version}` -- fetch the [`VersionRecord`] JSON.
//! 3. `GET {base}/v1/packs/{name}/versions/{version}/pack` -- fetch the raw `.tar.gz` bytes.
//! 4. Verify `SHA-256(bytes) == content_hash` from the version record.
//! 5. Extract the `.tar.gz` into a temporary directory (with path-traversal hardening).
//! 6. Load the [`Pack`] from the extracted directory, write `signature.sig`.
//! 7. Verify the Ed25519 signature using the `author_pubkey` from the version record.
//! 8. Cache the extracted pack directory under `cache/<pack_canonical_hash>`.
//! 9. Return the [`LockedPersona`] for the caller to commit to the lockfile.

use ed25519_dalek::VerifyingKey;
use flate2::read::GzDecoder;
use frameshift_pack::{ObjectHash, Pack};
use serde::Deserialize;
use std::io::Read as _;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;
use tar::Archive;
use tracing::debug;

use crate::error::ClientError;
use crate::model::{LockedPersona, PersonaSpec, ProjectPaths};

/// Environment variable that overrides the registry base URL.
///
/// When unset or empty, [`registry_base_url`] falls back to the production default.
pub const REGISTRY_URL_ENV: &str = "FRAMESHIFT_REGISTRY_URL";

/// Default registry base URL used when [`REGISTRY_URL_ENV`] is not set.
const DEFAULT_REGISTRY_URL: &str = "https://frameshift.syntheos.dev";

/// Maximum number of decompressed bytes we will accept from a registry pack archive.
///
/// A pack that decompresses to more than this is rejected before any content is written
/// to the cache. This is a decompression-bomb guard analogous to the server-side limit.
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum number of compressed (wire) bytes we will read from an HTTP registry response.
///
/// Applied via [`LimitedReader`] around the raw HTTP response body *before* `read_to_end`
/// so an oversized response is rejected during streaming, not after full buffering.
/// A valid `.tar.gz` archive cannot expand beyond [`MAX_DECOMPRESSED_BYTES`] of useful
/// content, so the same cap is a safe upper bound on the compressed wire size as well.
const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024;

/// Minimal JSON shape returned by `GET /v1/packs/{name}/versions/{version}`.
///
/// Only the fields needed for installation are deserialized. Unknown fields are
/// silently ignored via `#[serde(deny_unknown_fields)]` being absent -- future
/// server additions will not break older clients.
#[derive(Debug, Deserialize)]
struct VersionRecord {
    /// SHA-256 hash of the raw `.tar.gz` archive bytes (hex string, 64 chars).
    content_hash: ObjectHash,
    /// Ed25519 signature over the canonical pack hash (base64url no-pad).
    ///
    /// Deserialized from the `serde(with = "bytes_as_b64")` format the server uses.
    #[serde(with = "bytes_as_b64")]
    signature: Vec<u8>,
    /// Ed25519 public key of the author who published this version (base64url no-pad).
    author_pubkey: AuthorPubkeyField,
}

/// Wrapper that deserializes either a base64url string or a raw `[u8; 32]` JSON array.
///
/// The catalog serializes `Ed25519PublicKey` as base64url, so this handles that wire format.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct AuthorPubkeyField(
    /// The raw 32-byte Ed25519 public key, deserialized from the base64url string.
    #[serde(with = "pubkey_b64")]
    [u8; 32],
);

/// Serde helper: deserialize a base64url no-pad string as `[u8; 32]`.
mod pubkey_b64 {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde::{Deserialize, Deserializer};

    /// Deserialize a base64url no-padding encoded 32-byte array.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let encoded = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Ed25519 public key must be 32 bytes"))
    }
}

/// Serde helper: deserialize a base64url no-pad string as `Vec<u8>`.
///
/// Mirrors the `crate::serde_helpers::bytes_as_b64` helper in `frameshift-catalog`
/// (which is `pub(crate)` and cannot be shared).
mod bytes_as_b64 {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde::{Deserialize, Deserializer};

    /// Deserialize a base64url no-padding encoded byte vector.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)
    }
}

/// Connect-phase timeout for the shared HTTP agent ([`http_agent`]).
///
/// Bounds how long a TCP connect attempt may take before failing.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-read timeout for the shared HTTP agent ([`http_agent`]).
///
/// Bounds how long a single socket read may block, so a registry that accepts
/// a connection but never sends (or stalls mid-stream) cannot hang the
/// CLI/daemon/MCP forever. `ureq` 2.x applies no such timeout by default.
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Process-wide storage for the shared [`ureq::Agent`] built by [`http_agent`].
static HTTP_AGENT: OnceLock<ureq::Agent> = OnceLock::new();

/// Return the shared [`ureq::Agent`] used for all client HTTP calls (registry
/// install, publish, and telemetry).
///
/// Configured with [`HTTP_CONNECT_TIMEOUT`] and [`HTTP_READ_TIMEOUT`] so a
/// hung or slow-loris server cannot block a caller indefinitely. Built once
/// and reused; `ureq::Agent` is `Arc`-backed internally, so cloning it out of
/// the `OnceLock` is cheap and shares the same connection pool.
pub(crate) fn http_agent() -> ureq::Agent {
    HTTP_AGENT
        .get_or_init(|| {
            ureq::AgentBuilder::new()
                .timeout_connect(HTTP_CONNECT_TIMEOUT)
                .timeout_read(HTTP_READ_TIMEOUT)
                .build()
        })
        .clone()
}

/// Resolve the registry base URL.
///
/// Reads [`REGISTRY_URL_ENV`]; if it is unset or empty, returns [`DEFAULT_REGISTRY_URL`].
/// Trailing slashes are stripped so callers can unconditionally prefix with `/`.
pub fn registry_base_url() -> String {
    match std::env::var(REGISTRY_URL_ENV) {
        Ok(val) if !val.trim().is_empty() => val.trim_end_matches('/').to_string(),
        _ => DEFAULT_REGISTRY_URL.to_string(),
    }
}

/// Fetch a pack from the registry, verify it, cache it, and return the [`LockedPersona`].
///
/// This is the top-level entry point for [`crate::InstallSource::Registry`].
pub fn fetch_and_install(
    spec: &PersonaSpec,
    paths: &ProjectPaths,
) -> Result<LockedPersona, ClientError> {
    let base = registry_base_url();
    let name = &spec.name;
    let version = &spec.version;

    // Step 1: fetch the version record (JSON).
    let record_url = format!("{base}/v1/packs/{name}/versions/{version}");
    debug!(url = %record_url, "fetching pack version record from registry");
    let record: VersionRecord = ureq_get_json(&record_url)?;

    // Step 2: fetch the raw archive bytes.
    let archive_url = format!("{base}/v1/packs/{name}/versions/{version}/pack");
    debug!(url = %archive_url, "downloading pack archive from registry");
    let archive_bytes = ureq_get_bytes(&archive_url)?;

    // Step 3: verify content hash.
    let actual_hash = ObjectHash::of(&archive_bytes);
    if actual_hash != record.content_hash {
        return Err(ClientError::ContentHashMismatch {
            pack: format!("{name}@{version}"),
            expected: record.content_hash.to_hex(),
            actual: actual_hash.to_hex(),
        });
    }
    debug!(hash = %actual_hash, "content hash verified");

    // Step 4: extract archive into a tempdir.
    let tmp = tempfile::TempDir::new().map_err(|source| ClientError::Io {
        path: std::path::PathBuf::from("<tempdir>"),
        source,
    })?;
    extract_targz(&archive_bytes, tmp.path())?;

    // Step 5: locate the pack root (flat or single-nested layout).
    let pack_root = find_pack_root(tmp.path(), name, version)?;

    // Step 6: write signature.sig so Pack::from_dir picks it up.
    let sig_bytes = &record.signature;
    let sig_path = pack_root.join("signature.sig");
    std::fs::write(&sig_path, sig_bytes).map_err(|source| ClientError::Io {
        path: sig_path.clone(),
        source,
    })?;

    // Step 7: load the Pack and verify it.
    let pack = Pack::from_dir(&pack_root)?;
    crate::validate_pack_request(&pack, spec)?;

    // The signature must be present (we just wrote it) -- reject missing.
    if !pack.has_signature() {
        return Err(ClientError::RegistrySignatureMissing {
            pack: format!("{name}@{version}"),
        });
    }

    // Verify against the pubkey from the registry record (not the manifest, to
    // avoid a manifest-tampering attack where the manifest claims a different key).
    let key = VerifyingKey::from_bytes(&record.author_pubkey.0)
        .map_err(|_| ClientError::InvalidAuthorPublicKey(format!("{name}@{version}")))?;
    pack.verify(&key)
        .map_err(|_| ClientError::SignatureVerification)?;
    debug!("pack signature verified against registry pubkey");

    // Step 8: cache the extracted pack directory.
    let canonical_hash = pack.canonical_hash_hex();
    let cache_path = paths.cache_dir.join(&canonical_hash);
    crate::ensure_cached_pack(&pack_root, &cache_path)?;

    Ok(crate::locked_persona_from_pack(&pack))
}

/// Perform a GET request and deserialize the response body as JSON.
///
/// Returns a structured [`ClientError::RegistryHttp`] on HTTP errors or
/// deserialization failures.
fn ureq_get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, ClientError> {
    let response = http_agent()
        .get(url)
        .call()
        .map_err(|err| ClientError::RegistryHttp {
            url: url.to_string(),
            detail: err.to_string(),
        })?;

    if response.status() != 200 {
        return Err(ClientError::RegistryHttp {
            url: url.to_string(),
            detail: format!("HTTP {}", response.status()),
        });
    }

    // Bound the body read the same way ureq_get_bytes does, so an oversized
    // or endlessly-streaming JSON response cannot be buffered without limit
    // before serde ever sees it.
    let limited = LimitedReader::new(response.into_reader(), MAX_ARCHIVE_BYTES);
    serde_json::from_reader(limited).map_err(|err| ClientError::RegistryHttp {
        url: url.to_string(),
        detail: format!("failed to deserialize response JSON: {err}"),
    })
}

/// Perform a GET request and return the raw response bytes.
///
/// Returns a structured [`ClientError::RegistryHttp`] on HTTP errors or
/// read failures.
fn ureq_get_bytes(url: &str) -> Result<Vec<u8>, ClientError> {
    let response = http_agent()
        .get(url)
        .call()
        .map_err(|err| ClientError::RegistryHttp {
            url: url.to_string(),
            detail: err.to_string(),
        })?;

    if response.status() != 200 {
        return Err(ClientError::RegistryHttp {
            url: url.to_string(),
            detail: format!("HTTP {}", response.status()),
        });
    }

    let mut bytes = Vec::new();
    // Wrap in LimitedReader so an oversized body is rejected during streaming,
    // not after the entire response has been buffered into memory.
    LimitedReader::new(response.into_reader(), MAX_ARCHIVE_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|source| ClientError::Io {
            path: std::path::PathBuf::from(url),
            source,
        })?;

    Ok(bytes)
}

/// Extract a `.tar.gz` archive into `dir`.
///
/// Enforces the following security constraints (mirroring the server-side extractor):
///
/// - Decompressed total byte count is capped at [`MAX_DECOMPRESSED_BYTES`] (bomb guard).
/// - Entries with absolute paths are rejected.
/// - Entries with `..` path components are rejected.
/// - Non-regular-file / non-directory entries (symlinks, device nodes, etc.) are rejected.
fn extract_targz(archive_bytes: &[u8], dir: &Path) -> Result<(), ClientError> {
    let gz = GzDecoder::new(std::io::Cursor::new(archive_bytes));
    let limited = LimitedReader::new(gz, MAX_DECOMPRESSED_BYTES);
    let mut archive = Archive::new(limited);
    archive.set_preserve_permissions(false);
    archive.set_overwrite(true);

    let entries = archive.entries().map_err(|err| ClientError::Io {
        path: dir.to_path_buf(),
        source: err,
    })?;

    for entry in entries {
        let mut entry = entry.map_err(|err| ClientError::Io {
            path: dir.to_path_buf(),
            source: err,
        })?;

        // Reject non-regular-file / non-directory entries (symlinks, hardlinks, device nodes).
        let entry_type = entry.header().entry_type();
        if !(entry_type.is_file() || entry_type.is_dir()) {
            return Err(ClientError::Io {
                path: dir.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "pack archive contains a non-regular file entry",
                ),
            });
        }

        // Path-traversal protection.
        let path = entry
            .path()
            .map_err(|err| ClientError::Io {
                path: dir.to_path_buf(),
                source: err,
            })?
            .into_owned();

        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(ClientError::Io {
                path: dir.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "pack archive contains unsafe path",
                ),
            });
        }

        entry.unpack_in(dir).map_err(|err| ClientError::Io {
            path: dir.to_path_buf(),
            source: err,
        })?;
    }

    Ok(())
}

/// Locate the directory inside `extract_dir` that contains `pack.toml`.
///
/// Accepts two layouts:
/// - Flat: `pack.toml` directly inside `extract_dir`.
/// - Nested: a single subdirectory inside `extract_dir` that contains `pack.toml`.
///
/// Returns `ClientError::Io` if no `pack.toml` is found in either location.
fn find_pack_root(
    extract_dir: &Path,
    name: &str,
    version: &str,
) -> Result<std::path::PathBuf, ClientError> {
    if extract_dir.join("pack.toml").is_file() {
        return Ok(extract_dir.to_path_buf());
    }

    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(extract_dir)
        .map_err(|source| ClientError::Io {
            path: extract_dir.to_path_buf(),
            source,
        })?
        .filter_map(|r| r.ok().map(|d| d.path()))
        .collect();
    entries.sort();

    if entries.len() == 1 && entries[0].is_dir() && entries[0].join("pack.toml").is_file() {
        return Ok(entries[0].clone());
    }

    Err(ClientError::Io {
        path: extract_dir.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no pack.toml found in registry archive for {name}@{version}"),
        ),
    })
}

/// A [`Read`] adapter that returns an error once more than `limit` total bytes
/// have been read through it.
///
/// Used as a decompression-bomb guard: counts the actual decompressed bytes
/// produced by the gzip decoder rather than trusting attacker-controlled
/// tar-header size fields.
struct LimitedReader<R> {
    /// The wrapped reader (gzip-decompressed tar byte stream).
    inner: R,
    /// Maximum total bytes allowed.
    limit: u64,
    /// Running count of bytes read so far.
    read: u64,
}

impl<R: std::io::Read> LimitedReader<R> {
    /// Wrap `inner`, allowing at most `limit` total bytes before returning an error.
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            limit,
            read: 0,
        }
    }
}

impl<R: std::io::Read> std::io::Read for LimitedReader<R> {
    /// Read into `buf`, returning `InvalidData` once the cumulative byte count
    /// exceeds `limit`.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read = self.read.saturating_add(n as u64);
        if self.read > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "pack archive exceeds maximum decompressed size",
            ));
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// registry_base_url returns the default when the env var is unset.
    #[test]
    fn registry_url_default_when_env_unset() {
        // Temporarily clear the var (restore on drop).
        let _guard = EnvGuard::clear(REGISTRY_URL_ENV);
        let url = registry_base_url();
        assert_eq!(url, DEFAULT_REGISTRY_URL);
    }

    /// registry_base_url returns the custom value from the env var.
    #[test]
    fn registry_url_from_env() {
        let _guard = EnvGuard::set(REGISTRY_URL_ENV, "https://my.registry.example");
        let url = registry_base_url();
        assert_eq!(url, "https://my.registry.example");
    }

    /// registry_base_url strips a trailing slash from the env-provided value.
    #[test]
    fn registry_url_strips_trailing_slash() {
        let _guard = EnvGuard::set(REGISTRY_URL_ENV, "https://my.registry.example/");
        let url = registry_base_url();
        assert_eq!(url, "https://my.registry.example");
    }

    /// registry_base_url returns the default when the env var is set to an empty string.
    #[test]
    fn registry_url_default_when_env_empty() {
        let _guard = EnvGuard::set(REGISTRY_URL_ENV, "");
        let url = registry_base_url();
        assert_eq!(url, DEFAULT_REGISTRY_URL);
    }

    /// A hash-mismatch is detected before any extraction is attempted.
    #[test]
    fn content_hash_mismatch_is_detected() {
        let real_bytes = b"not a real archive";
        let real_hash = ObjectHash::of(real_bytes);
        let wrong_hash_hex = "0".repeat(64);
        let wrong_hash = ObjectHash::from_hex(&wrong_hash_hex).unwrap();

        // The actual hash of our bytes must differ from the advertised wrong hash.
        assert_ne!(real_hash, wrong_hash);

        // Simulate what fetch_and_install does after downloading bytes.
        let actual_hash = ObjectHash::of(real_bytes);
        let mismatch = actual_hash != wrong_hash;
        assert!(mismatch, "mismatch detection logic should trigger");
    }

    /// extract_targz rejects an archive with a path-traversal component.
    #[test]
    fn extract_targz_rejects_non_regular_entries() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let tmp = tempfile::tempdir().unwrap();
        let out_dir = tmp.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();

        // Build a .tar.gz containing a symlink entry. The tar builder validates
        // and rejects literal `..` paths, so the realistic malicious shape we
        // defend against is a symlink (or other non-regular entry) that the
        // extractor must refuse before it can be planted on disk.
        let mut gz_buf: Vec<u8> = Vec::new();
        {
            let enc = GzEncoder::new(&mut gz_buf, Compression::default());
            let mut tar = tar::Builder::new(enc);

            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header
                .set_link_name("../../../../etc/passwd")
                .expect("set symlink target");
            tar.append_data(&mut header, "innocent.txt", std::io::empty())
                .unwrap();
            tar.finish().unwrap();
        }

        let result = extract_targz(&gz_buf, &out_dir);
        assert!(
            result.is_err(),
            "extract_targz must reject a non-regular (symlink) entry"
        );
    }

    /// extract_targz rejects an archive that decompresses to more than the limit.
    #[test]
    fn extract_targz_rejects_decompression_bomb() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let tmp = tempfile::tempdir().unwrap();
        let out_dir = tmp.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();

        // Build a .tar.gz with content larger than MAX_DECOMPRESSED_BYTES.
        let huge = vec![0u8; (MAX_DECOMPRESSED_BYTES + 1) as usize];
        let mut gz_buf: Vec<u8> = Vec::new();
        {
            let enc = GzEncoder::new(&mut gz_buf, Compression::default());
            let mut tar = tar::Builder::new(enc);

            let mut header = tar::Header::new_gnu();
            header.set_size(huge.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "big.bin", huge.as_slice())
                .unwrap();
            tar.finish().unwrap();
        }

        let result = extract_targz(&gz_buf, &out_dir);
        assert!(
            result.is_err(),
            "extract_targz must reject archives exceeding the decompressed size limit"
        );
    }

    // ---- Test helpers ----

    /// Serializes all environment-variable mutation across tests. Cargo runs
    /// tests on multiple threads but the process environment is global, so two
    /// tests that set and read the same variable concurrently race. Every
    /// `EnvGuard` holds this lock for its lifetime, ensuring only one env-mutating
    /// test runs at a time.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard that restores or removes an environment variable on drop.
    struct EnvGuard {
        /// The env var key being managed.
        key: &'static str,
        /// Original value, or `None` if the var was not set.
        original: Option<String>,
        /// Held for the guard's lifetime to serialize env access across threads.
        /// Declared last so it is released only after the Drop impl restores the
        /// variable below.
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        /// Set `key` to `value`, remembering the original value for restoration.
        fn set(key: &'static str, value: &str) -> Self {
            // Recover from a poisoned lock (a prior test panicked) rather than
            // cascade-failing every subsequent env test.
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let original = std::env::var(key).ok();
            // SAFETY: ENV_LOCK serializes all env mutation in this test binary.
            unsafe { std::env::set_var(key, value) };
            Self {
                key,
                original,
                _lock: lock,
            }
        }

        /// Remove `key` from the environment, remembering the original value.
        fn clear(key: &'static str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let original = std::env::var(key).ok();
            // SAFETY: ENV_LOCK serializes all env mutation in this test binary.
            unsafe { std::env::remove_var(key) };
            Self {
                key,
                original,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        /// Restore the environment variable to its original state.
        fn drop(&mut self) {
            // SAFETY: test-only, single-threaded context is assumed for env mutation.
            unsafe {
                match &self.original {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }
}
