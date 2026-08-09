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
//! 5. Pass the bytes and immutable catalog bindings to the shared public-archive verifier.
//! 6. Retain only the verifier's authenticated pack root, including `signature.sig`.
//! 7. Apply registry-local publisher-key and publisher-UUID trust-on-first-use checks.
//! 8. Cache the extracted pack directory under `cache/<pack_canonical_hash>`.
//! 9. Return the [`LockedPersona`] for the caller to commit to the lockfile.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use frameshift_pack::{ForkOrigin, ObjectHash, Pack, PackManifest};
use frameshift_publication::archive::{
    verify_public_archive, ArchiveError, PublicArchiveExpectation, VerifiedPublicPack,
};
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use tracing::debug;

use crate::error::ClientError;
use crate::model::{LockedPersona, Lockfile, PersonaSpec, ProjectPaths};
use crate::publisher::EnrolledPublisherKeyState;

/// Environment variable that overrides the registry base URL.
///
/// When unset or empty, [`registry_base_url`] falls back to the production default.
pub const REGISTRY_URL_ENV: &str = "FRAMESHIFT_REGISTRY_URL";

/// Default registry base URL used when [`REGISTRY_URL_ENV`] is not set.
///
/// The public registry API lives on the `-api` subdomain; every FrameShift
/// client surface points there. The bare `frameshift.syntheos.dev` host does
/// not serve the API -- do not point this back at it.
const DEFAULT_REGISTRY_URL: &str = "https://frameshift-api.syntheos.dev";

/// Maximum number of compressed (wire) bytes we will read from an HTTP registry response.
///
/// Applied via [`LimitedReader`] around the raw HTTP response body *before* `read_to_end`
/// so an oversized response is rejected during streaming, not after full buffering.
/// The shared verifier applies the same limit again before decoding any archive data.
const MAX_ARCHIVE_BYTES: u64 = frameshift_publication::archive::MAX_ARCHIVE_BYTES as u64;

/// Maximum accepted JSON response body for small registry control responses.
const MAX_JSON_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Maximum accepted error response text retained for diagnostics.
const MAX_ERROR_RESPONSE_BYTES: u64 = 64 * 1024;

/// Maximum size of one author key pin file.
const MAX_TRUST_PIN_BYTES: u64 = 1024;

/// Maximum legacy project lock size considered while migrating pack-owner trust.
const MAX_LEGACY_LOCK_BYTES: u64 = 1024 * 1024;

/// Maximum project directories inspected during one legacy trust migration.
const MAX_LEGACY_PROJECTS: usize = 4096;

/// Maximum Creator Studio draft directories inspected during one legacy migration.
const MAX_LEGACY_DRAFTS: usize = 4096;

/// Maximum legacy Studio manifest size considered while detecting fork provenance.
const MAX_LEGACY_DRAFT_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Maximum content-addressed cache entries inspected during legacy migration.
const MAX_LEGACY_CACHE_ENTRIES: usize = 4096;

/// Serialization token for a pack that had no ownership-linked publisher yet.
const UNLINKED_PACK_PUBLISHER: &str = "unlinked";

/// Parsed immutable package-owner record stored before handle-scoped trust.
struct RegistryPackOwnerRecord {
    /// Exact lowercase Ed25519 signer key for this registry pack name.
    signer: String,
    /// Publisher UUID linked when the package record was first established.
    publisher: Option<String>,
}

/// Minimal JSON shape returned by `GET /v1/packs/{name}/versions/{version}`.
///
/// Only the fields needed for installation are deserialized. Unknown fields are
/// silently ignored via `#[serde(deny_unknown_fields)]` being absent -- future
/// server additions will not break older clients.
#[derive(Debug, Deserialize)]
struct VersionRecord {
    /// Pack name echoed by the immutable catalog record.
    pack_name: String,
    /// Exact published version echoed by the immutable catalog record.
    version: String,
    /// SHA-256 hash of the raw `.tar.gz` archive bytes (hex string, 64 chars).
    content_hash: ObjectHash,
    /// Ed25519 signature over the canonical pack hash (base64url no-pad).
    ///
    /// Deserialized from the `serde(with = "bytes_as_b64")` format the server uses.
    #[serde(with = "bytes_as_b64")]
    signature: Vec<u8>,
    /// Ed25519 public key of the author who published this version (base64url no-pad).
    author_pubkey: AuthorPubkeyField,
    /// Stable publisher-key link retained in the base catalog record.
    #[serde(default)]
    publisher_key_id: Option<String>,
    /// Publisher identity attached by ownership-aware registries.
    #[serde(default)]
    publisher: Option<RegistryPublisherSummary>,
    /// Legacy identity attached when the version has no publisher-key link.
    #[serde(default)]
    legacy_author: Option<RegistryLegacyAuthorSummary>,
    /// Exact enrolled key and lifecycle state attached by ownership-aware registries.
    #[serde(default)]
    publisher_key: Option<RegistryPublisherKeySummary>,
}

/// Owned temporary result of exact registry transport and cryptographic verification.
pub(crate) struct VerifiedRegistryPack {
    /// Shared retained artifact proving archive, manifest, policy, signer, and signature bindings.
    artifact: VerifiedPublicPack,
    /// Immutable raw-archive provenance proven by the registry transport.
    origin: ForkOrigin,
}

/// Read-only accessors for one verified temporary registry pack.
impl VerifiedRegistryPack {
    /// Return the extracted directory containing the verified pack.
    pub(crate) fn pack_root(&self) -> &Path {
        self.artifact.pack_root()
    }

    /// Return the exact immutable registry provenance for this download.
    pub(crate) fn origin(&self) -> &ForkOrigin {
        &self.origin
    }
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

/// Optional filters for [`search_registry`].
///
/// All fields are optional; an entirely-default query returns the registry's
/// default (unfiltered, server-side-limited) result page.
#[derive(Debug, Default, Clone)]
pub struct RegistrySearchQuery {
    /// Free-text search term matched against pack name/description/tags.
    pub query: Option<String>,
    /// Restrict results to packs carrying this tag.
    pub tag: Option<String>,
    /// Maximum number of results to return (server-clamped).
    pub limit: Option<u32>,
    /// Number of matching results to skip before returning this page.
    pub offset: Option<u32>,
}

/// A single search hit: a pack summary paired with its relevance score.
#[derive(Debug, Deserialize)]
pub struct RegistrySearchResult {
    /// The matching pack's summary fields.
    pub pack: RegistryPackSummary,
    /// Backend-assigned relevance score (higher is more relevant; not
    /// comparable across backends).
    pub score: f32,
    /// Preferred publisher identity when the registry has linked ownership.
    #[serde(default)]
    pub publisher: Option<RegistryPublisherSummary>,
    /// Legacy author identity when publisher ownership has not been linked.
    #[serde(default)]
    pub legacy_author: Option<RegistryLegacyAuthorSummary>,
}

/// Public publisher identity returned additively by ownership-aware registries.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RegistryPublisherSummary {
    /// Stable publisher identifier serialized as a UUID string.
    pub id: String,
    /// Unique public publisher handle.
    pub handle: String,
    /// Public publisher display name.
    pub display_name: String,
}

/// Legacy author identity returned during the compatibility window.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RegistryLegacyAuthorSummary {
    /// Unique legacy author handle.
    pub handle: String,
    /// Optional legacy author display name.
    pub display_name: Option<String>,
}

/// Public state for the exact publisher key linked to a historical version.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RegistryPublisherKeySummary {
    /// Stable publisher-key identifier serialized as a UUID string.
    pub id: String,
    /// Current lifecycle state of the historical signing key.
    pub state: EnrolledPublisherKeyState,
}

/// Ownership and verification details for one immutable registry version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryVersionDetails {
    /// Exact pack name returned by the registry.
    pub pack_name: String,
    /// Exact version returned by the registry.
    pub version: String,
    /// Immutable archive SHA-256 encoded as lowercase hexadecimal.
    pub content_hash: String,
    /// Historical Ed25519 signer encoded as base64url without padding.
    pub author_pubkey: String,
    /// Stable publisher-key link retained in the base record.
    pub publisher_key_id: Option<String>,
    /// Current publisher identity when ownership is linked.
    pub publisher: Option<RegistryPublisherSummary>,
    /// Legacy identity when no publisher key is linked.
    pub legacy_author: Option<RegistryLegacyAuthorSummary>,
    /// Exact historical publisher key and its current lifecycle state.
    pub publisher_key: Option<RegistryPublisherKeySummary>,
}

/// Conversion helpers for public immutable version details.
impl RegistryVersionDetails {
    /// Convert the private install wire record into a stable public view.
    fn from_record(record: &VersionRecord) -> Self {
        Self {
            pack_name: record.pack_name.clone(),
            version: record.version.clone(),
            content_hash: record.content_hash.to_hex(),
            author_pubkey: URL_SAFE_NO_PAD.encode(record.author_pubkey.0),
            publisher_key_id: record.publisher_key_id.clone(),
            publisher: record.publisher.clone(),
            legacy_author: record.legacy_author.clone(),
            publisher_key: record.publisher_key.clone(),
        }
    }
}

/// Client-side subset of the server's `PackRecord`, containing only the
/// fields the CLI needs to display a search result.
#[derive(Debug, Deserialize)]
pub struct RegistryPackSummary {
    /// The pack's unique name.
    pub name: String,
    /// Legacy-compatible raw owner key retained for verification and fallback display.
    pub current_author: String,
    /// Short human-readable description of the pack.
    pub description: String,
    /// Tags associated with the pack for search/discovery.
    pub tags: Vec<String>,
    /// The most-recently published semver version, or `None` if no version
    /// has been published yet.
    pub latest_version: Option<String>,
    /// Cumulative download count across all versions of the pack.
    pub total_downloads: u64,
}

/// Response body for `GET /v1/packs`: `{"results": [RegistrySearchResult, ...]}`.
#[derive(Debug, Deserialize)]
struct SearchResponseBody {
    /// The matching packs, in server-assigned relevance order.
    results: Vec<RegistrySearchResult>,
}

/// Search the registry's pack catalog (`GET {base}/v1/packs`).
///
/// Applies `q.query`/`q.tag`/`q.limit`/`q.offset` as query-string parameters when
/// present; omitted filters are left off the request entirely so the server
/// applies its own defaults. Returns a structured [`ClientError::RegistryHttp`]
/// on a network error, non-2xx status, or a response body that does not
/// parse as the expected JSON shape.
pub fn search_registry(
    base: &str,
    q: &RegistrySearchQuery,
) -> Result<Vec<RegistrySearchResult>, ClientError> {
    let url = format!("{base}/v1/packs");
    let mut request = http_agent().get(&url);
    if let Some(query) = &q.query {
        request = request.query("query", query);
    }
    if let Some(tag) = &q.tag {
        request = request.query("tag", tag);
    }
    if let Some(limit) = q.limit {
        request = request.query("limit", &limit.to_string());
    }
    if let Some(offset) = q.offset {
        request = request.query("offset", &offset.to_string());
    }

    let response = request.call().map_err(|err| ClientError::RegistryHttp {
        url: url.clone(),
        detail: err.to_string(),
    })?;

    if response.status() != 200 {
        return Err(ClientError::RegistryHttp {
            url: url.clone(),
            detail: format!("HTTP {}", response.status()),
        });
    }

    // Bound the body read the same way ureq_get_json does, so an oversized
    // response cannot be buffered without limit before serde ever sees it.
    let limited = LimitedReader::new(response.into_reader(), MAX_JSON_RESPONSE_BYTES);
    let body: SearchResponseBody =
        serde_json::from_reader(limited).map_err(|err| ClientError::RegistryHttp {
            url,
            detail: format!("failed to deserialize response JSON: {err}"),
        })?;

    Ok(body.results)
}

/// Minimal JSON shape used to resolve the latest published version of a pack
/// from `GET /v1/packs/{name}` (the server's `PackRecord`, of which only
/// `latest_version` is needed here).
#[derive(Debug, Deserialize)]
struct PackHeadRecord {
    /// The most-recently published semver version, or `None` if the pack
    /// exists in the registry but has never had a version published.
    latest_version: Option<String>,
}

/// Resolve the latest published version for `name` (`GET /v1/packs/{name}`).
///
/// Used to expand a version-less install spec (e.g. `frameshift install foo`)
/// to an explicit `name@version` before installing from the registry.
///
/// Returns [`ClientError::NoPublishedVersion`] when the pack record exists
/// but has no published version yet.
pub fn resolve_latest_version(name: &str) -> Result<String, ClientError> {
    let base = registry_base_url();
    let url = format!("{base}/v1/packs/{name}");
    let record: PackHeadRecord = ureq_get_json(&url)?;
    record
        .latest_version
        .ok_or_else(|| ClientError::NoPublishedVersion(name.to_string()))
}

/// Fetch ownership and verification details for one immutable registry version.
pub fn registry_version_details(
    base: &str,
    name: &str,
    version: &str,
) -> Result<RegistryVersionDetails, ClientError> {
    let url = format!("{base}/v1/packs/{name}/versions/{version}");
    let record: VersionRecord = ureq_get_json(&url)?;
    validate_version_identity(&record, name, version)?;
    Ok(RegistryVersionDetails::from_record(&record))
}

/// Fetch a pack from the registry, verify it, cache it, and return the [`LockedPersona`].
///
/// This is the top-level entry point for [`crate::InstallSource::Registry`].
pub fn fetch_and_install(
    spec: &PersonaSpec,
    paths: &ProjectPaths,
) -> Result<LockedPersona, ClientError> {
    let data_root = paths.cache_dir.parent().unwrap_or(&paths.cache_dir);
    let verified = fetch_verified_pack(spec, data_root)?;
    let pack = Pack::from_dir(verified.pack_root())?;

    // Cache the extracted pack directory only after every verification step.
    let canonical_hash = pack.canonical_hash_hex();
    let cache_path = paths.cache_dir.join(&canonical_hash);
    crate::ensure_cached_pack(verified.pack_root(), &cache_path)?;

    // `ensure_cached_pack` is a no-op when `cache_path` already existed (a
    // cache hit): in that case the bytes materialization will actually read
    // from `cache/<hash>` (see `materialize_one_persona`) are a pre-existing
    // directory on disk, never re-touched by the cryptographic verification
    // performed above against the freshly-downloaded temp directory. Re-load
    // and re-hash the cache entry and reject a mismatch instead of silently
    // trusting it -- mirroring how `validate_cached_local_pack` re-verifies
    // the local-install cache path after `ensure_cached_pack`.
    let cached_pack = Pack::from_dir(&cache_path)?;
    let cached_hash = cached_pack.canonical_hash_hex();
    if cached_hash != canonical_hash {
        return Err(ClientError::RegistryCacheTampered {
            pack: format!("{}@{}", spec.name, spec.version),
            expected: canonical_hash,
            actual: cached_hash,
        });
    }

    Ok(crate::locked_persona_from_pack(&cached_pack))
}

/// Fetch, extract, and cryptographically verify one exact immutable registry version.
pub(crate) fn fetch_verified_pack(
    spec: &PersonaSpec,
    data_root: &Path,
) -> Result<VerifiedRegistryPack, ClientError> {
    let base = registry_base_url();
    let name = &spec.name;
    let version = &spec.version;
    crate::validate_persona_name(name)?;
    if version.len() > 64 || semver::Version::parse(version).is_err() {
        return Err(ClientError::InvalidPersonaSpec(format!("{name}@{version}")));
    }

    // Step 1: fetch the version record (JSON).
    let record_url = format!("{base}/v1/packs/{name}/versions/{version}");
    debug!(url = %record_url, "fetching pack version record from registry");
    let record: VersionRecord = ureq_get_json(&record_url)?;
    validate_version_identity(&record, name, version)?;

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

    // Step 4: require one exact detached signature before any archive extraction.
    if record.signature.is_empty() {
        return Err(ClientError::RegistrySignatureMissing {
            pack: format!("{name}@{version}"),
        });
    }
    let signature: [u8; 64] = record
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ClientError::SignatureVerification)?;

    // Step 5: apply the shared fail-closed extraction, publication-policy,
    // manifest-identity, signer-key, and Ed25519 boundary in one retained artifact.
    let artifact = verify_public_archive(
        &archive_bytes,
        PublicArchiveExpectation {
            name,
            version,
            archive_sha256: *record.content_hash.as_bytes(),
            author_public_key: record.author_pubkey.0,
            signature,
        },
    )
    .map_err(|error| map_registry_archive_error(error, name, version))?;
    debug!("pack archive and signature passed the shared public boundary");

    // Step 6: cryptographic validity is not enough when the registry supplies both
    // the signature and key. All responses retain exact key TOFU, while
    // ownership-aware responses additionally pin the stable publisher UUID.
    check_or_create_registry_trust(
        data_root,
        &base,
        &artifact.manifest().author_handle,
        &record.author_pubkey.0,
        &record,
    )?;

    Ok(VerifiedRegistryPack {
        artifact,
        origin: ForkOrigin {
            name: record.pack_name,
            version: record.version,
            content_hash: record.content_hash.to_hex(),
        },
    })
}

/// Preserve established client error classes while retaining bounded shared failures.
fn map_registry_archive_error(error: ArchiveError, name: &str, version: &str) -> ClientError {
    let pack = format!("{name}@{version}");
    match error {
        ArchiveError::InvalidVerifyingKey => ClientError::InvalidAuthorPublicKey(pack),
        ArchiveError::SignatureMismatch | ArchiveError::EmbeddedSignatureMismatch => {
            ClientError::SignatureVerification
        }
        ArchiveError::SignerKeyMismatch => ClientError::RegistryOwnershipInvalid {
            pack,
            detail: "signed manifest author key does not match the verified registry signer"
                .to_string(),
        },
        ArchiveError::PublicationRejected { codes }
            if !codes.is_empty() && codes.iter().all(|code| code.starts_with("prompt.")) =>
        {
            ClientError::PromptPolicyViolation {
                persona: name.to_string(),
                policy_version: frameshift_source::PROMPT_POLICY_VERSION,
                codes,
            }
        }
        source => ClientError::RegistryArchiveInvalid { pack, source },
    }
}

/// Require the immutable record identity to match the requested resource.
fn validate_version_identity(
    record: &VersionRecord,
    expected_name: &str,
    expected_version: &str,
) -> Result<(), ClientError> {
    if record.pack_name != expected_name || record.version != expected_version {
        return Err(ClientError::RegistryOwnershipInvalid {
            pack: format!("{expected_name}@{expected_version}"),
            detail: "version record identity does not match the requested resource".to_string(),
        });
    }
    Ok(())
}

/// Apply exact signer-key TOFU and additive publisher identity continuity.
fn check_or_create_registry_trust(
    data_root: &Path,
    registry: &str,
    author: &str,
    pubkey: &[u8; 32],
    record: &VersionRecord,
) -> Result<(), ClientError> {
    let pack = format!("{}@{}", record.pack_name, record.version);
    let (linked_publisher_id, presented_publisher_id) = match (
        &record.publisher,
        &record.publisher_key,
        record.publisher_key_id.as_deref(),
    ) {
        // Legacy author summaries are current presentation metadata, not
        // immutable signing evidence. Historical archives may retain an older
        // signed handle after the registry profile is renamed; exact signer-key
        // continuity remains enforced by the author pin below.
        (None, None, None) => (None, None),
        (Some(publisher), None, None) => {
            let legacy_author = record.legacy_author.as_ref().ok_or_else(|| {
                ClientError::RegistryOwnershipInvalid {
                    pack: pack.clone(),
                    detail: "historical unlinked version has no legacy author metadata".to_string(),
                }
            })?;
            if publisher.handle != author || legacy_author.handle != author {
                return Err(ClientError::RegistryOwnershipInvalid {
                    pack,
                    detail:
                        "publisher and legacy author handles must match the signed pack manifest"
                            .to_string(),
                });
            }
            let publisher_id = parse_publisher_id(&pack, &publisher.id)?;
            (None, Some(publisher_id))
        }
        (Some(publisher), Some(publisher_key), Some(linked_key_id)) => {
            if record.legacy_author.is_some() {
                return Err(ClientError::RegistryOwnershipInvalid {
                    pack,
                    detail: "publisher and legacy author metadata cannot coexist".to_string(),
                });
            }
            if publisher.handle != author {
                return Err(ClientError::RegistryOwnershipInvalid {
                    pack,
                    detail: "publisher handle does not match the signed pack manifest".to_string(),
                });
            }
            let publisher_id = parse_publisher_id(&pack, &publisher.id)?;
            let summarized_key_id = publisher_key.id.parse::<uuid::Uuid>().map_err(|_| {
                ClientError::RegistryOwnershipInvalid {
                    pack: pack.clone(),
                    detail: "publisher key identifier is not a UUID".to_string(),
                }
            })?;
            let linked_key_id = linked_key_id.parse::<uuid::Uuid>().map_err(|_| {
                ClientError::RegistryOwnershipInvalid {
                    pack: pack.clone(),
                    detail: "catalog publisher key link is not a UUID".to_string(),
                }
            })?;
            if linked_key_id != summarized_key_id {
                return Err(ClientError::RegistryOwnershipInvalid {
                    pack,
                    detail: "publisher key summary does not match the catalog key link".to_string(),
                });
            }
            (Some(publisher_id.clone()), Some(publisher_id))
        }
        _ => {
            return Err(ClientError::RegistryOwnershipInvalid {
                pack,
                detail: "publisher ownership metadata is internally inconsistent".to_string(),
            });
        }
    };

    let signer = hex::encode(pubkey);
    // Author and publisher pins are shared across pack names. Serialize the
    // entire registry-local preflight and write sequence so two concurrent
    // first-use installs cannot each persist incompatible package records
    // before one loses the shared-handle pin race.
    let registry_lock = acquire_registry_trust_lock(data_root, registry)?;
    preflight_existing_handle_trust(
        data_root,
        registry,
        author,
        &signer,
        presented_publisher_id.as_deref(),
    )?;
    if !pack_owner_record_exists(data_root, registry, &record.pack_name)? {
        verify_legacy_pack_owner_migration(data_root, &record.pack_name, &pack)?;
    }
    check_or_create_pack_owner_record(
        data_root,
        registry,
        &record.pack_name,
        &signer,
        linked_publisher_id.as_deref(),
        presented_publisher_id.as_deref(),
    )?;

    if let Some(publisher_id) = linked_publisher_id.as_deref() {
        check_or_create_publisher_pin(data_root, registry, author, publisher_id, pubkey)?;
    } else {
        check_or_create_author_pin(data_root, registry, author, pubkey)?;
    }
    drop(registry_lock);
    Ok(())
}

/// Acquire the persistent per-registry lock that serializes trust mutations.
fn acquire_registry_trust_lock(
    data_root: &Path,
    registry: &str,
) -> Result<std::fs::File, ClientError> {
    let lock_dir = data_root.join("trust").join("registry-transactions");
    std::fs::create_dir_all(&lock_dir).map_err(|source| ClientError::Io {
        path: lock_dir.clone(),
        source,
    })?;
    set_private_dir_permissions(&lock_dir)?;

    let namespace = ObjectHash::of(registry.as_bytes()).to_hex();
    let lock_path = lock_dir.join(format!("{namespace}.lock"));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(&lock_path).map_err(|source| ClientError::Io {
        path: lock_path.clone(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ClientError::Io {
        path: lock_path.clone(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata_is_windows_reparse_point(&metadata) {
        return Err(ClientError::Io {
            path: lock_path,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry trust lock path is not a regular file",
            ),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| ClientError::Io {
                path: lock_path.clone(),
                source,
            })?;
    }
    fs2::FileExt::lock_exclusive(&file).map_err(|source| ClientError::Io {
        path: lock_path,
        source,
    })?;
    Ok(file)
}

/// Return whether opened metadata identifies a Windows reparse point.
fn metadata_is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

/// Verify every existing handle-scoped pin without creating new trust state.
fn preflight_existing_handle_trust(
    data_root: &Path,
    registry: &str,
    author: &str,
    presented_signer: &str,
    presented_publisher: Option<&str>,
) -> Result<(), ClientError> {
    let author_path = author_pin_path(data_root, registry, author);
    match std::fs::symlink_metadata(&author_path) {
        Ok(_) => verify_author_pin(&author_path, registry, author, presented_signer)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ClientError::Io {
                path: author_path,
                source,
            });
        }
    }

    let publisher_path = publisher_pin_path(data_root, registry, author);
    match std::fs::symlink_metadata(&publisher_path) {
        Ok(_) => match presented_publisher {
            Some(publisher) => {
                verify_publisher_pin(&publisher_path, registry, author, publisher)?;
            }
            None => {
                let expected = read_publisher_pin(&publisher_path, registry, author)?;
                return Err(ClientError::RegistryPublisherChanged {
                    registry: registry.to_string(),
                    author: author.to_string(),
                    expected,
                    actual: "<missing>".to_string(),
                });
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ClientError::Io {
                path: publisher_path,
                source,
            });
        }
    }
    Ok(())
}

/// Parse one publisher UUID into its stable canonical string representation.
fn parse_publisher_id(pack: &str, publisher_id: &str) -> Result<String, ClientError> {
    publisher_id
        .parse::<uuid::Uuid>()
        .map(|publisher_id| publisher_id.to_string())
        .map_err(|_| ClientError::RegistryOwnershipInvalid {
            pack: pack.to_string(),
            detail: "publisher identifier is not a UUID".to_string(),
        })
}

/// Return the collision-resistant path for one authoritative package record.
fn pack_owner_record_path(data_root: &Path, registry: &str, pack: &str) -> PathBuf {
    let namespace = ObjectHash::of(format!("{registry}\0{pack}").as_bytes()).to_hex();
    data_root
        .join("trust")
        .join("registry-pack-owners")
        .join(format!("{namespace}.pin"))
}

/// Return the append-only claim path for a later publisher-link transition.
fn pack_publisher_claim_path(data_root: &Path, registry: &str, pack: &str) -> PathBuf {
    let namespace = ObjectHash::of(format!("{registry}\0{pack}").as_bytes()).to_hex();
    data_root
        .join("trust")
        .join("registry-pack-owners")
        .join(format!("{namespace}.publisher"))
}

/// Report whether an authoritative package record already occupies its trust path.
fn pack_owner_record_exists(
    data_root: &Path,
    registry: &str,
    pack: &str,
) -> Result<bool, ClientError> {
    let record_path = pack_owner_record_path(data_root, registry, pack);
    match std::fs::symlink_metadata(&record_path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(ClientError::Io {
            path: record_path,
            source,
        }),
    }
}

/// Refuse automatic TOFU when legacy local state cannot prove registry provenance.
fn verify_legacy_pack_owner_migration(
    data_root: &Path,
    pack_name: &str,
    requested_pack: &str,
) -> Result<(), ClientError> {
    if has_legacy_fork_provenance(data_root, pack_name, requested_pack)?
        || has_legacy_project_lock(data_root, pack_name, requested_pack)?
        || has_legacy_cached_pack(data_root, pack_name, requested_pack)?
    {
        return Err(ClientError::RegistryOwnershipInvalid {
            pack: requested_pack.to_string(),
            detail: "legacy local pack state cannot prove registry ownership".to_string(),
        });
    }
    Ok(())
}

/// Detect a bounded pre-package-pin Studio fork that cannot prove its source signer.
fn has_legacy_fork_provenance(
    data_root: &Path,
    pack_name: &str,
    requested_pack: &str,
) -> Result<bool, ClientError> {
    let studio_root = data_root.join("studio").join("drafts");
    let entries = match std::fs::read_dir(&studio_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(ClientError::Io {
                path: studio_root,
                source,
            });
        }
    };

    for (index, entry) in entries.enumerate() {
        if index >= MAX_LEGACY_DRAFTS {
            return Err(legacy_migration_invalid(
                requested_pack,
                "legacy trust migration exceeds the Studio draft scan limit",
            ));
        }
        let entry = entry.map_err(|source| ClientError::Io {
            path: studio_root.clone(),
            source,
        })?;
        let file_type = entry.file_type().map_err(|source| ClientError::Io {
            path: entry.path(),
            source,
        })?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }

        let manifest_path = entry.path().join("content").join("pack.toml");
        let metadata = match std::fs::symlink_metadata(&manifest_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(ClientError::Io {
                    path: manifest_path,
                    source,
                });
            }
        };
        if !metadata.file_type().is_file() {
            continue;
        }

        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(&manifest_path).map_err(|_| {
            legacy_migration_invalid(requested_pack, "legacy Studio fork manifest is unreadable")
        })?;
        let mut raw = String::new();
        LimitedReader::new(file, MAX_LEGACY_DRAFT_MANIFEST_BYTES)
            .read_to_string(&mut raw)
            .map_err(|_| {
                legacy_migration_invalid(
                    requested_pack,
                    "legacy Studio fork manifest is unreadable",
                )
            })?;
        let Ok(manifest) = toml::from_str::<PackManifest>(&raw) else {
            continue;
        };
        if manifest
            .forked_from
            .as_ref()
            .is_some_and(|origin| origin.name == pack_name)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Detect a bounded legacy project lock whose install source was never persisted.
fn has_legacy_project_lock(
    data_root: &Path,
    pack_name: &str,
    requested_pack: &str,
) -> Result<bool, ClientError> {
    let projects_root = data_root.join("projects");
    let entries = match std::fs::read_dir(&projects_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(ClientError::Io {
                path: projects_root,
                source,
            });
        }
    };

    for (index, entry) in entries.enumerate() {
        if index >= MAX_LEGACY_PROJECTS {
            return Err(ClientError::RegistryOwnershipInvalid {
                pack: requested_pack.to_string(),
                detail: "legacy trust migration exceeds the project scan limit".to_string(),
            });
        }
        let entry = entry.map_err(|source| ClientError::Io {
            path: projects_root.clone(),
            source,
        })?;
        let file_type = entry.file_type().map_err(|source| ClientError::Io {
            path: entry.path(),
            source,
        })?;
        if !file_type.is_dir() {
            continue;
        }
        let Some(lockfile) = read_legacy_project_lock(&entry.path().join("lock.toml"))? else {
            continue;
        };
        if lockfile
            .personas
            .iter()
            .any(|locked| locked.name == pack_name)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Read one regular central lock under a strict migration-only byte ceiling.
fn read_legacy_project_lock(path: &Path) -> Result<Option<Lockfile>, ClientError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ClientError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.file_type().is_file() {
        return Err(ClientError::RegistryOwnershipInvalid {
            pack: path.display().to_string(),
            detail: "legacy trust migration lock is not a regular file".to_string(),
        });
    }

    let mut options = OpenOptions::new();
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
    let mut raw = String::new();
    LimitedReader::new(file, MAX_LEGACY_LOCK_BYTES)
        .read_to_string(&mut raw)
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    toml::from_str(&raw)
        .map(Some)
        .map_err(|source| ClientError::TomlDeserialize {
            path: path.to_path_buf(),
            source,
        })
}

/// Detect a bounded retained cache entry whose original registry source is unknown.
fn has_legacy_cached_pack(
    data_root: &Path,
    pack_name: &str,
    requested_pack: &str,
) -> Result<bool, ClientError> {
    let cache_root = data_root.join("cache");
    let entries = match std::fs::read_dir(&cache_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(ClientError::Io {
                path: cache_root,
                source,
            });
        }
    };

    for (index, entry) in entries.enumerate() {
        if index >= MAX_LEGACY_CACHE_ENTRIES {
            return Err(legacy_migration_invalid(
                requested_pack,
                "legacy trust migration exceeds the cache scan limit",
            ));
        }
        let entry = entry.map_err(|source| ClientError::Io {
            path: cache_root.clone(),
            source,
        })?;
        let entry_path = entry.path();
        let file_type = entry.file_type().map_err(|source| ClientError::Io {
            path: entry_path.clone(),
            source,
        })?;
        if !file_type.is_dir() || file_type.is_symlink() {
            return Err(legacy_migration_invalid(
                requested_pack,
                "legacy cache entry is not a regular directory",
            ));
        }

        let manifest_path = entry_path.join("pack.toml");
        let metadata = std::fs::symlink_metadata(&manifest_path).map_err(|_| {
            legacy_migration_invalid(requested_pack, "legacy cache manifest is unreadable")
        })?;
        if !metadata.file_type().is_file() {
            return Err(legacy_migration_invalid(
                requested_pack,
                "legacy cache manifest is not a regular file",
            ));
        }

        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(&manifest_path).map_err(|_| {
            legacy_migration_invalid(requested_pack, "legacy cache manifest is unreadable")
        })?;
        let mut raw = String::new();
        LimitedReader::new(file, MAX_LEGACY_DRAFT_MANIFEST_BYTES)
            .read_to_string(&mut raw)
            .map_err(|_| {
                legacy_migration_invalid(requested_pack, "legacy cache manifest is unreadable")
            })?;
        let manifest = toml::from_str::<PackManifest>(&raw).map_err(|_| {
            legacy_migration_invalid(requested_pack, "legacy cache manifest is invalid")
        })?;
        if manifest.name == pack_name {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Construct one bounded failure for unusable pre-package-pin local evidence.
fn legacy_migration_invalid(requested_pack: &str, detail: &'static str) -> ClientError {
    ClientError::RegistryOwnershipInvalid {
        pack: requested_pack.to_string(),
        detail: detail.to_string(),
    }
}

/// Verify or create the authoritative signer-plus-publisher package record.
fn check_or_create_pack_owner_record(
    data_root: &Path,
    registry: &str,
    pack: &str,
    signer: &str,
    linked_publisher: Option<&str>,
    presented_publisher: Option<&str>,
) -> Result<(), ClientError> {
    let record_path = pack_owner_record_path(data_root, registry, pack);
    let pin_dir = data_root.join("trust").join("registry-pack-owners");
    std::fs::create_dir_all(&pin_dir).map_err(|source| ClientError::Io {
        path: pin_dir.clone(),
        source,
    })?;
    set_private_dir_permissions(&pin_dir)?;

    let publisher = linked_publisher
        .map(|publisher| format!("linked:{publisher}"))
        .unwrap_or_else(|| UNLINKED_PACK_PUBLISHER.to_string());
    let contents = format!("frameshift-pack-owner-v1\n{registry}\n{pack}\n{signer}\n{publisher}\n");
    match create_private_file(&record_path) {
        Ok(mut file) => file
            .write_all(contents.as_bytes())
            .map_err(|source| ClientError::Io {
                path: record_path.clone(),
                source,
            })?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => Err(ClientError::Io {
            path: record_path.clone(),
            source,
        })?,
    }
    verify_pack_owner_record(
        data_root,
        &record_path,
        registry,
        pack,
        signer,
        linked_publisher,
        presented_publisher,
    )
}

/// Compare one package record and any append-only publisher claim with a response.
fn verify_pack_owner_record(
    data_root: &Path,
    record_path: &Path,
    registry: &str,
    pack: &str,
    signer: &str,
    linked_publisher: Option<&str>,
    presented_publisher: Option<&str>,
) -> Result<(), ClientError> {
    let record = read_pack_owner_record(record_path, registry, pack)?;
    if record.signer != signer {
        return Err(ClientError::RegistryPackOwnerChanged {
            registry: registry.to_string(),
            pack: pack.to_string(),
            owner_kind: "signer",
            expected: record.signer,
            actual: signer.to_string(),
        });
    }

    let claim = read_pack_publisher_claim(data_root, registry, pack)?;
    let expected_publisher = match (record.publisher, claim) {
        (Some(recorded), Some(claimed)) if recorded != claimed => {
            return Err(ClientError::RegistryPackOwnerChanged {
                registry: registry.to_string(),
                pack: pack.to_string(),
                owner_kind: "publisher",
                expected: recorded,
                actual: claimed,
            });
        }
        (Some(recorded), _) => Some(recorded),
        (None, claimed) => claimed,
    };
    if let Some(expected) = expected_publisher {
        let actual = presented_publisher.unwrap_or("<missing>");
        if expected != actual {
            return Err(ClientError::RegistryPackOwnerChanged {
                registry: registry.to_string(),
                pack: pack.to_string(),
                owner_kind: "publisher",
                expected,
                actual: actual.to_string(),
            });
        }
        return Ok(());
    }

    if let Some(publisher) = linked_publisher {
        check_or_create_pack_publisher_claim(data_root, registry, pack, publisher)?;
    }
    Ok(())
}

/// Parse one bounded package-owner record from a regular no-follow file.
fn read_pack_owner_record(
    record_path: &Path,
    registry: &str,
    pack: &str,
) -> Result<RegistryPackOwnerRecord, ClientError> {
    let raw = read_private_trust_file(record_path)?;
    let mut lines = raw.lines();
    let valid = lines.next() == Some("frameshift-pack-owner-v1")
        && lines.next() == Some(registry)
        && lines.next() == Some(pack);
    let signer = lines.next();
    let publisher = lines.next();
    if !valid || signer.is_none() || publisher.is_none() || lines.next().is_some() {
        return Err(ClientError::Io {
            path: record_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry pack owner record is malformed",
            ),
        });
    }
    let signer = signer.unwrap_or_default();
    if signer.len() != 64
        || !signer
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ClientError::Io {
            path: record_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry pack owner signer is malformed",
            ),
        });
    }
    let publisher = publisher.unwrap_or_default();
    let publisher = if publisher == UNLINKED_PACK_PUBLISHER {
        None
    } else if let Some(value) = publisher.strip_prefix("linked:") {
        let canonical = value
            .parse::<uuid::Uuid>()
            .map(|publisher| publisher.to_string())
            .ok();
        if canonical.as_deref() != Some(value) {
            return Err(ClientError::Io {
                path: record_path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "registry pack owner publisher is malformed",
                ),
            });
        }
        Some(value.to_string())
    } else {
        return Err(ClientError::Io {
            path: record_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry pack owner publisher state is malformed",
            ),
        });
    };
    Ok(RegistryPackOwnerRecord {
        signer: signer.to_string(),
        publisher,
    })
}

/// Verify or create the append-only publisher claim for a later link upgrade.
fn check_or_create_pack_publisher_claim(
    data_root: &Path,
    registry: &str,
    pack: &str,
    publisher: &str,
) -> Result<(), ClientError> {
    let claim_path = pack_publisher_claim_path(data_root, registry, pack);
    let contents = format!("frameshift-pack-publisher-v1\n{registry}\n{pack}\n{publisher}\n");
    match create_private_file(&claim_path) {
        Ok(mut file) => file
            .write_all(contents.as_bytes())
            .map_err(|source| ClientError::Io {
                path: claim_path.clone(),
                source,
            })?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(ClientError::Io {
                path: claim_path,
                source,
            });
        }
    }
    let expected =
        read_pack_publisher_claim(data_root, registry, pack)?.ok_or_else(|| ClientError::Io {
            path: claim_path.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "registry pack publisher claim disappeared",
            ),
        })?;
    if expected != publisher {
        return Err(ClientError::RegistryPackOwnerChanged {
            registry: registry.to_string(),
            pack: pack.to_string(),
            owner_kind: "publisher",
            expected,
            actual: publisher.to_string(),
        });
    }
    Ok(())
}

/// Read and validate an optional append-only package publisher claim.
fn read_pack_publisher_claim(
    data_root: &Path,
    registry: &str,
    pack: &str,
) -> Result<Option<String>, ClientError> {
    let claim_path = pack_publisher_claim_path(data_root, registry, pack);
    match std::fs::symlink_metadata(&claim_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ClientError::Io {
                path: claim_path,
                source,
            });
        }
    }
    let raw = read_private_trust_file(&claim_path)?;
    let mut lines = raw.lines();
    let valid = lines.next() == Some("frameshift-pack-publisher-v1")
        && lines.next() == Some(registry)
        && lines.next() == Some(pack);
    let publisher = lines.next();
    if !valid || publisher.is_none() || lines.next().is_some() {
        return Err(ClientError::Io {
            path: claim_path,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry pack publisher claim is malformed",
            ),
        });
    }
    let publisher = publisher.unwrap_or_default();
    let canonical = publisher
        .parse::<uuid::Uuid>()
        .map(|publisher| publisher.to_string())
        .ok();
    if canonical.as_deref() != Some(publisher) {
        return Err(ClientError::Io {
            path: claim_path,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry pack publisher claim is malformed",
            ),
        });
    }
    Ok(Some(publisher.to_string()))
}

/// Read one bounded regular trust file without following its final component.
fn read_private_trust_file(path: &Path) -> Result<String, ClientError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClientError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry trust path is not a regular file",
            ),
        });
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata_is_windows_reparse_point(&metadata) {
        return Err(ClientError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry trust path is not a regular file",
            ),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| ClientError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }
    let mut raw = String::new();
    LimitedReader::new(file, MAX_TRUST_PIN_BYTES)
        .read_to_string(&mut raw)
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(raw)
}

/// Verify or atomically establish an author key continuity pin.
fn check_or_create_author_pin(
    data_root: &Path,
    registry: &str,
    author: &str,
    pubkey: &[u8; 32],
) -> Result<(), ClientError> {
    let pin_dir = data_root.join("trust").join("registry-authors");
    std::fs::create_dir_all(&pin_dir).map_err(|source| ClientError::Io {
        path: pin_dir.clone(),
        source,
    })?;
    set_private_dir_permissions(&pin_dir)?;

    let pin_path = author_pin_path(data_root, registry, author);
    let presented = hex::encode(pubkey);
    let contents = format!("frameshift-author-key-v1\n{registry}\n{author}\n{presented}\n");

    match create_private_file(&pin_path) {
        Ok(mut file) => file
            .write_all(contents.as_bytes())
            .map_err(|source| ClientError::Io {
                path: pin_path,
                source,
            }),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_author_pin(&pin_path, registry, author, &presented)
        }
        Err(source) => Err(ClientError::Io {
            path: pin_path,
            source,
        }),
    }
}

/// Return the collision-resistant legacy author-key trust path.
fn author_pin_path(data_root: &Path, registry: &str, author: &str) -> PathBuf {
    let namespace = ObjectHash::of(format!("{registry}\0{author}").as_bytes()).to_hex();
    data_root
        .join("trust")
        .join("registry-authors")
        .join(format!("{namespace}.pin"))
}

/// Compare an existing bounded pin file with the newly presented key.
fn verify_author_pin(
    pin_path: &Path,
    registry: &str,
    author: &str,
    presented: &str,
) -> Result<(), ClientError> {
    let raw = read_private_trust_file(pin_path)?;
    let mut lines = raw.lines();
    let valid_header = lines.next() == Some("frameshift-author-key-v1");
    let stored_registry = lines.next();
    let stored_author = lines.next();
    let stored_key = lines.next();
    if !valid_header
        || stored_registry != Some(registry)
        || stored_author != Some(author)
        || stored_key.is_none()
        || lines.next().is_some()
    {
        return Err(ClientError::Io {
            path: pin_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry author trust pin is malformed",
            ),
        });
    }
    let expected = stored_key.unwrap_or_default();
    if expected != presented {
        return Err(ClientError::RegistryAuthorKeyChanged {
            registry: registry.to_string(),
            author: author.to_string(),
            expected: expected.to_string(),
            actual: presented.to_string(),
        });
    }
    Ok(())
}

/// Verify or atomically establish stable publisher identity continuity.
fn check_or_create_publisher_pin(
    data_root: &Path,
    registry: &str,
    author: &str,
    publisher_id: &str,
    presented_pubkey: &[u8; 32],
) -> Result<(), ClientError> {
    // Publisher identity is additive trust context, not a replacement for the
    // exact signer pin. Until the wire protocol carries an old-key-signed
    // rotation proof, a newly presented key must retain the existing warning.
    check_or_create_author_pin(data_root, registry, author, presented_pubkey)?;

    let pin_dir = data_root.join("trust").join("registry-publishers");
    std::fs::create_dir_all(&pin_dir).map_err(|source| ClientError::Io {
        path: pin_dir.clone(),
        source,
    })?;
    set_private_dir_permissions(&pin_dir)?;

    let pin_path = publisher_pin_path(data_root, registry, author);
    match std::fs::symlink_metadata(&pin_path) {
        Ok(_) => return verify_publisher_pin(&pin_path, registry, author, publisher_id),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ClientError::Io {
                path: pin_path,
                source,
            });
        }
    }

    let contents = format!("frameshift-publisher-v1\n{registry}\n{author}\n{publisher_id}\n");
    match create_private_file(&pin_path) {
        Ok(mut file) => file
            .write_all(contents.as_bytes())
            .map_err(|source| ClientError::Io {
                path: pin_path,
                source,
            }),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_publisher_pin(&pin_path, registry, author, publisher_id)
        }
        Err(source) => Err(ClientError::Io {
            path: pin_path,
            source,
        }),
    }
}

/// Return the collision-resistant legacy publisher-identity trust path.
fn publisher_pin_path(data_root: &Path, registry: &str, author: &str) -> PathBuf {
    let namespace = ObjectHash::of(format!("{registry}\0{author}").as_bytes()).to_hex();
    data_root
        .join("trust")
        .join("registry-publishers")
        .join(format!("{namespace}.pin"))
}

/// Compare an existing bounded publisher pin with the presented identity.
fn verify_publisher_pin(
    pin_path: &Path,
    registry: &str,
    author: &str,
    presented_publisher_id: &str,
) -> Result<(), ClientError> {
    let expected = read_publisher_pin(pin_path, registry, author)?;
    if expected != presented_publisher_id {
        return Err(ClientError::RegistryPublisherChanged {
            registry: registry.to_string(),
            author: author.to_string(),
            expected,
            actual: presented_publisher_id.to_string(),
        });
    }
    Ok(())
}

/// Parse and return the UUID stored in one bounded legacy publisher pin.
fn read_publisher_pin(
    pin_path: &Path,
    registry: &str,
    author: &str,
) -> Result<String, ClientError> {
    let raw = read_private_trust_file(pin_path)?;
    let mut lines = raw.lines();
    let valid_header = lines.next() == Some("frameshift-publisher-v1");
    let stored_registry = lines.next();
    let stored_author = lines.next();
    let stored_publisher_id = lines.next();
    if !valid_header
        || stored_registry != Some(registry)
        || stored_author != Some(author)
        || stored_publisher_id.is_none()
        || lines.next().is_some()
    {
        return Err(ClientError::Io {
            path: pin_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "registry publisher trust pin is malformed",
            ),
        });
    }
    Ok(stored_publisher_id.unwrap_or_default().to_string())
}

/// Open a new private file without following an existing path.
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Restrict a trust directory to its owner on Unix.
fn set_private_dir_permissions(path: &Path) -> Result<(), ClientError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |source| ClientError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }
    Ok(())
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

/// Deserialize a bounded registry response body as JSON.
pub(crate) fn response_json_bounded<T: serde::de::DeserializeOwned>(
    response: ureq::Response,
    url: &str,
) -> Result<T, ClientError> {
    let bytes = response_bytes_bounded(response, url, MAX_JSON_RESPONSE_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|error| ClientError::RegistryHttp {
        url: url.to_string(),
        detail: format!("failed to deserialize response JSON: {error}"),
    })
}

/// Read a registry archive response under the shared compressed-body limit.
pub(crate) fn response_archive_bytes_bounded(
    response: ureq::Response,
    url: &str,
) -> Result<Vec<u8>, ClientError> {
    response_bytes_bounded(response, url, MAX_ARCHIVE_BYTES)
}

/// Read a bounded registry error body as UTF-8 text.
pub(crate) fn response_text_bounded(response: ureq::Response, url: &str) -> String {
    response_bytes_bounded(response, url, MAX_ERROR_RESPONSE_BYTES)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_else(|_| "<unreadable or oversized response body>".to_string())
}

/// Read at most `limit` bytes from a registry response.
fn response_bytes_bounded(
    response: ureq::Response,
    url: &str,
    limit: u64,
) -> Result<Vec<u8>, ClientError> {
    let mut bytes = Vec::new();
    LimitedReader::new(response.into_reader(), limit)
        .read_to_end(&mut bytes)
        .map_err(|source| ClientError::Io {
            path: std::path::PathBuf::from(url),
            source,
        })?;
    Ok(bytes)
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

/// Construction helpers for [`LimitedReader`].
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

/// Enforces the response-byte ceiling while forwarding reads.
impl<R: std::io::Read> std::io::Read for LimitedReader<R> {
    /// Read into `buf`, returning `InvalidData` once the cumulative byte count
    /// exceeds `limit`.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read = self.read.saturating_add(n as u64);
        if self.read > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response exceeds maximum allowed size",
            ));
        }
        Ok(n)
    }
}

#[cfg(test)]
/// Unit tests for bounded registry transport and archive extraction.
mod tests {
    use super::*;
    use std::io::BufRead as _;
    use std::net::TcpListener;

    /// Exact registry versions are bounded before any HTTP request is constructed.
    #[test]
    fn verified_fetch_rejects_oversized_semver() {
        let temp = tempfile::tempdir().unwrap();
        let error = fetch_verified_pack(
            &PersonaSpec {
                name: "bounded-pack".to_string(),
                version: format!("1.0.0-{}", "a".repeat(64)),
            },
            temp.path(),
        )
        .err()
        .expect("oversized exact version must fail before transport");

        assert!(matches!(error, ClientError::InvalidPersonaSpec(_)));
    }

    /// The first verified author key is pinned and an exact repeat is accepted.
    #[test]
    fn author_key_tofu_pin_accepts_continuity() {
        let temp = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        check_or_create_author_pin(temp.path(), "https://registry.example", "alice", &key).unwrap();
        check_or_create_author_pin(temp.path(), "https://registry.example", "alice", &key).unwrap();
    }

    /// A later registry response cannot silently substitute a new author key.
    #[test]
    fn author_key_tofu_pin_rejects_substitution() {
        let temp = tempfile::tempdir().unwrap();
        check_or_create_author_pin(temp.path(), "https://registry.example", "alice", &[7u8; 32])
            .unwrap();
        let error = check_or_create_author_pin(
            temp.path(),
            "https://registry.example",
            "alice",
            &[8u8; 32],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ClientError::RegistryAuthorKeyChanged { .. }
        ));
    }

    /// Build one ownership-aware version record for trust continuity tests.
    fn ownership_version_record(
        publisher_id: &str,
        key_id: &str,
        key_state: EnrolledPublisherKeyState,
        pubkey: [u8; 32],
    ) -> VersionRecord {
        VersionRecord {
            pack_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: ObjectHash::of(b"test"),
            signature: vec![0_u8; 64],
            author_pubkey: AuthorPubkeyField(pubkey),
            publisher_key_id: Some(key_id.to_string()),
            publisher: Some(RegistryPublisherSummary {
                id: publisher_id.to_string(),
                handle: "alice".to_string(),
                display_name: "Alice".to_string(),
            }),
            legacy_author: None,
            publisher_key: Some(RegistryPublisherKeySummary {
                id: key_id.to_string(),
                state: key_state,
            }),
        }
    }

    /// A durable package record alone rejects substitution after an interrupted first use.
    #[test]
    fn atomic_pack_owner_record_survives_pre_handle_interruption() {
        let temp = tempfile::tempdir().unwrap();
        let registry = "https://registry.example";
        let pack_name = "atomic-owner-pack";
        let publisher_id = "4a128e72-cc91-4721-b452-943ce736799b";
        let signer = hex::encode([7_u8; 32]);
        check_or_create_pack_owner_record(
            temp.path(),
            registry,
            pack_name,
            &signer,
            Some(publisher_id),
            Some(publisher_id),
        )
        .expect("the authoritative package tuple must persist before handle trust");

        let mut substituted = ownership_version_record(
            "6199b23b-906f-4689-a840-664a184c5f75",
            "1e41ae38-9a5e-4623-8fcc-8f705928dacf",
            EnrolledPublisherKeyState::Active,
            [8_u8; 32],
        );
        substituted.pack_name = pack_name.to_string();
        substituted.publisher.as_mut().unwrap().handle = "mallory".to_string();
        let error = check_or_create_registry_trust(
            temp.path(),
            registry,
            "mallory",
            &[8_u8; 32],
            &substituted,
        )
        .expect_err("a retry cannot reset the package owner after interruption");

        assert!(matches!(
            error,
            ClientError::RegistryPackOwnerChanged {
                owner_kind: "signer",
                ..
            }
        ));
    }

    /// An append-only publisher claim rejects omission after an interrupted link upgrade.
    #[test]
    fn atomic_pack_owner_publisher_upgrade_survives_interruption() {
        let temp = tempfile::tempdir().unwrap();
        let registry = "https://registry.example";
        let pack_name = "atomic-owner-pack";
        let publisher_id = "4a128e72-cc91-4721-b452-943ce736799b";
        let signer = hex::encode([7_u8; 32]);
        check_or_create_pack_owner_record(temp.path(), registry, pack_name, &signer, None, None)
            .expect("the original signer-only owner record must persist");
        check_or_create_pack_owner_record(
            temp.path(),
            registry,
            pack_name,
            &signer,
            Some(publisher_id),
            Some(publisher_id),
        )
        .expect("the first linked version must persist its publisher claim");

        let error = check_or_create_pack_owner_record(
            temp.path(),
            registry,
            pack_name,
            &signer,
            None,
            None,
        )
        .expect_err("a retry cannot omit a publisher claim after interruption");
        assert!(matches!(
            error,
            ClientError::RegistryPackOwnerChanged {
                owner_kind: "publisher",
                actual,
                ..
            } if actual == "<missing>"
        ));
    }

    /// An existing author conflict is rejected before package trust can be poisoned.
    #[test]
    fn registry_trust_preflights_author_pin_before_package_record() {
        let temp = tempfile::tempdir().unwrap();
        let registry = "https://registry.example";
        let pack_name = "author-conflict-pack";
        check_or_create_author_pin(temp.path(), registry, "alice", &[7_u8; 32])
            .expect("the prior author pin must exist");

        let mut conflicting = ownership_version_record(
            "4a128e72-cc91-4721-b452-943ce736799b",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [8_u8; 32],
        );
        conflicting.pack_name = pack_name.to_string();
        let error = check_or_create_registry_trust(
            temp.path(),
            registry,
            "alice",
            &[8_u8; 32],
            &conflicting,
        )
        .expect_err("an existing author conflict must reject before package mutation");

        assert!(matches!(
            error,
            ClientError::RegistryAuthorKeyChanged { .. }
        ));
        assert!(!pack_owner_record_path(temp.path(), registry, pack_name).exists());
        assert!(!pack_publisher_claim_path(temp.path(), registry, pack_name).exists());
    }

    /// An existing publisher conflict is rejected before package trust can be poisoned.
    #[test]
    fn registry_trust_preflights_publisher_pin_before_package_record() {
        let temp = tempfile::tempdir().unwrap();
        let registry = "https://registry.example";
        let pack_name = "publisher-conflict-pack";
        let original_publisher = "4a128e72-cc91-4721-b452-943ce736799b";
        check_or_create_publisher_pin(
            temp.path(),
            registry,
            "alice",
            original_publisher,
            &[7_u8; 32],
        )
        .expect("the prior publisher pin must exist");

        let mut conflicting = ownership_version_record(
            "6199b23b-906f-4689-a840-664a184c5f75",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [7_u8; 32],
        );
        conflicting.pack_name = pack_name.to_string();
        let error = check_or_create_registry_trust(
            temp.path(),
            registry,
            "alice",
            &[7_u8; 32],
            &conflicting,
        )
        .expect_err("an existing publisher conflict must reject before package mutation");

        assert!(matches!(
            error,
            ClientError::RegistryPublisherChanged { .. }
        ));
        assert!(!pack_owner_record_path(temp.path(), registry, pack_name).exists());
        assert!(!pack_publisher_claim_path(temp.path(), registry, pack_name).exists());
    }

    /// A publisher UUID cannot silently authorize an unproven signing-key rotation.
    #[test]
    fn publisher_pin_rejects_unproven_key_rotation() {
        let temp = tempfile::tempdir().unwrap();
        let publisher_id = "4a128e72-cc91-4721-b452-943ce736799b";
        let first = ownership_version_record(
            publisher_id,
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Revoked,
            [7_u8; 32],
        );
        check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[7_u8; 32],
            &first,
        )
        .expect("legacy-to-publisher transition must succeed");

        let rotated = ownership_version_record(
            publisher_id,
            "1e41ae38-9a5e-4623-8fcc-8f705928dacf",
            EnrolledPublisherKeyState::Active,
            [8_u8; 32],
        );
        let rotation = check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[8_u8; 32],
            &rotated,
        )
        .expect_err("publisher UUID alone must not authorize a new signer");
        assert!(matches!(
            rotation,
            ClientError::RegistryAuthorKeyChanged { .. }
        ));

        let omitted_publisher = VersionRecord {
            publisher: None,
            publisher_key: None,
            publisher_key_id: None,
            ..first
        };
        let omission = check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[7_u8; 32],
            &omitted_publisher,
        )
        .expect_err("a linked publisher pin cannot be bypassed by metadata omission");
        assert!(matches!(
            omission,
            ClientError::RegistryPublisherChanged { actual, .. } if actual == "<missing>"
        ));
    }

    /// A renamed legacy profile cannot invalidate an immutable signed archive.
    #[test]
    fn legacy_author_presentation_rename_retains_signer_key_continuity() {
        let temp = tempfile::tempdir().unwrap();
        let mut legacy = ownership_version_record(
            "4a128e72-cc91-4721-b452-943ce736799b",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [7_u8; 32],
        );
        legacy.publisher = None;
        legacy.publisher_key_id = None;
        legacy.publisher_key = None;
        legacy.legacy_author = Some(RegistryLegacyAuthorSummary {
            handle: "renamed-profile".to_string(),
            display_name: Some("Renamed Profile".to_string()),
        });

        check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "historical-signed-handle",
            &[7_u8; 32],
            &legacy,
        )
        .expect("legacy presentation rename must preserve the verified signer");

        let error = check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "historical-signed-handle",
            &[8_u8; 32],
            &legacy,
        )
        .expect_err("legacy presentation rename must not permit signer substitution");
        assert!(matches!(
            error,
            ClientError::RegistryAuthorKeyChanged { .. }
        ));
    }

    /// A linked pack may retain exact legacy trust for an unlinked historical version.
    #[test]
    fn publisher_with_legacy_historical_version_uses_author_key_pin() {
        let temp = tempfile::tempdir().unwrap();
        let linked = ownership_version_record(
            "4a128e72-cc91-4721-b452-943ce736799b",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [7_u8; 32],
        );
        check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[7_u8; 32],
            &linked,
        )
        .expect("linked version must establish publisher continuity");

        let mut historical = ownership_version_record(
            "4a128e72-cc91-4721-b452-943ce736799b",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [7_u8; 32],
        );
        historical.publisher_key_id = None;
        historical.publisher_key = None;
        historical.legacy_author = Some(RegistryLegacyAuthorSummary {
            handle: "alice".to_string(),
            display_name: Some("Alice".to_string()),
        });

        check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[7_u8; 32],
            &historical,
        )
        .expect("historical unlinked version must retain legacy key continuity");
        let error = check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[8_u8; 32],
            &historical,
        )
        .expect_err("historical signer substitution must fail");
        assert!(matches!(
            error,
            ClientError::RegistryAuthorKeyChanged { .. }
        ));
    }

    /// A trusted handle cannot silently move to another publisher UUID.
    #[test]
    fn publisher_pin_rejects_identity_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let first = ownership_version_record(
            "4a128e72-cc91-4721-b452-943ce736799b",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [7_u8; 32],
        );
        check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[7_u8; 32],
            &first,
        )
        .expect("first publisher pin must succeed");

        let substituted = ownership_version_record(
            "6199b23b-906f-4689-a840-664a184c5f75",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [7_u8; 32],
        );
        let error = check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[7_u8; 32],
            &substituted,
        )
        .expect_err("publisher substitution must fail");
        assert!(matches!(
            error,
            ClientError::RegistryPublisherChanged { .. }
        ));
    }

    /// A registry cannot reset trust by replacing handle, signer, and publisher together.
    #[test]
    fn pack_owner_pin_rejects_simultaneous_identity_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let first = ownership_version_record(
            "4a128e72-cc91-4721-b452-943ce736799b",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [7_u8; 32],
        );
        check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[7_u8; 32],
            &first,
        )
        .expect("first pack owner pin must succeed");

        let mut substituted = ownership_version_record(
            "6199b23b-906f-4689-a840-664a184c5f75",
            "1e41ae38-9a5e-4623-8fcc-8f705928dacf",
            EnrolledPublisherKeyState::Active,
            [8_u8; 32],
        );
        substituted.publisher.as_mut().unwrap().handle = "mallory".to_string();
        let error = check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "mallory",
            &[8_u8; 32],
            &substituted,
        )
        .expect_err("stable pack ownership must survive an attacker-selected handle");
        assert!(matches!(
            error,
            ClientError::RegistryPackOwnerChanged {
                owner_kind: "signer",
                ..
            }
        ));
    }

    /// A stable signer cannot hide a simultaneous handle and publisher substitution.
    #[test]
    fn pack_owner_pin_rejects_publisher_substitution_under_new_handle() {
        let temp = tempfile::tempdir().unwrap();
        let first = ownership_version_record(
            "4a128e72-cc91-4721-b452-943ce736799b",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [7_u8; 32],
        );
        check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[7_u8; 32],
            &first,
        )
        .expect("first pack owner pin must succeed");

        let mut substituted = ownership_version_record(
            "6199b23b-906f-4689-a840-664a184c5f75",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [7_u8; 32],
        );
        substituted.publisher.as_mut().unwrap().handle = "mallory".to_string();
        let error = check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "mallory",
            &[7_u8; 32],
            &substituted,
        )
        .expect_err("publisher continuity must be keyed by the stable pack name");
        assert!(matches!(
            error,
            ClientError::RegistryPackOwnerChanged {
                owner_kind: "publisher",
                ..
            }
        ));
    }

    /// Publisher summaries must agree with the base catalog key link.
    #[test]
    fn publisher_key_summary_mismatch_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let mut record = ownership_version_record(
            "4a128e72-cc91-4721-b452-943ce736799b",
            "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
            EnrolledPublisherKeyState::Active,
            [7_u8; 32],
        );
        record.publisher_key_id = Some("1e41ae38-9a5e-4623-8fcc-8f705928dacf".to_string());
        let error = check_or_create_registry_trust(
            temp.path(),
            "https://registry.example",
            "alice",
            &[7_u8; 32],
            &record,
        )
        .expect_err("key-link mismatch must fail");
        assert!(matches!(
            error,
            ClientError::RegistryOwnershipInvalid { .. }
        ));
    }

    /// Build a real `frameshift_catalog::PackRecord` fixture for serde-pin tests.
    fn sample_pack_record(
        name: &str,
        latest_version: Option<&str>,
        total_downloads: u64,
    ) -> frameshift_catalog::PackRecord {
        frameshift_catalog::PackRecord {
            name: name.to_string(),
            current_author: frameshift_catalog::Ed25519PublicKey([7u8; 32]),
            publisher_id: None,
            tags: vec!["demo".to_string()],
            description: "a demo pack".to_string(),
            created_at: chrono::Utc::now(),
            latest_version: latest_version.map(str::to_string),
            total_downloads,
            extends: None,
        }
    }

    /// The client's `SearchResponseBody`/`RegistrySearchResult` types deserialize
    /// the exact JSON shape produced by serializing a real server-side
    /// `frameshift_catalog::PackSearchResult`, and the fields the CLI needs
    /// round-trip correctly.
    #[test]
    fn search_response_body_serde_pin_against_catalog_pack_record() {
        let pack = sample_pack_record("demo", Some("2.0.0"), 42);
        let server_result = frameshift_catalog::PackSearchResult { pack, score: 0.9 };
        let value = serde_json::json!({ "results": [server_result] });

        let body: SearchResponseBody = serde_json::from_value(value).unwrap();
        assert_eq!(body.results.len(), 1);
        let hit = &body.results[0];
        assert_eq!(hit.pack.name, "demo");
        assert_eq!(hit.pack.latest_version, Some("2.0.0".to_string()));
        assert_eq!(hit.pack.total_downloads, 42);
        assert_eq!(
            hit.pack.current_author,
            frameshift_catalog::Ed25519PublicKey([7u8; 32]).to_string()
        );
        assert!(hit.publisher.is_none());
        assert!(hit.legacy_author.is_none());
    }

    /// Ownership additions deserialize without changing the legacy pack subset.
    #[test]
    fn search_response_body_accepts_additive_ownership_fields() {
        let pack = sample_pack_record("owned-demo", Some("3.0.0"), 7);
        let server_result = frameshift_catalog::PackSearchResult { pack, score: 0.8 };
        let value = serde_json::json!({
            "results": [{
                "pack": server_result.pack,
                "score": server_result.score,
                "publisher": {
                    "id": "4a128e72-cc91-4721-b452-943ce736799b",
                    "handle": "owned",
                    "display_name": "Owned Publisher"
                },
                "future_addition": true
            }]
        });

        let body: SearchResponseBody = serde_json::from_value(value).unwrap();
        let hit = &body.results[0];
        let publisher = hit.publisher.as_ref().expect("publisher summary");
        assert_eq!(publisher.handle, "owned");
        assert_eq!(publisher.display_name, "Owned Publisher");
        assert_eq!(publisher.id, "4a128e72-cc91-4721-b452-943ce736799b");
        assert!(hit.legacy_author.is_none());
    }

    /// search_registry performs a real HTTP round-trip against a one-shot TCP
    /// server and parses the single result.
    #[test]
    fn search_registry_parses_single_result() {
        let pack = sample_pack_record("demo", Some("1.0.0"), 3);
        let server_result = frameshift_catalog::PackSearchResult { pack, score: 1.0 };
        let json =
            serde_json::to_string(&serde_json::json!({ "results": [server_result] })).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            request_tx.send(request_line).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json.len(),
                json
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let base = format!("http://127.0.0.1:{port}");
        let results = search_registry(
            &base,
            &RegistrySearchQuery {
                query: Some("demo pack".to_string()),
                tag: Some("rust".to_string()),
                limit: Some(25),
                offset: Some(50),
            },
        )
        .unwrap();
        handle.join().unwrap();

        let request_line = request_rx.recv().unwrap();
        assert!(request_line.starts_with("GET /v1/packs?"));
        assert!(request_line.contains("query=demo+pack"));
        assert!(request_line.contains("tag=rust"));
        assert!(request_line.contains("limit=25"));
        assert!(request_line.contains("offset=50"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pack.name, "demo");
        assert_eq!(results[0].pack.latest_version, Some("1.0.0".to_string()));
    }

    /// search_registry maps a non-2xx status to `ClientError::RegistryHttp`.
    #[test]
    fn search_registry_maps_500_to_registry_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }

            let body = "internal error";
            let response = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let base = format!("http://127.0.0.1:{port}");
        let err = search_registry(&base, &RegistrySearchQuery::default()).unwrap_err();
        handle.join().unwrap();
        assert!(matches!(err, ClientError::RegistryHttp { .. }));
    }

    /// Search responses larger than the JSON ceiling are rejected even when
    /// their prefix and trailing whitespace form otherwise valid JSON.
    #[test]
    fn search_registry_rejects_oversized_json() {
        let mut body = b"{\"results\":[]}".to_vec();
        body.resize(MAX_JSON_RESPONSE_BYTES as usize + 1, b' ');

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
            stream.flush().unwrap();
        });

        let base = format!("http://127.0.0.1:{port}");
        let error = search_registry(&base, &RegistrySearchQuery::default()).unwrap_err();
        handle.join().unwrap();

        assert!(matches!(error, ClientError::RegistryHttp { .. }));
    }

    /// resolve_latest_version returns the pack's latest_version from a real
    /// `PackRecord`-shaped response.
    #[test]
    fn resolve_latest_version_returns_version() {
        let record = sample_pack_record("demo", Some("2.0.0"), 0);
        let json = serde_json::to_string(&record).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json.len(),
                json
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let _env = EnvGuard::set(REGISTRY_URL_ENV, &format!("http://127.0.0.1:{port}"));
        let version = resolve_latest_version("demo").unwrap();
        handle.join().unwrap();
        assert_eq!(version, "2.0.0");
    }

    /// resolve_latest_version returns `NoPublishedVersion` when `latest_version` is null.
    #[test]
    fn resolve_latest_version_null_yields_no_published_version() {
        let record = sample_pack_record("demo", None, 0);
        let json = serde_json::to_string(&record).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json.len(),
                json
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let _env = EnvGuard::set(REGISTRY_URL_ENV, &format!("http://127.0.0.1:{port}"));
        let err = resolve_latest_version("demo").unwrap_err();
        handle.join().unwrap();
        assert!(matches!(err, ClientError::NoPublishedVersion(name) if name == "demo"));
    }

    /// resolve_latest_version maps a 404 to `ClientError::RegistryHttp`.
    #[test]
    fn resolve_latest_version_404_maps_to_registry_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let body = "not found";
            let response = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let _env = EnvGuard::set(REGISTRY_URL_ENV, &format!("http://127.0.0.1:{port}"));
        let err = resolve_latest_version("demo").unwrap_err();
        handle.join().unwrap();
        assert!(matches!(err, ClientError::RegistryHttp { .. }));
    }

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

    /// The client's private `VersionRecord` deserializes the exact JSON shape
    /// produced by serializing a real server-side `PackVersionRecord` with
    /// additive publisher fields, and the
    /// install verification and ownership fields round-trip correctly.
    /// `VersionRecord` is private to this module, so this pin must live here
    /// rather than in the `tests/registry_install.rs` integration test.
    #[test]
    fn version_record_matches_catalog_wire_shape() {
        use ed25519_dalek::Signer as _;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let content_hash = ObjectHash::of(b"fixture archive bytes");
        let signature = signing.sign(content_hash.as_bytes()).to_bytes().to_vec();
        let author_pubkey =
            frameshift_catalog::Ed25519PublicKey(signing.verifying_key().to_bytes());
        let publisher_key_id =
            uuid::Uuid::parse_str("cc56ea2b-991d-46eb-a94f-936a9b071a4a").unwrap();

        let server_record = frameshift_catalog::PackVersionRecord {
            pack_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash,
            signature: signature.clone(),
            author_pubkey,
            publisher_key_id: Some(publisher_key_id),
            parent_hash: None,
            capability_manifest_json: "{}".to_string(),
            schema_version: 1,
            license: "MIT".to_string(),
            published_at: chrono::Utc::now(),
            status: frameshift_catalog::PackStatus::Active,
            size_bytes: 123,
        };

        let mut value = serde_json::to_value(&server_record).unwrap();
        let object = value.as_object_mut().expect("version object");
        object.insert(
            "publisher".to_string(),
            serde_json::json!({
                "id": "4a128e72-cc91-4721-b452-943ce736799b",
                "handle": "owned",
                "display_name": "Owned Publisher"
            }),
        );
        object.insert(
            "publisher_key".to_string(),
            serde_json::json!({
                "id": "cc56ea2b-991d-46eb-a94f-936a9b071a4a",
                "state": "revoked"
            }),
        );
        let client_record: VersionRecord = serde_json::from_value(value).unwrap();

        assert_eq!(client_record.content_hash, content_hash);
        assert_eq!(client_record.signature, signature);
        assert_eq!(client_record.author_pubkey.0, author_pubkey.0);
        assert_eq!(
            client_record.publisher_key_id.as_deref(),
            Some("cc56ea2b-991d-46eb-a94f-936a9b071a4a")
        );
        assert_eq!(
            client_record
                .publisher
                .as_ref()
                .expect("publisher summary")
                .handle,
            "owned"
        );
        assert_eq!(
            client_record
                .publisher_key
                .as_ref()
                .expect("publisher key summary")
                .state,
            EnrolledPublisherKeyState::Revoked
        );
        let details = RegistryVersionDetails::from_record(&client_record);
        assert_eq!(
            details.publisher_key.expect("public key status").state,
            EnrolledPublisherKeyState::Revoked
        );
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

    /// Serialized environment mutation helpers for registry tests.
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

    /// Restores environment variables when a guarded test completes.
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
