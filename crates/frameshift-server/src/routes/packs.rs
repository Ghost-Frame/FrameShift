//! Pack read endpoints under `/v1/packs`.
//!
//! The read router is anonymous. This module also exports the authenticated
//! [`publish_pack`] handler, which the application router mounts separately with
//! signed-request middleware.
//!
//! # Endpoints
//!
//! | Method | Path | Handler |
//! |---|---|---|
//! | GET | `/v1/packs` | [`search_packs`] |
//! | GET | `/v1/packs/{name}` | [`get_pack`] |
//! | GET | `/v1/packs/{name}/versions` | [`list_pack_versions`] |
//! | GET | `/v1/packs/{name}/versions/{version}` | [`get_pack_version`] |
//! | GET | `/v1/packs/{name}/versions/{version}/pack` | [`download_pack_bytes`] |
//!
//! # Path validation
//!
//! Pack names (`{name}`) are validated by [`validate_pack_name`] before any
//! catalog call. Names must match `[A-Za-z0-9_-]+` with no `/`, `..`, or other
//! path-traversal sequences. Invalid names produce a `400 Bad Request`.

use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use frameshift_catalog::filters::{PackSearchFilters, SortMode};
use frameshift_catalog::records::{
    PackRecord, PackVersionRecord, PublisherKeyRecord, PublisherProfileRecord,
};
use frameshift_catalog::status::PackStatus;
use frameshift_catalog::Ed25519PublicKey;
use frameshift_catalog::{CatalogError, MembershipState, PublisherKeyState, PublisherRole};
use frameshift_objects::{ObjectHash, ObjectStoreError};
use frameshift_pack::Pack;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::auth::VerifiedSigner;
use crate::error::AppError;
use crate::middleware::account::AuthenticatedAccount;
use crate::state::AppState;

/// Resolved signing authority for one legacy author or account-backed publisher.
struct PublishAuthority {
    /// Public key used to verify both request and pack signatures.
    pubkey: Ed25519PublicKey,
    /// Enrolled key identifier for account-backed publisher history.
    publisher_key_id: Option<Uuid>,
    /// Public publisher identity returned for account-backed publication.
    publisher: Option<PublisherSummary>,
    /// Enrolled key state returned for account-backed publication.
    publisher_key: Option<PublisherKeySummary>,
}

/// Stable public publisher identity attached additively to pack responses.
#[derive(Clone, Debug, Serialize)]
pub struct PublisherSummary {
    /// Stable publisher identifier.
    pub id: Uuid,
    /// Unique public publisher handle.
    pub handle: String,
    /// Public publisher display name.
    pub display_name: String,
}

/// Legacy author identity attached while compatibility fallback remains enabled.
#[derive(Clone, Debug, Serialize)]
pub struct LegacyAuthorSummary {
    /// Unique legacy author handle.
    pub handle: String,
    /// Optional legacy author display name.
    pub display_name: Option<String>,
}

/// Public state for the exact publisher key that signed a pack version.
#[derive(Clone, Debug, Serialize)]
pub struct PublisherKeySummary {
    /// Stable publisher key identifier.
    pub id: Uuid,
    /// Current lifecycle state of the historical signing key.
    pub state: PublisherKeyState,
}

/// Additive ownership response for one pack record.
#[derive(Debug, Serialize)]
pub struct PackResponse {
    /// Existing pack fields retained at their original JSON locations.
    #[serde(flatten)]
    pub pack: PackRecord,
    /// Preferred publisher identity when the pack has a linked owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<PublisherSummary>,
    /// Legacy author fallback when no publisher link exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_author: Option<LegacyAuthorSummary>,
}

/// Additive ownership response for one search result.
#[derive(Debug, Serialize)]
pub struct PackSearchResponse {
    /// Existing search result fields retained at their original JSON locations.
    #[serde(flatten)]
    pub result: frameshift_catalog::PackSearchResult,
    /// Preferred publisher identity when the pack has a linked owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<PublisherSummary>,
    /// Legacy author fallback when no publisher link exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_author: Option<LegacyAuthorSummary>,
}

/// Additive ownership response for one immutable pack version.
#[derive(Debug, Serialize)]
pub struct PackVersionResponse {
    /// Existing version fields retained at their original JSON locations.
    #[serde(flatten)]
    pub version: PackVersionRecord,
    /// Current publisher identity for the parent pack, when linked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<PublisherSummary>,
    /// Legacy signer identity when the version lacks a publisher key link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_author: Option<LegacyAuthorSummary>,
    /// Exact historical publisher key state when the version is linked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_key: Option<PublisherKeySummary>,
}

/// Request-local ownership lookup cache used to avoid repeated catalog reads.
struct OwnershipResolver<'a> {
    /// Shared server state containing the catalog backend.
    state: &'a AppState,
    /// Publisher summaries already resolved by stable identifier.
    publishers: HashMap<Uuid, PublisherSummary>,
    /// Legacy author summaries already resolved by signer key.
    legacy_authors: HashMap<Ed25519PublicKey, Option<LegacyAuthorSummary>>,
    /// Publisher keys already loaded by stable identifier.
    publisher_keys: HashMap<Uuid, PublisherKeyRecord>,
}

/// Ownership enrichment helpers that enforce publisher links fail closed.
impl<'a> OwnershipResolver<'a> {
    /// Create an empty request-local resolver.
    fn new(state: &'a AppState) -> Self {
        Self {
            state,
            publishers: HashMap::new(),
            legacy_authors: HashMap::new(),
            publisher_keys: HashMap::new(),
        }
    }

    /// Resolve a linked publisher or report an internal consistency failure.
    async fn publisher(&mut self, id: Uuid) -> Result<PublisherSummary, AppError> {
        if let Some(summary) = self.publishers.get(&id) {
            return Ok(summary.clone());
        }
        let profile = self
            .state
            .catalog
            .get_publisher(id)
            .await
            .map_err(|error| linked_catalog_error(error, "publisher", format!("publisher {id}")))?;
        let summary = publisher_summary(&profile);
        self.publishers.insert(id, summary.clone());
        Ok(summary)
    }

    /// Resolve a legacy signer when one exists without failing on absence.
    async fn legacy_author(
        &mut self,
        pubkey: Ed25519PublicKey,
    ) -> Result<Option<LegacyAuthorSummary>, AppError> {
        if let Some(summary) = self.legacy_authors.get(&pubkey) {
            return Ok(summary.clone());
        }
        let summary = match self.state.catalog.lookup_author(&pubkey).await {
            Ok(author) => Some(LegacyAuthorSummary {
                handle: author.handle,
                display_name: author.display_name,
            }),
            Err(CatalogError::NotFound { .. }) => None,
            Err(error) => return Err(AppError::from_catalog(error, "author")),
        };
        self.legacy_authors.insert(pubkey, summary.clone());
        Ok(summary)
    }

    /// Resolve and validate the exact publisher key linked to a version.
    async fn publisher_key(
        &mut self,
        publisher_id: Uuid,
        version: &PackVersionRecord,
    ) -> Result<PublisherKeySummary, AppError> {
        let key_id = version.publisher_key_id.ok_or_else(|| {
            AppError::Internal("publisher key resolution requires a linked key".to_string())
        })?;
        if !self.publisher_keys.contains_key(&key_id) {
            let key = self
                .state
                .catalog
                .get_publisher_key(key_id)
                .await
                .map_err(|error| {
                    linked_catalog_error(error, "publisher key", format!("publisher key {key_id}"))
                })?;
            self.publisher_keys.insert(key.id, key);
        }
        let key = self.publisher_keys.get(&key_id).ok_or_else(|| {
            AppError::Internal(format!(
                "version {}@{} links missing publisher key {key_id}",
                version.pack_name, version.version
            ))
        })?;
        if key.publisher_id != publisher_id || key.public_key != version.author_pubkey {
            return Err(AppError::Internal(format!(
                "version {}@{} publisher key evidence does not match its owner or signer",
                version.pack_name, version.version
            )));
        }
        Ok(PublisherKeySummary {
            id: key.id,
            state: key.state,
        })
    }

    /// Enrich one pack while allowing legacy fallback only when no publisher is linked.
    async fn pack_response(&mut self, pack: PackRecord) -> Result<PackResponse, AppError> {
        let (publisher, legacy_author) = match pack.publisher_id {
            Some(id) => (Some(self.publisher(id).await?), None),
            None => (None, self.legacy_author(pack.current_author).await?),
        };
        Ok(PackResponse {
            pack,
            publisher,
            legacy_author,
        })
    }

    /// Enrich one search result while retaining its original score and pack fields.
    async fn search_response(
        &mut self,
        result: frameshift_catalog::PackSearchResult,
    ) -> Result<PackSearchResponse, AppError> {
        let (publisher, legacy_author) = match result.pack.publisher_id {
            Some(id) => (Some(self.publisher(id).await?), None),
            None => (None, self.legacy_author(result.pack.current_author).await?),
        };
        Ok(PackSearchResponse {
            result,
            publisher,
            legacy_author,
        })
    }

    /// Enrich one version with parent ownership and exact signing-key evidence.
    async fn version_response(
        &mut self,
        pack: &PackRecord,
        version: PackVersionRecord,
    ) -> Result<PackVersionResponse, AppError> {
        let publisher = match pack.publisher_id {
            Some(id) => Some(self.publisher(id).await?),
            None => None,
        };
        let (legacy_author, publisher_key) = match version.publisher_key_id {
            Some(_) => {
                let publisher_id = pack.publisher_id.ok_or_else(|| {
                    AppError::Internal(format!(
                        "version {}@{} links a publisher key without a publisher owner",
                        version.pack_name, version.version
                    ))
                })?;
                (
                    None,
                    Some(self.publisher_key(publisher_id, &version).await?),
                )
            }
            None => (self.legacy_author(version.author_pubkey).await?, None),
        };
        Ok(PackVersionResponse {
            version,
            publisher,
            legacy_author,
            publisher_key,
        })
    }
}

/// Build the public subset of one publisher profile.
fn publisher_summary(profile: &PublisherProfileRecord) -> PublisherSummary {
    PublisherSummary {
        id: profile.id,
        handle: profile.handle.clone(),
        display_name: profile.display_name.clone(),
    }
}

/// Convert a missing linked record into an internal consistency failure.
fn linked_catalog_error(error: CatalogError, kind: &str, link: String) -> AppError {
    match error {
        CatalogError::NotFound { .. } => {
            AppError::Internal(format!("{kind} link is dangling: {link}"))
        }
        other => AppError::from_catalog(other, "ownership"),
    }
}

/// Build the packs **read** sub-router, mounted at `/v1/packs`.
///
/// Routes (all anonymous):
/// - `GET /` -> [`search_packs`]
/// - `GET /{name}` -> [`get_pack`]
/// - `GET /{name}/versions` -> [`list_pack_versions`]
/// - `GET /{name}/versions/{version}` -> [`get_pack_version`]
/// - `GET /{name}/versions/{version}/pack` -> [`download_pack_bytes`]
///
/// The mutating `POST /v1/packs` ([`publish_pack`]) is wired separately in
/// [`crate::router::app`] so it can carry the signed-request auth layer; it is
/// deliberately NOT part of this read router.
pub fn packs_router() -> Router<AppState> {
    Router::new()
        .route("/", get(search_packs))
        .route("/{name}", get(get_pack))
        .route("/{name}/versions", get(list_pack_versions))
        .route("/{name}/versions/{version}", get(get_pack_version))
        .route("/{name}/versions/{version}/pack", get(download_pack_bytes))
}

/// Response body for a successful `POST /v1/packs` publish.
#[derive(Debug, Serialize)]
pub struct PublishResponse {
    /// The canonical SHA-256 hash of the published pack (hex string).
    ///
    /// This is the same value the author signed and is independent of the
    /// archive encoding used during upload.
    pub pack_hash: String,
    /// The pack name (from the pack manifest).
    pub name: String,
    /// The pack version string (from the pack manifest).
    pub version: String,
    /// The handle of the author who published the pack.
    pub author_handle: String,
    /// Account-backed publisher identity when this was a publisher write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<PublisherSummary>,
    /// Exact enrolled key used for an account-backed publisher write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_key: Option<PublisherKeySummary>,
}

/// Maximum decoded size of an uploaded pack archive (16 MiB).
///
/// The compressed upload is gated by the server-level
/// `RequestBodyLimitLayer`; this constant caps the decompressed total so a
/// malicious gzip bomb cannot exhaust the temp directory.
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum number of filesystem entries accepted from one uploaded archive.
const MAX_ARCHIVE_ENTRIES: usize = 256;

/// Multipart fields collected from a publish upload.
///
/// All three are required; missing any of them produces `400 Bad Request`.
#[derive(Default)]
struct PublishFields {
    /// Raw bytes of the uploaded `.tar.gz` pack archive.
    pack_archive: Option<Vec<u8>>,
    /// Raw 64-byte Ed25519 signature over the canonical pack hash.
    signature: Option<Vec<u8>>,
    /// The handle of the publishing author, used to look up the registered key.
    author_handle: Option<String>,
}

/// Stream a multipart body into [`PublishFields`].
///
/// Reads each part in order, accumulating bytes for `pack` and `signature`
/// fields and parsing `author_handle` as UTF-8. Unknown fields are silently
/// skipped. Returns `Err(AppError::BadRequest)` on any multipart parsing
/// failure.
async fn collect_multipart(mut multipart: Multipart) -> Result<PublishFields, AppError> {
    let mut fields = PublishFields::default();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("malformed multipart body: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "pack" => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("pack field read failed: {e}")))?;
                fields.pack_archive = Some(bytes.to_vec());
            }
            "signature" => {
                let bytes = field.bytes().await.map_err(|e| {
                    AppError::BadRequest(format!("signature field read failed: {e}"))
                })?;
                fields.signature = Some(bytes.to_vec());
            }
            "author_handle" => {
                let text = field.text().await.map_err(|e| {
                    AppError::BadRequest(format!("author_handle field read failed: {e}"))
                })?;
                fields.author_handle = Some(text);
            }
            _ => {
                // Drain and ignore unknown fields.
                let _ = field.bytes().await;
            }
        }
    }
    Ok(fields)
}

/// A [`std::io::Read`] adapter that fails once more than `limit` total bytes
/// have been pulled from the underlying reader.
///
/// This is the decompression-bomb guard. It counts the *actual* bytes read
/// through the gzip decoder, so a tar entry that lies about its size in the
/// header (e.g. declares `size = 0` while carrying megabytes of data) cannot
/// bypass the ceiling -- the cap is enforced on real decompressed throughput,
/// not on the attacker-controlled header field.
struct LimitedReader<R> {
    /// The wrapped reader (the gzip-decompressed tar byte stream).
    inner: R,
    /// Maximum number of bytes allowed to be read in total.
    limit: u64,
    /// Running count of bytes read so far.
    read: u64,
}

/// Construction helpers for [`LimitedReader`].
impl<R: std::io::Read> LimitedReader<R> {
    /// Wrap `inner`, allowing at most `limit` total bytes to be read.
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            limit,
            read: 0,
        }
    }
}

/// Enforces the decompressed-byte ceiling while forwarding reads.
impl<R: std::io::Read> std::io::Read for LimitedReader<R> {
    /// Read into `buf`, returning an error once the cumulative byte count would
    /// exceed `limit`.
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

/// Extract a `.tar.gz` archive into `dir`, enforcing
/// [`MAX_DECOMPRESSED_BYTES`] and [`MAX_ARCHIVE_ENTRIES`] across all entries.
///
/// Uses synchronous tar/flate2 inside `tokio::task::spawn_blocking` so the
/// async runtime stays responsive on large uploads.
async fn extract_targz(archive_bytes: Vec<u8>, dir: std::path::PathBuf) -> Result<(), AppError> {
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(archive_bytes));
        // Cap the actual decompressed byte count (not the attacker-controlled
        // tar header `size` field) so a forged header cannot exhaust the temp
        // directory.
        let limited = LimitedReader::new(gz, MAX_DECOMPRESSED_BYTES);
        let mut archive = tar::Archive::new(limited);
        archive.set_preserve_permissions(false);
        archive.set_overwrite(true);

        let entries = archive.entries().map_err(|e| {
            // The underlying io::Error text may embed the server's temp
            // directory path; log it internally and return a generic,
            // path-free message to the client.
            tracing::warn!(error = %e, "failed to read tar entries");
            AppError::BadRequest("invalid archive: unreadable tar entries".to_string())
        })?;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_ARCHIVE_ENTRIES {
                return Err(AppError::BadRequest(
                    "pack archive contains too many entries".to_string(),
                ));
            }
            let mut entry = entry.map_err(|e| {
                tracing::warn!(error = %e, "failed to read tar entry");
                AppError::BadRequest("invalid archive: unreadable tar entry".to_string())
            })?;
            // Reject any entry that is not a regular file or directory. Symlinks,
            // hardlinks, and device nodes have no legitimate place in a pack and
            // could be used to plant a link that escapes the extraction dir or
            // is later read through.
            let entry_type = entry.header().entry_type();
            if !(entry_type.is_file() || entry_type.is_dir()) {
                return Err(AppError::BadRequest(
                    "pack archive contains a non-regular file entry".to_string(),
                ));
            }
            // Path-traversal protection: only allow paths relative to dir.
            let path = entry
                .path()
                .map_err(|e| {
                    tracing::warn!(error = %e, "failed to read tar entry path");
                    AppError::BadRequest("invalid archive: unreadable entry path".to_string())
                })?
                .into_owned();
            if path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(AppError::BadRequest(
                    "pack archive contains unsafe path".to_string(),
                ));
            }
            entry.unpack_in(&dir).map_err(|e| {
                // io::Error from unpack_in may embed the server's absolute
                // temp-directory path; log it internally, keep the client
                // response generic.
                tracing::warn!(error = %e, "failed to unpack tar entry");
                AppError::BadRequest("invalid archive: failed to extract entry".to_string())
            })?;
        }
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(format!("tar extraction task panicked: {e}")))?
}

/// Determine the pack root directory inside an extraction target.
///
/// A pack tarball can either be flat (`pack.toml` at the root of the extract
/// dir) or nested (`<single-dir>/pack.toml`). This helper detects both
/// shapes and returns the correct path. Returns `AppError::BadRequest` if
/// no `pack.toml` is found.
fn find_pack_root(extract_dir: &std::path::Path) -> Result<std::path::PathBuf, AppError> {
    if extract_dir.join("pack.toml").is_file() {
        return Ok(extract_dir.to_path_buf());
    }
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(extract_dir)
        .map_err(|e| AppError::BadRequest(format!("read extract dir: {e}")))?
        .filter_map(|r| r.ok().map(|d| d.path()))
        .collect();
    entries.sort();
    if entries.len() == 1 && entries[0].is_dir() && entries[0].join("pack.toml").is_file() {
        return Ok(entries[0].clone());
    }
    Err(AppError::BadRequest(
        "pack archive does not contain a pack.toml at the root".to_string(),
    ))
}

/// `POST /v1/packs`
///
/// Publish a new pack version. Accepts a multipart upload with three fields:
///
/// - `pack`: the pack contents as a gzipped tar archive.
/// - `signature`: the raw 64-byte Ed25519 signature over the canonical pack
///   hash (the same value returned by [`frameshift_pack::Pack::canonical_hash`]).
/// - `author_handle`: the legacy author or account-backed publisher handle.
///
/// # Authentication
///
/// The mutating route carries the signed-request layer
/// ([`crate::middleware::auth::require_signed_request`]), so by the time this
/// handler runs a [`VerifiedSigner`] extension is present, proving the live
/// request was signed by some Ed25519 key. Legacy handles require the verified
/// signer to remain their registered author key. Account-backed publisher
/// handles additionally require a validated bearer account with an active
/// owner membership, and the request signer must be an active enrolled key for
/// that publisher. The pack content signature is verified against the same
/// request signer in both modes.
///
/// # Response
///
/// `200 OK` with body [`PublishResponse`].
///
/// # Errors
///
/// - `400 Bad Request` -- missing required multipart field, malformed pack
///   archive, signature is not 64 bytes, the pack's declared author handle
///   does not match the supplied `author_handle`, or the manifest carries the
///   `local-unsigned` author_pubkey sentinel (reserved for unsigned local
///   packs, never publishable).
/// - `401 Unauthorized` -- author handle not registered, account bearer is
///   absent or invalid for an account-backed publisher, request signer is not
///   authorized, or the pack content signature does not verify.
/// - `403 Forbidden` -- bearer account lacks an active owner membership.
/// - `409 Conflict` -- `(name, version)` already published.
/// - `500 Internal Server Error` -- catalog or object store backend failure.
pub async fn publish_pack(
    State(state): State<AppState>,
    Extension(signer): Extension<VerifiedSigner>,
    authenticated: Option<Extension<AuthenticatedAccount>>,
    multipart: Multipart,
) -> Result<Response, AppError> {
    if state.config.publisher_pubkeys.is_empty() {
        return Err(AppError::NotFound("pack publishing disabled".to_string()));
    }
    if !state.config.publisher_allowed(&signer.pubkey) {
        return Err(AppError::Forbidden("publisher is not admitted".to_string()));
    }
    let fields = collect_multipart(multipart).await?;

    let pack_archive = fields
        .pack_archive
        .ok_or_else(|| AppError::BadRequest("missing multipart field: pack".to_string()))?;
    let signature_bytes = fields
        .signature
        .ok_or_else(|| AppError::BadRequest("missing multipart field: signature".to_string()))?;
    let author_handle = fields.author_handle.ok_or_else(|| {
        AppError::BadRequest("missing multipart field: author_handle".to_string())
    })?;

    if signature_bytes.len() != 64 {
        return Err(AppError::BadRequest(format!(
            "signature must be exactly 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    let sig_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppError::BadRequest("signature must be 64 bytes".to_string()))?;
    let signature = Signature::from_bytes(&sig_arr);

    let authority = resolve_publish_authority(
        &state,
        &author_handle,
        signer.pubkey,
        authenticated.as_ref().map(|extension| &extension.0),
    )
    .await?;
    let pubkey = authority.pubkey;

    let verifying_key = VerifyingKey::from_bytes(&pubkey.0)
        .map_err(|e| AppError::Internal(format!("invalid registered pubkey: {e}")))?;

    // Extract tar.gz into a tempdir, then load the pack from the extracted
    // directory. The TempDir is dropped at the end of the function and the
    // bytes are moved into the object store before that point.
    let tmp = tempfile::TempDir::new().map_err(|e| AppError::Internal(format!("tempdir: {e}")))?;
    extract_targz(pack_archive.clone(), tmp.path().to_path_buf()).await?;

    let pack_root = find_pack_root(tmp.path())?;

    // Write the supplied signature into the pack dir under `signature.sig` so
    // Pack::verify can pick it up via its on-disk load path.
    std::fs::write(pack_root.join("signature.sig"), &signature_bytes)
        .map_err(|e| AppError::Internal(format!("write signature.sig: {e}")))?;

    let pack = Pack::from_dir(&pack_root).map_err(|e| {
        // `PackError` variants can embed the server's absolute temp-directory
        // path (e.g. `Io`, `NonUtf8Path`); log the detailed error server-side
        // and return a generic, path-free message to the client.
        tracing::warn!(error = %e, "failed to load pack from extracted archive");
        AppError::BadRequest("invalid pack".to_string())
    })?;

    // Verify signature against canonical hash using the registered pubkey.
    // This is the authentication check: a wrong key means 401.
    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(&pack.canonical_hash(), &signature)
        .map_err(|_| AppError::Unauthorized("authentication failed".to_string()))?;

    let manifest = pack.manifest().clone();

    // Manifest's declared handle must match the supplied one. A mismatch is a
    // client bug, not an auth failure.
    if manifest.author_handle != author_handle {
        return Err(AppError::BadRequest(format!(
            "manifest author_handle '{}' does not match form author_handle '{}'",
            manifest.author_handle, author_handle
        )));
    }

    // The local-unsigned author_pubkey sentinel is reserved for unsigned local
    // packs; it must never enter the catalog, even under a valid signature
    // from a registered author (clients would misclassify the installed pack).
    if manifest.is_local_unsigned() {
        return Err(AppError::BadRequest(
            "manifest author_pubkey \"local-unsigned\" is not publishable; declare the author's \
             real Ed25519 public key (64 lowercase hex chars)"
                .to_string(),
        ));
    }
    if manifest.author_pubkey != hex::encode(pubkey.0) {
        tracing::warn!(
            handle = %author_handle,
            "manifest author key does not match registered author key"
        );
        return Err(AppError::BadRequest(
            "manifest author_pubkey does not match the registered author".to_string(),
        ));
    }

    let canonical_hex = pack.canonical_hash_hex();

    // Reject duplicates BEFORE touching the object store. We use the existing
    // `get_pack_version` read; a NotFound result means we may proceed.
    // Without a single trait-level transaction we accept that two concurrent
    // publishes of the same (name, version) may both pass this check; the
    // catalog adapter's own uniqueness constraint is the final authority and
    // the second call will return `Conflict`.
    match state
        .catalog
        .get_pack_version(&manifest.name, &manifest.version)
        .await
    {
        Ok(_) => {
            return Err(AppError::Conflict(format!(
                "pack version already published: {}@{}",
                manifest.name, manifest.version
            )));
        }
        Err(CatalogError::NotFound { .. }) => {}
        Err(e) => return Err(AppError::from_catalog(e, "pack_version")),
    }

    // Store the uploaded archive bytes. We address by the SHA-256 of the
    // bytes-on-the-wire so the existing FsPackStore verify-on-write contract
    // holds. The canonical pack hash (independent of archive encoding) is
    // recorded as `pack_hash` in the response.
    let content_hash = ObjectHash::of(&pack_archive);
    let object_existed = state
        .objects
        .exists(&content_hash)
        .await
        .map_err(|e| AppError::Internal(format!("object store exists check failed: {e}")))?;
    if let Err(e) = state.objects.put(&content_hash, &pack_archive).await {
        return Err(map_object_put_error(e));
    }

    let parent_hash = manifest
        .parent_hash
        .as_deref()
        .and_then(|s| s.strip_prefix("sha256:").or(Some(s)))
        .and_then(|s| ObjectHash::from_hex(s).ok());

    let capability_manifest_json = match &manifest.capability_manifest {
        Some(cm) => serde_json::to_string(cm)
            .map_err(|e| AppError::Internal(format!("capability_manifest serialize: {e}")))?,
        None => "{}".to_string(),
    };

    let version_record = PackVersionRecord {
        pack_name: manifest.name.clone(),
        version: manifest.version.clone(),
        content_hash,
        signature: signature_bytes.clone(),
        author_pubkey: pubkey,
        publisher_key_id: authority.publisher_key_id,
        parent_hash,
        capability_manifest_json,
        schema_version: manifest.schema_version,
        license: manifest.license.clone().unwrap_or_default(),
        published_at: Utc::now(),
        status: PackStatus::Active,
        size_bytes: pack_archive.len() as u64,
    };

    let quota = frameshift_catalog::PublishQuota {
        max_versions: (state.config.max_versions_per_author != 0)
            .then_some(state.config.max_versions_per_author),
        max_bytes: (state.config.max_bytes_per_author != 0)
            .then_some(state.config.max_bytes_per_author),
        max_total_bytes: (state.config.max_total_bytes != 0)
            .then_some(state.config.max_total_bytes),
    };
    if let Err(e) = state
        .catalog
        .register_pack_version_with_quota(version_record, quota)
        .await
    {
        // Deterministic policy rejections must not consume object-store space.
        // Before deleting, search by content hash because an identical
        // concurrent publish may have committed after our duplicate precheck.
        // Catalog read failures retain the object: leaking space is safer than
        // deleting a blob that may back a committed version.
        if !object_existed
            && matches!(
                &e,
                CatalogError::Validation(_) | CatalogError::Unauthorized { .. }
            )
        {
            let referenced = match state
                .catalog
                .get_active_pack_version_by_hash(&content_hash)
                .await
            {
                Ok(_) => true,
                Err(CatalogError::NotFound { .. }) => false,
                Err(read_error) => {
                    tracing::error!(
                        pack = %manifest.name,
                        version = %manifest.version,
                        error = %read_error,
                        "retaining rejected publication object after catalog read failure"
                    );
                    true
                }
            };
            if !referenced {
                if let Err(delete_error) = state.objects.delete(&content_hash).await {
                    tracing::error!(
                        hash = %content_hash,
                        error = %delete_error,
                        "failed to reclaim object after rejected publication"
                    );
                }
            }
        }
        return Err(AppError::from_catalog(e, "pack_version"));
    }

    // Record the `extends` base persona name from the manifest onto the pack
    // head record. This is a best-effort update: if it fails, the pack is still
    // published but the extends field will be missing from search results.
    if let Err(e) = state
        .catalog
        .set_pack_extends(&manifest.name, manifest.extends.as_deref())
        .await
    {
        tracing::warn!(
            pack = %manifest.name,
            error = %e,
            "set_pack_extends failed after successful publish; extends field not set"
        );
    }

    // Record the manifest's description and tags onto the pack head record so
    // that marketplace full-text search (which ranks on `description`) can find
    // this pack. Best-effort: if it fails, the pack is still published but will
    // be invisible to query search and show blank metadata until a follow-up
    // metadata update succeeds.
    let description = manifest.description.clone().unwrap_or_default();
    if let Err(e) = state
        .catalog
        .set_pack_metadata(&manifest.name, &description, &manifest.tags)
        .await
    {
        tracing::warn!(
            pack = %manifest.name,
            error = %e,
            "set_pack_metadata failed after successful publish; description/tags not set"
        );
    }

    // Best-effort: ensure the parent pack record exists so that `GET /v1/packs/{name}`
    // resolves. The catalog trait does not expose a separate "upsert pack" call,
    // so we rely on backends that auto-create the parent record on
    // `register_pack_version` (per the trait's documented invariant).

    // Increment the publish counter after all catalog and object-store calls
    // have succeeded. Failures above return early via `?`, so reaching this
    // point guarantees a fully committed publish.
    state.metrics.packs_published_total.inc();

    let response = PublishResponse {
        pack_hash: canonical_hex,
        name: manifest.name,
        version: manifest.version,
        author_handle,
        publisher: authority.publisher,
        publisher_key: authority.publisher_key,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Resolve legacy handle ownership or require an active account-backed publisher authority.
async fn resolve_publish_authority(
    state: &AppState,
    author_handle: &str,
    signer_pubkey: Ed25519PublicKey,
    authenticated: Option<&AuthenticatedAccount>,
) -> Result<PublishAuthority, AppError> {
    match state.catalog.get_publisher_by_handle(author_handle).await {
        Ok(profile) => {
            let legacy_pubkey = match state.catalog.get_handle_pubkey(author_handle).await {
                Ok(pubkey) => Some(pubkey),
                Err(CatalogError::NotFound { .. }) => None,
                Err(error) => return Err(AppError::from_catalog(error, "handle")),
            };
            return resolve_account_publisher_authority(
                state,
                profile,
                signer_pubkey,
                authenticated,
                legacy_pubkey,
            )
            .await;
        }
        Err(CatalogError::NotFound { .. }) => {}
        Err(error) => return Err(AppError::from_catalog(error, "publisher")),
    }

    match state.catalog.get_handle_pubkey(author_handle).await {
        Ok(pubkey) => {
            if signer_pubkey != pubkey {
                tracing::warn!(
                    handle = %author_handle,
                    signer = %signer_pubkey,
                    "publish attempt where request signer is not the handle owner"
                );
                return Err(AppError::Unauthorized("authentication failed".to_string()));
            }
            Ok(PublishAuthority {
                pubkey,
                publisher_key_id: None,
                publisher: None,
                publisher_key: None,
            })
        }
        Err(CatalogError::NotFound { .. }) => {
            tracing::warn!(
                handle = %author_handle,
                "publish attempt for unregistered author handle"
            );
            Err(AppError::Unauthorized("authentication failed".to_string()))
        }
        Err(error) => Err(AppError::from_catalog(error, "handle")),
    }
}

/// Require active account ownership and an active enrolled key for one publisher.
async fn resolve_account_publisher_authority(
    state: &AppState,
    profile: PublisherProfileRecord,
    signer_pubkey: Ed25519PublicKey,
    authenticated: Option<&AuthenticatedAccount>,
    legacy_pubkey: Option<Ed25519PublicKey>,
) -> Result<PublishAuthority, AppError> {
    let authenticated =
        authenticated.ok_or_else(|| AppError::Unauthorized("authentication failed".to_string()))?;
    let membership = state
        .catalog
        .get_publisher_membership(authenticated.account.id, profile.id)
        .await
        .map_err(|error| match error {
            CatalogError::NotFound { .. } => {
                AppError::Forbidden("active publisher ownership required".to_string())
            }
            other => AppError::from_catalog(other, "publisher membership"),
        })?;
    if membership.role != PublisherRole::Owner || membership.state != MembershipState::Active {
        return Err(AppError::Forbidden(
            "active publisher ownership required".to_string(),
        ));
    }
    let keys = state
        .catalog
        .list_publisher_keys(profile.id)
        .await
        .map_err(|error| AppError::from_catalog(error, "publisher key"))?;
    if legacy_pubkey
        .is_some_and(|legacy_pubkey| !keys.iter().any(|key| key.public_key == legacy_pubkey))
    {
        return Err(AppError::Internal(format!(
            "publisher {} conflicts with an unrelated legacy handle key",
            profile.id
        )));
    }
    let key = keys
        .into_iter()
        .find(|key| key.public_key == signer_pubkey && key.state == PublisherKeyState::Active)
        .ok_or_else(|| AppError::Unauthorized("authentication failed".to_string()))?;
    Ok(PublishAuthority {
        pubkey: signer_pubkey,
        publisher_key_id: Some(key.id),
        publisher: Some(publisher_summary(&profile)),
        publisher_key: Some(PublisherKeySummary {
            id: key.id,
            state: key.state,
        }),
    })
}

/// Map an [`ObjectStoreError`] from a publish-time `put` into the appropriate
/// [`AppError`]. `HashMismatch` here is a server bug (we computed the hash
/// ourselves) so it maps to `Internal`.
fn map_object_put_error(err: ObjectStoreError) -> AppError {
    match err {
        ObjectStoreError::HashMismatch { .. } => {
            AppError::Internal(format!("object store hash mismatch on put: {err}"))
        }
        ObjectStoreError::QuotaExceeded { .. } => {
            AppError::Internal(format!("object store quota exceeded: {err}"))
        }
        other => AppError::Internal(format!("object store put failed: {other}")),
    }
}

/// Validate a pack name path segment.
///
/// Accepted characters: `[A-Za-z0-9_-]`. The name must be non-empty and must
/// not contain `/`, `..`, or any other path-traversal sequence.
///
/// Returns `AppError::BadRequest` if the name fails validation.
///
/// # Examples
///
/// ```
/// use frameshift_server::routes::packs::validate_pack_name;
///
/// // valid names
/// assert!(validate_pack_name("my-persona").is_ok());
/// assert!(validate_pack_name("MyPersona_v2").is_ok());
///
/// // invalid names
/// assert!(validate_pack_name("../etc/passwd").is_err());
/// assert!(validate_pack_name("a/b").is_err());
/// assert!(validate_pack_name("").is_err());
/// ```
pub fn validate_pack_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() {
        return Err(AppError::BadRequest(
            "pack name must not be empty".to_string(),
        ));
    }
    if name.contains("..") || name.contains('/') {
        return Err(AppError::BadRequest(
            "pack name must not contain path traversal sequences".to_string(),
        ));
    }
    let all_valid = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !all_valid {
        return Err(AppError::BadRequest(
            "pack name must match [A-Za-z0-9_-]+".to_string(),
        ));
    }
    Ok(())
}

/// Validate a pack version string for safe interpolation into HTTP responses.
///
/// Versions are typically semver-shaped (`1.2.3`, `1.0.0-rc.1+build.5`) so the
/// allowed character set is `[A-Za-z0-9._+-]+`.  This is intentionally broader
/// than [`validate_pack_name`] to admit dots, plus signs, and other semver
/// punctuation while still blocking path traversal sequences (`..`, `/`) and
/// any byte that could break a `Content-Disposition` header value (CR, LF,
/// quotes, backslashes, non-ASCII).
///
/// # Errors
///
/// Returns [`AppError::BadRequest`] when the version is empty, contains a
/// path-traversal sequence, or contains a character outside the allowed set.
pub fn validate_pack_version(version: &str) -> Result<(), AppError> {
    if version.is_empty() {
        return Err(AppError::BadRequest(
            "pack version must not be empty".to_string(),
        ));
    }
    if version.contains("..") || version.contains('/') {
        return Err(AppError::BadRequest(
            "pack version must not contain path traversal sequences".to_string(),
        ));
    }
    let all_valid = version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'));
    if !all_valid {
        return Err(AppError::BadRequest(
            "pack version must match [A-Za-z0-9._+-]+".to_string(),
        ));
    }
    Ok(())
}

/// Query parameters accepted by `GET /v1/packs`.
///
/// All fields are optional. `sort` defaults to `recent`; `limit` defaults to
/// `20`; `offset` defaults to `0`. Clients that omit `limit` receive the
/// backend's default page size rather than all results.
#[derive(Debug, Default, Deserialize)]
pub struct SearchQuery {
    /// Full-text search query matched against pack name and description.
    pub query: Option<String>,

    /// Filter by a single tag (exact match).
    pub tag: Option<String>,

    /// Filter by author public key (base64url-no-padding).
    pub author: Option<String>,

    /// Sort mode: `trending`, `top-rated`, or `recent`.
    ///
    /// Invalid values produce a `400 Bad Request`.
    pub sort: Option<String>,

    /// Maximum number of results to return. Clamped to `config.max_search_limit`.
    ///
    /// A value of `0` is valid and returns an empty array.
    pub limit: Option<u32>,

    /// Number of results to skip before returning matches.
    pub offset: Option<u32>,

    /// Filter by base persona pack name (exact match on the `extends` column).
    ///
    /// Returns only packs whose manifest declared they extend the given base pack.
    /// `None` (parameter omitted) means no filter is applied.
    pub extends: Option<String>,
}

/// Response body for `GET /v1/packs`.
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    /// The matching pack records with relevance scores.
    pub results: Vec<PackSearchResponse>,
}

/// `GET /v1/packs?query=&tag=&author=&sort=&limit=&offset=`
///
/// Search the catalog with optional filters. Anonymous; no auth required at
/// this milestone.
///
/// The `limit` parameter is clamped to `config.max_search_limit`. When clamped,
/// the response includes a `Warning` header: `299 - "limit clamped to <max>"`.
///
/// # Response
///
/// `200 OK` with body `{"results": [PackSearchResult, ...]}`.
///
/// # Backend calls
///
/// - `catalog.search_packs(filters)` -- single catalog read.
///
/// # Errors
///
/// - `400 Bad Request` if `sort` is not one of `trending`, `top-rated`, `recent`.
/// - `400 Bad Request` if `limit` exceeds the configured `max_search_limit`
///   (instead of a Warning, this only applies when the hard cap would be exceeded).
///   Actually: limit is clamped with a Warning header, not rejected.
/// - `500 Internal Server Error` on backend failure (request-id only; no
///   internal details in body).
pub async fn search_packs(
    State(state): State<AppState>,
    Query(q): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let sort = match q.sort.as_deref() {
        None | Some("recent") => SortMode::Recent,
        Some("trending") => SortMode::Trending,
        Some("top-rated") => SortMode::TopRated,
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "invalid sort mode '{other}'; must be one of: trending, top-rated, recent"
            )));
        }
    };

    let max = state.config.max_search_limit;
    let raw_limit = q.limit.unwrap_or(20);
    let clamped = raw_limit.min(max);
    let was_clamped = clamped < raw_limit;

    // Decode the optional author filter (base64url-no-pad Ed25519 public key).
    // An invalid value is a client error rather than a silently-ignored filter.
    let author = match q.author.as_deref() {
        Some(s) => Some(s.parse::<Ed25519PublicKey>().map_err(|_| {
            AppError::BadRequest(
                "author must be a base64url-encoded Ed25519 public key".to_string(),
            )
        })?),
        None => None,
    };

    let filters = PackSearchFilters {
        query: q.query,
        tag: q.tag,
        author,
        target_context: None,
        extends: q.extends,
        sort,
        limit: clamped,
        offset: q.offset.unwrap_or(0),
    };

    let raw_results = state
        .catalog
        .search_packs(&filters)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack"))?;
    let results = if state.config.publisher_ownership_reads {
        let mut resolver = OwnershipResolver::new(&state);
        let mut enriched = Vec::with_capacity(raw_results.len());
        for result in raw_results {
            enriched.push(resolver.search_response(result).await?);
        }
        enriched
    } else {
        raw_results
            .into_iter()
            .map(|result| PackSearchResponse {
                result,
                publisher: None,
                legacy_author: None,
            })
            .collect()
    };

    // Increment the search counter after a successful catalog call.
    state.metrics.searches_total.inc();

    let body = Json(SearchResponse { results });

    if was_clamped {
        let warning_value = format!("299 - \"limit clamped to {max}\"");
        let mut resp = (StatusCode::OK, body).into_response();
        if let Ok(hv) = HeaderValue::from_str(&warning_value) {
            resp.headers_mut().insert("Warning", hv);
        }
        Ok(resp)
    } else {
        Ok((StatusCode::OK, body).into_response())
    }
}

/// `GET /v1/packs/{name}`
///
/// Retrieve the top-level pack record for the given pack name.
///
/// # Response
///
/// `200 OK` with a flattened [`PackResponse`]. Ownership fields are omitted when
/// read enrichment is disabled.
///
/// # Backend calls
///
/// - `catalog.get_pack(name)` -- loads the pack.
/// - Ownership profile or legacy author lookup when read enrichment is enabled.
///
/// # Errors
///
/// - `400 Bad Request` if `name` contains path-traversal sequences or invalid
///   characters (see [`validate_pack_name`]).
/// - `404 Not Found` if no pack with this name exists.
/// - `500 Internal Server Error` on backend failure (request-id only; no
///   internal details in body).
pub async fn get_pack(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<PackResponse>, AppError> {
    validate_pack_name(&name)?;
    let pack = state
        .catalog
        .get_pack(&name)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack"))?;
    let response = if state.config.publisher_ownership_reads {
        OwnershipResolver::new(&state).pack_response(pack).await?
    } else {
        PackResponse {
            pack,
            publisher: None,
            legacy_author: None,
        }
    };
    Ok(Json(response))
}

/// Query parameters accepted by `GET /v1/packs/{name}/versions`.
///
/// Both fields are optional. `limit` defaults to `100` and is clamped to
/// `config.max_search_limit`, mirroring [`SearchQuery`]; `offset` defaults to
/// `0`.
#[derive(Debug, Default, Deserialize)]
pub struct VersionsQuery {
    /// Maximum number of version records to return. Clamped to
    /// `config.max_search_limit`.
    ///
    /// A value of `0` is valid and returns an empty array.
    pub limit: Option<u32>,

    /// Number of version records to skip before returning matches, applied
    /// after ordering by `published_at ASC`.
    pub offset: Option<u32>,
}

/// `GET /v1/packs/{name}/versions?limit=&offset=`
///
/// List published versions of a pack, ordered by `published_at ASC`.
///
/// The `limit` parameter defaults to `100` and is clamped to
/// `config.max_search_limit`, the same convention [`search_packs`] uses. When
/// clamped, the response includes a `Warning` header:
/// `299 - "limit clamped to <max>"`.
///
/// The catalog trait's `list_pack_versions` has no `limit`/`offset` of its
/// own (unlike [`frameshift_catalog::CatalogBackend::list_authors`]), so
/// pagination is applied here, over the full version list returned by the
/// backend, rather than pushed down into the query.
///
/// # Response
///
/// `200 OK` with a JSON array of [`PackVersionResponse`] values, containing at
/// most `limit` records starting at `offset`.
///
/// # Backend calls
///
/// - `catalog.list_pack_versions(name)` -- loads the page source.
/// - Parent pack and ownership lookups when read enrichment is enabled.
///
/// # Errors
///
/// - `400 Bad Request` if `name` fails [`validate_pack_name`].
/// - `404 Not Found` if the pack does not exist.
/// - `500 Internal Server Error` on backend failure.
pub async fn list_pack_versions(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<VersionsQuery>,
) -> Result<Response, AppError> {
    validate_pack_name(&name)?;

    let max = state.config.max_search_limit;
    let raw_limit = q.limit.unwrap_or(100);
    let clamped = raw_limit.min(max);
    let was_clamped = clamped < raw_limit;
    let offset = q.offset.unwrap_or(0) as usize;

    let versions = state
        .catalog
        .list_pack_versions(&name)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack"))?;

    let page: Vec<_> = versions
        .into_iter()
        .skip(offset)
        .take(clamped as usize)
        .collect();
    let page = if state.config.publisher_ownership_reads {
        let pack = load_version_parent(&state, &name).await?;
        let mut resolver = OwnershipResolver::new(&state);
        let mut enriched = Vec::with_capacity(page.len());
        for version in page {
            enriched.push(resolver.version_response(&pack, version).await?);
        }
        enriched
    } else {
        page.into_iter()
            .map(|version| PackVersionResponse {
                version,
                publisher: None,
                legacy_author: None,
                publisher_key: None,
            })
            .collect()
    };

    let body = Json(page);

    if was_clamped {
        let warning_value = format!("299 - \"limit clamped to {max}\"");
        let mut resp = (StatusCode::OK, body).into_response();
        if let Ok(hv) = HeaderValue::from_str(&warning_value) {
            resp.headers_mut().insert("Warning", hv);
        }
        Ok(resp)
    } else {
        Ok((StatusCode::OK, body).into_response())
    }
}

/// `GET /v1/packs/{name}/versions/{version}`
///
/// Retrieve a specific version record for the given pack and semver string.
///
/// # Response
///
/// `200 OK` with a flattened [`PackVersionResponse`]. Ownership fields are
/// omitted when read enrichment is disabled.
///
/// # Backend calls
///
/// - `catalog.get_pack_version(name, version)` -- loads the version.
/// - Parent pack and ownership lookups when read enrichment is enabled.
///
/// # Errors
///
/// - `400 Bad Request` if `name` fails [`validate_pack_name`].
/// - `404 Not Found` if the pack or version does not exist.
/// - `500 Internal Server Error` on backend failure.
pub async fn get_pack_version(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<PackVersionResponse>, AppError> {
    validate_pack_name(&name)?;
    validate_pack_version(&version)?;
    let record = state
        .catalog
        .get_pack_version(&name, &version)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack_version"))?;
    let response = if state.config.publisher_ownership_reads {
        let pack = load_version_parent(&state, &name).await?;
        OwnershipResolver::new(&state)
            .version_response(&pack, record)
            .await?
    } else {
        PackVersionResponse {
            version: record,
            publisher: None,
            legacy_author: None,
            publisher_key: None,
        }
    };
    Ok(Json(response))
}

/// Load a version's parent pack and fail closed when the relationship is broken.
async fn load_version_parent(state: &AppState, name: &str) -> Result<PackRecord, AppError> {
    state
        .catalog
        .get_pack(name)
        .await
        .map_err(|error| linked_catalog_error(error, "pack", format!("version parent {name}")))
}

/// `GET /v1/packs/{name}/versions/{version}/pack`
///
/// Download the raw pack archive bytes for the given version.
///
/// The catalog is queried first to confirm the version exists and to obtain
/// the `content_hash`. The object store is then queried for the bytes. If the
/// catalog has the version but the object store does not have the blob, a
/// `502 Bad Gateway` is returned to indicate a storage inconsistency.
///
/// # Response
///
/// `200 OK` with:
/// - `Content-Type: application/octet-stream`
/// - `Content-Disposition: attachment; filename="<name>-<version>.pack"`
/// - Binary pack archive as the response body.
///
/// # Backend calls
///
/// 1. `catalog.get_pack_version(name, version)` -- to retrieve `content_hash`.
/// 2. `objects.get(content_hash)` -- to retrieve the pack bytes.
///
/// # Errors
///
/// - `400 Bad Request` if `name` fails [`validate_pack_name`].
/// - `404 Not Found` if the pack or version does not exist in the catalog.
/// - `500 Internal Server Error` on catalog or object store backend failure
///   (request-id only; no internal details in body).
/// - `502 Bad Gateway` if the catalog version record exists but the object
///   store does not have the corresponding blob. This indicates a storage
///   inconsistency that requires operator intervention.
pub async fn download_pack_bytes(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Response, AppError> {
    validate_pack_name(&name)?;
    // Version is interpolated into a `Content-Disposition` header value; reject
    // any input that would break header validity or smuggle CR/LF.  Uses a
    // semver-shaped allowlist so legitimate versions (`1.2.3`, `1.0.0-rc.1`)
    // pass while CRLF, quotes, backslashes, and path-traversal sequences fail
    // with a 400 (not a 500 at header construction time).
    validate_pack_version(&version)?;

    // Step 1: confirm version exists and get the content hash.
    let version_record = state
        .catalog
        .get_pack_version(&name, &version)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack_version"))?;

    // Do not serve tombstoned (taken-down) versions, even via the direct URL.
    // Search already hides them; this closes the direct-download bypass so a
    // takedown is effective on every path. A 404 (not 403) avoids confirming
    // that the version ever existed.
    if !matches!(version_record.status, PackStatus::Active) {
        return Err(AppError::NotFound(format!(
            "pack version not found: {name}@{version}"
        )));
    }

    // Step 2: fetch bytes from the object store.
    // A NotFound here means catalog/objects are inconsistent -> 502.
    let bytes = state
        .objects
        .get(&version_record.content_hash)
        .await
        .map_err(|e| AppError::from_objects(e, "pack"))?;

    let disposition = format!("attachment; filename=\"{name}-{version}.pack\"");

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&disposition).map_err(|e| {
                AppError::Internal(format!("invalid content-disposition header: {e}"))
            })?,
        )
        .body(Body::from(bytes))
        .map_err(|e| AppError::Internal(format!("response builder error: {e}")))?;

    // Count successful direct-download responses.
    state.metrics.pack_downloads_total.inc();

    // Record the download event for trending ranking -- feeds the 7-day velocity
    // used by SortMode::Trending. Best-effort: a failure here must not fail the
    // download the client already received.
    if let Err(e) = state.catalog.record_download(&name, &version).await {
        tracing::warn!(pack = %name, version = %version, error = %e, "record_download failed");
    }

    // Increment the cumulative download counter -- feeds `total_downloads` on
    // the pack record shown on the marketplace catalog page. Best-effort: same
    // policy as record_download above; warn and continue on failure. NotFound
    // is unreachable here (the version record was fetched above), but the
    // best-effort pattern handles it safely regardless.
    if let Err(e) = state
        .catalog
        .increment_download_counter(&name, &version)
        .await
    {
        tracing::warn!(pack = %name, version = %version, error = %e, "increment_download_counter failed");
    }

    Ok(response)
}
