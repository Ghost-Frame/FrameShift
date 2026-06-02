//! Pack read endpoints under `/v1/packs`.
//!
//! All endpoints are anonymous (no authentication required at this milestone).
//! Write and publish endpoints are deferred to a follow-up milestone.
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
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use frameshift_catalog::filters::{PackSearchFilters, SortMode};
use frameshift_catalog::records::PackVersionRecord;
use frameshift_catalog::status::PackStatus;
use frameshift_catalog::CatalogError;
use frameshift_objects::{ObjectHash, ObjectStoreError};
use frameshift_pack::Pack;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::AppState;

/// HTTP header used to carry the session token for publish endpoints.
///
/// TODO(M5): real session token verification. For now any non-empty value is
/// accepted to gate the endpoint without coupling to a full auth system.
pub const SESSION_HEADER: &str = "x-frameshift-session";

/// Build the packs sub-router, mounted at `/v1/packs`.
///
/// Routes:
/// - `GET /` -> [`search_packs`]
/// - `GET /{name}` -> [`get_pack`]
/// - `GET /{name}/versions` -> [`list_pack_versions`]
/// - `GET /{name}/versions/{version}` -> [`get_pack_version`]
/// - `GET /{name}/versions/{version}/pack` -> [`download_pack_bytes`]
pub fn packs_router() -> Router<AppState> {
    Router::new()
        .route("/", get(search_packs).post(publish_pack))
        .route("/{name}", get(get_pack))
        .route(
            "/{name}/telemetry",
            get(crate::routes::telemetry::get_pack_telemetry),
        )
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
}

/// Maximum decoded size of an uploaded pack archive (16 MiB).
///
/// The compressed upload is gated by the server-level
/// `RequestBodyLimitLayer`; this constant caps the decompressed total so a
/// malicious gzip bomb cannot exhaust the temp directory.
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;

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

/// Verify that a non-empty `X-Frameshift-Session` header is present.
///
/// Returns `Ok(())` if the header exists and contains at least one
/// non-whitespace character. Returns `AppError::BadRequest` with a
/// `401`-shaped message via `unauthorized` otherwise.
///
/// TODO(M5): real session token verification (currently accepts any
/// non-empty value).
pub fn verify_session_header(headers: &HeaderMap) -> Result<(), AppError> {
    let token = headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if token.is_none() {
        return Err(AppError::Unauthorized(
            "missing or empty X-Frameshift-Session header".to_string(),
        ));
    }
    Ok(())
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

/// Extract a `.tar.gz` archive into `dir`, enforcing
/// [`MAX_DECOMPRESSED_BYTES`] across all entries.
///
/// Uses synchronous tar/flate2 inside `tokio::task::spawn_blocking` so the
/// async runtime stays responsive on large uploads.
async fn extract_targz(archive_bytes: Vec<u8>, dir: std::path::PathBuf) -> Result<(), AppError> {
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(archive_bytes));
        let mut archive = tar::Archive::new(gz);
        archive.set_preserve_permissions(false);
        archive.set_overwrite(true);

        let mut total: u64 = 0;
        let entries = archive
            .entries()
            .map_err(|e| AppError::BadRequest(format!("tar entries: {e}")))?;
        for entry in entries {
            let mut entry =
                entry.map_err(|e| AppError::BadRequest(format!("tar entry: {e}")))?;
            let size = entry.header().size().unwrap_or(0);
            total = total.saturating_add(size);
            if total > MAX_DECOMPRESSED_BYTES {
                return Err(AppError::BadRequest(format!(
                    "pack archive exceeds maximum decompressed size of {MAX_DECOMPRESSED_BYTES} bytes"
                )));
            }
            // Path-traversal protection: only allow paths relative to dir.
            let path = entry
                .path()
                .map_err(|e| AppError::BadRequest(format!("tar entry path: {e}")))?
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
            entry
                .unpack_in(&dir)
                .map_err(|e| AppError::BadRequest(format!("tar unpack: {e}")))?;
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
/// - `author_handle`: the handle of the publishing author. Used to look up the
///   registered Ed25519 public key in the catalog; the signature is verified
///   against that key.
///
/// Requires a non-empty `X-Frameshift-Session` header. Real session token
/// verification is deferred (TODO(M5)).
///
/// # Response
///
/// `200 OK` with body [`PublishResponse`].
///
/// # Errors
///
/// - `400 Bad Request` -- missing required multipart field, malformed pack
///   archive, signature is not 64 bytes, or the pack's declared author handle
///   does not match the supplied `author_handle`.
/// - `401 Unauthorized` -- session header missing/empty, author handle not
///   registered, or signature does not verify against the registered key.
/// - `409 Conflict` -- `(name, version)` already published.
/// - `500 Internal Server Error` -- catalog or object store backend failure.
pub async fn publish_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Response, AppError> {
    verify_session_header(&headers)?;

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

    // Look up the author's registered Ed25519 pubkey via the handle. A missing
    // handle is an authentication failure (401), not a 404, because the caller
    // is asserting authority they do not actually hold.
    let pubkey = match state.catalog.get_handle_pubkey(&author_handle).await {
        Ok(k) => k,
        Err(CatalogError::NotFound { .. }) => {
            return Err(AppError::Unauthorized(format!(
                "author handle not registered: {author_handle}"
            )));
        }
        Err(e) => return Err(AppError::from_catalog(e, "handle")),
    };
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

    let pack = Pack::from_dir(&pack_root)
        .map_err(|e| AppError::BadRequest(format!("invalid pack: {e}")))?;

    // Verify signature against canonical hash using the registered pubkey.
    // This is the authentication check: a wrong key means 401.
    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(&pack.canonical_hash(), &signature)
        .map_err(|_| AppError::Unauthorized("signature verification failed".to_string()))?;

    let manifest = pack.manifest().clone();

    // Manifest's declared handle must match the supplied one. A mismatch is a
    // client bug, not an auth failure.
    if manifest.author_handle != author_handle {
        return Err(AppError::BadRequest(format!(
            "manifest author_handle '{}' does not match form author_handle '{}'",
            manifest.author_handle, author_handle
        )));
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
        parent_hash,
        capability_manifest_json,
        schema_version: manifest.schema_version,
        conformance_score: manifest
            .conformance_baseline
            .as_ref()
            .map(|baseline| baseline.score),
        conformance_bundle_hash: manifest
            .conformance_baseline
            .as_ref()
            .map(|baseline| baseline.bundle_hash.clone()),
        license: manifest.license.clone().unwrap_or_default(),
        published_at: Utc::now(),
        status: PackStatus::Active,
        size_bytes: pack_archive.len() as u64,
    };

    // We deliberately do NOT roll back the object store on a catalog conflict.
    // The store is content-addressed so a re-put of the same bytes is a no-op,
    // and orphan blobs are reclaimable by a separate GC sweep. At-least-once
    // semantics are acceptable here.
    if let Err(e) = state.catalog.register_pack_version(version_record).await {
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

    // Best-effort: ensure the parent pack record exists so that `GET /v1/packs/{name}`
    // resolves. The catalog trait does not expose a separate "upsert pack" call,
    // so we rely on backends that auto-create the parent record on
    // `register_pack_version` (per the trait's documented invariant).

    let response = PublishResponse {
        pack_hash: canonical_hex,
        name: manifest.name,
        version: manifest.version,
        author_handle,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
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
/// ```ignore
/// // valid names
/// validate_pack_name("my-persona").is_ok();
/// validate_pack_name("MyPersona_v2").is_ok();
///
/// // invalid names
/// validate_pack_name("../etc/passwd").is_err();
/// validate_pack_name("a/b").is_err();
/// validate_pack_name("").is_err();
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
    pub results: Vec<frameshift_catalog::PackSearchResult>,
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

    let filters = PackSearchFilters {
        query: q.query,
        tag: q.tag,
        author: None, // author pubkey decoding deferred; pass None for now
        target_context: None,
        extends: q.extends,
        sort,
        limit: clamped,
        offset: q.offset.unwrap_or(0),
    };

    let results = state
        .catalog
        .search_packs(&filters)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack"))?;

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
/// `200 OK` with body `PackRecord` serialized as JSON.
///
/// # Backend calls
///
/// - `catalog.get_pack(name)` -- single catalog read.
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
) -> Result<Json<frameshift_catalog::PackRecord>, AppError> {
    validate_pack_name(&name)?;
    let pack = state
        .catalog
        .get_pack(&name)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack"))?;
    Ok(Json(pack))
}

/// `GET /v1/packs/{name}/versions`
///
/// List all published versions of a pack, ordered by `published_at ASC`.
///
/// # Response
///
/// `200 OK` with body `[PackVersionRecord, ...]`.
///
/// # Backend calls
///
/// - `catalog.list_pack_versions(name)` -- single catalog read.
///
/// # Errors
///
/// - `400 Bad Request` if `name` fails [`validate_pack_name`].
/// - `404 Not Found` if the pack does not exist.
/// - `500 Internal Server Error` on backend failure.
pub async fn list_pack_versions(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<frameshift_catalog::PackVersionRecord>>, AppError> {
    validate_pack_name(&name)?;
    let versions = state
        .catalog
        .list_pack_versions(&name)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack"))?;
    Ok(Json(versions))
}

/// `GET /v1/packs/{name}/versions/{version}`
///
/// Retrieve a specific version record for the given pack and semver string.
///
/// # Response
///
/// `200 OK` with body `PackVersionRecord` serialized as JSON.
///
/// # Backend calls
///
/// - `catalog.get_pack_version(name, version)` -- single catalog read.
///
/// # Errors
///
/// - `400 Bad Request` if `name` fails [`validate_pack_name`].
/// - `404 Not Found` if the pack or version does not exist.
/// - `500 Internal Server Error` on backend failure.
pub async fn get_pack_version(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<frameshift_catalog::PackVersionRecord>, AppError> {
    validate_pack_name(&name)?;
    let record = state
        .catalog
        .get_pack_version(&name, &version)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack_version"))?;
    Ok(Json(record))
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

    Ok(response)
}
