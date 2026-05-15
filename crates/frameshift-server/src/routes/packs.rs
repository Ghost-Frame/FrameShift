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
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use frameshift_catalog::filters::{PackSearchFilters, SortMode};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::AppState;

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
        .route("/", get(search_packs))
        .route("/{name}", get(get_pack))
        .route("/{name}/versions", get(list_pack_versions))
        .route("/{name}/versions/{version}", get(get_pack_version))
        .route("/{name}/versions/{version}/pack", get(download_pack_bytes))
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
