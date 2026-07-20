//! Author endpoints under `/v1/authors`.
//!
//! # Read (anonymous)
//!
//! - `GET /` -> [`list_authors_route`] -- paginated listing of all
//!   registered authors.
//! - `GET /{pubkey}` -> [`get_author`] -- look up an author by base64url
//!   Ed25519 public key.
//!
//! # Write (Ed25519 signed-request authenticated)
//!
//! These carry the signed-request layer (wired in [`crate::router::app`]), so a
//! verified [`crate::auth::VerifiedSigner`] identifies the live caller:
//!
//! - `POST /` -> [`register_author_route`] -- claim a handle for the *signing*
//!   key. The new author's pubkey is taken from the verified signer, so a
//!   caller can only register a handle for a key they actually control.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use frameshift_catalog::identity::Ed25519PublicKey;
use frameshift_catalog::records::AuthorRecord;
use frameshift_catalog::CatalogError;
use serde::{Deserialize, Serialize};

use crate::auth::VerifiedSigner;
use crate::error::AppError;
use crate::state::AppState;

/// Build the authors **read** sub-router, mounted at `/v1/authors`.
///
/// Routes:
/// - `GET /` -> [`list_authors_route`]
/// - `GET /{pubkey}` -> [`get_author`]
///
/// The mutating routes are built by [`authors_write_router`] and wired with the
/// signed-request layer in [`crate::router::app`]; that router also declares a
/// `POST /` (`register_author_route`), which axum merges with this router's
/// `GET /` onto the same path, mirroring how `packs_router`'s `GET /` and
/// [`crate::routes::packs::publish_pack`]'s `POST /` share `/v1/packs`.
pub fn authors_router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_authors_route))
        .route("/{pubkey}", get(get_author))
}

/// Build the authors **write** sub-router (mutating routes only).
///
/// Returned without any auth layer; [`crate::router::app`] applies the
/// signed-request `route_layer` before merging it with [`authors_router`].
///
/// Routes:
/// - `POST /` -> [`register_author_route`]
pub fn authors_write_router() -> Router<AppState> {
    Router::new().route("/", post(register_author_route))
}

/// `GET /v1/authors/{pubkey}`
///
/// Look up a registered author by their base64url-encoded Ed25519 public key.
///
/// The `pubkey` path segment must be a valid base64url-no-padding string that
/// decodes to exactly 32 bytes. Any other value produces a `400 Bad Request`
/// response before the catalog is queried.
///
/// # Response
///
/// `200 OK` with body `AuthorRecord` serialized as JSON.
///
/// # Errors
///
/// - `400 Bad Request` if `pubkey` is not valid base64url or decodes to a
///   length other than 32 bytes.
/// - `404 Not Found` if no author is registered for this key.
/// - `500 Internal Server Error` on catalog backend failure (request-id only;
///   no internal details in body).
pub async fn get_author(
    State(state): State<AppState>,
    Path(pubkey_b64): Path<String>,
) -> Result<Json<frameshift_catalog::AuthorRecord>, AppError> {
    let key = parse_pubkey(&pubkey_b64)?;
    let author = state
        .catalog
        .lookup_author(&key)
        .await
        .map_err(|e| AppError::from_catalog(e, "author"))?;
    Ok(Json(author))
}

/// Query parameters accepted by `GET /v1/authors`.
///
/// Both fields are optional. `limit` defaults to `100` and is clamped to
/// `config.max_search_limit`, mirroring
/// [`crate::routes::packs::SearchQuery`] and
/// [`crate::routes::packs::VersionsQuery`]; `offset` defaults to `0`.
#[derive(Debug, Default, Deserialize)]
pub struct AuthorsListQuery {
    /// Maximum number of author records to return. Clamped to
    /// `config.max_search_limit`.
    ///
    /// A value of `0` is valid and returns an empty array.
    pub limit: Option<u32>,

    /// Number of author records to skip before returning matches.
    pub offset: Option<u32>,
}

/// Response body for `GET /v1/authors`.
#[derive(Debug, Serialize)]
pub struct AuthorsListResponse {
    /// The requested page of registered authors, in the stable order
    /// documented on [`frameshift_catalog::CatalogBackend::list_authors`].
    pub authors: Vec<frameshift_catalog::AuthorRecord>,
}

/// `GET /v1/authors?limit=&offset=`
///
/// List registered authors. Anonymous; no auth required.
///
/// The `limit` parameter defaults to `100` and is clamped to
/// `config.max_search_limit`, the same convention
/// [`crate::routes::packs::search_packs`] and
/// [`crate::routes::packs::list_pack_versions`] use. When clamped, the
/// response includes a `Warning` header: `299 - "limit clamped to <max>"`.
///
/// Unlike `GET /v1/packs/{name}/versions`, pagination here is pushed all the
/// way down into `catalog.list_authors(limit, offset)`, which already
/// accepts both parameters at the trait level.
///
/// # Response
///
/// `200 OK` with body `{"authors": [AuthorRecord, ...]}`.
///
/// # Backend calls
///
/// - `catalog.list_authors(limit, offset)` -- single catalog read.
///
/// # Errors
///
/// - `500 Internal Server Error` on backend failure (request-id only; no
///   internal details in body).
pub async fn list_authors_route(
    State(state): State<AppState>,
    Query(q): Query<AuthorsListQuery>,
) -> Result<Response, AppError> {
    let max = state.config.max_search_limit;
    let raw_limit = q.limit.unwrap_or(100);
    let clamped = raw_limit.min(max);
    let was_clamped = clamped < raw_limit;
    let offset = q.offset.unwrap_or(0);

    let authors = state
        .catalog
        .list_authors(clamped, offset)
        .await
        .map_err(|e| AppError::from_catalog(e, "author"))?;

    let body = Json(AuthorsListResponse { authors });

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

/// Request body for `POST /v1/authors`.
#[derive(Debug, Deserialize)]
pub struct RegisterAuthorRequest {
    /// The handle to claim (e.g. `"alice"`). Validated by [`validate_handle`].
    pub handle: String,
    /// Optional human-readable display name. An empty/whitespace-only string is
    /// treated as `None` (the catalog rejects empty display names).
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Response body for a successful author registration.
#[derive(Debug, Serialize)]
pub struct RegisterAuthorResponse {
    /// The handle that was registered.
    pub handle: String,
    /// The base64url-no-pad Ed25519 public key the handle now maps to (the
    /// verified request signer).
    pub pubkey: String,
}

/// `POST /v1/authors`
///
/// Register a new author and claim a handle for the **signing key**.
///
/// The author's public key is taken from the verified signed-request signer
/// ([`VerifiedSigner`]) -- the request body does NOT carry a key -- so a caller
/// can only ever register a handle for a key they actually control. The handle
/// is also written to the handles table (mirroring the offline seed tool) so
/// the publish path resolves it via `get_handle_pubkey`.
///
/// # Response
///
/// `201 Created` with body [`RegisterAuthorResponse`].
///
/// # Errors
///
/// - `400 Bad Request` -- the handle fails [`validate_handle`].
/// - `409 Conflict` -- the handle is already owned by a different key, or the
///   signing key is already registered under a different handle.
/// - `500 Internal Server Error` -- catalog backend failure.
pub async fn register_author_route(
    State(state): State<AppState>,
    Extension(signer): Extension<VerifiedSigner>,
    Json(body): Json<RegisterAuthorRequest>,
) -> Result<Response, AppError> {
    if state.config.publisher_pubkeys.is_empty() {
        return Err(AppError::NotFound(
            "publisher registration disabled".to_string(),
        ));
    }
    if !state.config.publisher_allowed(&signer.pubkey) {
        return Err(AppError::Forbidden("publisher is not admitted".to_string()));
    }
    validate_handle(&body.handle)?;

    // Do not let registration hijack an existing handle. `register_author` below
    // guards the `authors` table, but a handle can exist in the `handles` table
    // with no matching `authors` row (the seed tool calls `set_handle_pubkey`
    // directly), so without this check an attacker could register such a handle
    // and have the `set_handle_pubkey` call below overwrite its owner. Only
    // the current owner may idempotently confirm their own handle; a
    // different owner is a 409. Done before any write so a
    // rejected registration leaves no partial `authors` row behind.
    match state.catalog.get_handle_pubkey(&body.handle).await {
        Ok(current) if current != signer.pubkey => {
            return Err(AppError::Conflict(format!(
                "handle already taken by {current}"
            )));
        }
        // Handle is unowned (free) or already owned by this signer: proceed.
        Ok(_) | Err(CatalogError::NotFound { .. }) => {}
        Err(e) => return Err(AppError::from_catalog(e, "handle")),
    }

    // Treat empty/whitespace display names as absent; the catalog rejects "".
    let display_name = match body.display_name {
        Some(s) if s.trim().is_empty() => None,
        other => other,
    };

    let record = AuthorRecord {
        pubkey: signer.pubkey,
        handle: body.handle.clone(),
        display_name,
        created_at: Utc::now(),
        oauth_links: vec![],
    };

    state
        .catalog
        .register_author(record)
        .await
        .map_err(|e| AppError::from_catalog(e, "author"))?;

    // Populate the handles table so `get_handle_pubkey` (publish path) resolves
    // the new handle to this key.
    state
        .catalog
        .set_handle_pubkey(&body.handle, signer.pubkey)
        .await
        .map_err(|e| AppError::from_catalog(e, "handle"))?;

    let resp = RegisterAuthorResponse {
        handle: body.handle,
        pubkey: signer.pubkey.to_string(),
    };
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

/// Validate a handle string.
///
/// Accepted: 1..=64 characters from `[A-Za-z0-9_-]`. Returns
/// [`AppError::BadRequest`] otherwise.
fn validate_handle(handle: &str) -> Result<(), AppError> {
    if handle.is_empty() || handle.len() > 64 {
        return Err(AppError::BadRequest(
            "handle must be between 1 and 64 characters".to_string(),
        ));
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError::BadRequest(
            "handle must match [A-Za-z0-9_-]+".to_string(),
        ));
    }
    Ok(())
}

/// Parse a base64url-no-padding string into an [`Ed25519PublicKey`].
///
/// Returns `AppError::BadRequest` if:
/// - the string exceeds 256 characters (length cap),
/// - any character is outside the base64url alphabet `[A-Za-z0-9_-]`
///   (charset guard -- avoids injecting arbitrary bytes into the catalog key),
/// - the string is not valid base64url, or
/// - the decoded byte slice is not exactly 32 bytes.
fn parse_pubkey(b64: &str) -> Result<Ed25519PublicKey, AppError> {
    // Length cap -- reject obviously oversized inputs before any allocation.
    if b64.len() > 256 {
        return Err(AppError::BadRequest(
            "pubkey exceeds maximum length".to_string(),
        ));
    }
    // Charset guard -- only allow base64url characters ([A-Za-z0-9_-]).
    if !b64
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError::BadRequest(
            "pubkey contains characters outside the base64url alphabet".to_string(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| AppError::BadRequest("pubkey is not valid base64url".to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("pubkey must decode to exactly 32 bytes".to_string()))?;
    Ok(Ed25519PublicKey(arr))
}
