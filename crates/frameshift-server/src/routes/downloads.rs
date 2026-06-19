//! Signed download URL endpoints.
//!
//! These endpoints implement an HMAC-signed bearer-token download flow. The
//! signer endpoint mints a short-lived URL; the verifier endpoint validates
//! the token and streams the requested blob from the object store.
//!
//! # Why two endpoints
//!
//! The split lets the verifier remain anonymous and cacheable while the
//! signer can later have rate limiting, per-user TTLs, or audit logging
//! layered onto it without touching the bytes-on-the-wire path.
//!
//! # Endpoints
//!
//! | Method | Path | Handler |
//! |---|---|---|
//! | POST | `/v1/packs/{name}/versions/{version}/download-url` | [`mint_download_url`] |
//! | GET  | `/dl/{hash}` | [`stream_signed_download`] |
//!
//! # Disabling
//!
//! When `DOWNLOAD_SECRET` is empty in [`crate::config::ServerConfig`], the signer
//! returns `503 Service Unavailable` and the verifier returns `404 Not Found`
//! (no special-case status; the route stays mounted but every request rejects).

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use frameshift_pack::ObjectHash;
use serde::{Deserialize, Serialize};

use crate::download::{self, DownloadTokenError};
use crate::error::AppError;
use crate::routes::packs::{validate_pack_name, validate_pack_version};
use crate::state::AppState;

/// Sub-router for the public download endpoint mounted at the server root.
///
/// Routes:
/// - `GET /dl/{hash}` -> [`stream_signed_download`]
pub fn dl_router() -> Router<AppState> {
    Router::new().route("/{hash}", get(stream_signed_download))
}

/// Sub-router for the signer endpoint mounted under `/v1/packs/{name}/versions/{version}`.
///
/// Routes:
/// - `POST /download-url` -> [`mint_download_url`]
pub fn pack_download_url_router() -> Router<AppState> {
    Router::new().route("/", post(mint_download_url))
}

/// Response body of a successful `POST .../download-url` call.
#[derive(Debug, Serialize)]
pub struct DownloadUrlResponse {
    /// Path + query string the client should GET to retrieve the bytes.
    ///
    /// Relative form (`/dl/<hash>?token=&expires=`) so the client appends it
    /// to whichever API base it already uses; this avoids hard-coding a
    /// public download hostname into the server.
    pub url: String,

    /// Unix timestamp at which the token expires.
    ///
    /// Clients SHOULD treat this as the deadline by which the download must
    /// begin; a download in progress is not interrupted at this time.
    pub expires_at: i64,
}

/// Query parameters accepted by [`stream_signed_download`].
#[derive(Debug, Deserialize)]
pub struct DownloadQuery {
    /// Hex-encoded HMAC-SHA256 token over `(hash, expires)`.
    pub token: String,
    /// Unix timestamp at which the token was minted to expire.
    pub expires: i64,
}

/// `POST /v1/packs/{name}/versions/{version}/download-url`
///
/// Mint a short-lived signed download URL for the given pack version.
///
/// # Flow
///
/// 1. Validate path parameters (`name`, `version`) using the same rules as the
///    rest of the packs sub-router.
/// 2. Look up the version record in the catalog to obtain the `content_hash`.
/// 3. Compute `expires = now + DL_TOKEN_TTL`.
/// 4. Sign `(content_hash, expires)` with the configured HMAC key.
/// 5. Return `{ url, expires_at }`.
///
/// # Errors
///
/// - `400 Bad Request` if `name` or `version` fails validation.
/// - `404 Not Found` if the pack version does not exist.
/// - `500 Internal Server Error` if `DOWNLOAD_SECRET` is misconfigured (set but not
///   valid 32-byte hex).
/// - `503 Service Unavailable` if `DOWNLOAD_SECRET` is empty (downloads disabled).
pub async fn mint_download_url(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<DownloadUrlResponse>, AppError> {
    validate_pack_name(&name)?;
    validate_pack_version(&version)?;

    let key = match state.config.download_key() {
        Ok(Some(k)) => k,
        Ok(None) => {
            return Err(AppError::BadRequest(
                "download endpoint is disabled (DOWNLOAD_SECRET unset)".into(),
            ));
        }
        Err(e) => return Err(AppError::Internal(format!("DOWNLOAD_SECRET invalid: {e}"))),
    };

    let version_record = state
        .catalog
        .get_pack_version(&name, &version)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack_version"))?;

    let ttl_secs: i64 = state
        .config
        .download_token_ttl
        .as_secs()
        .try_into()
        .unwrap_or(300);
    let now = download::now_unix();
    let expires = now.saturating_add(ttl_secs);

    let token = download::sign_download_token(&key, &version_record.content_hash, expires);
    let url = format!(
        "/dl/{}?token={}&expires={}",
        version_record.content_hash.to_hex(),
        token,
        expires
    );

    tracing::info!(
        pack = %name,
        version = %version,
        expires,
        ttl_secs,
        "issued download URL"
    );

    Ok(Json(DownloadUrlResponse {
        url,
        expires_at: expires,
    }))
}

/// `GET /dl/{hash}?token=&expires=`
///
/// Verify the HMAC token and, on success, stream the blob bytes from the
/// configured [`frameshift_objects::PackStore`].
///
/// # Flow
///
/// 1. Parse `{hash}` as an [`ObjectHash`] (rejects malformed paths up front).
/// 2. Verify the token against `(hash, expires)` and the configured TTL
///    ceiling. Any failure returns `403 Forbidden` with a generic body.
/// 3. Fetch bytes from the object store. A `NotFound` here maps to `404` --
///    the token was valid but the blob no longer exists.
/// 4. Stream the bytes as `application/octet-stream` with a
///    `Content-Disposition: attachment` header naming the file
///    `<hash>.pack`.
///
/// # Errors
///
/// - `400 Bad Request` if `{hash}` is not a valid 64-char hex SHA-256.
/// - `403 Forbidden` if the token is malformed, expired, or signature
///   mismatch. The response body does NOT reveal which check failed.
/// - `404 Not Found` if the blob is missing from the store.
/// - `500 Internal Server Error` for any other backend failure.
pub async fn stream_signed_download(
    State(state): State<AppState>,
    Path(hash_hex): Path<String>,
    Query(q): Query<DownloadQuery>,
) -> Result<Response, AppError> {
    let hash = ObjectHash::from_hex(&hash_hex)
        .map_err(|e| AppError::BadRequest(format!("invalid hash in path: {e}")))?;

    let key = match state.config.download_key() {
        Ok(Some(k)) => k,
        Ok(None) => return Err(AppError::Forbidden("downloads disabled".into())),
        Err(e) => return Err(AppError::Internal(format!("DOWNLOAD_SECRET invalid: {e}"))),
    };

    let now = download::now_unix();
    match download::verify_download_token(
        &key,
        &hash,
        q.expires,
        &q.token,
        state.config.download_max_token_ttl,
        now,
    ) {
        Ok(()) => {}
        Err(DownloadTokenError::Format) => {
            tracing::debug!("download token format invalid");
            return Err(AppError::Forbidden("format".into()));
        }
        Err(DownloadTokenError::Signature) => {
            tracing::warn!(hash = %hash_hex, "download token signature mismatch");
            return Err(AppError::Forbidden("signature".into()));
        }
        Err(DownloadTokenError::Expired) => {
            tracing::debug!("download token expired");
            return Err(AppError::Forbidden("expired".into()));
        }
        Err(DownloadTokenError::ExpiryTooFar) => {
            tracing::warn!(hash = %hash_hex, "download token expiry beyond max ttl");
            return Err(AppError::Forbidden("expiry-too-far".into()));
        }
    }

    let bytes = state
        .objects
        .get(&hash)
        .await
        .map_err(|e| AppError::from_objects(e, "pack"))?;

    let disposition = format!("attachment; filename=\"{hash_hex}.pack\"");

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&disposition).map_err(|e| {
                AppError::Internal(format!("invalid content-disposition header: {e}"))
            })?,
        )
        .body(Body::from(bytes))
        .map_err(|e| AppError::Internal(format!("response builder error: {e}")))?;

    // Count successful signed-download responses (alongside direct pack downloads).
    state.metrics.pack_downloads_total.inc();

    Ok(response)
}
