//! `GET /v1/authors/{pubkey}` -- author lookup by Ed25519 public key.
//!
//! The `{pubkey}` path segment is a base64url-no-padding encoded 32-byte
//! Ed25519 public key. Invalid encodings and wrong-length keys are rejected
//! with `400 Bad Request` before the catalog is queried.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use frameshift_catalog::identity::Ed25519PublicKey;

use crate::error::AppError;
use crate::state::AppState;

/// Build the authors sub-router, mounted at `/v1/authors`.
///
/// Routes:
/// - `GET /{pubkey}` -> [`get_author`]
pub fn authors_router() -> Router<AppState> {
    Router::new().route("/{pubkey}", get(get_author))
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
/// # Backend calls
///
/// - `catalog.lookup_author(pubkey)` -- single catalog read.
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

/// Parse a base64url-no-padding string into an [`Ed25519PublicKey`].
///
/// Returns `AppError::BadRequest` if the string is not valid base64url or if
/// the decoded byte slice is not exactly 32 bytes.
fn parse_pubkey(b64: &str) -> Result<Ed25519PublicKey, AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| AppError::BadRequest("pubkey is not valid base64url".to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("pubkey must decode to exactly 32 bytes".to_string()))?;
    Ok(Ed25519PublicKey(arr))
}
