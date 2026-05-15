//! `GET /v1/handles/{handle}` -- author lookup by human-readable handle.
//!
//! Handles are unique human-readable aliases for author public keys (e.g.
//! `"alice"`). The `{handle}` path segment is taken verbatim from the URL;
//! no additional validation is applied beyond what Axum's path extractor
//! provides. The catalog is the authority on whether a handle exists.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};

use crate::error::AppError;
use crate::state::AppState;

/// Build the handles sub-router, mounted at `/v1/handles`.
///
/// Routes:
/// - `GET /{handle}` -> [`get_handle`]
pub fn handles_router() -> Router<AppState> {
    Router::new().route("/{handle}", get(get_handle))
}

/// `GET /v1/handles/{handle}`
///
/// Look up a registered author by their unique handle string.
///
/// # Response
///
/// `200 OK` with body `AuthorRecord` serialized as JSON.
///
/// # Backend calls
///
/// - `catalog.lookup_author_by_handle(handle)` -- single catalog read.
///
/// # Errors
///
/// - `404 Not Found` if no author is registered with this handle.
/// - `500 Internal Server Error` on catalog backend failure (request-id only;
///   no internal details in body).
pub async fn get_handle(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Json<frameshift_catalog::AuthorRecord>, AppError> {
    let author = state
        .catalog
        .lookup_author_by_handle(&handle)
        .await
        .map_err(|e| AppError::from_catalog(e, "author"))?;
    Ok(Json(author))
}
