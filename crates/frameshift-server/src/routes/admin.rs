//! Administrative endpoints under `/v1/admin`.
//!
//! # Endpoints
//!
//! | Method | Path | Handler |
//! |---|---|---|
//! | POST | `/v1/admin/packs/{name}/{version}/tombstone` | [`tombstone_pack_route`] |
//!
//! # Authentication and authorization
//!
//! Every route in this module carries the Ed25519 signed-request layer
//! ([`crate::middleware::auth::require_signed_request`]), wired in
//! [`crate::router::app`] exactly like the other mutating routers. That layer
//! proves the request was produced by the holder of *some* Ed25519 key, but it
//! does not by itself grant admin authority --
//! [`CatalogBackend`](frameshift_catalog::CatalogBackend) deliberately does
//! not know about callers, so this module is the only place that enforces
//! the admin allowlist:
//!
//! - `state.config.admin_pubkeys` empty -- the admin surface is administratively
//!   disabled. Every request (even a validly signed one) gets a plain `404`, the
//!   same status an unmapped path would produce, so the route's existence is
//!   never disclosed while the allowlist is empty.
//! - Allowlist non-empty but the verified signer is not a member -- `403` with a
//!   fixed, generic body. The allowlist contents are never echoed anywhere.
//! - Allowlist non-empty and the verified signer is a member -- the request
//!   proceeds to the catalog call.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use chrono::Utc;
use frameshift_catalog::{TombstoneReason, TombstoneRecord};
use serde::{Deserialize, Serialize};

use crate::auth::VerifiedSigner;
use crate::error::AppError;
use crate::routes::packs::{validate_pack_name, validate_pack_version};
use crate::state::AppState;

/// Build the admin sub-router, mounted at `/v1/admin`.
///
/// Returned without any auth layer; [`crate::router::app`] applies the
/// signed-request `route_layer` before nesting this router, mirroring
/// [`crate::routes::authors::authors_write_router`].
///
/// Routes:
/// - `POST /packs/{name}/{version}/tombstone` -> [`tombstone_pack_route`]
pub fn admin_router() -> Router<AppState> {
    Router::new().route(
        "/packs/{name}/{version}/tombstone",
        post(tombstone_pack_route),
    )
}

/// Request body for `POST /v1/admin/packs/{name}/{version}/tombstone`.
#[derive(Debug, Deserialize)]
pub struct TombstoneRequest {
    /// Why this version is being taken down. Serialized/deserialized as one of
    /// `"author-request"`, `"tos-violation"`, `"dmca"` (see
    /// [`TombstoneReason`]).
    pub reason: TombstoneReason,
}

/// Response body for a successful tombstone.
#[derive(Debug, Serialize)]
pub struct TombstoneResponse {
    /// The pack name that was tombstoned.
    pub name: String,
    /// The version string that was tombstoned.
    pub version: String,
    /// Always the fixed string `"tombstoned"` on success.
    pub status: String,
}

/// `POST /v1/admin/packs/{name}/{version}/tombstone`
///
/// Mark a pack version as tombstoned (removed from public availability). This
/// is a one-way transition (`Active` -> `Tombstone`); see
/// [`frameshift_catalog::CatalogBackend::tombstone_pack`] for the trait-level
/// contract. Re-tombstoning an already-tombstoned version is accepted as
/// idempotent (last-writer-wins on `reason`/`recorded_at`), matching the
/// Postgres adapter's documented choice -- this endpoint never surfaces a
/// `409` from the tombstone operation itself.
///
/// # Authorization
///
/// The signed-request middleware has already verified the caller controls
/// `signer.pubkey` by the time this handler runs. This handler additionally
/// checks that key against `state.config.admin_pubkeys` -- see the module
/// documentation for the exact disable/forbid/allow semantics.
///
/// # Response
///
/// `200 OK` with body [`TombstoneResponse`].
///
/// # Errors
///
/// - `404 Not Found` -- the admin allowlist is empty (endpoint disabled), or
///   the pack version does not exist.
/// - `403 Forbidden` -- the verified signer is not on the admin allowlist.
/// - `400 Bad Request` -- `name`/`version` fail path validation.
/// - `500 Internal Server Error` -- catalog backend failure.
pub async fn tombstone_pack_route(
    State(state): State<AppState>,
    Extension(signer): Extension<VerifiedSigner>,
    Path((name, version)): Path<(String, String)>,
    Json(body): Json<TombstoneRequest>,
) -> Result<Response, AppError> {
    validate_pack_name(&name)?;
    validate_pack_version(&version)?;

    // Disabled surface: an empty allowlist must be indistinguishable from a
    // route that does not exist, so this check comes before anything else and
    // always returns 404, never 403.
    if state.config.admin_pubkeys.is_empty() {
        return Err(AppError::NotFound("not found".to_string()));
    }

    // Compare in the same base64url-no-pad string representation the config
    // was parsed into; `VerifiedSigner::pubkey`'s `Display` impl produces the
    // identical encoding.
    let signer_b64 = signer.pubkey.to_string();
    if !state.config.admin_pubkeys.iter().any(|k| k == &signer_b64) {
        tracing::warn!(
            signer = %signer.pubkey,
            "tombstone attempt by a verified key that is not on the admin allowlist"
        );
        return Err(AppError::Forbidden(
            "signer is not an authorized admin".to_string(),
        ));
    }

    let record = TombstoneRecord {
        reason: body.reason,
        recorded_at: Utc::now(),
    };

    state
        .catalog
        .tombstone_pack(&name, &version, record)
        .await
        .map_err(|e| AppError::from_catalog(e, "pack_version"))?;

    let resp = TombstoneResponse {
        name,
        version,
        status: "tombstoned".to_string(),
    };
    Ok((StatusCode::OK, Json(resp)).into_response())
}
