//! Signed-request authentication middleware.
//!
//! [`require_signed_request`] is applied (via `route_layer`) to the mutating
//! endpoints only. It buffers the request body so the SHA-256 over the exact
//! bytes can be recomputed, verifies the Ed25519 signed-request envelope (see
//! [`crate::auth`]), and -- on success -- reinjects the buffered body and
//! stamps a [`crate::auth::VerifiedSigner`] into the request extensions for the
//! downstream handler.
//!
//! Read endpoints never carry this layer, so their bodies are never buffered.

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::auth;
use crate::error::AppError;
use crate::state::AppState;

/// Verify the Ed25519 signed-request envelope on a mutating request.
///
/// Buffers the body up to `config.max_request_bytes`, recomputes its hash,
/// verifies the signature/timestamp/nonce, and on success reinjects the body
/// and inserts a [`auth::VerifiedSigner`] extension. On any verification
/// failure it returns the opaque `401` produced by [`auth::verify`].
pub async fn require_signed_request(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let (parts, body) = req.into_parts();

    // Parse the credential headers before touching the (potentially large) body.
    let params = auth::parse_headers(&parts.headers)?;

    // The signer signs the uppercase HTTP method and the FULL URI path (no
    // query). Because this layer is attached inside nested routers, `parts.uri`
    // has already had the nest prefix stripped (e.g. `/v1/authors` -> `/`), so
    // we read `OriginalUri` -- the full path as the client sent it, which is
    // what the client signed. Falls back to `parts.uri` for non-nested routes.
    let method = parts.method.as_str().to_ascii_uppercase();
    let path = parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .map(|original| original.0.path().to_string())
        .unwrap_or_else(|| parts.uri.path().to_string());

    // Buffer the full body so the signed SHA-256 can be recomputed. The global
    // `RequestBodyLimitLayer` already caps inbound size; we pass the same limit
    // to `to_bytes` as a defensive second bound.
    let limit = state.config.max_request_bytes;
    let bytes: Bytes = axum::body::to_bytes(body, limit).await.map_err(|_| {
        AppError::BadRequest("request body exceeds limit or could not be read".to_string())
    })?;

    let pubkey = auth::verify(
        &params,
        &method,
        &path,
        &bytes,
        auth::unix_now(),
        state.config.signed_request_max_skew,
        &state.auth_nonces,
    )?;

    // Reinject the buffered body so body-consuming extractors (Multipart, Json)
    // can read it; the content-type header (with multipart boundary) survives
    // because we preserve `parts` verbatim.
    let mut req = Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(auth::VerifiedSigner { pubkey });

    Ok(next.run(req).await)
}
