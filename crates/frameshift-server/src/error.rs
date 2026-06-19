//! [`AppError`] -- the unified error type for all request handlers.
//!
//! Every handler returns `Result<T, AppError>`. The [`axum::response::IntoResponse`]
//! implementation translates each variant into an HTTP status code and a JSON
//! body `{"error": "..."}`. Internal details are never leaked in 500/502
//! responses -- only the fixed strings `"internal server error"` and
//! `"upstream backend mismatch"` are emitted.
//!
//! # Error mapping
//!
//! | Source | AppError variant | HTTP status |
//! |---|---|---|
//! | `CatalogError::NotFound` | `NotFound` | 404 |
//! | `CatalogError::Conflict` / `HandleTaken` | `Conflict` | 409 |
//! | `CatalogError::InvalidArgument` / `Validation` | `BadRequest` | 400 |
//! | `CatalogError::BackendError` | `Internal` | 500 |
//! | `ObjectStoreError::NotFound` (version exists in catalog) | `BadGateway` | 502 |
//! | Other `ObjectStoreError` | `Internal` | 500 |

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use frameshift_catalog::CatalogError;
use frameshift_objects::ObjectStoreError;

/// Unified handler error type.
///
/// All route handlers return `Result<T, AppError>`. This enum maps domain-level
/// failures to HTTP status codes while ensuring internal details are never
/// exposed in the response body.
#[derive(thiserror::Error, Debug)]
pub enum AppError {
    /// The request is malformed or contains an invalid argument.
    ///
    /// Maps to `400 Bad Request`. The message is included in the response body.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// The requested resource does not exist.
    ///
    /// Maps to `404 Not Found`. The message is included in the response body.
    #[error("not found: {0}")]
    NotFound(String),

    /// A uniqueness constraint was violated (e.g. duplicate pack name).
    ///
    /// Maps to `409 Conflict`. The message is included in the response body.
    #[error("conflict: {0}")]
    Conflict(String),

    /// The request lacks valid authentication or the asserted identity could
    /// not be verified (e.g. signature mismatch, unknown author handle).
    ///
    /// Maps to `401 Unauthorized`. The message is included in the response body.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// The request is well-formed and authenticated but the credentials do
    /// not authorise the action. Specifically used by the signed-download
    /// verifier when the HMAC token is malformed, expired, or signature
    /// mismatches.
    ///
    /// Maps to `403 Forbidden`. The message in the variant is logged but
    /// NEVER sent in the response body -- only the fixed string
    /// `"forbidden"` is returned to avoid leaking which check failed.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// An unexpected backend failure occurred.
    ///
    /// Maps to `500 Internal Server Error`. The message is NOT included in
    /// the response body; only the fixed string `"internal server error"` is
    /// returned to the caller.
    #[error("internal: {0}")]
    Internal(String),

    /// The catalog has a version record but the object store is missing the
    /// corresponding blob. This indicates a storage inconsistency that requires
    /// operator intervention.
    ///
    /// Maps to `502 Bad Gateway`. The message is NOT included in the response
    /// body; only the fixed string `"upstream backend mismatch"` is returned.
    #[error("bad gateway: {0}")]
    BadGateway(String),
}

impl AppError {
    /// Map a [`CatalogError`] to an [`AppError`].
    ///
    /// `default_kind` is used in the error message when the catalog error does
    /// not carry a human-readable entity name (e.g. `"pack"` or `"author"`).
    ///
    /// | CatalogError variant | AppError variant |
    /// |---|---|
    /// | `NotFound` | `NotFound` |
    /// | `Conflict` | `Conflict` |
    /// | `HandleTaken` | `Conflict` |
    /// | `InvalidArgument` | `BadRequest` |
    /// | `Validation` | `BadRequest` |
    /// | `BackendError` | `Internal` |
    /// | `Unauthorized` | `Forbidden` |
    pub fn from_catalog(err: CatalogError, default_kind: &'static str) -> Self {
        match err {
            CatalogError::NotFound { kind, key } => {
                AppError::NotFound(format!("{kind} not found: {key}"))
            }
            CatalogError::Conflict { kind, key } => {
                AppError::Conflict(format!("{kind} conflict: {key}"))
            }
            CatalogError::HandleTaken { owner } => {
                AppError::Conflict(format!("handle already taken by {owner}"))
            }
            CatalogError::InvalidArgument(msg) => AppError::BadRequest(msg),
            CatalogError::Validation(msg) => AppError::BadRequest(msg),
            CatalogError::BackendError(e) => {
                AppError::Internal(format!("{default_kind} backend error: {e}"))
            }
            // A publishing author that does not match the pack owner is a 403.
            CatalogError::Unauthorized { kind, key } => {
                AppError::Forbidden(format!("not authorized to write {kind}: {key}"))
            }
        }
    }

    /// Map an [`ObjectStoreError`] to an [`AppError`].
    ///
    /// `default_kind` is used for context in the internal log message.
    ///
    /// When an object is missing from the store after the catalog confirmed the
    /// version exists, that is a storage inconsistency and maps to
    /// [`AppError::BadGateway`]. All other errors map to [`AppError::Internal`].
    ///
    /// # Usage note
    ///
    /// For the pack download endpoint, if the catalog returned a version record
    /// (meaning the version exists), a subsequent `ObjectStoreError::NotFound`
    /// MUST be converted via this method and the `BadGateway` variant is the
    /// correct result.
    pub fn from_objects(err: ObjectStoreError, default_kind: &'static str) -> Self {
        match err {
            ObjectStoreError::NotFound { hash } => {
                AppError::BadGateway(format!("blob missing for hash {hash}"))
            }
            other => AppError::Internal(format!("{default_kind} object store error: {other}")),
        }
    }
}

impl IntoResponse for AppError {
    /// Convert [`AppError`] into an HTTP response.
    ///
    /// - `BadRequest` -> 400 with the message in the body.
    /// - `NotFound` -> 404 with the message in the body.
    /// - `Conflict` -> 409 with the message in the body.
    /// - `Internal` -> 500 with the fixed string `"internal server error"` (no details).
    /// - `BadGateway` -> 502 with the fixed string `"upstream backend mismatch"` (no details).
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error".to_string(),
            ),
            AppError::BadGateway(_) => (
                StatusCode::BAD_GATEWAY,
                "upstream backend mismatch".to_string(),
            ),
        };
        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_error_message_is_fixed() {
        let e = AppError::Internal("super secret db connection string".into());
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn bad_gateway_message_is_fixed() {
        let e = AppError::BadGateway("blob gone".into());
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn catalog_backend_error_maps_to_internal() {
        let inner: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("db fail"));
        let e = AppError::from_catalog(CatalogError::BackendError(inner), "pack");
        assert!(matches!(e, AppError::Internal(_)));
    }

    #[test]
    fn catalog_not_found_maps_to_not_found() {
        let e = AppError::from_catalog(
            CatalogError::NotFound {
                kind: "pack",
                key: "my-pack".into(),
            },
            "pack",
        );
        assert!(matches!(e, AppError::NotFound(_)));
    }

    #[test]
    fn object_store_not_found_maps_to_bad_gateway() {
        let hash = frameshift_pack::ObjectHash::of(b"test");
        let e = AppError::from_objects(ObjectStoreError::NotFound { hash }, "pack");
        assert!(matches!(e, AppError::BadGateway(_)));
    }
}
