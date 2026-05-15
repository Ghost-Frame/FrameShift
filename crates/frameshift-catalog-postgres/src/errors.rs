//! Error mapping from diesel and bb8 errors to [`frameshift_catalog::CatalogError`].
//!
//! Library code never returns raw diesel or bb8 errors to callers -- they are
//! always translated here into the appropriate [`CatalogError`] variant.

use frameshift_catalog::CatalogError;

/// Map a [`diesel::result::Error`] to a [`CatalogError`].
///
/// The `kind` parameter names the entity type being operated on (e.g. `"pack"`,
/// `"author"`). The `key` parameter is the lookup key or conflicting value,
/// used to populate `NotFound.key` and `Conflict.key`.
///
/// # Mapping rules
///
/// | Diesel error | CatalogError |
/// |---|---|
/// | `NotFound` | `NotFound { kind, key }` |
/// | `UniqueViolation` | `Conflict { kind, key }` |
/// | `ForeignKeyViolation` | `Validation(message)` |
/// | anything else | `BackendError(boxed)` |
pub(crate) fn map_diesel_error(
    err: diesel::result::Error,
    kind: &'static str,
    key: String,
) -> CatalogError {
    use diesel::result::{DatabaseErrorKind, Error};
    match err {
        Error::NotFound => CatalogError::NotFound { kind, key },
        Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
            CatalogError::Conflict { kind, key }
        }
        Error::DatabaseError(DatabaseErrorKind::ForeignKeyViolation, info) => {
            tracing::debug!(detail = %info.message(), "foreign key violation");
            CatalogError::Validation("foreign key constraint violated".to_string())
        }
        other => CatalogError::BackendError(Box::new(other)),
    }
}

/// Map a [`bb8::RunError<diesel_async::pooled_connection::PoolError>`] to a [`CatalogError`].
///
/// Pool timeout is mapped to `BackendError` with a "pool timeout" message.
/// Application errors (connection failures) are boxed directly to preserve the
/// original error source chain. Wrapping via `std::io::Error::other(e.to_string())`
/// would discard the source; boxing the original keeps `#[source]` intact for callers
/// that inspect the error chain.
pub(crate) fn map_pool_error(
    err: bb8::RunError<diesel_async::pooled_connection::PoolError>,
) -> CatalogError {
    match err {
        bb8::RunError::TimedOut => CatalogError::BackendError(Box::new(std::io::Error::other(
            "pool timeout: no connection available within connect_timeout",
        ))),
        bb8::RunError::User(e) => CatalogError::BackendError(Box::new(e)),
    }
}

/// Map a migration error (boxed std::error::Error) to a [`CatalogError`].
///
/// Migration errors are always unexpected; they are wrapped as `BackendError`.
pub(crate) fn map_migration_error(err: Box<dyn std::error::Error + Send + Sync>) -> CatalogError {
    CatalogError::BackendError(err)
}
