//! Error types for the memory adapter layer.
//!
//! [`MemoryError`] covers every failure mode callers need to distinguish.
//! Backends map their internal errors into these variants before surfacing them.

use crate::types::MemoryId;

/// All errors that a [`crate::MemoryAdapter`] implementation can return.
///
/// Every variant carries enough context for the caller to decide whether
/// to retry, surface to the user, or propagate silently.
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    /// No memory exists with the given identifier.
    #[error("memory not found: {0}")]
    NotFound(MemoryId),

    /// The adapter could not reach its backing store.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// The caller is not authorized to perform the requested operation.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// The backing store is rate-limiting requests.
    ///
    /// `retry_after_secs` is `Some` when the store specifies a back-off period.
    #[error("rate limited (retry after {retry_after_secs:?} seconds)")]
    RateLimited {
        /// Optional number of seconds to wait before retrying.
        retry_after_secs: Option<u64>,
    },

    /// The query string is syntactically or semantically invalid.
    #[error("invalid query: {0}")]
    InvalidQuery(String),

    /// The backing store has no remaining capacity.
    #[error("storage full")]
    StorageFull,

    /// An unclassified backend error.
    ///
    /// Use a more specific variant whenever the caller could reasonably
    /// distinguish the failure; fall back to this only for truly opaque errors.
    #[error("backend error: {0}")]
    Backend(String),

    /// The adapter was supplied an invalid or unusable configuration.
    ///
    /// Returned during construction when a required config value is missing,
    /// out of range, or refers to a path that cannot be created.
    #[error("configuration error: {0}")]
    Configuration(String),
}
