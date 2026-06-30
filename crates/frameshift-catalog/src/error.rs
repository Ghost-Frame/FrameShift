//! Error types for the catalog backend.
//!
//! All catalog operations return `Result<T, CatalogError>`. Concrete adapters
//! (e.g. the Postgres adapter) map driver-specific failures into
//! `CatalogError::BackendError` and well-understood constraint violations into
//! the appropriate named variant.

use crate::identity::Ed25519PublicKey;

/// Errors returned by [`crate::backend::CatalogBackend`] methods.
///
/// Each variant covers a distinct failure class so callers can branch without
/// inspecting string messages. Adapters MUST map their internal error types
/// into these variants; opaque failures belong in `BackendError`.
///
/// # Design note
///
/// `NotFound` and `Conflict` carry a `kind` field (a `&'static str` naming the
/// entity type, e.g. `"pack"` or `"author"`) so that generic error renderers
/// can produce useful messages without pattern-matching the key string.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// The requested resource was not found.
    ///
    /// `kind` names the entity type (e.g. `"author"`, `"pack"`, `"handle"`).
    /// `key` is the lookup key that was searched (pubkey hex, pack name, etc.).
    #[error("{kind} not found: {key}")]
    NotFound {
        /// The entity type that was looked up.
        kind: &'static str,
        /// The lookup key that produced no result.
        key: String,
    },

    /// A uniqueness constraint was violated (other than handle uniqueness).
    ///
    /// `kind` names the entity type and `key` names the conflicting value.
    #[error("{kind} already exists: {key}")]
    Conflict {
        /// The entity type for which a duplicate was detected.
        kind: &'static str,
        /// The conflicting key value.
        key: String,
    },

    /// A handle registration failed because the handle is owned by another key.
    ///
    /// Returns the public key of the current owner so the caller can surface a
    /// meaningful error message (e.g. "handle 'alice' is owned by <pubkey>").
    #[error("handle already taken by {owner}")]
    HandleTaken {
        /// The public key of the existing handle owner.
        owner: Ed25519PublicKey,
    },

    /// The caller supplied an argument that is structurally invalid.
    ///
    /// Examples: empty display name string, signature with wrong byte length,
    /// pack name that does not match the name inside the version record.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The backend returned an unexpected error that does not map to a named variant.
    ///
    /// Contains the underlying error so that callers can log or propagate it.
    /// Use `source()` to access the wrapped error.
    #[error("catalog backend error: {0}")]
    BackendError(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A domain-level validation rule was violated.
    ///
    /// Distinct from `InvalidArgument`: use this for business-rule failures
    /// (e.g. "cannot register a new version for a tombstoned pack") rather than
    /// structural argument problems.
    #[error("validation error: {0}")]
    Validation(String),

    /// The caller is not permitted to perform the requested operation.
    ///
    /// Used when the requesting author's pubkey does not match the stored
    /// owner, e.g. a co-publish / name-squat attempt on a pack owned by
    /// another author.
    ///
    /// `kind` names the guarded entity type (e.g. `"pack"`).
    /// `key` is the entity key involved (e.g. the pack name).
    #[error("unauthorized: {kind} {key}")]
    Unauthorized {
        /// The entity type for which authorization was denied.
        kind: &'static str,
        /// The key of the entity that was accessed.
        key: String,
    },
}

/// Health status reported by [`crate::backend::CatalogBackend::health`].
///
/// Backends return this from their `health` method so that monitoring systems
/// can distinguish "up" from "degraded" without parsing the detail string.
///
/// # Usage
///
/// If `healthy` is `false`, the `detail` string SHOULD contain a brief
/// human-readable description of the degraded component (e.g. "database
/// connection pool exhausted"). Callers MUST NOT rely on the content of
/// `detail` for control flow.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthStatus {
    /// Whether the backend is fully operational.
    pub healthy: bool,
    /// Human-readable description of the current health state.
    ///
    /// When `healthy` is `true`, this is typically an empty string or "ok".
    /// When `healthy` is `false`, this describes the degraded condition.
    pub detail: String,
}

#[cfg(test)]
/// Unit tests for `CatalogError` display formatting.
mod tests {
    use super::*;

    #[test]
    /// Verify `NotFound` displays the kind and key.
    fn catalog_error_not_found_display() {
        let e = CatalogError::NotFound {
            kind: "pack",
            key: "my-pack".to_string(),
        };
        assert_eq!(e.to_string(), "pack not found: my-pack");
    }

    #[test]
    /// Verify `Conflict` displays the kind and key.
    fn catalog_error_conflict_display() {
        let e = CatalogError::Conflict {
            kind: "author",
            key: "alice".to_string(),
        };
        assert_eq!(e.to_string(), "author already exists: alice");
    }

    #[test]
    /// Verify `HandleTaken` displays the owner pubkey.
    fn catalog_error_handle_taken_display() {
        let key = Ed25519PublicKey([1u8; 32]);
        let e = CatalogError::HandleTaken { owner: key };
        let s = e.to_string();
        assert!(s.contains("handle already taken by"));
    }

    #[test]
    /// Verify `InvalidArgument` displays the message.
    fn catalog_error_invalid_argument_display() {
        let e = CatalogError::InvalidArgument("bad sig length".to_string());
        assert_eq!(e.to_string(), "invalid argument: bad sig length");
    }

    #[test]
    /// Verify `BackendError` displays the wrapper message.
    fn catalog_error_backend_error_display() {
        let inner: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("db timeout"));
        let e = CatalogError::BackendError(inner);
        assert!(e.to_string().contains("catalog backend error"));
    }

    #[test]
    /// Verify `Validation` displays the message.
    fn catalog_error_validation_display() {
        let e = CatalogError::Validation("cannot publish to tombstoned pack".to_string());
        assert_eq!(
            e.to_string(),
            "validation error: cannot publish to tombstoned pack"
        );
    }
}
