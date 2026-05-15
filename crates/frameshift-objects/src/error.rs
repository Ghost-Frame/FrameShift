//! Error type for [`crate::PackStore`] operations.
//!
//! All store methods return `Result<T, ObjectStoreError>`. Adapters MUST map
//! their internal failures into these named variants. Opaque backend failures
//! belong in [`ObjectStoreError::BackendError`]; well-understood domain
//! violations map to the specific named variants.
//!
//! # Design principle
//!
//! Callers are expected to branch on variants, not inspect string messages.
//! Every variant carries enough structured context to produce a useful error
//! message without string parsing.

use crate::ObjectHash;

/// Errors returned by [`crate::PackStore`] methods.
///
/// Each variant covers a distinct failure class. Adapters MUST map their
/// internal error types into these variants rather than tunneling arbitrary
/// strings through [`ObjectStoreError::BackendError`] for known conditions.
///
/// # Variant selection guide
///
/// | Condition | Variant |
/// |-----------|---------|
/// | `get` or `delete` of a key that does not exist | [`NotFound`](Self::NotFound) |
/// | `put` of a key that already has a MATCHING object | idempotent `Ok(())` |
/// | `put` of a key where hash(bytes) != supplied hash | [`HashMismatch`](Self::HashMismatch) |
/// | Backend quota exceeded mid-write | [`QuotaExceeded`](Self::QuotaExceeded) |
/// | All other backend failures | [`BackendError`](Self::BackendError) |
#[derive(Debug, thiserror::Error)]
pub enum ObjectStoreError {
    /// The requested object does not exist in the store.
    ///
    /// Returned by [`PackStore::get`](crate::PackStore::get) and
    /// [`PackStore::delete`](crate::PackStore::delete) when no object is found
    /// for the given hash.
    ///
    /// Note: [`PackStore::exists`](crate::PackStore::exists) NEVER returns this
    /// variant -- it returns `Ok(false)` for absent objects.
    #[error("object not found: {hash}")]
    NotFound {
        /// The hash that was requested but not present in the store.
        hash: ObjectHash,
    },

    /// A `put` was rejected because an object with the same hash already exists
    /// and was written by a concurrent caller.
    ///
    /// This variant is reserved for scenarios where the adapter cannot resolve
    /// a concurrent-write race and the content cannot be verified. Under normal
    /// operation, `put` with matching bytes is idempotent (`Ok(())`).
    ///
    /// See also: [`HashMismatch`](Self::HashMismatch) for the case where bytes
    /// are present but do not match.
    #[error("object already exists: {hash}")]
    AlreadyExists {
        /// The hash of the object that already exists.
        hash: ObjectHash,
    },

    /// The SHA-256 hash of the supplied bytes does not match the supplied hash key.
    ///
    /// This is the error returned when the caller provides a hash that is
    /// inconsistent with the content it supplies. Implementations MUST verify
    /// `hash(bytes) == hash` before persisting (verify-on-write).
    ///
    /// It is also returned when a `put` targets an existing key whose stored
    /// content hashes to a different value than the supplied bytes -- an
    /// adversarial-input scenario.
    #[error("hash mismatch: expected {expected}, actual hash of supplied bytes was {actual}")]
    HashMismatch {
        /// The hash supplied by the caller as the address for this object.
        expected: ObjectHash,
        /// The SHA-256 hash of the bytes that were actually provided.
        actual: ObjectHash,
    },

    /// The backend encountered an unexpected error not covered by a named variant.
    ///
    /// Use [`std::error::Error::source`] to access the wrapped error. Adapters
    /// SHOULD log the inner error before wrapping it so that diagnostic
    /// information is preserved.
    #[error("object store backend error: {0}")]
    BackendError(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A `put` could not complete because the storage quota would be exceeded.
    ///
    /// The adapter MUST ensure no partial bytes are observable when returning
    /// this error -- the write must be fully rolled back or never committed.
    ///
    /// `used_bytes` is the store's current usage before the rejected write.
    /// `max_bytes` is the configured quota ceiling.
    #[error("storage quota exceeded: used {used_bytes} bytes, limit is {max_bytes} bytes")]
    QuotaExceeded {
        /// Current number of bytes used in the store before the rejected write.
        used_bytes: u64,
        /// Configured maximum number of bytes the store may hold.
        max_bytes: u64,
    },
}
