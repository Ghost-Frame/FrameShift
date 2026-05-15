//! The [`PackStore`] async trait: the canonical interface for content-addressed
//! blob storage of pack archives in the frameshift workspace.
//!
//! Import this module via the crate root re-exports:
//! `use frameshift_objects::{PackStore, ObjectHash, ObjectStoreError}`.

use crate::{ObjectHash, ObjectStoreError, ObjectStoreHealth};

/// Content-addressed blob store for pack archives.
///
/// Objects are addressed by their 32-byte [`ObjectHash`] (SHA-256 digest,
/// re-exported from `frameshift-pack`). The hash IS the address; no secondary
/// identifier is used.
///
/// # Contracts
///
/// - **Verify-on-write.** Implementations MUST verify that SHA-256(bytes) ==
///   supplied hash BEFORE persisting. Any mismatch returns
///   [`ObjectStoreError::HashMismatch`]. This is the only mechanism that
///   enforces the content-addressing invariant against caller bugs.
///
/// - **Idempotent `put`.** A `put` of an existing hash with MATCHING content
///   is a no-op success (`Ok(())`). A `put` of an existing hash with
///   DIFFERENT content (impossible if hashing is correct, but treated as
///   adversarial input) returns [`ObjectStoreError::HashMismatch`].
///
/// - **Concurrent `put` safety.** Two concurrent `put` calls for the same
///   (hash, bytes) pair MUST both return `Ok(())`; no `AlreadyExists`, no
///   data race.
///
/// - **Visibility atomicity.** After `put` returns `Ok(())`, a subsequent
///   `get` for the same hash from ANY task observes the full bytes.
///   Partial writes MUST NOT be observable; if a write is interrupted or the
///   quota is exceeded, no partial object becomes visible.
///
/// - **Verify-on-read** is OPTIONAL and adapter-configurable. Adapters that
///   enable it SHOULD return [`ObjectStoreError::BackendError`] if the stored
///   bytes do not match the key on read.
///
/// # Auth boundary
///
/// This trait DOES NOT enforce caller identity or pack signatures. The HTTP
/// server and signing layer verify authenticity before any `put` reaches the
/// store.
///
/// # Dyn-safety
///
/// The trait has no generic parameters and no `Self`-returning methods, so
/// it is usable as `dyn PackStore`. Wrap in `Arc<dyn PackStore>` for shared
/// ownership across tasks.
#[async_trait::async_trait]
pub trait PackStore: Send + Sync {
    /// Store `bytes` under the content address `hash`.
    ///
    /// Implementations MUST:
    ///
    /// 1. Compute SHA-256(bytes) and compare it to `hash`.
    /// 2. If they differ, return [`ObjectStoreError::HashMismatch`] without
    ///    writing anything.
    /// 3. If `hash` already exists with matching content, return `Ok(())`.
    /// 4. Otherwise, write the bytes atomically so that no partial write is
    ///    ever observable by a concurrent reader.
    ///
    /// A zero-byte payload is valid; zero bytes have a deterministic SHA-256
    /// and may be stored normally.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::HashMismatch`] -- SHA-256(bytes) != `hash`, or
    ///   an existing object at the same key has different content.
    /// - [`ObjectStoreError::QuotaExceeded`] -- the write would exceed the
    ///   configured storage quota. No partial bytes must be observable.
    /// - [`ObjectStoreError::BackendError`] -- the underlying storage
    ///   returned an unexpected error.
    async fn put(&self, hash: &ObjectHash, bytes: &[u8]) -> Result<(), ObjectStoreError>;

    /// Retrieve the bytes stored under `hash`.
    ///
    /// Returns the exact bytes that were supplied to a prior successful `put`
    /// for the same `hash`.
    ///
    /// A `get` immediately after a successful `put` from the same task MUST
    /// return those bytes (linearizable within a task). Cross-task visibility
    /// is guaranteed after `put` returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::NotFound`] -- no object exists for `hash`.
    /// - [`ObjectStoreError::BackendError`] -- the underlying storage
    ///   returned an unexpected error. Adapters that enable verify-on-read
    ///   SHOULD return `BackendError` (not `HashMismatch`) when the stored
    ///   bytes do not match the key, because the mismatch is a backend
    ///   corruption, not a caller error.
    async fn get(&self, hash: &ObjectHash) -> Result<Vec<u8>, ObjectStoreError>;

    /// Return `true` if an object exists for `hash`, `false` if not.
    ///
    /// This method NEVER returns [`ObjectStoreError::NotFound`]. Absent
    /// objects produce `Ok(false)`. [`NotFound`](ObjectStoreError::NotFound)
    /// is reserved for operations that require the object to be present
    /// (i.e. [`get`](Self::get) and [`delete`](Self::delete)).
    ///
    /// Implementations SHOULD make this cheaper than a full `get` where
    /// possible (e.g. a filesystem `stat`, a database `EXISTS` query).
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::BackendError`] -- the backend could not be
    ///   queried (e.g. I/O error, connection failure).
    async fn exists(&self, hash: &ObjectHash) -> Result<bool, ObjectStoreError>;

    /// Remove the object at `hash` from the store.
    ///
    /// After a successful `delete`, [`exists`](Self::exists) returns
    /// `Ok(false)` and [`get`](Self::get) returns
    /// [`ObjectStoreError::NotFound`] for the same hash.
    ///
    /// Concurrent reads during a `delete` are adapter-specific; the trait
    /// does not promise reader stability after `delete` is called.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::NotFound`] -- no object exists for `hash`.
    ///   Silent success for absent objects is NOT provided; callers that
    ///   need idempotent deletion must call [`exists`](Self::exists) first
    ///   or match and swallow `NotFound`.
    /// - [`ObjectStoreError::BackendError`] -- the underlying storage
    ///   returned an unexpected error.
    async fn delete(&self, hash: &ObjectHash) -> Result<(), ObjectStoreError>;

    /// List object hashes whose byte representation begins with `prefix`.
    ///
    /// Returns at most `limit` hashes in unspecified order (adapters MAY
    /// sort lexicographically but are not required to).
    ///
    /// Useful for catalog reconciliation and garbage-collection sweeps
    /// without enumerating the entire store.
    ///
    /// # Prefix semantics
    ///
    /// - A prefix of 1-8 bytes is typical.
    /// - An empty prefix (`&[]`) is legal; it returns up to `limit` hashes
    ///   from the entire store.
    /// - A prefix longer than 32 bytes (the hash length) can never match any
    ///   hash and MUST return `Ok(vec![])` without error.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::BackendError`] -- the underlying storage
    ///   returned an unexpected error.
    async fn list_prefix(
        &self,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<ObjectHash>, ObjectStoreError>;

    /// Return a health snapshot for this store.
    ///
    /// The returned [`ObjectStoreHealth`] carries a `healthy` flag plus
    /// optional capacity counters. Implementations SHOULD NOT perform
    /// expensive full scans here; return `None` for any counter that
    /// would require one.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::BackendError`] -- the backend could not be
    ///   reached or queried.
    async fn health(&self) -> Result<ObjectStoreHealth, ObjectStoreError>;
}
