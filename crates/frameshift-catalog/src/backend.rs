//! The [`CatalogBackend`] async trait and its contract.
//!
//! Adapters (e.g. the Postgres adapter in `frameshift-catalog-postgres`) implement
//! this trait and translate the generic catalog operations into driver-specific
//! calls. The HTTP server depends only on `dyn CatalogBackend`; it never
//! imports adapter crates directly.

use async_trait::async_trait;

use crate::error::{CatalogError, HealthStatus};
use crate::filters::{PackSearchFilters, PackSearchResult};
use crate::identity::Ed25519PublicKey;
use crate::records::{AuthorRecord, PackRecord, PackVersionRecord};
use crate::status::TombstoneRecord;

/// Catalog backend for the persona marketplace.
///
/// Implementations persist authors, packs, pack versions, tag indices, and
/// download counters. All methods are async and return [`CatalogError`] on
/// failure; concrete error mapping (e.g. database-specific failure modes) is
/// the adapter's responsibility.
///
/// # Invariants implementations must uphold
///
/// - `register_author` MUST be idempotent for an identical `(pubkey, handle)`
///   pair: re-registering the same author with the same handle is a no-op that
///   returns `Ok(())`. Re-registering the same pubkey with a different handle,
///   or the same handle with a different pubkey, returns `CatalogError::Conflict`
///   or `CatalogError::HandleTaken` respectively.
/// - `register_pack_version` MUST be transactional: either the version row and
///   the parent pack's `latest_version` field both commit, or neither does.
///   Partial writes are not acceptable.
/// - `search_packs` MUST return a deterministic ordering for results with equal
///   scores, using `name ASC` as the tiebreaker, so that paginated results are
///   stable across requests.
/// - `tombstone_pack` MUST be a one-way transition: `Active` -> `Tombstone`.
///   An attempt to tombstone an already-tombstoned version MAY be treated as a
///   no-op (idempotent) or MAY return `CatalogError::Conflict` -- document the
///   adapter's choice.
/// - `increment_download_counter` for a pack name that does not exist MUST
///   return `CatalogError::NotFound`.
///
/// # Auth boundary
///
/// This trait DOES NOT enforce caller identity. `set_handle_pubkey`,
/// `tombstone_pack`, and similar mutations trust the caller. The HTTP server
/// layer is responsible for verifying ed25519 signatures before invoking these
/// methods.
///
/// # Object safety
///
/// This trait is object-safe when used via `async_trait`. Use
/// `Box<dyn CatalogBackend>` or `Arc<dyn CatalogBackend>` for dynamic dispatch.
#[async_trait]
pub trait CatalogBackend: Send + Sync {
    /// Register a new author or confirm that an identical author already exists.
    ///
    /// Idempotent for an identical `(pubkey, handle)` pair. Returns
    /// `CatalogError::HandleTaken` if the handle is owned by a different pubkey.
    /// Returns `CatalogError::Conflict` if the pubkey is already registered with
    /// a different handle.
    ///
    /// # Errors
    ///
    /// - `CatalogError::HandleTaken` -- the handle is already owned by another key.
    /// - `CatalogError::Conflict` -- the pubkey is registered with a different handle.
    /// - `CatalogError::Validation` -- `display_name` is `Some("")` (empty string).
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn register_author(&self, record: AuthorRecord) -> Result<(), CatalogError>;

    /// Look up an author by their Ed25519 public key.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"author"`) -- no author with this pubkey.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn lookup_author(&self, pubkey: &Ed25519PublicKey) -> Result<AuthorRecord, CatalogError>;

    /// Look up an author by their unique handle string.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"author"`) -- no author with this handle.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn lookup_author_by_handle(&self, handle: &str) -> Result<AuthorRecord, CatalogError>;

    /// List all registered authors, paginated by `limit` and `offset`.
    ///
    /// Returns an empty `Vec` if `offset` is beyond the total author count.
    /// Order is implementation-defined but MUST be stable (e.g. `created_at ASC`).
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn list_authors(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuthorRecord>, CatalogError>;

    /// Register a new version of a pack.
    ///
    /// The parent pack record is created if it does not yet exist, and its
    /// `latest_version` is updated atomically within the same transaction.
    ///
    /// `record.signature` MUST be exactly 64 bytes; any other length returns
    /// `CatalogError::InvalidArgument`.
    ///
    /// # Errors
    ///
    /// - `CatalogError::Conflict` -- `(pack_name, version)` already registered.
    /// - `CatalogError::InvalidArgument` -- `signature` is not 64 bytes.
    /// - `CatalogError::Validation` -- e.g. attempt to publish to a tombstoned pack.
    /// - `CatalogError::Unauthorized` -- the pack already exists and its
    ///   `current_author` does not match `record.author_pubkey` (co-publish
    ///   / name-squat rejection).
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn register_pack_version(&self, record: PackVersionRecord) -> Result<(), CatalogError>;

    /// Retrieve the top-level pack record for the given pack name.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack"`) -- no pack with this name.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn get_pack(&self, name: &str) -> Result<PackRecord, CatalogError>;

    /// Retrieve a specific version record for the given pack and version string.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack_version"`) -- no such version.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn get_pack_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<PackVersionRecord, CatalogError>;

    /// List all versions of a pack, ordered by `published_at ASC`.
    ///
    /// Returns an empty `Vec` if the pack has no published versions. Returns
    /// `CatalogError::NotFound` if the pack does not exist at all.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack"`) -- pack does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn list_pack_versions(&self, name: &str) -> Result<Vec<PackVersionRecord>, CatalogError>;

    /// Search for packs matching the given filters.
    ///
    /// Returns results ordered by the sort mode specified in `filters`, with a
    /// deterministic `name ASC` tiebreaker for equal scores. Tombstoned versions
    /// are excluded from results unless the adapter explicitly supports
    /// `include_tombstoned` (which this filter set does not -- future extension).
    ///
    /// Returns an empty `Vec` (not an error) when no packs match.
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn search_packs(
        &self,
        filters: &PackSearchFilters,
    ) -> Result<Vec<PackSearchResult>, CatalogError>;

    /// Increment the download counter for a specific pack version.
    ///
    /// Also increments the parent pack's `total_downloads` field. Returns the
    /// new value of the version-level download counter after incrementing.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack_version"`) -- the pack or version
    ///   does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn increment_download_counter(
        &self,
        name: &str,
        version: &str,
    ) -> Result<u64, CatalogError>;

    /// Mark a specific pack version as tombstoned.
    ///
    /// The version record is retained; only its `status` field transitions from
    /// `PackStatus::Active` to `PackStatus::Tombstone`. Content-addressed
    /// retrieval by hash still works after tombstoning.
    ///
    /// Adapter MUST document whether re-tombstoning an already-tombstoned version
    /// is idempotent or returns `CatalogError::Conflict`.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack_version"`) -- the version does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn tombstone_pack(
        &self,
        name: &str,
        version: &str,
        record: TombstoneRecord,
    ) -> Result<(), CatalogError>;

    /// Retrieve the Ed25519 public key currently mapped to a handle.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"handle"`) -- the handle does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn get_handle_pubkey(&self, handle: &str) -> Result<Ed25519PublicKey, CatalogError>;

    /// Update the public key mapped to an existing handle.
    ///
    /// The caller is responsible for verifying ownership before invoking this
    /// method. The catalog does not verify that the caller controls the new key.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"handle"`) -- the handle does not exist.
    /// - `CatalogError::InvalidArgument` -- the pubkey is structurally invalid
    ///   (e.g. all-zero bytes, if the adapter validates this).
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn set_handle_pubkey(
        &self,
        handle: &str,
        pubkey: Ed25519PublicKey,
    ) -> Result<(), CatalogError>;

    /// Record a single download event for a specific pack version in the audit log.
    ///
    /// Inserts one row into the `pack_downloads` audit table with the current
    /// timestamp. This is the write side of the trending feature; `search_packs`
    /// with `SortMode::Trending` reads from the same table to compute 7-day
    /// download velocity.
    ///
    /// This method is best-effort: callers SHOULD invoke it after a successful
    /// object-store fetch, but a failure here MUST NOT prevent the download from
    /// being served. The recommended pattern is to log and discard the error at
    /// the call site rather than surfacing it to the end user.
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` -- unexpected backend failure (e.g. pool
    ///   exhausted, DB unreachable). The download itself should still be served.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn record_download(&self, pack_name: &str, version: &str) -> Result<(), CatalogError>;

    /// Return the current health status of the backend.
    ///
    /// A healthy backend returns `HealthStatus { healthy: true, detail: "ok" }`.
    /// A degraded backend returns `healthy: false` with a description of the
    /// failure in `detail`. This method SHOULD NOT itself return `Err`; prefer
    /// returning `Ok(HealthStatus { healthy: false, ... })` for degraded states.
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` -- the backend is so degraded it cannot
    ///   even construct a health response.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn health(&self) -> Result<HealthStatus, CatalogError>;

    /// Set the `extends` field on the pack head record.
    ///
    /// Records the base persona pack name from the manifest `extends` field.
    /// Pass `None` to clear the value (root pack with no base). This is a
    /// best-effort update called after `register_pack_version`; the caller
    /// MUST ensure the pack row already exists (i.e. `register_pack_version`
    /// succeeded) before calling this method.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack"`) -- the pack does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn set_pack_extends(
        &self,
        pack_name: &str,
        extends: Option<&str>,
    ) -> Result<(), CatalogError>;

    /// Set the `description` and `tags` fields on the pack head record.
    ///
    /// Records the marketplace-facing description and discovery tags from the
    /// manifest so that `search_packs` (which ranks on `description`) can find
    /// published packs. This is a best-effort update called after
    /// `register_pack_version`; the caller MUST ensure the pack row already
    /// exists (i.e. `register_pack_version` succeeded) before calling this
    /// method.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack"`) -- the pack does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn set_pack_metadata(
        &self,
        name: &str,
        description: &str,
        tags: &[String],
    ) -> Result<(), CatalogError>;
}
