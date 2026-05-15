//! The [`MemoryAdapter`] trait definition.
//!
//! Implementations live in separate crates (e.g. `frameshift-memory-http`,
//! `frameshift-memory-sqlite`). This crate only defines the contract.

use async_trait::async_trait;

use crate::error::MemoryError;
use crate::types::{Filters, HealthStatus, Memory, MemoryId, Metadata};

/// Pluggable async interface to a knowledge/memory store.
///
/// Implementations must be `Send + Sync` so they can be held behind an
/// `Arc<dyn MemoryAdapter>` or `Box<dyn MemoryAdapter>` in multi-threaded
/// async runtimes.
///
/// The six methods cover the full lifecycle of a stored memory:
/// create, search, retrieve, list, delete, and health check.
#[async_trait]
pub trait MemoryAdapter: Send + Sync {
    /// Store a new memory entry and return its assigned identifier.
    ///
    /// # Parameters
    /// - `text`     -- the content to persist.
    /// - `tags`     -- caller-supplied labels used for filtering.
    /// - `metadata` -- arbitrary key-value data attached to the entry.
    ///
    /// # Errors
    /// Returns [`MemoryError::StorageFull`] when the backing store has no
    /// remaining capacity, [`MemoryError::ConnectionFailed`] on transport
    /// errors, or [`MemoryError::Unauthorized`] on permission failures.
    async fn store(
        &self,
        text: &str,
        tags: &[String],
        metadata: Metadata,
    ) -> Result<MemoryId, MemoryError>;

    /// Search for memories semantically close to `query`.
    ///
    /// # Parameters
    /// - `query`   -- the search string (plain text or embedding input).
    /// - `k`       -- maximum number of results to return; `0` returns an empty `Vec`.
    /// - `filters` -- additional constraints applied after semantic ranking.
    ///
    /// # Errors
    /// Returns [`MemoryError::InvalidQuery`] when the query is malformed,
    /// [`MemoryError::ConnectionFailed`] on transport errors, or
    /// [`MemoryError::RateLimited`] when the store is throttling.
    async fn search(
        &self,
        query: &str,
        k: usize,
        filters: &Filters,
    ) -> Result<Vec<Memory>, MemoryError>;

    /// Retrieve a single memory by its identifier.
    ///
    /// # Errors
    /// Returns [`MemoryError::NotFound`] when no memory with the given ID exists.
    async fn recall(&self, id: &MemoryId) -> Result<Memory, MemoryError>;

    /// Return a paginated slice of all stored memories.
    ///
    /// # Parameters
    /// - `limit`  -- maximum number of entries to return.
    /// - `offset` -- number of entries to skip before collecting.
    ///
    /// # Errors
    /// Returns [`MemoryError::ConnectionFailed`] on transport errors.
    async fn list(&self, limit: usize, offset: usize) -> Result<Vec<Memory>, MemoryError>;

    /// Permanently delete the memory with the given identifier.
    ///
    /// # Errors
    /// Returns [`MemoryError::NotFound`] when no memory with the given ID exists.
    async fn forget(&self, id: &MemoryId) -> Result<(), MemoryError>;

    /// Report the operational health of this adapter.
    ///
    /// Implementations should probe the backing store and measure round-trip
    /// latency where practical.
    ///
    /// # Errors
    /// Returns [`MemoryError::ConnectionFailed`] only when the health check
    /// itself cannot be performed; a degraded-but-reachable store should
    /// return `Ok(HealthStatus { healthy: false, .. })` instead.
    async fn health(&self) -> Result<HealthStatus, MemoryError>;
}
