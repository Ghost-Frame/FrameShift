//! Mock [`MemoryAdapter`] implementation for integration tests.
//!
//! Only [`MemoryAdapter::health`] has meaningful behavior, driven by the
//! `healthy` field set at construction. The remaining trait methods are
//! stubs: no test in this crate exercises the memory CRUD surface (store,
//! search, recall, list, forget) because the server does not yet expose it.

use async_trait::async_trait;

use frameshift_memory::{
    Filters, HealthStatus, Memory, MemoryAdapter, MemoryError, MemoryId, Metadata,
};

/// In-memory [`MemoryAdapter`] stub for integration tests.
///
/// Construct with `MockMemoryAdapter { healthy: true }` or `{ healthy: false }`
/// to control the outcome of [`MemoryAdapter::health`].
///
/// Each `tests/*.rs` file builds an independent test binary; only
/// `integration.rs` currently constructs this mock, so it appears dead in the
/// other binaries (`authors_write`, `publish`, `telemetry`) that compile this
/// shared `mocks` module without referencing it.
#[allow(dead_code)]
pub struct MockMemoryAdapter {
    /// Whether [`MemoryAdapter::health`] reports `healthy: true`.
    pub healthy: bool,
}

#[async_trait]
impl MemoryAdapter for MockMemoryAdapter {
    /// Stub: not exercised by any current test.
    async fn store(
        &self,
        _text: &str,
        _tags: &[String],
        _metadata: Metadata,
    ) -> Result<MemoryId, MemoryError> {
        Ok(MemoryId::new())
    }

    /// Stub: not exercised by any current test.
    async fn search(
        &self,
        _query: &str,
        _k: usize,
        _filters: &Filters,
    ) -> Result<Vec<Memory>, MemoryError> {
        Ok(Vec::new())
    }

    /// Stub: not exercised by any current test.
    async fn recall(&self, id: &MemoryId) -> Result<Memory, MemoryError> {
        Err(MemoryError::NotFound(id.clone()))
    }

    /// Stub: not exercised by any current test.
    async fn list(&self, _limit: usize, _offset: usize) -> Result<Vec<Memory>, MemoryError> {
        Ok(Vec::new())
    }

    /// Stub: not exercised by any current test.
    async fn forget(&self, id: &MemoryId) -> Result<(), MemoryError> {
        Err(MemoryError::NotFound(id.clone()))
    }

    /// Reports health according to the `healthy` field set at construction.
    async fn health(&self) -> Result<HealthStatus, MemoryError> {
        Ok(HealthStatus {
            healthy: self.healthy,
            message: if self.healthy {
                "mock memory adapter is healthy".to_string()
            } else {
                "mock memory adapter is unhealthy".to_string()
            },
            latency_ms: Some(0),
        })
    }
}
