//! Health status type for [`crate::PackStore`] implementations.
//!
//! Adapters return [`ObjectStoreHealth`] from
//! [`PackStore::health`](crate::PackStore::health) so that monitoring systems
//! can observe store availability and capacity without knowing backend
//! internals.

/// Health status reported by a [`crate::PackStore`] implementation.
///
/// The `healthy` flag is the authoritative signal. Optional counters
/// (`total_objects`, `total_bytes`) provide capacity information when the
/// backend can compute them cheaply. If computing a counter would require a
/// full scan that could harm production throughput, the adapter SHOULD return
/// `None` for that field.
///
/// The `detail` string is for human consumption only. Callers MUST NOT parse
/// it for control flow -- use the typed fields instead. When `healthy` is
/// `false`, `detail` SHOULD describe the degraded condition briefly (e.g.
/// `"connection pool exhausted"`).
///
/// # Invariants
///
/// - `total_bytes >= total_objects` (every object has at least 0 bytes).
/// - Neither counter is authoritative under concurrent writes; they represent a
///   best-effort snapshot at the time `health()` was called.
#[derive(Debug, Clone)]
pub struct ObjectStoreHealth {
    /// Whether the store is fully operational.
    ///
    /// `false` means the adapter considers itself unavailable or degraded.
    /// `true` means requests should succeed under normal conditions.
    pub healthy: bool,

    /// Total number of objects currently stored, if cheaply available.
    ///
    /// `None` if the backend cannot determine this without an expensive scan.
    pub total_objects: Option<u64>,

    /// Total number of bytes occupied by stored objects, if cheaply available.
    ///
    /// `None` if the backend cannot determine this without an expensive scan.
    pub total_bytes: Option<u64>,

    /// Human-readable description of the current health state.
    ///
    /// Use for logging and dashboards only. Never parse for control flow.
    pub detail: String,
}
