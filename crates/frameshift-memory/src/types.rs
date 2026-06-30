//! Common data types shared across all memory adapter implementations.
//!
//! Types in this module are designed to be backend-agnostic. They travel
//! across crate boundaries, so all carry full Serde support.

use std::collections::BTreeMap;
use std::fmt;

/// Opaque identifier for a stored memory entry.
///
/// Wraps a [`uuid::Uuid`] and exposes stable serialization as a UUID string.
/// Two `MemoryId` values are equal when their underlying UUIDs are equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MemoryId(pub uuid::Uuid);

impl MemoryId {
    /// Generate a new random [`MemoryId`].
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Wrap an existing [`uuid::Uuid`] in a [`MemoryId`].
    pub fn from_uuid(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for MemoryId {
    /// Returns a fixed nil (all-zeroes) sentinel UUID.
    ///
    /// Use [`MemoryId::new()`] to generate a unique random id.
    fn default() -> Self {
        Self(uuid::Uuid::nil())
    }
}

impl fmt::Display for MemoryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single stored memory entry.
///
/// Returned by [`crate::MemoryAdapter::recall`], [`crate::MemoryAdapter::search`],
/// and [`crate::MemoryAdapter::list`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Memory {
    /// Stable identifier for this memory.
    pub id: MemoryId,

    /// The text content of the memory.
    pub text: String,

    /// Caller-supplied tags used for filtering and retrieval.
    pub tags: Vec<String>,

    /// Arbitrary key-value metadata attached to this memory.
    pub metadata: Metadata,

    /// When this memory was first stored.
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When this memory was last modified, if it has been updated since creation.
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Flexible key-value metadata attached to a [`Memory`].
///
/// The inner map is flattened during serialization so that metadata keys
/// appear at the top level of the containing JSON object rather than nested
/// under a `"metadata"` key.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Metadata {
    /// The underlying map of metadata fields.
    #[serde(flatten)]
    pub inner: BTreeMap<String, serde_json::Value>,
}

impl Metadata {
    /// Create an empty [`Metadata`] instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a key-value pair, overwriting any existing value for `key`.
    pub fn insert(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.inner.insert(key.into(), value);
    }

    /// Look up a value by key.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.inner.get(key)
    }
}

/// Filters used to narrow a [`crate::MemoryAdapter::search`] or
/// [`crate::MemoryAdapter::list`] result set.
///
/// Every field is optional; a [`Filters::default()`] value applies no
/// restrictions.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Filters {
    /// Restrict to memories that carry **any** of the listed tags.
    ///
    /// `None` means no tag filter is applied.
    pub tags: Option<Vec<String>>,

    /// Restrict to memories created after this timestamp (inclusive).
    pub after: Option<chrono::DateTime<chrono::Utc>>,

    /// Restrict to memories created before this timestamp (inclusive).
    pub before: Option<chrono::DateTime<chrono::Utc>>,

    /// Restrict to memories whose metadata contains all of the listed key-value pairs.
    pub metadata: Option<BTreeMap<String, serde_json::Value>>,
}

/// Snapshot of an adapter's operational health.
///
/// Returned by [`crate::MemoryAdapter::health`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthStatus {
    /// Whether the adapter considers itself fully operational.
    pub healthy: bool,

    /// Human-readable description of the current health state.
    pub message: String,

    /// Round-trip latency to the backing store, in milliseconds.
    ///
    /// `None` when the adapter did not measure latency.
    pub latency_ms: Option<u64>,
}

/// The set of operations a pack may require from a memory adapter.
///
/// Used in capability manifests to declare which adapter methods the pack
/// actually calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryOp {
    /// Store a new memory entry.
    Store,
    /// Search memories by semantic query.
    Search,
    /// Retrieve a specific memory by ID.
    Recall,
    /// List stored memories with pagination.
    List,
    /// Delete a memory by ID.
    Forget,
    /// Check adapter health.
    Health,
}

/// How strongly a pack depends on the presence of a memory adapter.
///
/// Declared in a capability manifest's `memory_required` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryRequirement {
    /// The pack does not use memory at all.
    #[default]
    None,
    /// The pack can operate without memory but may use it when available.
    Soft,
    /// The pack cannot function without a memory adapter.
    Hard,
}
