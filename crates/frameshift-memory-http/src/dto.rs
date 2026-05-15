//! Wire-format DTOs for the HTTP memory adapter.
//!
//! These types mirror [`frameshift_memory`] types but carry their own serde
//! shapes suitable for JSON serialization over the wire. Metadata fields are
//! flattened; tags in filter requests are sorted lexicographically; timestamps
//! are RFC3339 strings in UTC.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Request body for `POST {base}/store`.
#[derive(Debug, Serialize)]
pub(crate) struct StoreRequest<'a> {
    /// The text content to persist.
    pub text: &'a str,

    /// Caller-supplied tags. Sent as-is (sorting is the server's concern for
    /// the canonical `store` call; the [`FiltersDto`] sorts for search).
    pub tags: &'a [String],

    /// Arbitrary key-value metadata, serialized as a flat JSON object.
    #[serde(flatten)]
    pub metadata: &'a BTreeMap<String, serde_json::Value>,
}

/// Response body for a successful `POST {base}/store` (status 201).
#[derive(Debug, Deserialize)]
pub(crate) struct StoreResponse {
    /// The assigned identifier for the newly stored memory.
    pub id: Uuid,

    /// When the memory was created (RFC3339).
    ///
    /// Deserialized from the wire but not used further; the caller receives
    /// only the `MemoryId`. Retained to keep the wire contract complete.
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

/// Request body for `POST {base}/search`.
#[derive(Debug, Serialize)]
pub(crate) struct SearchRequest<'a> {
    /// The search query string.
    pub query: &'a str,

    /// Maximum number of results to return.
    pub k: usize,

    /// Additional constraints on the result set.
    pub filters: FiltersDto<'a>,
}

/// Wire representation of [`frameshift_memory::Filters`].
///
/// Tags are sorted lexicographically before serialization.
/// Timestamps are RFC3339 strings.
/// Metadata is serialized as a sorted JSON object (BTreeMap order).
#[derive(Debug, Serialize)]
pub(crate) struct FiltersDto<'a> {
    /// Tags to filter by, sorted lexicographically. `None` means no tag filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<&'a str>>,

    /// Restrict to memories created at or after this timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<DateTime<Utc>>,

    /// Restrict to memories created at or before this timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<DateTime<Utc>>,

    /// Restrict to memories whose metadata contains all of these key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<&'a BTreeMap<String, serde_json::Value>>,
}

/// Response body for `POST {base}/search` (status 200).
#[derive(Debug, Deserialize)]
pub(crate) struct SearchResponse {
    /// The matched memories in ranked order.
    pub results: Vec<MemoryDto>,
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

/// Response body for `GET {base}/memories?limit=&offset=` (status 200).
#[derive(Debug, Deserialize)]
pub(crate) struct ListResponse {
    /// The paginated memory entries.
    pub items: Vec<MemoryDto>,
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/// Response body for `GET {base}/health` (status 200).
#[derive(Debug, Deserialize)]
pub(crate) struct HealthResponse {
    /// Whether the remote store is fully operational.
    pub healthy: bool,

    /// Human-readable description of the health state.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Memory (wire shape)
// ---------------------------------------------------------------------------

/// Wire representation of a stored memory entry.
///
/// Metadata fields are flattened so they appear at the top level of the JSON
/// object rather than nested under a `"metadata"` key.
#[derive(Debug, Deserialize)]
pub(crate) struct MemoryDto {
    /// Stable identifier.
    pub id: Uuid,

    /// The text content.
    pub text: String,

    /// Caller-supplied tags.
    pub tags: Vec<String>,

    /// When the memory was first stored (RFC3339).
    pub created_at: DateTime<Utc>,

    /// When the memory was last modified, if ever (RFC3339).
    pub updated_at: Option<DateTime<Utc>>,

    /// Arbitrary metadata fields, flattened at the top level.
    #[serde(flatten)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}
