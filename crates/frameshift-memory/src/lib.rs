//! # frameshift-memory
//!
//! Defines the pluggable memory adapter contract for the Personify persona
//! marketplace platform.
//!
//! This crate contains:
//! - [`MemoryAdapter`] -- the async trait all backend implementations must satisfy.
//! - Common data types ([`Memory`], [`MemoryId`], [`Metadata`], [`Filters`],
//!   [`HealthStatus`], [`MemoryOp`], [`MemoryRequirement`]).
//! - [`MemoryError`] -- the unified error enum for all adapter operations.
//!
//! Concrete backends live in separate crates (e.g. `frameshift-memory-http`,
//! `frameshift-memory-sqlite`) and depend on this crate for the shared surface.
//!
//! ## Example
//!
//! ```rust,ignore
//! use frameshift_memory::{MemoryAdapter, Metadata, Filters};
//!
//! async fn use_adapter(adapter: &dyn MemoryAdapter) {
//!     let id = adapter
//!         .store("Hello world", &[], Metadata::new())
//!         .await
//!         .expect("store failed");
//!     let memory = adapter.recall(&id).await.expect("recall failed");
//!     assert_eq!(memory.text, "Hello world");
//! }
//! ```

pub mod adapter;
pub mod error;
pub mod types;

// Flatten the public surface so callers can write `frameshift_memory::MemoryAdapter`
// rather than `frameshift_memory::adapter::MemoryAdapter`.

pub use adapter::MemoryAdapter;
pub use error::MemoryError;
pub use types::{Filters, HealthStatus, Memory, MemoryId, MemoryOp, MemoryRequirement, Metadata};

/// Unit and integration tests for the frameshift-memory crate.
///
/// Covers type correctness, serialization contracts, error display,
/// and the `MockAdapter` which proves the trait is implementable and object-safe.
#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::Utc;

    use super::*;

    // -----------------------------------------------------------------------
    // MemoryId tests
    // -----------------------------------------------------------------------

    /// Consecutive calls to `MemoryId::new()` must never return equal values.
    #[test]
    fn memory_id_new_generates_unique_ids() {
        let a = MemoryId::new();
        let b = MemoryId::new();
        assert_ne!(a, b, "consecutive MemoryId::new() calls must be unique");
    }

    /// `Display` for `MemoryId` must emit the UUID string, not a struct debug representation.
    #[test]
    fn memory_id_display_shows_uuid_string() {
        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let id = MemoryId::from_uuid(uuid);
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
    }

    /// `MemoryId` must survive a JSON serialize-deserialize roundtrip unchanged.
    #[test]
    fn memory_id_roundtrip_json() {
        let id = MemoryId::new();
        let json = serde_json::to_string(&id).expect("serialize MemoryId");
        let restored: MemoryId = serde_json::from_str(&json).expect("deserialize MemoryId");
        assert_eq!(id, restored);
    }

    // -----------------------------------------------------------------------
    // Memory tests
    // -----------------------------------------------------------------------

    /// `Memory` must serialize to JSON and deserialize back with all fields intact.
    #[test]
    fn memory_roundtrip_json() {
        let mem = Memory {
            id: MemoryId::new(),
            text: "test memory content".into(),
            tags: vec!["tag-a".into(), "tag-b".into()],
            metadata: Metadata::new(),
            created_at: Utc::now(),
            updated_at: None,
        };
        let json = serde_json::to_string(&mem).expect("serialize Memory");
        let restored: Memory = serde_json::from_str(&json).expect("deserialize Memory");
        assert_eq!(mem.text, restored.text);
        assert_eq!(mem.tags, restored.tags);
        assert_eq!(mem.id, restored.id);
    }

    // -----------------------------------------------------------------------
    // Metadata tests
    // -----------------------------------------------------------------------

    /// `Metadata::insert` and `Metadata::get` must store and retrieve values correctly.
    #[test]
    fn metadata_insert_and_get() {
        let mut meta = Metadata::new();
        meta.insert("key", serde_json::json!("value"));
        assert_eq!(meta.get("key"), Some(&serde_json::json!("value")));
        assert_eq!(meta.get("missing"), None);
    }

    /// `Metadata` uses `#[serde(flatten)]` -- keys must appear at the top level
    /// of the serialized JSON object, not nested under an `"inner"` key.
    #[test]
    fn metadata_flatten_serialization() {
        let mut meta = Metadata::new();
        meta.insert("source", serde_json::json!("test-source"));
        meta.insert("priority", serde_json::json!(1));

        let json = serde_json::to_string(&meta).expect("serialize Metadata");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");
        assert_eq!(value["source"], serde_json::json!("test-source"));
        assert_eq!(value["priority"], serde_json::json!(1));
        // There must be no nested "inner" key.
        assert!(value.get("inner").is_none());
    }

    /// `Metadata` must survive a JSON serialize-deserialize roundtrip with values intact.
    #[test]
    fn metadata_roundtrip_json() {
        let mut meta = Metadata::new();
        meta.insert("a", serde_json::json!(42));
        let json = serde_json::to_string(&meta).expect("serialize Metadata");
        let restored: Metadata = serde_json::from_str(&json).expect("deserialize Metadata");
        assert_eq!(restored.get("a"), Some(&serde_json::json!(42)));
    }

    // -----------------------------------------------------------------------
    // Filters tests
    // -----------------------------------------------------------------------

    /// `Filters::default()` must leave every field as `None` (no filtering applied).
    #[test]
    fn filters_default_is_all_none() {
        let f = Filters::default();
        assert!(f.tags.is_none());
        assert!(f.after.is_none());
        assert!(f.before.is_none());
        assert!(f.metadata.is_none());
    }

    /// `Filters` must survive a JSON serialize-deserialize roundtrip with values intact.
    #[test]
    fn filters_roundtrip_json() {
        let f = Filters {
            tags: Some(vec!["rust".into()]),
            after: Some(Utc::now()),
            before: None,
            metadata: None,
        };
        let json = serde_json::to_string(&f).expect("serialize Filters");
        let restored: Filters = serde_json::from_str(&json).expect("deserialize Filters");
        assert_eq!(restored.tags, f.tags);
    }

    // -----------------------------------------------------------------------
    // HealthStatus tests
    // -----------------------------------------------------------------------

    /// `HealthStatus` must survive a JSON serialize-deserialize roundtrip with all fields intact.
    #[test]
    fn health_status_roundtrip_json() {
        let hs = HealthStatus {
            healthy: true,
            message: "all good".into(),
            latency_ms: Some(12),
        };
        let json = serde_json::to_string(&hs).expect("serialize HealthStatus");
        let restored: HealthStatus = serde_json::from_str(&json).expect("deserialize HealthStatus");
        assert_eq!(restored.healthy, hs.healthy);
        assert_eq!(restored.message, hs.message);
        assert_eq!(restored.latency_ms, hs.latency_ms);
    }

    // -----------------------------------------------------------------------
    // MemoryOp tests
    // -----------------------------------------------------------------------

    /// Every `MemoryOp` variant must serialize to its lowercase string name.
    #[test]
    fn memory_op_serializes_as_lowercase() {
        assert_eq!(
            serde_json::to_string(&MemoryOp::Store).unwrap(),
            "\"store\""
        );
        assert_eq!(
            serde_json::to_string(&MemoryOp::Search).unwrap(),
            "\"search\""
        );
        assert_eq!(
            serde_json::to_string(&MemoryOp::Recall).unwrap(),
            "\"recall\""
        );
        assert_eq!(serde_json::to_string(&MemoryOp::List).unwrap(), "\"list\"");
        assert_eq!(
            serde_json::to_string(&MemoryOp::Forget).unwrap(),
            "\"forget\""
        );
        assert_eq!(
            serde_json::to_string(&MemoryOp::Health).unwrap(),
            "\"health\""
        );
    }

    // -----------------------------------------------------------------------
    // MemoryRequirement tests
    // -----------------------------------------------------------------------

    /// The default `MemoryRequirement` must be `None` (pack does not require memory).
    #[test]
    fn memory_requirement_default_is_none() {
        assert_eq!(MemoryRequirement::default(), MemoryRequirement::None);
    }

    /// Every `MemoryRequirement` variant must serialize to its lowercase string name.
    #[test]
    fn memory_requirement_serializes_as_lowercase() {
        assert_eq!(
            serde_json::to_string(&MemoryRequirement::None).unwrap(),
            "\"none\""
        );
        assert_eq!(
            serde_json::to_string(&MemoryRequirement::Soft).unwrap(),
            "\"soft\""
        );
        assert_eq!(
            serde_json::to_string(&MemoryRequirement::Hard).unwrap(),
            "\"hard\""
        );
    }

    // -----------------------------------------------------------------------
    // MemoryError tests
    // -----------------------------------------------------------------------

    /// Every `MemoryError` variant must produce a human-readable `Display` string
    /// that contains the variant's key noun phrase.
    #[test]
    fn memory_error_display_is_informative() {
        let id = MemoryId::from_uuid(
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        );
        assert!(
            MemoryError::NotFound(id).to_string().contains("not found"),
            "NotFound display should mention 'not found'"
        );
        assert!(MemoryError::ConnectionFailed("timeout".into())
            .to_string()
            .contains("connection failed"),);
        assert!(MemoryError::Unauthorized("forbidden".into())
            .to_string()
            .contains("unauthorized"),);
        assert!(MemoryError::RateLimited {
            retry_after_secs: Some(30)
        }
        .to_string()
        .contains("rate limited"),);
        assert!(MemoryError::InvalidQuery("bad syntax".into())
            .to_string()
            .contains("invalid query"),);
        assert!(MemoryError::StorageFull
            .to_string()
            .contains("storage full"));
        assert!(MemoryError::Backend("internal".into())
            .to_string()
            .contains("backend error"),);
    }

    // -----------------------------------------------------------------------
    // MockAdapter -- proves trait is implementable and object-safe
    // -----------------------------------------------------------------------

    /// In-memory mock that stores memories in a `Vec` behind a `Mutex`.
    ///
    /// Used to verify that `MemoryAdapter` is implementable and object-safe
    /// (`Box<dyn MemoryAdapter>` must compile and work).
    struct MockAdapter {
        /// The in-memory store; guarded by a `Mutex` for interior mutability.
        memories: Mutex<Vec<Memory>>,
    }

    /// Constructor and helper methods for `MockAdapter`.
    impl MockAdapter {
        /// Create an empty `MockAdapter` with no stored memories.
        fn new() -> Self {
            Self {
                memories: Mutex::new(Vec::new()),
            }
        }
    }

    /// `MemoryAdapter` implementation for `MockAdapter`.
    ///
    /// Provides a minimal in-process backend with substring search and
    /// position-stable storage (entries are appended; deletion uses `retain`).
    #[async_trait]
    impl MemoryAdapter for MockAdapter {
        /// Append a new memory entry and return its assigned `MemoryId`.
        async fn store(
            &self,
            text: &str,
            tags: &[String],
            metadata: Metadata,
        ) -> Result<MemoryId, MemoryError> {
            let id = MemoryId::new();
            let mem = Memory {
                id: id.clone(),
                text: text.to_owned(),
                tags: tags.to_vec(),
                metadata,
                created_at: Utc::now(),
                updated_at: None,
            };
            self.memories
                .lock()
                .map_err(|e| MemoryError::Backend(e.to_string()))?
                .push(mem);
            Ok(id)
        }

        /// Return up to `k` memories whose text contains `query` as a substring.
        /// Returns an empty `Vec` immediately when `k == 0`.
        async fn search(
            &self,
            query: &str,
            k: usize,
            _filters: &Filters,
        ) -> Result<Vec<Memory>, MemoryError> {
            if k == 0 {
                return Ok(Vec::new());
            }
            let guard = self
                .memories
                .lock()
                .map_err(|e| MemoryError::Backend(e.to_string()))?;
            Ok(guard
                .iter()
                .filter(|m| m.text.contains(query))
                .take(k)
                .cloned()
                .collect())
        }

        /// Return the memory with the given `id`, or `MemoryError::NotFound`.
        async fn recall(&self, id: &MemoryId) -> Result<Memory, MemoryError> {
            let guard = self
                .memories
                .lock()
                .map_err(|e| MemoryError::Backend(e.to_string()))?;
            guard
                .iter()
                .find(|m| &m.id == id)
                .cloned()
                .ok_or_else(|| MemoryError::NotFound(id.clone()))
        }

        /// Return up to `limit` memories starting from `offset`.
        async fn list(&self, limit: usize, offset: usize) -> Result<Vec<Memory>, MemoryError> {
            let guard = self
                .memories
                .lock()
                .map_err(|e| MemoryError::Backend(e.to_string()))?;
            Ok(guard.iter().skip(offset).take(limit).cloned().collect())
        }

        /// Remove the memory with the given `id`, or return `MemoryError::NotFound`.
        async fn forget(&self, id: &MemoryId) -> Result<(), MemoryError> {
            let mut guard = self
                .memories
                .lock()
                .map_err(|e| MemoryError::Backend(e.to_string()))?;
            let initial_len = guard.len();
            guard.retain(|m| &m.id != id);
            if guard.len() == initial_len {
                return Err(MemoryError::NotFound(id.clone()));
            }
            Ok(())
        }

        /// Always report healthy; the mock never goes down.
        async fn health(&self) -> Result<HealthStatus, MemoryError> {
            Ok(HealthStatus {
                healthy: true,
                message: "mock adapter is always healthy".into(),
                latency_ms: Some(0),
            })
        }
    }

    /// Compile-time proof that `MemoryAdapter` is object-safe: a value of
    /// type `Box<dyn MemoryAdapter>` must be constructible.
    fn _assert_object_safe(_: Box<dyn MemoryAdapter>) {}

    /// Store a memory and immediately recall it; text and tags must match.
    #[tokio::test]
    async fn mock_adapter_store_and_recall() {
        let adapter = MockAdapter::new();
        let id = adapter
            .store("hello memory", &["tag1".into()], Metadata::new())
            .await
            .expect("store must succeed");

        let mem = adapter.recall(&id).await.expect("recall must succeed");
        assert_eq!(mem.text, "hello memory");
        assert_eq!(mem.tags, vec!["tag1".to_string()]);
    }

    /// Recalling a non-existent ID must return `MemoryError::NotFound`.
    #[tokio::test]
    async fn mock_adapter_recall_not_found() {
        let adapter = MockAdapter::new();
        let missing = MemoryId::new();
        let err = adapter
            .recall(&missing)
            .await
            .expect_err("must be NotFound");
        assert!(matches!(err, MemoryError::NotFound(_)));
    }

    /// Forgetting a non-existent ID must return `MemoryError::NotFound`.
    #[tokio::test]
    async fn mock_adapter_forget_not_found() {
        let adapter = MockAdapter::new();
        let missing = MemoryId::new();
        let err = adapter
            .forget(&missing)
            .await
            .expect_err("must be NotFound");
        assert!(matches!(err, MemoryError::NotFound(_)));
    }

    /// Searching with `k = 0` must return an empty `Vec` without error,
    /// regardless of how many memories are stored.
    #[tokio::test]
    async fn mock_adapter_search_k_zero_returns_empty() {
        let adapter = MockAdapter::new();
        adapter
            .store("some text", &[], Metadata::new())
            .await
            .expect("store");
        let results = adapter
            .search("some", 0, &Filters::default())
            .await
            .expect("search with k=0 must not error");
        assert!(results.is_empty());
    }

    /// `list` with `limit = 2` and `offset = 1` must return exactly 2 entries
    /// when at least 3 memories are stored.
    #[tokio::test]
    async fn mock_adapter_list_pagination() {
        let adapter = MockAdapter::new();
        for i in 0..5 {
            let mut meta = Metadata::new();
            meta.insert("i", serde_json::json!(i));
            adapter
                .store(&format!("memory {i}"), &[], meta)
                .await
                .expect("store");
        }
        let page = adapter.list(2, 1).await.expect("list");
        assert_eq!(page.len(), 2, "limit 2, offset 1 should return 2 entries");
    }

    /// After `forget`, the memory must no longer be reachable via `recall`.
    #[tokio::test]
    async fn mock_adapter_forget_removes_entry() {
        let adapter = MockAdapter::new();
        let id = adapter
            .store("to be forgotten", &[], Metadata::new())
            .await
            .expect("store");
        adapter.forget(&id).await.expect("forget");
        let err = adapter.recall(&id).await.expect_err("must be gone");
        assert!(matches!(err, MemoryError::NotFound(_)));
    }

    /// `health` must report `healthy: true` for the mock adapter.
    #[tokio::test]
    async fn mock_adapter_health() {
        let adapter = MockAdapter::new();
        let status = adapter.health().await.expect("health");
        assert!(status.healthy);
    }

    /// `store` and `recall` must work correctly when the adapter is held as
    /// `Box<dyn MemoryAdapter>`, proving runtime object-safety.
    #[tokio::test]
    async fn mock_adapter_held_as_box_dyn() {
        let adapter: Box<dyn MemoryAdapter> = Box::new(MockAdapter::new());
        let id = adapter
            .store("via dyn", &[], Metadata::new())
            .await
            .expect("store via Box<dyn MemoryAdapter>");
        let mem = adapter
            .recall(&id)
            .await
            .expect("recall via Box<dyn MemoryAdapter>");
        assert_eq!(mem.text, "via dyn");
    }
}
