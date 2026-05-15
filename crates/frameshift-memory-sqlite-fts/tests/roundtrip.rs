//! Integration tests for `frameshift-memory-sqlite-fts`.
//!
//! Each test creates its own temporary SQLite database so tests are fully
//! isolated and can run in parallel.

use frameshift_memory::{Filters, MemoryAdapter, MemoryError, Metadata};
use frameshift_memory_sqlite_fts::{SqliteFtsAdapter, SqliteFtsConfig};
use tempfile::tempdir;

/// Build a fresh [`SqliteFtsAdapter`] backed by a temp file.
async fn make_adapter() -> (SqliteFtsAdapter, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("memories.db");
    let adapter = SqliteFtsAdapter::new(SqliteFtsConfig { path, pool_size: 2 })
        .await
        .expect("new adapter");
    (adapter, dir)
}

// ---------------------------------------------------------------------------
// store -> recall roundtrip
// ---------------------------------------------------------------------------

/// Storing a memory and recalling it by ID must return the identical content.
#[tokio::test]
async fn store_recall_roundtrip() {
    let (adapter, _dir) = make_adapter().await;

    let mut meta = Metadata::new();
    meta.insert("source", serde_json::json!("test"));

    let id = adapter
        .store(
            "hello world",
            &["greet".into(), "world".into()],
            meta.clone(),
        )
        .await
        .expect("store");

    let mem = adapter.recall(&id).await.expect("recall");

    assert_eq!(mem.id, id);
    assert_eq!(mem.text, "hello world");
    assert!(mem.tags.contains(&"greet".to_string()));
    assert!(mem.tags.contains(&"world".to_string()));
    assert_eq!(mem.metadata.get("source"), Some(&serde_json::json!("test")));
    assert!(mem.updated_at.is_none());
}

// ---------------------------------------------------------------------------
// FTS search
// ---------------------------------------------------------------------------

/// A stored memory must be findable by a keyword present in its text.
#[tokio::test]
async fn search_by_fts_keyword_finds_entry() {
    let (adapter, _dir) = make_adapter().await;

    let id = adapter
        .store("rusty bicycle lane", &[], Metadata::new())
        .await
        .expect("store");

    let results = adapter
        .search("bicycle", 10, &Filters::default())
        .await
        .expect("search");

    assert!(!results.is_empty(), "should have at least one result");
    assert!(results.iter().any(|m| m.id == id), "stored id must appear");
}

// ---------------------------------------------------------------------------
// BM25 ranking
// ---------------------------------------------------------------------------

/// Search results are ordered by BM25 relevance. A document where the query
/// term appears more times than in another document of similar length must
/// rank higher (appear earlier in the results list).
#[tokio::test]
async fn search_ranks_more_relevant_docs_higher() {
    let (adapter, _dir) = make_adapter().await;

    // Pad the corpus with many irrelevant documents so BM25 IDF is meaningful.
    // All padding docs are a similar length (~10 words) to establish a baseline.
    for i in 0..20u32 {
        adapter
            .store(
                &format!("unrelated document about cooking baking number {i} food kitchen"),
                &[],
                Metadata::new(),
            )
            .await
            .expect("store padding");
    }

    // Both target docs are the same length (10 words each) so BM25 length
    // normalization does not affect the relative ranking. The only difference
    // is term frequency for "zebra".
    //
    // Low-relevance: "zebra" appears once out of 10 words.
    let id_low = adapter
        .store(
            "zebra animal nature wildlife savanna africa plains grassland fauna ecology",
            &[],
            Metadata::new(),
        )
        .await
        .expect("store low relevance");

    // High-relevance: "zebra" appears five times out of 10 words.
    let id_high = adapter
        .store(
            "zebra zebra zebra zebra zebra animal nature wildlife savanna africa",
            &[],
            Metadata::new(),
        )
        .await
        .expect("store high relevance");

    let results = adapter
        .search("zebra", 10, &Filters::default())
        .await
        .expect("search");

    // Both documents must appear.
    assert!(
        results.iter().any(|m| m.id == id_low),
        "low-relevance doc must appear"
    );
    assert!(
        results.iter().any(|m| m.id == id_high),
        "high-relevance doc must appear"
    );

    // The high-relevance document must rank first (lower BM25 score = more relevant).
    let pos_high = results.iter().position(|m| m.id == id_high).unwrap();
    let pos_low = results.iter().position(|m| m.id == id_low).unwrap();
    assert!(
        pos_high < pos_low,
        "high-relevance doc must rank before low-relevance doc (pos_high={pos_high}, pos_low={pos_low})"
    );
}

// ---------------------------------------------------------------------------
// forget -> recall returns NotFound
// ---------------------------------------------------------------------------

/// After forgetting a memory, recalling it must return `NotFound`.
#[tokio::test]
async fn store_forget_recall_returns_not_found() {
    let (adapter, _dir) = make_adapter().await;

    let id = adapter
        .store("temporary memory", &[], Metadata::new())
        .await
        .expect("store");

    adapter.forget(&id).await.expect("forget");

    let err = adapter.recall(&id).await.expect_err("must be NotFound");
    assert!(matches!(err, MemoryError::NotFound(_)));
}

// ---------------------------------------------------------------------------
// list with limit/offset -- most-recent first
// ---------------------------------------------------------------------------

/// `list` must return entries ordered by `created_at` descending and honour
/// `limit` and `offset`.
#[tokio::test]
async fn list_limit_offset_most_recent_first() {
    let (adapter, _dir) = make_adapter().await;

    // Insert 5 memories with a small sleep so timestamps differ.
    let mut ids = Vec::new();
    for i in 0..5u32 {
        // Use metadata to track insertion order.
        let mut meta = Metadata::new();
        meta.insert("order", serde_json::json!(i));
        let id = adapter
            .store(&format!("memory {i}"), &[], meta)
            .await
            .expect("store");
        ids.push(id);
        // Yield briefly so SQLite wall-clock timestamps can differ.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    // limit=2, offset=0 should return the two most recent (order 4 and 3).
    let page = adapter.list(2, 0).await.expect("list");
    assert_eq!(page.len(), 2);
    // The most-recently inserted id is ids[4].
    assert_eq!(page[0].id, ids[4], "first result must be most recent");
    assert_eq!(page[1].id, ids[3]);

    // limit=3, offset=2 should return orders 2, 1, 0.
    let page2 = adapter.list(3, 2).await.expect("list page 2");
    assert_eq!(page2.len(), 3);
    assert_eq!(page2[0].id, ids[2]);
}

// ---------------------------------------------------------------------------
// Tag intersection filter
// ---------------------------------------------------------------------------

/// `filters.tags` must restrict results to memories that have ALL listed tags.
#[tokio::test]
async fn filters_tags_intersection() {
    let (adapter, _dir) = make_adapter().await;

    let id_both = adapter
        .store(
            "has both tags",
            &["alpha".into(), "beta".into()],
            Metadata::new(),
        )
        .await
        .expect("store both");

    let _id_alpha = adapter
        .store("has only alpha", &["alpha".into()], Metadata::new())
        .await
        .expect("store alpha");

    let filters = Filters {
        tags: Some(vec!["alpha".into(), "beta".into()]),
        ..Default::default()
    };

    let results = adapter.search("both", 10, &filters).await.expect("search");
    assert_eq!(
        results.len(),
        1,
        "only the entry with both tags should match"
    );
    assert_eq!(results[0].id, id_both);
}

// ---------------------------------------------------------------------------
// Time range filters
// ---------------------------------------------------------------------------

/// `filters.after` and `filters.before` must restrict results by `created_at`.
#[tokio::test]
async fn filters_after_before() {
    let (adapter, _dir) = make_adapter().await;

    // Sleep 1.1s before recording before_time so that any entries stored
    // after this point are guaranteed to have a created_at in a different
    // unix-second bucket.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let before_time = chrono::Utc::now();
    // Sleep 1.1s again so the "early entry" timestamp is strictly after before_time.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    adapter
        .store("early entry", &[], Metadata::new())
        .await
        .expect("store early");

    // Sleep so the second entry has a strictly later timestamp.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let mid_time = chrono::Utc::now();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let id_late = adapter
        .store("late entry", &[], Metadata::new())
        .await
        .expect("store late");

    // Query with `after = mid_time` should exclude the early entry.
    let filters = Filters {
        after: Some(mid_time),
        ..Default::default()
    };
    let results = adapter
        .search("entry", 10, &filters)
        .await
        .expect("search after");
    assert_eq!(results.len(), 1, "only the late entry should appear");
    assert_eq!(results[0].id, id_late);

    // Query with `before = before_time` should return nothing (both entries are after).
    let filters_before = Filters {
        before: Some(before_time),
        ..Default::default()
    };
    let results_empty = adapter
        .search("entry", 10, &filters_before)
        .await
        .expect("search before");
    assert!(
        results_empty.is_empty(),
        "no entries should predate before_time"
    );
}

// ---------------------------------------------------------------------------
// Short-circuit cases
// ---------------------------------------------------------------------------

/// An all-whitespace query must return an empty `Vec` without error.
#[tokio::test]
async fn search_empty_query_returns_empty() {
    let (adapter, _dir) = make_adapter().await;

    adapter
        .store("something stored", &[], Metadata::new())
        .await
        .expect("store");

    let results = adapter
        .search("   ", 10, &Filters::default())
        .await
        .expect("search whitespace");
    assert!(results.is_empty(), "whitespace query must return empty");
}

/// `k = 0` must return an empty `Vec` without error.
#[tokio::test]
async fn search_k_zero_returns_empty() {
    let (adapter, _dir) = make_adapter().await;

    adapter
        .store("something stored", &[], Metadata::new())
        .await
        .expect("store");

    let results = adapter
        .search("something", 0, &Filters::default())
        .await
        .expect("search k=0");
    assert!(results.is_empty(), "k=0 must return empty");
}

// ---------------------------------------------------------------------------
// Migration idempotency
// ---------------------------------------------------------------------------

/// Opening the same database file twice must not fail -- migrations are
/// idempotent.
#[tokio::test]
async fn migrations_idempotent_across_two_new_calls() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("idempotent.db");

    let adapter1 = SqliteFtsAdapter::new(SqliteFtsConfig {
        path: path.clone(),
        pool_size: 2,
    })
    .await
    .expect("first new()");

    let id = adapter1
        .store("persisted across opens", &[], Metadata::new())
        .await
        .expect("store");

    drop(adapter1);

    let adapter2 = SqliteFtsAdapter::new(SqliteFtsConfig {
        path: path.clone(),
        pool_size: 2,
    })
    .await
    .expect("second new() -- must not fail with duplicate table errors");

    let mem = adapter2.recall(&id).await.expect("recall after re-open");
    assert_eq!(mem.text, "persisted across opens");
}

// ---------------------------------------------------------------------------
// forget not found
// ---------------------------------------------------------------------------

/// Forgetting a non-existent ID must return `NotFound`.
#[tokio::test]
async fn forget_nonexistent_returns_not_found() {
    let (adapter, _dir) = make_adapter().await;

    let missing = frameshift_memory::MemoryId::new();
    let err = adapter
        .forget(&missing)
        .await
        .expect_err("must be NotFound");
    assert!(matches!(err, MemoryError::NotFound(_)));
}

// ---------------------------------------------------------------------------
// health
// ---------------------------------------------------------------------------

/// The adapter must report itself as healthy after successful construction.
#[tokio::test]
async fn health_reports_healthy() {
    let (adapter, _dir) = make_adapter().await;
    let status = adapter.health().await.expect("health");
    assert!(status.healthy);
    assert!(status.latency_ms.is_some());
}
