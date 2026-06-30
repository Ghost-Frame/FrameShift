//! [`SqliteFtsAdapter`] -- SQLite FTS5-backed [`MemoryAdapter`] implementation.
//!
//! All SQL is executed inside `deadpool_sqlite::interact()` closures so that
//! the blocking SQLite calls never occupy an async thread. The async interface
//! is preserved via the `async_trait` macro.

use std::path::PathBuf;
use std::time::Instant;

use async_trait::async_trait;
use deadpool_sqlite::{Config as PoolConfig, Pool, Runtime};
use frameshift_memory::{
    Filters, HealthStatus, Memory, MemoryAdapter, MemoryError, MemoryId, Metadata,
};
use rusqlite::OptionalExtension;

use crate::error::SqliteFtsError;
use crate::migrate::run_migrations;

/// Configuration for [`SqliteFtsAdapter`].
#[derive(Debug, Clone)]
pub struct SqliteFtsConfig {
    /// Path to the SQLite database file.
    ///
    /// The parent directory is created automatically if it does not exist.
    pub path: PathBuf,

    /// Maximum number of connections in the deadpool-sqlite pool.
    pub pool_size: usize,
}

/// SQLite FTS5-backed implementation of [`MemoryAdapter`].
///
/// Stores memories in a local SQLite database with WAL mode and FTS5
/// full-text search. Concurrent reads are supported via the connection pool;
/// writes are serialised by SQLite's WAL locking.
pub struct SqliteFtsAdapter {
    /// Connection pool to the underlying SQLite database.
    pool: Pool,
}

impl SqliteFtsAdapter {
    /// Open (or create) the database at `config.path` and return a ready adapter.
    ///
    /// On first call the schema migration is applied. Subsequent calls on the
    /// same file are idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::Configuration`] when the parent directory cannot
    /// be created, or [`MemoryError::ConnectionFailed`] when the pool or
    /// PRAGMAs cannot be applied.
    pub async fn new(config: SqliteFtsConfig) -> Result<Self, MemoryError> {
        // Create the parent directory if needed.
        if let Some(parent) = config.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    MemoryError::Configuration(format!(
                        "cannot create parent directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }

        // Build the deadpool-sqlite pool.
        let pool_cfg = PoolConfig::new(config.path.to_string_lossy().into_owned());
        let pool = pool_cfg
            .builder(Runtime::Tokio1)
            .map_err(|e| MemoryError::Configuration(format!("pool builder error: {e}")))?
            .max_size(config.pool_size)
            .build()
            .map_err(|e| MemoryError::Configuration(format!("pool build error: {e}")))?;

        // Apply PRAGMAs and run migrations on a single bootstrap connection.
        let conn = pool
            .get()
            .await
            .map_err(|e| MemoryError::ConnectionFailed(e.to_string()))?;

        conn.interact(|c| -> Result<(), SqliteFtsError> {
            c.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA busy_timeout=5000;",
            )?;
            run_migrations(c)?;
            Ok(())
        })
        .await
        .map_err(SqliteFtsError::from)
        .map_err(MemoryError::from)?
        .map_err(MemoryError::from)?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl MemoryAdapter for SqliteFtsAdapter {
    /// Persist a new memory and return its generated [`MemoryId`].
    ///
    /// Tags are stored in the `memory_tags` table and the FTS index is updated
    /// automatically via the `memories_fts_insert` trigger.
    async fn store(
        &self,
        text: &str,
        tags: &[String],
        metadata: Metadata,
    ) -> Result<MemoryId, MemoryError> {
        let id = MemoryId::new();
        let id_str = id.to_string();
        let text_owned = text.to_owned();
        let tags_owned = tags.to_vec();
        let metadata_json = serde_json::to_string(&metadata)
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?;

        let conn = self
            .pool
            .get()
            .await
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?;

        conn.interact(move |c| -> Result<(), SqliteFtsError> {
            let now = chrono::Utc::now().timestamp();
            c.execute(
                "INSERT INTO memories (id, text, created_at, metadata) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![id_str, text_owned, now, metadata_json],
            )?;

            for tag in &tags_owned {
                c.execute(
                    "INSERT OR IGNORE INTO memory_tags (memory_id, tag) VALUES (?1, ?2)",
                    rusqlite::params![id_str, tag],
                )?;
            }

            Ok(())
        })
        .await
        .map_err(SqliteFtsError::from)
        .map_err(MemoryError::from)?
        .map_err(MemoryError::from)?;

        Ok(id)
    }

    /// Search memories using FTS5 full-text search with optional filters.
    ///
    /// Returns up to `k` results ranked by BM25 relevance. An all-whitespace
    /// query or `k == 0` returns an empty `Vec` without querying SQLite.
    async fn search(
        &self,
        query: &str,
        k: usize,
        filters: &Filters,
    ) -> Result<Vec<Memory>, MemoryError> {
        // Short-circuit for trivial cases.
        if k == 0 {
            return Ok(Vec::new());
        }
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }

        // M1 -- Harden the FTS5 query string before building the phrase expression.
        //
        // (a) NUL bytes ('\0') truncate the SQLite C-string and silently change
        //     query semantics -- reject any query that contains one.
        if query.contains('\0') {
            return Err(MemoryError::InvalidQuery(
                "query must not contain NUL bytes".into(),
            ));
        }
        // (b) Cap query length to prevent SQLite expression-depth exhaustion.
        /// Maximum allowed FTS5 query length in bytes.
        const MAX_QUERY_LEN: usize = 1024;
        if query.len() > MAX_QUERY_LEN {
            return Err(MemoryError::InvalidQuery(format!(
                "query exceeds maximum length of {MAX_QUERY_LEN} bytes"
            )));
        }

        // Escape the user query for FTS5: wrap in double quotes and double any
        // internal double quotes to prevent injection into the FTS5 expression.
        let escaped = query.replace('"', "\"\"");
        let fts_query = format!("\"{escaped}\"");

        let filters_owned = filters.clone();
        let k_i64 = i64::try_from(k).unwrap_or(i64::MAX);

        let conn = self
            .pool
            .get()
            .await
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?;

        let rows = conn
            .interact(move |c| -> Result<Vec<RawMemoryRow>, SqliteFtsError> {
                // Strategy: query the FTS table directly with MATCH so that
                // bm25() has proper FTS context. Additional non-FTS filters are
                // applied as WHERE conditions on the joined memories table.
                //
                // All user values are bound as parameters -- never interpolated.

                // Use owned Value enum so the params vec is Send.
                // params[0] is always the FTS MATCH query.
                let mut params: Vec<rusqlite::types::Value> = Vec::new();
                params.push(rusqlite::types::Value::Text(fts_query));

                // Extra WHERE conditions on the memories table (non-FTS).
                let mut extra_conditions: Vec<String> = Vec::new();

                // Tag intersection filter.
                if let Some(tags) = &filters_owned.tags {
                    if !tags.is_empty() {
                        let n = tags.len();
                        let placeholders: Vec<String> = tags
                            .iter()
                            .enumerate()
                            .map(|(i, _)| format!("?{}", params.len() + 1 + i))
                            .collect();
                        extra_conditions.push(format!(
                            "m.id IN (SELECT memory_id FROM memory_tags WHERE tag IN ({}) GROUP BY memory_id HAVING COUNT(DISTINCT tag) = {})",
                            placeholders.join(", "),
                            n
                        ));
                        for tag in tags {
                            params.push(rusqlite::types::Value::Text(tag.clone()));
                        }
                    }
                }

                // Time range filters.
                if let Some(after) = &filters_owned.after {
                    let ts = after.timestamp();
                    extra_conditions.push(format!("m.created_at >= ?{}", params.len() + 1));
                    params.push(rusqlite::types::Value::Integer(ts));
                }
                if let Some(before) = &filters_owned.before {
                    let ts = before.timestamp();
                    extra_conditions.push(format!("m.created_at < ?{}", params.len() + 1));
                    params.push(rusqlite::types::Value::Integer(ts));
                }

                // Metadata key=value filters using JSON1.
                //
                // M2 -- Validate each metadata key before building the JSON path.
                // An unvalidated key such as `[0]` or `a.b` produces an invalid
                // or unexpected path that silently disables the filter. Only keys
                // matching [A-Za-z0-9_] (non-empty) are accepted; any other key
                // causes the entire search to return an error so callers notice
                // the malformed input rather than receiving silently unfiltered
                // results.
                if let Some(meta_map) = &filters_owned.metadata {
                    for (key, value) in meta_map {
                        // Reject empty keys or keys containing non-identifier chars.
                        if key.is_empty()
                            || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        {
                            return Err(SqliteFtsError::InvalidQuery(format!(
                                "metadata filter key {key:?} is invalid; \
                                 only [A-Za-z0-9_] characters are allowed"
                            )));
                        }
                        let json_path = format!("$.{key}");
                        let value_str = value.to_string();
                        // Use json_extract and compare via json(); bind both path and value.
                        extra_conditions.push(format!(
                            "json_extract(m.metadata, ?{}) = json(?{})",
                            params.len() + 1,
                            params.len() + 2
                        ));
                        params.push(rusqlite::types::Value::Text(json_path));
                        params.push(rusqlite::types::Value::Text(value_str));
                    }
                }

                // Build the SQL. The FTS table is the primary driver so that
                // bm25() is called in proper FTS5 query context. The memories
                // table is joined to get stored columns and apply extra filters.
                let extra_where = if extra_conditions.is_empty() {
                    String::new()
                } else {
                    format!("AND {}", extra_conditions.join(" AND "))
                };

                let sql = format!(
                    "SELECT m.id, m.text, m.created_at, m.updated_at, m.metadata, \
                     bm25(memories_fts) AS score \
                     FROM memories_fts \
                     JOIN memories m ON m.rowid = memories_fts.rowid \
                     WHERE memories_fts MATCH ?1 \
                     {extra_where} \
                     ORDER BY score \
                     LIMIT ?{limit_idx}",
                    limit_idx = params.len() + 1
                );
                params.push(rusqlite::types::Value::Integer(k_i64));

                // Convert owned Values to ToSql refs for query_map.
                let param_refs: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();

                let mut stmt = c.prepare(&sql)?;
                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    Ok(RawMemoryRow {
                        id: row.get(0)?,
                        text: row.get(1)?,
                        created_at: row.get(2)?,
                        updated_at: row.get(3)?,
                        metadata_json: row.get(4)?,
                    })
                })?;

                rows.collect::<Result<Vec<_>, _>>().map_err(SqliteFtsError::from)
            })
            .await
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?
            .map_err(MemoryError::from)?;

        // Release the connection before rows_to_memories re-enters the pool via
        // fetch_tags_for_id. With pool_size == 1 holding conn here deadlocks.
        drop(conn);

        // Fetch tags and assemble Memory values.
        rows_to_memories(rows, &self.pool).await
    }

    /// Retrieve a single memory by its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::NotFound`] when no memory with `id` exists.
    async fn recall(&self, id: &MemoryId) -> Result<Memory, MemoryError> {
        let id_str = id.to_string();
        let conn = self
            .pool
            .get()
            .await
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?;

        let row_opt = conn
            .interact(move |c| -> Result<Option<RawMemoryRow>, SqliteFtsError> {
                c.query_row(
                    "SELECT id, text, created_at, updated_at, metadata FROM memories WHERE id = ?1",
                    rusqlite::params![id_str],
                    |row| {
                        Ok(RawMemoryRow {
                            id: row.get(0)?,
                            text: row.get(1)?,
                            created_at: row.get(2)?,
                            updated_at: row.get(3)?,
                            metadata_json: row.get(4)?,
                        })
                    },
                )
                .optional()
                .map_err(SqliteFtsError::from)
            })
            .await
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?
            .map_err(MemoryError::from)?;

        // Release the connection before fetch_tags_for_id re-enters the pool.
        // With pool_size == 1 holding conn here deadlocks.
        drop(conn);

        match row_opt {
            None => Err(MemoryError::NotFound(id.clone())),
            Some(row) => {
                let tags = fetch_tags_for_id(&row.id, &self.pool).await?;
                row_to_memory(row, tags).map_err(MemoryError::from)
            }
        }
    }

    /// Return a paginated slice of all stored memories, most-recent first.
    ///
    /// # Parameters
    ///
    /// - `limit`  -- maximum number of entries to return.
    /// - `offset` -- number of entries to skip before collecting.
    async fn list(&self, limit: usize, offset: usize) -> Result<Vec<Memory>, MemoryError> {
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let offset_i64 = i64::try_from(offset).unwrap_or(i64::MAX);

        let conn = self
            .pool
            .get()
            .await
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?;

        let rows = conn
            .interact(move |c| -> Result<Vec<RawMemoryRow>, SqliteFtsError> {
                let mut stmt = c.prepare(
                    "SELECT id, text, created_at, updated_at, metadata \
                     FROM memories \
                     ORDER BY created_at DESC \
                     LIMIT ?1 OFFSET ?2",
                )?;
                let rows = stmt.query_map(rusqlite::params![limit_i64, offset_i64], |row| {
                    Ok(RawMemoryRow {
                        id: row.get(0)?,
                        text: row.get(1)?,
                        created_at: row.get(2)?,
                        updated_at: row.get(3)?,
                        metadata_json: row.get(4)?,
                    })
                })?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(SqliteFtsError::from)
            })
            .await
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?
            .map_err(MemoryError::from)?;

        // Release the connection before rows_to_memories re-enters the pool via
        // fetch_tags_for_id. With pool_size == 1 holding conn here deadlocks.
        drop(conn);

        rows_to_memories(rows, &self.pool).await
    }

    /// Permanently delete the memory with the given identifier.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::NotFound`] when no memory with `id` exists.
    async fn forget(&self, id: &MemoryId) -> Result<(), MemoryError> {
        let id_str = id.to_string();
        let conn = self
            .pool
            .get()
            .await
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?;

        let affected = conn
            .interact(move |c| -> Result<usize, SqliteFtsError> {
                let n = c.execute(
                    "DELETE FROM memories WHERE id = ?1",
                    rusqlite::params![id_str],
                )?;
                Ok(n)
            })
            .await
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?
            .map_err(MemoryError::from)?;

        if affected == 0 {
            return Err(MemoryError::NotFound(id.clone()));
        }
        Ok(())
    }

    /// Report the operational health of this adapter.
    ///
    /// Performs a lightweight `SELECT 1` to measure round-trip latency.
    async fn health(&self) -> Result<HealthStatus, MemoryError> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(SqliteFtsError::from)
            .map_err(MemoryError::from)?;

        let start = Instant::now();
        let result = conn
            .interact(|c| -> Result<(), SqliteFtsError> {
                c.execute_batch("SELECT 1")?;
                Ok(())
            })
            .await;
        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(())) => Ok(HealthStatus {
                healthy: true,
                message: "sqlite adapter is healthy".into(),
                latency_ms: Some(latency_ms),
            }),
            Ok(Err(e)) => Ok(HealthStatus {
                healthy: false,
                message: format!("sqlite error: {e}"),
                latency_ms: Some(latency_ms),
            }),
            Err(e) => Err(MemoryError::ConnectionFailed(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// A raw row read from the `memories` table before tag and metadata assembly.
struct RawMemoryRow {
    /// UUID string identifying this memory.
    id: String,
    /// The stored text content.
    text: String,
    /// Unix epoch seconds when this memory was created.
    created_at: i64,
    /// Unix epoch seconds when this memory was last updated, if ever.
    updated_at: Option<i64>,
    /// JSON-serialised metadata blob.
    metadata_json: String,
}

/// Fetch tags for a single memory ID from the pool.
async fn fetch_tags_for_id(id: &str, pool: &Pool) -> Result<Vec<String>, MemoryError> {
    let id_owned = id.to_owned();
    let conn = pool
        .get()
        .await
        .map_err(SqliteFtsError::from)
        .map_err(MemoryError::from)?;

    let tags = conn
        .interact(move |c| -> Result<Vec<String>, SqliteFtsError> {
            let mut stmt =
                c.prepare("SELECT tag FROM memory_tags WHERE memory_id = ?1 ORDER BY tag")?;
            let rows = stmt.query_map(rusqlite::params![id_owned], |row| row.get(0))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(SqliteFtsError::from)
        })
        .await
        .map_err(SqliteFtsError::from)
        .map_err(MemoryError::from)?
        .map_err(MemoryError::from)?;

    Ok(tags)
}

/// Assemble a [`Memory`] from a [`RawMemoryRow`] and its tags.
fn row_to_memory(row: RawMemoryRow, tags: Vec<String>) -> Result<Memory, SqliteFtsError> {
    let id = uuid::Uuid::parse_str(&row.id)
        .map(MemoryId::from_uuid)
        .map_err(SqliteFtsError::from)?;

    let created_at =
        chrono::DateTime::from_timestamp(row.created_at, 0).unwrap_or_else(chrono::Utc::now);

    let updated_at = row
        .updated_at
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

    let metadata: Metadata =
        serde_json::from_str(&row.metadata_json).map_err(SqliteFtsError::from)?;

    Ok(Memory {
        id,
        text: row.text,
        tags,
        metadata,
        created_at,
        updated_at,
    })
}

/// Convert a batch of [`RawMemoryRow`] values to [`Memory`], fetching tags for
/// each row in sequence.
///
/// This is an N+1 pattern but acceptable for the expected row counts here.
/// A single-query JOIN alternative would require more complex deserialization.
async fn rows_to_memories(
    rows: Vec<RawMemoryRow>,
    pool: &Pool,
) -> Result<Vec<Memory>, MemoryError> {
    let mut memories = Vec::with_capacity(rows.len());
    for row in rows {
        let tags = fetch_tags_for_id(&row.id, pool).await?;
        let mem = row_to_memory(row, tags).map_err(MemoryError::from)?;
        memories.push(mem);
    }
    Ok(memories)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use frameshift_memory::{Filters, MemoryAdapter, MemoryError};
    use tempfile::TempDir;

    use super::{SqliteFtsAdapter, SqliteFtsConfig};

    /// Build an adapter backed by a temporary file database that is cleaned up
    /// when `_dir` is dropped.
    async fn make_adapter() -> (SqliteFtsAdapter, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("test.db");
        let adapter = SqliteFtsAdapter::new(SqliteFtsConfig { path, pool_size: 2 })
            .await
            .expect("adapter init");
        (adapter, dir)
    }

    /// M1 -- A query containing a NUL byte must be rejected with InvalidQuery.
    #[tokio::test]
    async fn search_rejects_nul_byte_in_query() {
        let (adapter, _dir) = make_adapter().await;
        let query = "hello\0world";
        let result = adapter.search(query, 10, &Filters::default()).await;
        match result {
            Err(MemoryError::InvalidQuery(msg)) => {
                assert!(
                    msg.contains("NUL"),
                    "error message should mention NUL: {msg}"
                );
            }
            other => panic!("expected InvalidQuery for NUL byte, got: {other:?}"),
        }
    }

    /// M1 -- A query longer than 1024 bytes must be rejected with InvalidQuery.
    #[tokio::test]
    async fn search_rejects_overlength_query() {
        let (adapter, _dir) = make_adapter().await;
        // Build a query that exceeds the 1024-byte cap.
        let query = "a".repeat(1025);
        let result = adapter.search(&query, 10, &Filters::default()).await;
        match result {
            Err(MemoryError::InvalidQuery(msg)) => {
                assert!(
                    msg.contains("1024"),
                    "error message should mention the limit: {msg}"
                );
            }
            other => panic!("expected InvalidQuery for overlength query, got: {other:?}"),
        }
    }

    /// M1 -- A query exactly at the length cap (1024 bytes) must be accepted
    /// (no error from the length check itself).
    #[tokio::test]
    async fn search_accepts_query_at_length_limit() {
        let (adapter, _dir) = make_adapter().await;
        let query = "a".repeat(1024);
        // We expect either Ok (empty results) or a backend SQLite error, but
        // NOT an InvalidQuery length error.
        let result = adapter.search(&query, 10, &Filters::default()).await;
        match result {
            Err(MemoryError::InvalidQuery(msg)) if msg.contains("1024") => {
                panic!("query at exactly 1024 bytes should not be rejected by length check: {msg}");
            }
            _ => { /* pass -- may be Ok([]) or a different error */ }
        }
    }

    /// M2 -- A metadata filter key containing bracket notation (`[0]`) must
    /// be rejected with InvalidQuery.
    #[tokio::test]
    async fn search_rejects_bracket_metadata_key() {
        let (adapter, _dir) = make_adapter().await;
        let mut meta = BTreeMap::new();
        meta.insert("[0]".to_string(), serde_json::json!("value"));
        let filters = Filters {
            metadata: Some(meta),
            ..Filters::default()
        };
        let result = adapter.search("hello", 10, &filters).await;
        match result {
            Err(MemoryError::InvalidQuery(msg)) => {
                assert!(
                    msg.contains("[0]"),
                    "error message should include the offending key: {msg}"
                );
            }
            other => panic!("expected InvalidQuery for bracket key, got: {other:?}"),
        }
    }

    /// M2 -- A metadata filter key containing a dot (`a.b`) must be rejected
    /// with InvalidQuery.
    #[tokio::test]
    async fn search_rejects_dotted_metadata_key() {
        let (adapter, _dir) = make_adapter().await;
        let mut meta = BTreeMap::new();
        meta.insert("a.b".to_string(), serde_json::json!(42));
        let filters = Filters {
            metadata: Some(meta),
            ..Filters::default()
        };
        let result = adapter.search("hello", 10, &filters).await;
        match result {
            Err(MemoryError::InvalidQuery(msg)) => {
                assert!(
                    msg.contains("a.b"),
                    "error message should include the offending key: {msg}"
                );
            }
            other => panic!("expected InvalidQuery for dotted key, got: {other:?}"),
        }
    }

    /// M2 -- A metadata filter key with only valid identifier characters must
    /// be accepted (no InvalidQuery error from key validation).
    #[tokio::test]
    async fn search_accepts_valid_metadata_key() {
        let (adapter, _dir) = make_adapter().await;
        let mut meta = BTreeMap::new();
        meta.insert("valid_key_123".to_string(), serde_json::json!("ok"));
        let filters = Filters {
            metadata: Some(meta),
            ..Filters::default()
        };
        // Expect Ok (empty results -- no stored memories) not an InvalidQuery.
        let result = adapter.search("hello", 10, &filters).await;
        match result {
            Ok(_) => { /* pass */ }
            Err(MemoryError::InvalidQuery(msg)) => {
                panic!("valid metadata key should not be rejected: {msg}");
            }
            Err(other) => panic!("unexpected error for valid metadata key: {other:?}"),
        }
    }

    /// M2 -- An empty metadata filter key must be rejected with InvalidQuery.
    #[tokio::test]
    async fn search_rejects_empty_metadata_key() {
        let (adapter, _dir) = make_adapter().await;
        let mut meta = BTreeMap::new();
        meta.insert(String::new(), serde_json::json!("value"));
        let filters = Filters {
            metadata: Some(meta),
            ..Filters::default()
        };
        let result = adapter.search("hello", 10, &filters).await;
        match result {
            Err(MemoryError::InvalidQuery(_)) => { /* pass */ }
            other => panic!("expected InvalidQuery for empty metadata key, got: {other:?}"),
        }
    }
}
