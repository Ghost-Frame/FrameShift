//! Internal error type for `frameshift-memory-sqlite-fts`.
//!
//! [`SqliteFtsError`] captures every failure that can arise during pool
//! creation, connection setup, or SQL execution. It implements
//! `Into<MemoryError>` so the adapter methods can use `?` cleanly.

use frameshift_memory::MemoryError;

/// Internal errors specific to the SQLite FTS adapter.
///
/// These are distinct from [`MemoryError`] to allow fine-grained handling
/// within the crate before mapping to the public surface.
#[derive(Debug, thiserror::Error)]
pub enum SqliteFtsError {
    /// A rusqlite operation failed.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The deadpool-sqlite pool returned an error while acquiring a connection.
    #[error("pool error: {0}")]
    Pool(#[from] deadpool_sqlite::PoolError),

    /// An `interact()` closure panicked or was aborted.
    #[error("interact error: {0}")]
    Interact(String),

    /// A JSON serialisation or deserialisation step failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A UUID parse step failed.
    #[error("uuid parse error: {0}")]
    Uuid(#[from] uuid::Error),

    /// The database file path or its parent could not be created.
    #[error("configuration error: {0}")]
    Configuration(String),
}

impl From<SqliteFtsError> for MemoryError {
    /// Map every [`SqliteFtsError`] variant to the closest [`MemoryError`] variant.
    fn from(e: SqliteFtsError) -> Self {
        match e {
            SqliteFtsError::Sqlite(inner) => MemoryError::Backend(inner.to_string()),
            SqliteFtsError::Pool(inner) => MemoryError::ConnectionFailed(inner.to_string()),
            SqliteFtsError::Interact(msg) => MemoryError::Backend(msg),
            SqliteFtsError::Json(inner) => MemoryError::Backend(inner.to_string()),
            SqliteFtsError::Uuid(inner) => MemoryError::Backend(inner.to_string()),
            SqliteFtsError::Configuration(msg) => MemoryError::Configuration(msg),
        }
    }
}

/// Convert a [`deadpool_sqlite::InteractError`] by capturing its `Display`.
impl From<deadpool_sqlite::InteractError> for SqliteFtsError {
    fn from(e: deadpool_sqlite::InteractError) -> Self {
        SqliteFtsError::Interact(e.to_string())
    }
}
