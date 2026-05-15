//! # frameshift-memory-sqlite-fts
//!
//! SQLite FTS5-backed implementation of the [`MemoryAdapter`] trait from
//! `frameshift-memory`.
//!
//! ## Features
//!
//! - Full-text search via SQLite's built-in FTS5 extension.
//! - Tag intersection filtering, time-range filtering, and JSON metadata filtering.
//! - WAL journal mode and `busy_timeout` for concurrent access.
//! - Automatic schema migration on first open.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use frameshift_memory_sqlite_fts::{SqliteFtsAdapter, SqliteFtsConfig};
//! use std::path::PathBuf;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = SqliteFtsConfig {
//!     path: PathBuf::from("/tmp/memories.db"),
//!     pool_size: 4,
//! };
//! let adapter = SqliteFtsAdapter::new(config).await?;
//! # Ok(())
//! # }
//! ```

mod adapter;
mod error;
mod migrate;

pub use adapter::SqliteFtsAdapter;
pub use error::SqliteFtsError;

/// Re-export config so callers do not need to name an internal module.
pub use adapter::SqliteFtsConfig;
