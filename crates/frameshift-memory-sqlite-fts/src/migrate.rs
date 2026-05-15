//! Schema migration logic for the SQLite FTS adapter.
//!
//! On every [`SqliteFtsAdapter::new`] call the migration runner:
//!
//! 1. Opens the `meta` table (creating it if absent) and reads `schema_version`.
//! 2. Compares it against the highest known migration index.
//! 3. Runs any pending migrations inside a single transaction.
//! 4. Writes the new `schema_version` to `meta`.
//!
//! All migrations are embedded at compile time via [`include_str!`].

use rusqlite::{Connection, OptionalExtension};

use crate::error::SqliteFtsError;

/// Embedded SQL for migration 0001.
const MIGRATION_0001: &str = include_str!("../migrations/0001_initial.sql");

/// Run all pending schema migrations against an open [`Connection`].
///
/// This function is intended to be called inside a `deadpool_sqlite::interact`
/// closure on a freshly-acquired connection.
///
/// # Errors
///
/// Returns [`SqliteFtsError::Sqlite`] if any SQL statement fails.
pub fn run_migrations(conn: &Connection) -> Result<(), SqliteFtsError> {
    // Determine the current schema version. If `meta` does not yet exist,
    // treat the database as version 0 (completely empty).
    let current_version = read_schema_version(conn)?;

    if current_version >= 1 {
        // All known migrations already applied.
        return Ok(());
    }

    // Apply migration 0001 inside a transaction so it is atomic.
    // Pass the full SQL string to execute_batch; SQLite handles multiple
    // statements including virtual table creation in a single call.
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(MIGRATION_0001)?;

    // Record the new schema version.
    tx.execute(
        "INSERT INTO meta (key, value) VALUES ('schema_version', '1')
         ON CONFLICT(key) DO UPDATE SET value = '1'",
        [],
    )?;

    tx.commit()?;
    Ok(())
}

/// Read the `schema_version` from the `meta` table.
///
/// Returns `0` when the table does not yet exist.
fn read_schema_version(conn: &Connection) -> Result<u32, SqliteFtsError> {
    // Check whether the `meta` table exists before querying it.
    let table_exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'",
        [],
        |row| row.get::<_, i64>(0),
    )? > 0;

    if !table_exists {
        return Ok(0);
    }

    let version: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;

    match version {
        Some(v) => v
            .parse::<u32>()
            .map_err(|e| SqliteFtsError::Configuration(format!("invalid schema_version: {e}"))),
        None => Ok(0),
    }
}
