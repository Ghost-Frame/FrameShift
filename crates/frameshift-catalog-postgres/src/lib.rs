//! # frameshift-catalog-postgres
//!
//! PostgreSQL adapter implementing [`frameshift_catalog::CatalogBackend`] via
//! `diesel-async` + `bb8` connection pooling and `diesel_migrations` for schema
//! management.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use frameshift_catalog_postgres::{PostgresCatalog, PostgresCatalogConfig};
//! use secrecy::SecretString;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), frameshift_catalog::CatalogError> {
//! let catalog = PostgresCatalog::new(PostgresCatalogConfig {
//!     url: SecretString::from("postgres://user:pass@localhost/catalog".to_string()),
//!     pool_size: 10,
//!     connect_timeout: Duration::from_secs(5),
//!     statement_timeout: Duration::from_secs(30),
//! })
//! .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Module structure
//!
//! - [`config`] -- [`PostgresCatalogConfig`] (connection URL + pool tuning).
//! - [`pool`] -- pool construction helper; applies `statement_timeout` on
//!   each new connection.
//! - [`schema`] -- Diesel `table!` macro declarations.
//! - [`models`] -- `Queryable`/`Insertable` row structs; conversion helpers
//!   between `Vec<u8>` BYTEA and domain newtypes.
//! - [`backend`] -- [`PostgresCatalog`] struct and [`CatalogBackend`] impl.
//! - [`errors`] -- mapping from Diesel/bb8 errors to [`CatalogError`].
//! - [`ownership_backfill`] -- dry-run-first transactional publisher ownership
//!   migration driven by a private exact-census manifest.
//!
//! ## Migration behaviour
//!
//! Migrations are embedded at compile time via `diesel_migrations::embed_migrations!`
//! and run automatically inside [`PostgresCatalog::new`]. Calling `new()` on a
//! database that is already fully migrated is a safe no-op.

pub mod backend;
pub mod config;
pub mod errors;
pub mod models;
pub mod ownership_backfill;
pub mod pool;
pub mod schema;

// Top-level re-exports for the public surface.
pub use backend::PostgresCatalog;
pub use config::PostgresCatalogConfig;
pub use ownership_backfill::{
    run_ownership_backfill, OwnershipBackfillApplied, OwnershipBackfillCensus,
    OwnershipBackfillError, OwnershipBackfillManifest, OwnershipBackfillMode,
    OwnershipBackfillPublisherCensus, OwnershipBackfillReport, OwnershipManifestKey,
    OwnershipManifestKeyState, OwnershipManifestModerationStatus, OwnershipManifestPack,
    OwnershipManifestPublisher, OwnershipManifestVersion, OWNERSHIP_BACKFILL_SCHEMA_VERSION,
};
