//! [`CatalogBackend`] implementation for PostgreSQL.
//!
//! [`PostgresCatalog`] holds a `bb8` pool and implements every method of the
//! trait by translating the typed catalog API into Diesel DSL queries executed
//! on `AsyncPgConnection` connections checked out from the pool.
//!
//! # Migrations
//!
//! Migrations are run automatically inside [`PostgresCatalog::new`] using
//! [`diesel_migrations::MigrationHarness::run_pending_migrations`]. Diesel
//! tracks applied migrations in the `__diesel_schema_migrations` table; calling
//! `new()` a second time is a safe no-op (only unapplied migrations are run).
//!
//! # Error mapping
//!
//! All Diesel errors are translated by [`crate::errors::map_diesel_error`].
//! Pool checkout failures are mapped by [`crate::errors::map_pool_error`].

use async_trait::async_trait;
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness as _};
use tracing::{debug, error, instrument};

use frameshift_catalog::{
    AuthorRecord, CatalogBackend, CatalogError, Ed25519PublicKey, HealthStatus, PackRecord,
    PackSearchFilters, PackSearchResult, PackVersionRecord, SortMode, TelemetrySignal,
    TombstoneRecord,
};

use crate::config::PostgresCatalogConfig;
use crate::errors::{map_diesel_error, map_migration_error, map_pool_error};
use crate::models::{
    telemetry_row_to_signal, vec_to_pubkey, AuthorRow, HandleRow, NewAuthorRow, NewHandleRow,
    NewPackRow, NewPackVersionRow, PackRow, PackVersionRow, TelemetryRow,
};
use crate::pool::{build_pool, PgPool};
use crate::schema::{authors, handles, pack_telemetry, pack_versions, packs};

/// Embedded migration files compiled into the binary at build time.
///
/// The path is relative to the crate root (where `Cargo.toml` lives), NOT the
/// source file. `cargo build` resolves it correctly as long as the `migrations/`
/// directory exists at `crates/frameshift-catalog-postgres/migrations/`.
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

/// Postgres-backed implementation of [`CatalogBackend`].
///
/// Holds a `bb8` connection pool. All trait methods are `async` and check out
/// a connection from the pool for the duration of each operation. Long-running
/// queries are subject to the `statement_timeout` configured via
/// [`PostgresCatalogConfig`].
///
/// # Thread safety
///
/// `PostgresCatalog` is `Send + Sync`. The pool is `Arc`-backed internally by
/// `bb8` and safe to share across threads and async tasks.
#[derive(Debug, Clone)]
pub struct PostgresCatalog {
    /// The bb8 connection pool.
    pool: PgPool,
}

/// Inherent methods on [`PostgresCatalog`]: constructor, pool accessor.
impl PostgresCatalog {
    /// Create a new [`PostgresCatalog`], open the connection pool, and run
    /// all pending embedded migrations.
    ///
    /// # Migration behaviour
    ///
    /// Migrations are embedded via `embed_migrations!` and run using Diesel's
    /// `MigrationHarness`. The `__diesel_schema_migrations` table tracks which
    /// migrations have already been applied, so calling `new()` on a database
    /// that already has all migrations applied is a safe no-op. This makes
    /// `new()` safe to call on every application startup.
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` -- pool construction failed (bad URL,
    ///   unreachable host) or a migration failed to apply.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn new(config: PostgresCatalogConfig) -> Result<Self, CatalogError> {
        let pool = build_pool(&config)
            .await
            .map_err(CatalogError::BackendError)?;

        // Run migrations using a synchronous connection (diesel_migrations
        // requires a sync connection for the migration harness).
        {
            use secrecy::ExposeSecret as _;
            let url = config.url.expose_secret().to_string();
            let migration_result = tokio::task::spawn_blocking(move || {
                let mut conn = diesel::PgConnection::establish(&url)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                conn.run_pending_migrations(MIGRATIONS)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?;
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            })
            .await
            .map_err(|e| {
                CatalogError::BackendError(Box::new(std::io::Error::other(e.to_string())))
            })?;

            migration_result.map_err(map_migration_error)?;
        }

        debug!(
            "PostgresCatalog initialised with pool_size={}",
            config.pool_size
        );
        Ok(Self { pool })
    }

    /// Return a reference to the underlying bb8 pool.
    ///
    /// Exposed for observability integrations that want to inspect pool state
    /// (e.g. idle connection count) without going through the trait.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// PostgreSQL implementation of all 14 [`CatalogBackend`] trait methods.
///
/// Each method checks out a connection from the pool, executes the relevant
/// Diesel DSL or raw SQL query, and maps driver errors to [`CatalogError`].
#[async_trait]
impl CatalogBackend for PostgresCatalog {
    /// Register a new author or confirm an identical author already exists.
    ///
    /// SQL shape:
    /// ```sql
    /// INSERT INTO authors (pubkey, handle, display_name, oauth_links)
    ///   VALUES ($1, $2, $3, $4)
    ///   ON CONFLICT DO NOTHING
    /// ```
    /// After the insert attempt, a `SELECT ... FROM authors WHERE handle = $handle`
    /// is used to determine whether a handle collision occurred. If the stored
    /// pubkey does not match the supplied pubkey, `CatalogError::HandleTaken` is
    /// returned with the current owner's key. If the stored pubkey matches, the
    /// registration is treated as a no-op and `Ok(())` is returned.
    ///
    /// A `UniqueViolation` on the `pubkey` column (same pubkey, different handle)
    /// surfaces as `CatalogError::Conflict` via the SELECT-after-INSERT path.
    #[instrument(skip(self, record), fields(handle = %record.handle))]
    async fn register_author(&self, record: AuthorRecord) -> Result<(), CatalogError> {
        if record.display_name.as_deref() == Some("") {
            return Err(CatalogError::Validation(
                "display_name must not be an empty string; use None instead".to_string(),
            ));
        }

        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let oauth_json = serde_json::to_value(&record.oauth_links)
            .map_err(|e| CatalogError::BackendError(Box::new(e)))?;

        let new_row = NewAuthorRow {
            pubkey: record.pubkey.0.to_vec(),
            handle: record.handle.clone(),
            display_name: record.display_name.clone(),
            oauth_links: oauth_json,
        };

        // Attempt insert; ON CONFLICT DO NOTHING means no error on duplicate.
        diesel::insert_into(authors::table)
            .values(&new_row)
            .on_conflict_do_nothing()
            .execute(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "author", record.handle.clone()))?;

        // Read back the stored row to check for handle collision.
        let existing: AuthorRow = authors::table
            .filter(authors::handle.eq(&record.handle))
            .select(AuthorRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "author", record.handle.clone()))?;

        // If handles match but pubkeys differ: someone else owns this handle.
        if existing.pubkey != record.pubkey.0.to_vec() {
            let owner = vec_to_pubkey(existing.pubkey)?;
            return Err(CatalogError::HandleTaken { owner });
        }

        // Check for the inverse: same pubkey registered with a different handle.
        let by_pubkey: AuthorRow = authors::table
            .filter(authors::pubkey.eq(record.pubkey.0.to_vec()))
            .select(AuthorRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "author", record.pubkey.to_string()))?;

        if by_pubkey.handle != record.handle {
            return Err(CatalogError::Conflict {
                kind: "author",
                key: record.pubkey.to_string(),
            });
        }

        Ok(())
    }

    /// Look up an author by their Ed25519 public key.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM authors WHERE pubkey = $1 LIMIT 1
    /// ```
    /// Uses the primary key index on `authors(pubkey)`.
    #[instrument(skip(self, pubkey), fields(pubkey = %pubkey))]
    async fn lookup_author(&self, pubkey: &Ed25519PublicKey) -> Result<AuthorRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row: AuthorRow = authors::table
            .filter(authors::pubkey.eq(pubkey.0.to_vec()))
            .select(AuthorRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "author", pubkey.to_string()))?;
        row.into_record()
    }

    /// Look up an author by their unique handle string.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM authors WHERE handle = $1 LIMIT 1
    /// ```
    /// Uses the UNIQUE index on `authors(handle)`.
    #[instrument(skip(self, handle), fields(handle = %handle))]
    async fn lookup_author_by_handle(&self, handle: &str) -> Result<AuthorRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row: AuthorRow = authors::table
            .filter(authors::handle.eq(handle))
            .select(AuthorRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "author", handle.to_string()))?;
        row.into_record()
    }

    /// List all registered authors, ordered by `created_at ASC`.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM authors ORDER BY created_at ASC LIMIT $1 OFFSET $2
    /// ```
    /// Returns an empty `Vec` when `offset` is beyond the total count.
    ///
    /// NOTE: Large offsets cause Postgres to scan and discard many rows.
    /// A keyset-pagination follow-up (paginate by `created_at` + `pubkey`)
    /// is tracked as a future improvement.
    #[instrument(skip(self))]
    async fn list_authors(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuthorRecord>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let rows: Vec<AuthorRow> = authors::table
            .select(AuthorRow::as_select())
            .order(authors::created_at.asc())
            .limit(i64::from(limit))
            .offset(i64::from(offset))
            .load(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "author", String::new()))?;
        rows.into_iter().map(|r| r.into_record()).collect()
    }

    /// Register a new version of a pack.
    ///
    /// Executed inside a single transaction:
    /// 1. Validate `signature` length is exactly 64 bytes.
    /// 2. Upsert the parent `packs` row (INSERT ... ON CONFLICT DO NOTHING) to
    ///    ensure the head record exists.
    /// 3. INSERT the new `pack_versions` row; a `UniqueViolation` on
    ///    `(pack_name, version)` maps to `CatalogError::Conflict`.
    /// 4. UPDATE `packs.latest_version` if the new version string is
    ///    lexicographically greater than the current one.
    ///
    /// NOTE: `latest_version` comparison is lexicographic, NOT true semver.
    /// This works correctly for zero-padded or consistently-formatted semver
    /// strings (e.g. "1.2.0" vs "1.10.0" would be misordered). A future
    /// improvement should add a semver-aware comparison when `semver` is added
    /// as a workspace dependency.
    #[instrument(skip(self, record), fields(pack = %record.pack_name, version = %record.version))]
    async fn register_pack_version(&self, record: PackVersionRecord) -> Result<(), CatalogError> {
        if record.signature.len() != 64 {
            return Err(CatalogError::InvalidArgument(format!(
                "signature must be exactly 64 bytes, got {}",
                record.signature.len()
            )));
        }

        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        // Build values outside the closure to avoid lifetime issues.
        let capability_json: serde_json::Value =
            serde_json::from_str(&record.capability_manifest_json).map_err(|e| {
                CatalogError::InvalidArgument(format!("capability_manifest_json: {e}"))
            })?;

        let status_json = serde_json::to_value(&record.status)
            .map_err(|e| CatalogError::BackendError(Box::new(e)))?;

        let new_pack = NewPackRow {
            name: record.pack_name.clone(),
            current_author: record.author_pubkey.0.to_vec(),
            tags: vec![],
            description: String::new(),
            latest_version: Some(record.version.clone()),
            extends: None,
        };

        let schema_version_i32 = i32::try_from(record.schema_version).map_err(|_| {
            CatalogError::InvalidArgument(format!(
                "schema_version {} exceeds i32::MAX",
                record.schema_version
            ))
        })?;
        let size_bytes_i64 = i64::try_from(record.size_bytes).map_err(|_| {
            CatalogError::InvalidArgument(format!(
                "size_bytes {} exceeds i64::MAX",
                record.size_bytes
            ))
        })?;
        let new_version = NewPackVersionRow {
            pack_name: record.pack_name.clone(),
            version: record.version.clone(),
            content_hash: record.content_hash.as_bytes().to_vec(),
            signature: record.signature.clone(),
            author_pubkey: record.author_pubkey.0.to_vec(),
            parent_hash: record.parent_hash.map(|h| h.as_bytes().to_vec()),
            capability_manifest_json: capability_json,
            schema_version: schema_version_i32,
            conformance_score: record.conformance_score,
            conformance_bundle_hash: record.conformance_bundle_hash.clone(),
            license: record.license.clone(),
            status: status_json,
            size_bytes: size_bytes_i64,
        };

        let pack_name_clone = record.pack_name.clone();
        let version_clone = record.version.clone();

        // `diesel_async::AsyncConnection::transaction` requires
        // `E: From<diesel::result::Error>`. We use a local wrapper that carries
        // either a CatalogError or a raw Diesel error, then unwrap after the
        // transaction completes.
        //
        // This avoids adding `From<diesel::result::Error>` to `CatalogError`
        // (which is a cross-crate type we cannot modify).
        enum TxError {
            Catalog(CatalogError),
            Diesel(diesel::result::Error),
        }
        /// Required by `diesel_async::AsyncConnection::transaction`, which
        /// constrains `E: From<diesel::result::Error>`.
        impl From<diesel::result::Error> for TxError {
            /// Wrap a raw Diesel error in `TxError::Diesel` for transport
            /// through the transaction boundary.
            fn from(e: diesel::result::Error) -> Self {
                TxError::Diesel(e)
            }
        }

        use diesel_async::AsyncConnection as _;
        let tx_result = conn
            .transaction::<(), TxError, _>(|conn| {
                let new_pack = new_pack.clone();
                let new_version = new_version.clone();
                let pack_name = pack_name_clone.clone();
                let version = version_clone.clone();
                Box::pin(async move {
                    // Upsert the parent pack row; do nothing if it already exists.
                    diesel::insert_into(packs::table)
                        .values(&new_pack)
                        .on_conflict(packs::name)
                        .do_nothing()
                        .execute(conn)
                        .await
                        .map_err(|e| {
                            TxError::Catalog(map_diesel_error(e, "pack", pack_name.clone()))
                        })?;

                    // Insert the version row.
                    diesel::insert_into(pack_versions::table)
                        .values(&new_version)
                        .execute(conn)
                        .await
                        .map_err(|e| {
                            TxError::Catalog(map_diesel_error(
                                e,
                                "pack_version",
                                format!("{pack_name}@{version}"),
                            ))
                        })?;

                    // Update latest_version if the new version string is lexicographically
                    // greater than the stored one. NOTE: lexicographic, NOT semver.
                    diesel::sql_query(
                        "UPDATE packs SET latest_version = $1 \
                         WHERE name = $2 \
                         AND (latest_version IS NULL OR latest_version < $1)",
                    )
                    .bind::<diesel::sql_types::Text, _>(version.clone())
                    .bind::<diesel::sql_types::Text, _>(pack_name.clone())
                    .execute(conn)
                    .await
                    .map_err(|e| {
                        TxError::Catalog(map_diesel_error(e, "pack", pack_name.clone()))
                    })?;

                    Ok(())
                })
            })
            .await;

        match tx_result {
            Ok(()) => Ok(()),
            Err(TxError::Catalog(e)) => Err(e),
            Err(TxError::Diesel(e)) => Err(map_diesel_error(e, "pack", record.pack_name.clone())),
        }
    }

    /// Retrieve the top-level pack record for the given pack name.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM packs WHERE name = $1 LIMIT 1
    /// ```
    /// Uses the primary key index on `packs(name)`.
    #[instrument(skip(self, name), fields(pack = %name))]
    async fn get_pack(&self, name: &str) -> Result<PackRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row: PackRow = packs::table
            .filter(packs::name.eq(name))
            .select(PackRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack", name.to_string()))?;
        row.into_record()
    }

    /// Retrieve a specific version record.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM pack_versions WHERE pack_name = $1 AND version = $2 LIMIT 1
    /// ```
    /// Uses the composite primary key index on `pack_versions(pack_name, version)`.
    #[instrument(skip(self, name, version), fields(pack = %name, version = %version))]
    async fn get_pack_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<PackVersionRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row: PackVersionRow = pack_versions::table
            .filter(
                pack_versions::pack_name
                    .eq(name)
                    .and(pack_versions::version.eq(version)),
            )
            .select(PackVersionRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack_version", format!("{name}@{version}")))?;
        row.into_record()
    }

    /// List all versions of a pack, ordered by `published_at ASC`.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM pack_versions WHERE pack_name = $1 ORDER BY published_at ASC
    /// ```
    /// First verifies the pack exists (returns `NotFound` if not), then lists versions.
    #[instrument(skip(self, name), fields(pack = %name))]
    async fn list_pack_versions(&self, name: &str) -> Result<Vec<PackVersionRecord>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        // Verify the pack exists.
        let pack_exists: bool = diesel::select(diesel::dsl::exists(
            packs::table.filter(packs::name.eq(name)),
        ))
        .get_result(&mut *conn)
        .await
        .map_err(|e| map_diesel_error(e, "pack", name.to_string()))?;

        if !pack_exists {
            return Err(CatalogError::NotFound {
                kind: "pack",
                key: name.to_string(),
            });
        }

        let rows: Vec<PackVersionRow> = pack_versions::table
            .filter(pack_versions::pack_name.eq(name))
            .select(PackVersionRow::as_select())
            .order(pack_versions::published_at.asc())
            .load(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack_version", name.to_string()))?;

        rows.into_iter().map(|r| r.into_record()).collect()
    }

    /// Search for packs matching the given filters.
    ///
    /// All filters are ANDed together. Sort modes:
    /// - `TopRated`: `ORDER BY total_downloads DESC, name ASC`
    /// - `Recent`: `ORDER BY created_at DESC, name ASC`
    /// - `Trending`: falls back to `total_downloads DESC` because v0.1 has no
    ///   per-day download audit table. See TODO below.
    ///
    /// Text query uses `plainto_tsquery('english', $query)` against the GIN FTS
    /// index on `to_tsvector('english', description || ' ' || name)`.
    /// `plainto_tsquery` is used (NOT `to_tsquery`) to safely handle user input
    /// that may contain FTS-special characters.
    ///
    /// Tag filter uses `tags @> ARRAY[$tag]::TEXT[]` (array containment) against
    /// the GIN index on `tags`.
    ///
    /// `target_context` filter adds a second array-containment clause,
    /// `tags @> ARRAY[$ctx]::TEXT[]`, requiring the pack's tags to include the
    /// specified runtime context string. When both `tag` and `target_context`
    /// are set, both `@>` clauses are ANDed (intersection of intersections),
    /// which Postgres resolves via the GIN index efficiently.
    ///
    /// NOTE: Large offsets degrade because Postgres must scan and skip rows.
    /// Keyset pagination is a tracked future improvement.
    #[instrument(skip(self, filters))]
    async fn search_packs(
        &self,
        filters: &PackSearchFilters,
    ) -> Result<Vec<PackSearchResult>, CatalogError> {
        // TODO: SortMode::Trending currently falls back to total_downloads DESC
        // because there is no per-version downloads audit table in v0.1 of the
        // schema. Once a `downloads_log(pack_name, version, ts)` table is added,
        // this should compute downloads in the last 7 days and order by that.

        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let limit_i = i64::from(filters.limit);
        let offset_i = i64::from(filters.offset);

        let rows: Vec<PackRow> = match (
            &filters.tag,
            &filters.target_context,
            &filters.author,
            &filters.query,
            &filters.extends,
        ) {
            (None, None, None, None, None) => match &filters.sort {
                SortMode::TopRated | SortMode::Trending => packs::table
                    .select(PackRow::as_select())
                    .order((packs::total_downloads.desc(), packs::name.asc()))
                    .limit(limit_i)
                    .offset(offset_i)
                    .load(&mut *conn)
                    .await
                    .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
                SortMode::Recent => packs::table
                    .select(PackRow::as_select())
                    .order((packs::created_at.desc(), packs::name.asc()))
                    .limit(limit_i)
                    .offset(offset_i)
                    .load(&mut *conn)
                    .await
                    .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            },
            _ => {
                // For combinations involving GIN tag, target_context, author, FTS,
                // or extends filters, use the raw-SQL helper which binds params safely via
                // numbered params.
                self.search_raw(
                    SearchParams {
                        tag: filters.tag.as_deref(),
                        target_context: filters.target_context.as_deref(),
                        author: filters.author.as_ref(),
                        query_text: filters.query.as_deref(),
                        extends: filters.extends.as_deref(),
                        sort: &filters.sort,
                        limit: limit_i,
                        offset: offset_i,
                    },
                    &mut conn,
                )
                .await?
            }
        };

        Ok(rows
            .into_iter()
            .filter_map(|r| r.into_record().ok())
            .map(|pack| PackSearchResult {
                pack,
                score: 1.0_f32,
            })
            .collect())
    }

    /// Increment the download counter for a specific pack.
    ///
    /// SQL shape:
    /// ```sql
    /// UPDATE packs SET total_downloads = total_downloads + 1
    ///   WHERE name = $1
    ///   RETURNING total_downloads
    /// ```
    /// Uses the primary key index on `packs(name)`. Returns `NotFound` when
    /// the specified version does not exist.
    #[instrument(skip(self, name, version), fields(pack = %name, version = %version))]
    async fn increment_download_counter(
        &self,
        name: &str,
        version: &str,
    ) -> Result<u64, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        // Verify the version exists before incrementing.
        let version_exists: bool = diesel::select(diesel::dsl::exists(
            pack_versions::table.filter(
                pack_versions::pack_name
                    .eq(name)
                    .and(pack_versions::version.eq(version)),
            ),
        ))
        .get_result(&mut *conn)
        .await
        .map_err(|e| map_diesel_error(e, "pack_version", format!("{name}@{version}")))?;

        if !version_exists {
            return Err(CatalogError::NotFound {
                kind: "pack_version",
                key: format!("{name}@{version}"),
            });
        }

        let new_count: i64 = diesel::update(packs::table.filter(packs::name.eq(name)))
            .set(packs::total_downloads.eq(packs::total_downloads + 1))
            .returning(packs::total_downloads)
            .get_result(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack", name.to_string()))?;

        Ok(new_count.max(0) as u64)
    }

    /// Mark a specific pack version as tombstoned.
    ///
    /// SQL shape:
    /// ```sql
    /// UPDATE pack_versions SET status = $1
    ///   WHERE pack_name = $2 AND version = $3
    /// ```
    /// The `status` column is set to the JSON serialisation of
    /// `PackStatus::Tombstone { reason, recorded_at }`. No rows are deleted.
    ///
    /// Re-tombstoning an already-tombstoned version is idempotent (last-writer
    /// wins). This differs from some adapters that return `Conflict` on
    /// re-tombstone; the choice here favors operational simplicity.
    #[instrument(skip(self, name, version, record), fields(pack = %name, version = %version))]
    async fn tombstone_pack(
        &self,
        name: &str,
        version: &str,
        record: TombstoneRecord,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let status = frameshift_catalog::PackStatus::Tombstone {
            reason: record.reason,
            recorded_at: record.recorded_at,
        };
        let status_json =
            serde_json::to_value(&status).map_err(|e| CatalogError::BackendError(Box::new(e)))?;

        let rows_affected = diesel::update(
            pack_versions::table.filter(
                pack_versions::pack_name
                    .eq(name)
                    .and(pack_versions::version.eq(version)),
            ),
        )
        .set(pack_versions::status.eq(status_json))
        .execute(&mut *conn)
        .await
        .map_err(|e| map_diesel_error(e, "pack_version", format!("{name}@{version}")))?;

        if rows_affected == 0 {
            return Err(CatalogError::NotFound {
                kind: "pack_version",
                key: format!("{name}@{version}"),
            });
        }

        Ok(())
    }

    /// Retrieve the Ed25519 public key currently mapped to a handle.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT pubkey FROM handles WHERE handle = $1 LIMIT 1
    /// ```
    /// Uses the primary key index on `handles(handle)`.
    #[instrument(skip(self, handle), fields(handle = %handle))]
    async fn get_handle_pubkey(&self, handle: &str) -> Result<Ed25519PublicKey, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row: HandleRow = handles::table
            .filter(handles::handle.eq(handle))
            .select(HandleRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "handle", handle.to_string()))?;
        vec_to_pubkey(row.pubkey)
    }

    /// Update the public key mapped to an existing handle.
    ///
    /// SQL shape:
    /// ```sql
    /// INSERT INTO handles (handle, pubkey) VALUES ($1, $2)
    ///   ON CONFLICT (handle) DO UPDATE SET pubkey = $2, updated_at = NOW()
    /// ```
    /// Uses the primary key index on `handles(handle)`. Upserts the row so
    /// that ownership can be transferred or established for the first time.
    ///
    /// The caller (HTTP server layer) MUST verify ownership before calling this
    /// method. The catalog does NOT verify that the caller controls the new key.
    #[instrument(skip(self, handle, pubkey), fields(handle = %handle))]
    async fn set_handle_pubkey(
        &self,
        handle: &str,
        pubkey: Ed25519PublicKey,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let new_row = NewHandleRow {
            handle: handle.to_string(),
            pubkey: pubkey.0.to_vec(),
        };

        diesel::insert_into(handles::table)
            .values(&new_row)
            .on_conflict(handles::handle)
            .do_update()
            .set((
                handles::pubkey.eq(pubkey.0.to_vec()),
                handles::updated_at.eq(Utc::now()),
            ))
            .execute(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "handle", handle.to_string()))?;

        Ok(())
    }

    /// Set the `extends` field on the pack head record.
    ///
    /// SQL shape:
    /// ```sql
    /// UPDATE packs SET extends = $1 WHERE name = $2
    /// ```
    /// Uses the primary key index on `packs(name)`. Returns `NotFound` if the
    /// pack does not exist (0 rows affected).
    #[instrument(skip(self, pack_name, extends), fields(pack = %pack_name))]
    async fn set_pack_extends(
        &self,
        pack_name: &str,
        extends: Option<&str>,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let rows_affected = diesel::sql_query("UPDATE packs SET extends = $1 WHERE name = $2")
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(
                extends.map(str::to_string),
            )
            .bind::<diesel::sql_types::Text, _>(pack_name.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack", pack_name.to_string()))?;

        if rows_affected == 0 {
            return Err(CatalogError::NotFound {
                kind: "pack",
                key: pack_name.to_string(),
            });
        }

        Ok(())
    }

    /// Accumulate telemetry signals for the catalog's M5 telemetry table.
    ///
    /// Each incoming signal is validated against the `pack_versions` table
    /// before being upserted into `pack_telemetry`. Counters are added to the
    /// stored count, scalar values overwrite the previous value, and
    /// `updated_at` is refreshed to the current UTC time.
    #[instrument(skip(self, signals))]
    async fn ingest_telemetry(&self, signals: Vec<TelemetrySignal>) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        for signal in signals {
            let version_exists: bool = diesel::select(diesel::dsl::exists(
                pack_versions::table.filter(
                    pack_versions::pack_name
                        .eq(&signal.pack_name)
                        .and(pack_versions::version.eq(&signal.version)),
                ),
            ))
            .get_result(&mut *conn)
            .await
            .map_err(|e| {
                map_diesel_error(
                    e,
                    "pack_version",
                    format!("{}@{}", signal.pack_name, signal.version),
                )
            })?;

            if !version_exists {
                return Err(CatalogError::NotFound {
                    kind: "pack_version",
                    key: format!("{}@{}", signal.pack_name, signal.version),
                });
            }

            let count = i64::try_from(signal.count).map_err(|_| {
                CatalogError::InvalidArgument(format!(
                    "telemetry count {} exceeds i64::MAX",
                    signal.count
                ))
            })?;
            let updated_at = Utc::now();
            let row = TelemetryRow {
                pack_name: signal.pack_name.clone(),
                version: signal.version.clone(),
                signal_kind: signal.kind.as_str().to_string(),
                signal_key: signal.key.clone(),
                count,
                value: signal.value,
                updated_at: updated_at.clone(),
            };

            diesel::insert_into(pack_telemetry::table)
                .values(&row)
                .on_conflict((
                    pack_telemetry::pack_name,
                    pack_telemetry::version,
                    pack_telemetry::signal_kind,
                    pack_telemetry::signal_key,
                ))
                .do_update()
                .set((
                    pack_telemetry::count.eq(pack_telemetry::count + row.count),
                    pack_telemetry::value.eq(row.value),
                    pack_telemetry::updated_at.eq(updated_at),
                ))
                .execute(&mut *conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack_telemetry", signal.pack_name.clone()))?;
        }

        Ok(())
    }

    /// Read accumulated telemetry for a pack, optionally filtered to a version.
    ///
    /// When `version` is `Some`, the adapter first verifies that the specific
    /// version exists and returns `NotFound` if it does not. When `version` is
    /// `None`, the pack head record is verified instead. The returned signals
    /// are ordered by version, kind, and key for deterministic iteration.
    #[instrument(skip(self, name, version))]
    async fn get_telemetry(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<Vec<TelemetrySignal>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        match version {
            Some(version) => {
                let version_exists: bool = diesel::select(diesel::dsl::exists(
                    pack_versions::table.filter(
                        pack_versions::pack_name
                            .eq(name)
                            .and(pack_versions::version.eq(version)),
                    ),
                ))
                .get_result(&mut *conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack_version", format!("{name}@{version}")))?;

                if !version_exists {
                    return Err(CatalogError::NotFound {
                        kind: "pack_version",
                        key: format!("{name}@{version}"),
                    });
                }
            }
            None => {
                let pack_exists: bool = diesel::select(diesel::dsl::exists(
                    packs::table.filter(packs::name.eq(name)),
                ))
                .get_result(&mut *conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", name.to_string()))?;

                if !pack_exists {
                    return Err(CatalogError::NotFound {
                        kind: "pack",
                        key: name.to_string(),
                    });
                }
            }
        }

        let mut query = pack_telemetry::table
            .filter(pack_telemetry::pack_name.eq(name))
            .into_boxed();
        if let Some(version) = version {
            query = query.filter(pack_telemetry::version.eq(version));
        }

        let rows: Vec<TelemetryRow> = query
            .select(TelemetryRow::as_select())
            .order((
                pack_telemetry::version.asc(),
                pack_telemetry::signal_kind.asc(),
                pack_telemetry::signal_key.asc(),
            ))
            .load(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack_telemetry", name.to_string()))?;

        rows.into_iter().map(telemetry_row_to_signal).collect()
    }

    /// Store the conformance score and bundle hash for a specific version.
    ///
    /// The score and bundle hash are written back onto the `pack_versions`
    /// row for the published version. Missing rows return `NotFound`.
    #[instrument(skip(self, name, version, score, bundle_hash))]
    async fn set_conformance_score(
        &self,
        name: &str,
        version: &str,
        score: f32,
        bundle_hash: &str,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let rows_affected = diesel::update(
            pack_versions::table.filter(
                pack_versions::pack_name
                    .eq(name)
                    .and(pack_versions::version.eq(version)),
            ),
        )
        .set((
            pack_versions::conformance_score.eq(Some(score)),
            pack_versions::conformance_bundle_hash.eq(Some(bundle_hash.to_string())),
        ))
        .execute(&mut *conn)
        .await
        .map_err(|e| map_diesel_error(e, "pack_version", format!("{name}@{version}")))?;

        if rows_affected == 0 {
            return Err(CatalogError::NotFound {
                kind: "pack_version",
                key: format!("{name}@{version}"),
            });
        }

        Ok(())
    }

    /// Return the current health status of this backend.
    ///
    /// Runs `SELECT 1` with a 1-second deadline. Returns `HealthStatus { healthy: true }`
    /// on success. Pool state (connection count, idle count) is included in `detail`.
    ///
    /// This method does NOT itself return `Err`; degraded states are returned
    /// as `Ok(HealthStatus { healthy: false, ... })`.
    #[instrument(skip(self))]
    async fn health(&self) -> Result<HealthStatus, CatalogError> {
        let checkout =
            tokio::time::timeout(std::time::Duration::from_secs(1), self.pool.get()).await;

        let state = self.pool.state();
        let detail = format!(
            "pool: connections={}, idle={}",
            state.connections, state.idle_connections
        );

        match checkout {
            Ok(Ok(mut conn)) => {
                let ping = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    diesel::sql_query("SELECT 1").execute(&mut *conn),
                )
                .await;
                match ping {
                    Ok(Ok(_)) => Ok(HealthStatus {
                        healthy: true,
                        detail,
                    }),
                    Ok(Err(e)) => {
                        error!("health check query failed: {e}");
                        Ok(HealthStatus {
                            healthy: false,
                            detail: format!("SELECT 1 failed: {e}; {detail}"),
                        })
                    }
                    Err(_) => Ok(HealthStatus {
                        healthy: false,
                        detail: format!("SELECT 1 timed out; {detail}"),
                    }),
                }
            }
            Ok(Err(e)) => {
                error!("health check pool checkout failed: {e}");
                Ok(HealthStatus {
                    healthy: false,
                    detail: format!("pool checkout failed: {e}; {detail}"),
                })
            }
            Err(_) => Ok(HealthStatus {
                healthy: false,
                detail: format!("pool checkout timed out; {detail}"),
            }),
        }
    }
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Parameters for the raw search query used inside [`PostgresCatalog::search_raw`].
///
/// Bundles optional filter values with pagination to stay within clippy's
/// function argument limit (max 7). All `Option` fields default to no filter.
struct SearchParams<'a> {
    /// Tag containment filter; `None` means no tag filter.
    pub tag: Option<&'a str>,
    /// Target context filter; `None` means no context filter.
    ///
    /// When set, adds `tags @> ARRAY[$ctx]::TEXT[]` (array containment)
    /// to the WHERE clause. If both `tag` and `target_context` are set, both
    /// containment clauses are ANDed (intersection of intersections).
    pub target_context: Option<&'a str>,
    /// Author pubkey filter; `None` means no author filter.
    pub author: Option<&'a Ed25519PublicKey>,
    /// Full-text search query; `None` means no FTS filter.
    pub query_text: Option<&'a str>,
    /// Base persona pack name filter; `None` means no extends filter.
    ///
    /// When set, adds `extends = $n` to the WHERE clause so only packs that
    /// extend the named base pack are returned.
    pub extends: Option<&'a str>,
    /// Sort mode to apply.
    pub sort: &'a SortMode,
    /// Maximum number of results (SQL LIMIT).
    pub limit: i64,
    /// Number of results to skip (SQL OFFSET).
    pub offset: i64,
}

/// Private search helpers for [`PostgresCatalog`].
impl PostgresCatalog {
    /// Execute the search query with variable optional filters using raw SQL
    /// with numbered bind parameters.
    ///
    /// Used by `search_packs` for combinations involving GIN tag containment,
    /// author filter, or FTS query text. All user-supplied values are bound via
    /// Diesel's typed bind API; no string interpolation of user values occurs.
    ///
    /// The eight filter combinations (tag x author x query) are enumerated
    /// explicitly so that each call site has fully typed binds -- Diesel's
    /// `sql_query` bind API changes the type at each `.bind()` call, requiring
    /// the full chain to be spelled out statically.
    async fn search_raw(
        &self,
        params: SearchParams<'_>,
        conn: &mut bb8::PooledConnection<
            '_,
            diesel_async::pooled_connection::AsyncDieselConnectionManager<
                diesel_async::AsyncPgConnection,
            >,
        >,
    ) -> Result<Vec<PackRow>, CatalogError> {
        let SearchParams {
            tag,
            target_context,
            author,
            query_text,
            extends,
            sort,
            limit,
            offset,
        } = params;
        let mut bind_idx: usize = 1;
        let mut where_parts: Vec<String> = Vec::new();

        if tag.is_some() {
            where_parts.push(format!("tags @> ARRAY[${bind_idx}]::TEXT[]"));
            bind_idx += 1;
        }
        if target_context.is_some() {
            where_parts.push(format!("tags @> ARRAY[${bind_idx}]::TEXT[]"));
            bind_idx += 1;
        }
        if author.is_some() {
            where_parts.push(format!("current_author = ${bind_idx}"));
            bind_idx += 1;
        }
        let fts_param_idx: Option<usize> = if query_text.is_some() {
            let idx = bind_idx;
            where_parts.push(format!(
                "to_tsvector('english', description || ' ' || name) \
                 @@ plainto_tsquery('english', ${idx})"
            ));
            bind_idx += 1;
            Some(idx)
        } else {
            None
        };
        if extends.is_some() {
            where_parts.push(format!("extends = ${bind_idx}"));
            bind_idx += 1;
        }

        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };

        let order_sql = match sort {
            SortMode::TopRated | SortMode::Trending => "ORDER BY total_downloads DESC, name ASC",
            SortMode::Recent => "ORDER BY created_at DESC, name ASC",
        };

        let limit_idx = bind_idx;
        let offset_idx = bind_idx + 1;

        // Include FTS score column for potential future use; discard in PackRow mapping.
        let _ = fts_param_idx;

        let sql = format!(
            "SELECT name, current_author, tags, description, created_at, \
             latest_version, total_downloads, extends \
             FROM packs \
             {where_sql} \
             {order_sql} \
             LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        // Enumerate all 32 filter combinations (tag x target_context x author x query x extends)
        // to satisfy Diesel's static typing for bind parameters.
        // Bind order: tag, target_context, author, query_text, extends, limit, offset.
        let rows: Vec<PackRow> = match (tag, target_context, author, query_text, extends) {
            (None, None, None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
        };

        Ok(rows)
    }
}
