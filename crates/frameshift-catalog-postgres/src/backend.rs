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
    PackSearchFilters, PackSearchResult, PackVersionRecord, SortMode, TombstoneRecord,
};

use crate::config::PostgresCatalogConfig;
use crate::errors::{map_diesel_error, map_migration_error, map_pool_error};
use crate::models::{
    vec_to_pubkey, AuthorRow, HandleRow, NewAuthorRow, NewHandleRow, NewPackDownloadRow, NewPackRow,
    NewPackVersionRow, PackRow, PackVersionRow,
};
use crate::pool::{build_pool, PgPool};
use crate::schema::{authors, handles, pack_downloads, pack_versions, packs};

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

/// PostgreSQL implementation of all 15 [`CatalogBackend`] trait methods.
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
    /// 2. If the pack head already exists, verify that the publishing author
    ///    matches the stored `current_author`; mismatches return
    ///    `CatalogError::Unauthorized` (D5: co-publish / name-squat guard).
    /// 3. Upsert the parent `packs` row (INSERT ... ON CONFLICT DO NOTHING) to
    ///    ensure the head record exists.
    /// 4. INSERT the new `pack_versions` row; a `UniqueViolation` on
    ///    `(pack_name, version)` maps to `CatalogError::Conflict`.
    /// 5. UPDATE `packs.latest_version` using true semver precedence (D8):
    ///    the stored `latest_version` is fetched inside the transaction and
    ///    compared with [`semver_gt`]; the UPDATE only runs when the new
    ///    version has strictly higher precedence.
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
            license: record.license.clone(),
            status: status_json,
            size_bytes: size_bytes_i64,
        };

        let pack_name_clone = record.pack_name.clone();
        let version_clone = record.version.clone();
        // Capture the incoming author bytes for the ownership check inside the tx.
        let incoming_author_bytes = record.author_pubkey.0.to_vec();

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
                let incoming_author = incoming_author_bytes.clone();
                Box::pin(async move {
                    // D5: If the pack head already exists, verify the publishing
                    // author matches the stored current_author. First-publish
                    // (no existing row) is always allowed.
                    let existing_pack: Option<PackRow> = packs::table
                        .filter(packs::name.eq(&pack_name))
                        .select(PackRow::as_select())
                        .first(conn)
                        .await
                        .optional()
                        .map_err(|e| {
                            TxError::Catalog(map_diesel_error(e, "pack", pack_name.clone()))
                        })?;

                    if let Some(ref existing) = existing_pack {
                        // Pack already exists -- check ownership.
                        if existing.current_author != incoming_author {
                            return Err(TxError::Catalog(CatalogError::Unauthorized {
                                kind: "pack",
                                key: pack_name.clone(),
                            }));
                        }
                    }

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

                    // D8: Update latest_version using true semver precedence.
                    // Read the current stored value (may have changed from the
                    // row we fetched above if this is a first insert), then
                    // compare using semver_gt before issuing the UPDATE.
                    let current_latest: Option<String> = packs::table
                        .filter(packs::name.eq(&pack_name))
                        .select(packs::latest_version)
                        .first(conn)
                        .await
                        .map_err(|e| {
                            TxError::Catalog(map_diesel_error(e, "pack", pack_name.clone()))
                        })?;

                    // Only update when the new version has strictly higher
                    // semver precedence than the stored latest.
                    let should_update = match &current_latest {
                        None => true,
                        Some(stored) => semver_gt(&version, stored),
                    };

                    if should_update {
                        diesel::update(packs::table.filter(packs::name.eq(&pack_name)))
                            .set(packs::latest_version.eq(Some(&version)))
                            .execute(conn)
                            .await
                            .map_err(|e| {
                                TxError::Catalog(map_diesel_error(e, "pack", pack_name.clone()))
                            })?;
                    }

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
    /// - `Trending`: ranks by count of `pack_downloads` rows in the last 7 days,
    ///   `DESC`, with `name ASC` as a deterministic tiebreaker.
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
                SortMode::Trending => {
                    // Trending with no additional filters: LEFT JOIN a 7-day
                    // download count subquery and sort by it.
                    self.search_trending_raw(
                        TrendingParams {
                            tag: None,
                            target_context: None,
                            author: None,
                            query_text: None,
                            extends: None,
                            limit: limit_i,
                            offset: offset_i,
                        },
                        &mut conn,
                    )
                    .await?
                }
                SortMode::TopRated => packs::table
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
                // or extends filters, use the appropriate raw-SQL helper.
                match &filters.sort {
                    SortMode::Trending => {
                        // Trending with additional filters: combine the WHERE
                        // clauses from the filter set with the 7-day join.
                        self.search_trending_raw(
                            TrendingParams {
                                tag: filters.tag.as_deref(),
                                target_context: filters.target_context.as_deref(),
                                author: filters.author.as_ref(),
                                query_text: filters.query.as_deref(),
                                extends: filters.extends.as_deref(),
                                limit: limit_i,
                                offset: offset_i,
                            },
                            &mut conn,
                        )
                        .await?
                    }
                    _ => {
                        // For combinations involving GIN tag, target_context, author, FTS,
                        // or extends filters, use the raw-SQL helper which binds params safely
                        // via numbered params.
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
                }
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

        let rows_affected = diesel::sql_query(
            "UPDATE packs SET extends = $1 WHERE name = $2",
        )
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

    /// Record a single download event for the given pack version.
    ///
    /// SQL shape:
    /// ```sql
    /// INSERT INTO pack_downloads (pack_name, version) VALUES ($1, $2)
    /// ```
    /// The `downloaded_at` column defaults to `NOW()` at the DB level.
    /// This is best-effort: callers SHOULD log and discard errors rather than
    /// surfacing them to end users.
    #[instrument(skip(self, pack_name, version), fields(pack = %pack_name, version = %version))]
    async fn record_download(&self, pack_name: &str, version: &str) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let row = NewPackDownloadRow {
            pack_name: pack_name.to_string(),
            version: version.to_string(),
        };

        diesel::insert_into(pack_downloads::table)
            .values(&row)
            .execute(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack_download", pack_name.to_string()))?;

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

/// Number of seconds in 7 days, used as the trending window bound.
///
/// Expressed as a constant so the value is clearly documented and appears
/// only once in the SQL strings below (no user-supplied value; safe to embed).
const TRENDING_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Parameters for the trending raw query used in [`PostgresCatalog::search_trending_raw`].
///
/// All optional filter fields work identically to [`SearchParams`]; the sort
/// field is omitted because trending always sorts by 7-day download count DESC.
struct TrendingParams<'a> {
    /// Tag containment filter; `None` means no tag filter.
    pub tag: Option<&'a str>,
    /// Target context filter; `None` means no context filter.
    pub target_context: Option<&'a str>,
    /// Author pubkey filter; `None` means no author filter.
    pub author: Option<&'a Ed25519PublicKey>,
    /// Full-text search query; `None` means no FTS filter.
    pub query_text: Option<&'a str>,
    /// Base persona pack name filter; `None` means no extends filter.
    pub extends: Option<&'a str>,
    /// Maximum number of results (SQL LIMIT).
    pub limit: i64,
    /// Number of results to skip (SQL OFFSET).
    pub offset: i64,
}

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

    /// Execute the trending search query, ranking packs by 7-day download count.
    ///
    /// The query LEFT JOINs a `pack_downloads` subquery that counts rows with
    /// `downloaded_at >= NOW() - INTERVAL '7 days'` grouped by `pack_name`.
    /// Results are ordered by that count DESC with `name ASC` as the tiebreaker.
    ///
    /// Optional WHERE filters (tag, target_context, author, FTS, extends) are
    /// ANDed in exactly as in [`search_raw`]. All user-supplied values are bound
    /// via Diesel's typed bind API; the 7-day interval is a constant embedded
    /// as a literal `$n` parameter (not string-interpolated user input).
    ///
    /// Because the filter combinations expand to 32 static branches (matching
    /// the enumeration in `search_raw`), the bind chains are spelled out
    /// explicitly to satisfy Diesel's static type system.
    async fn search_trending_raw(
        &self,
        params: TrendingParams<'_>,
        conn: &mut bb8::PooledConnection<
            '_,
            diesel_async::pooled_connection::AsyncDieselConnectionManager<
                diesel_async::AsyncPgConnection,
            >,
        >,
    ) -> Result<Vec<PackRow>, CatalogError> {
        let TrendingParams {
            tag,
            target_context,
            author,
            query_text,
            extends,
            limit,
            offset,
        } = params;

        // Build numbered WHERE clauses for optional filters.
        // Bind order matches the branch arms below: tag, target_context, author,
        // query_text, extends. The window interval is bound last before limit/offset.
        let mut bind_idx: usize = 1;
        let mut where_parts: Vec<String> = Vec::new();

        if tag.is_some() {
            where_parts.push(format!("p.tags @> ARRAY[${bind_idx}]::TEXT[]"));
            bind_idx += 1;
        }
        if target_context.is_some() {
            where_parts.push(format!("p.tags @> ARRAY[${bind_idx}]::TEXT[]"));
            bind_idx += 1;
        }
        if author.is_some() {
            where_parts.push(format!("p.current_author = ${bind_idx}"));
            bind_idx += 1;
        }
        if query_text.is_some() {
            where_parts.push(format!(
                "to_tsvector('english', p.description || ' ' || p.name) \
                 @@ plainto_tsquery('english', ${bind_idx})"
            ));
            bind_idx += 1;
        }
        if extends.is_some() {
            where_parts.push(format!("p.extends = ${bind_idx}"));
            bind_idx += 1;
        }

        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };

        // The subquery interval bound index comes after all filter params.
        let interval_idx = bind_idx;
        let limit_idx = bind_idx + 1;
        let offset_idx = bind_idx + 2;

        // The trending subquery counts pack_downloads rows within the rolling window.
        // `make_interval(secs => $n)` is used instead of string-interpolated INTERVAL
        // so the window duration is a bound parameter (even though it is a constant,
        // keeping it bound makes the pattern consistent with user values above).
        let sql = format!(
            "SELECT p.name, p.current_author, p.tags, p.description, p.created_at, \
             p.latest_version, p.total_downloads, p.extends \
             FROM packs p \
             LEFT JOIN ( \
                 SELECT pack_name, COUNT(*) AS dl_count \
                 FROM pack_downloads \
                 WHERE downloaded_at >= NOW() - make_interval(secs => ${interval_idx}) \
                 GROUP BY pack_name \
             ) td ON td.pack_name = p.name \
             {where_sql} \
             ORDER BY COALESCE(td.dl_count, 0) DESC, p.name ASC \
             LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        // Enumerate all 32 filter combinations so each call site has fully typed
        // bind chains. Bind order: tag, target_context, author, query_text, extends,
        // interval_seconds, limit, offset.
        let rows: Vec<PackRow> = match (tag, target_context, author, query_text, extends) {
            (None, None, None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
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
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
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
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
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
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
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
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
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
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
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
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
        };

        Ok(rows)
    }
}

// ── Semver comparison helper ────────────────────────────────────────────────

/// Parse a semver string into `(major, minor, patch, pre_release)`.
///
/// Build metadata (the `+` suffix per semver 2.0.0 §10) is stripped and
/// ignored. Pre-release is everything after the first `-` in the core
/// version string. Returns `None` when the input cannot be parsed as a valid
/// `major.minor.patch` triple.
fn parse_semver(s: &str) -> Option<(u64, u64, u64, Option<String>)> {
    // Strip build metadata suffix (e.g. "+build.1").
    let without_build = s.split('+').next().unwrap_or(s);

    // Split off optional pre-release suffix (e.g. "-rc.1").
    let (core, pre) = if let Some(idx) = without_build.find('-') {
        let (c, p) = without_build.split_at(idx);
        // `p` starts with '-'; drop that leading byte.
        (c, Some(p[1..].to_string()))
    } else {
        (without_build, None)
    };

    // Parse the three numeric components.
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let major = parts[0].parse::<u64>().ok()?;
    let minor = parts[1].parse::<u64>().ok()?;
    let patch = parts[2].parse::<u64>().ok()?;

    Some((major, minor, patch, pre))
}

/// Return `true` when `a` has strictly higher semver precedence than `b`.
///
/// Rules (per semver 2.0.0 §11):
/// - Compare major, minor, patch as unsigned integers in order.
/// - A release version (no pre-release suffix) has HIGHER precedence than the
///   same `(major, minor, patch)` with a pre-release tag.
///   Example: `1.0.0 > 1.0.0-rc.1`.
/// - When both have a pre-release tag and the numeric triple is equal, the
///   tags are compared lexicographically.
///
/// Unparseable versions are treated as lower than any parseable version.
/// If both sides are unparseable, returns `false` (not strictly greater).
fn semver_gt(a: &str, b: &str) -> bool {
    match (parse_semver(a), parse_semver(b)) {
        // `a` is unparseable -- can never be greater.
        (None, _) => false,
        // `b` is unparseable but `a` is valid -- `a` wins.
        (Some(_), None) => true,
        (Some((ma, mia, pa, pre_a)), Some((mb, mib, pb, pre_b))) => {
            // Numeric major/minor/patch comparison.
            if ma != mb {
                return ma > mb;
            }
            if mia != mib {
                return mia > mib;
            }
            if pa != pb {
                return pa > pb;
            }
            // Same numeric triple -- compare pre-release presence.
            // Release (None) > pre-release (Some) per semver.
            match (pre_a, pre_b) {
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (None, None) => false,
                (Some(pa_str), Some(pb_str)) => pa_str > pb_str,
            }
        }
    }
}

#[cfg(test)]
/// Unit tests for the semver comparison helper (D8).
mod semver_tests {
    use super::semver_gt;

    #[test]
    /// 1.10.0 must compare as greater than 1.9.0 (fails under lexicographic ordering).
    fn semver_gt_minor_numeric() {
        assert!(semver_gt("1.10.0", "1.9.0"), "1.10.0 should be > 1.9.0");
    }

    #[test]
    /// 1.0.0 (release) must compare as greater than 1.0.0-rc.1 (pre-release).
    fn semver_gt_release_over_prerelease() {
        assert!(
            semver_gt("1.0.0", "1.0.0-rc.1"),
            "1.0.0 should be > 1.0.0-rc.1"
        );
    }

    #[test]
    /// A version is not greater than itself.
    fn semver_gt_equal_returns_false() {
        assert!(!semver_gt("1.2.3", "1.2.3"));
    }

    #[test]
    /// A larger major wins regardless of minor and patch.
    fn semver_gt_major() {
        assert!(semver_gt("2.0.0", "1.99.99"));
    }

    #[test]
    /// A larger patch wins when major and minor are equal.
    fn semver_gt_patch() {
        assert!(semver_gt("1.2.4", "1.2.3"));
    }

    #[test]
    /// Two identical pre-release strings are not strictly greater.
    fn semver_gt_prerelease_equal_returns_false() {
        assert!(!semver_gt("1.0.0-alpha", "1.0.0-alpha"));
    }

    #[test]
    /// Build metadata suffix is stripped and does not affect comparison.
    fn semver_gt_build_metadata_stripped() {
        assert!(!semver_gt("1.0.0+build.1", "1.0.0+build.2"));
    }
}
