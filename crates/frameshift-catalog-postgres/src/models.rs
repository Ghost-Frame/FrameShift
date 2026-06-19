//! Diesel `Queryable`/`Insertable` row structs for the frameshift catalog schema.
//!
//! These structs map directly to database rows. They use primitive Rust types
//! (`Vec<u8>`, `serde_json::Value`) because Diesel's PostgreSQL driver works at
//! that level. Conversion to/from the domain types defined in `frameshift-catalog`
//! happens at the boundary in `backend.rs`.
//!
//! # BYTEA conversion convention
//!
//! `Ed25519PublicKey` and `ObjectHash` are stored as `Vec<u8>` (BYTEA) in the
//! DB layer. The conversion helpers at the bottom of this module convert between
//! `Vec<u8>` and the typed newtypes, returning `CatalogError::BackendError` when
//! the byte length is wrong (which indicates data corruption).

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde_json::Value as JsonValue;

use frameshift_catalog::{
    AuthorRecord, CatalogError, Ed25519PublicKey, OauthLink, ObjectHash, PackRecord, PackStatus,
    PackVersionRecord,
};

use crate::schema::{authors, handles, pack_downloads, pack_versions, packs};

/// Row struct for the `authors` table.
///
/// All BYTEA columns are `Vec<u8>`; JSON columns are `serde_json::Value`.
/// Converted to [`AuthorRecord`] via [`AuthorRow::into_record`].
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = authors)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct AuthorRow {
    /// Raw 32-byte Ed25519 public key.
    pub pubkey: Vec<u8>,
    /// Unique handle string.
    pub handle: String,
    /// Optional display name; None when not supplied.
    pub display_name: Option<String>,
    /// UTC registration timestamp.
    pub created_at: DateTime<Utc>,
    /// JSON array of OAuth links.
    pub oauth_links: JsonValue,
}

/// Insertable struct for the `authors` table.
///
/// Used by [`crate::backend::PostgresCatalog::register_author`] to insert a
/// new row. All fields are owned to satisfy Diesel's Insertable bounds.
#[derive(Debug, Insertable)]
#[diesel(table_name = authors)]
pub(crate) struct NewAuthorRow {
    /// Raw 32-byte Ed25519 public key.
    pub pubkey: Vec<u8>,
    /// Unique handle string.
    pub handle: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// JSON array of OAuth links.
    pub oauth_links: JsonValue,
}

/// Row struct for the `packs` table.
///
/// Converted to [`PackRecord`] via [`PackRow::into_record`].
///
/// `QueryableByName` is derived in addition to `Queryable` and `Selectable` so
/// that `PackRow` can be returned by `diesel::sql_query(...)` calls in
/// `search_raw`, where the column set is determined at runtime.
#[derive(Debug, Queryable, QueryableByName, Selectable)]
#[diesel(table_name = packs)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PackRow {
    /// Pack name string.
    pub name: String,
    /// Raw 32-byte Ed25519 pubkey of the current owner.
    pub current_author: Vec<u8>,
    /// Tag array.
    pub tags: Vec<String>,
    /// Short description.
    pub description: String,
    /// UTC creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Latest version string; None until first publish.
    pub latest_version: Option<String>,
    /// Cumulative download counter; stored as i64, converted to u64 on read.
    pub total_downloads: i64,
    /// Base persona pack name from the manifest `extends` field; None for root packs.
    pub extends: Option<String>,
}

/// Insertable struct for the `packs` table.
///
/// Used by [`crate::backend::PostgresCatalog::register_pack_version`] when
/// creating the parent pack row for the first time.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = packs)]
pub(crate) struct NewPackRow {
    /// Pack name string.
    pub name: String,
    /// Raw 32-byte Ed25519 pubkey of the initial owner.
    pub current_author: Vec<u8>,
    /// Initial tag list (empty at creation time; set by caller).
    pub tags: Vec<String>,
    /// Initial description.
    pub description: String,
    /// Initial latest_version (set to the first version being registered).
    pub latest_version: Option<String>,
    /// Base persona pack name from the manifest `extends` field; None for root packs.
    pub extends: Option<String>,
}

/// Row struct for the `pack_versions` table.
///
/// Converted to [`PackVersionRecord`] via [`PackVersionRow::into_record`].
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = pack_versions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PackVersionRow {
    /// Parent pack name.
    pub pack_name: String,
    /// Version string.
    pub version: String,
    /// Raw 32-byte SHA-256 content hash.
    pub content_hash: Vec<u8>,
    /// Raw 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
    /// Raw 32-byte Ed25519 author pubkey.
    pub author_pubkey: Vec<u8>,
    /// Optional raw 32-byte parent content hash.
    pub parent_hash: Option<Vec<u8>>,
    /// JSON capability manifest.
    pub capability_manifest_json: JsonValue,
    /// Pack schema version integer; stored as i32, converted to u32 on read.
    pub schema_version: i32,
    /// SPDX license string.
    pub license: String,
    /// UTC publication timestamp.
    pub published_at: DateTime<Utc>,
    /// JSON status object.
    pub status: JsonValue,
    /// Size in bytes; stored as i64, converted to u64 on read.
    pub size_bytes: i64,
}

/// Insertable struct for the `pack_versions` table.
///
/// Used by [`crate::backend::PostgresCatalog::register_pack_version`].
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = pack_versions)]
pub(crate) struct NewPackVersionRow {
    /// Parent pack name.
    pub pack_name: String,
    /// Version string.
    pub version: String,
    /// Raw 32-byte SHA-256 content hash.
    pub content_hash: Vec<u8>,
    /// Raw 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
    /// Raw 32-byte Ed25519 author pubkey.
    pub author_pubkey: Vec<u8>,
    /// Optional raw 32-byte parent content hash.
    pub parent_hash: Option<Vec<u8>>,
    /// JSON capability manifest.
    pub capability_manifest_json: JsonValue,
    /// Pack schema version integer; passed as i32 (u32 converted before insert).
    pub schema_version: i32,
    /// SPDX license string.
    pub license: String,
    /// JSON status object.
    pub status: JsonValue,
    /// Size in bytes; passed as i64 (u64 converted before insert).
    pub size_bytes: i64,
}

/// Row struct for the `handles` table.
///
/// Used by `get_handle_pubkey` and `set_handle_pubkey`.
/// The `handle` and `updated_at` fields are present to match the table schema
/// for `Queryable`/`Selectable` derivation; only `pubkey` is used by the current
/// trait surface. They are retained for forward compatibility.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = handles)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[allow(dead_code)]
pub(crate) struct HandleRow {
    /// Handle string.
    pub handle: String,
    /// Raw 32-byte Ed25519 pubkey of the current owner.
    pub pubkey: Vec<u8>,
    /// UTC timestamp of last ownership update.
    pub updated_at: DateTime<Utc>,
}

/// Insertable struct for the `handles` table.
#[derive(Debug, Insertable)]
#[diesel(table_name = handles)]
pub(crate) struct NewHandleRow {
    /// Handle string.
    pub handle: String,
    /// Raw 32-byte Ed25519 pubkey.
    pub pubkey: Vec<u8>,
}

/// Insertable struct for the `pack_downloads` audit table.
///
/// `downloaded_at` is omitted; the DB column defaults to `NOW()`.
/// Used by [`crate::backend::PostgresCatalog::record_download`].
#[derive(Debug, Insertable)]
#[diesel(table_name = pack_downloads)]
pub(crate) struct NewPackDownloadRow {
    /// Name of the pack that was downloaded.
    pub pack_name: String,
    /// Semver version string that was downloaded.
    pub version: String,
}

// ── Conversion helpers ──────────────────────────────────────────────────────

/// Convert a raw BYTEA `Vec<u8>` to an [`Ed25519PublicKey`].
///
/// Returns `CatalogError::BackendError` if the byte length is not 32, which
/// would indicate data corruption (the DB CHECK constraint should prevent this,
/// but we defend in depth).
pub(crate) fn vec_to_pubkey(bytes: Vec<u8>) -> Result<Ed25519PublicKey, CatalogError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        CatalogError::BackendError(Box::new(std::io::Error::other(format!(
            "author pubkey in DB has wrong length: {} bytes",
            v.len()
        ))))
    })?;
    Ok(Ed25519PublicKey(arr))
}

/// Convert a raw BYTEA `Vec<u8>` to an [`ObjectHash`].
///
/// Returns `CatalogError::BackendError` if the byte length is not 32.
pub(crate) fn vec_to_hash(bytes: Vec<u8>) -> Result<ObjectHash, CatalogError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        CatalogError::BackendError(Box::new(std::io::Error::other(format!(
            "content_hash in DB has wrong length: {} bytes",
            v.len()
        ))))
    })?;
    Ok(ObjectHash::from_bytes(arr))
}

impl AuthorRow {
    /// Convert this database row into an [`AuthorRecord`].
    ///
    /// Fails with `CatalogError::BackendError` if the stored `pubkey` byte
    /// slice is not exactly 32 bytes (data corruption) or if `oauth_links`
    /// cannot be deserialised from JSON.
    pub(crate) fn into_record(self) -> Result<AuthorRecord, CatalogError> {
        let pubkey = vec_to_pubkey(self.pubkey)?;
        let oauth_links: Vec<OauthLink> = serde_json::from_value(self.oauth_links)
            .map_err(|e| CatalogError::BackendError(Box::new(e)))?;
        Ok(AuthorRecord {
            pubkey,
            handle: self.handle,
            display_name: self.display_name,
            created_at: self.created_at,
            oauth_links,
        })
    }
}

impl PackRow {
    /// Convert this database row into a [`PackRecord`].
    ///
    /// `total_downloads` is stored as `i64` (Postgres BIGINT) and cast to `u64`.
    /// Negative values are clamped to 0 (should never occur in practice).
    pub(crate) fn into_record(self) -> Result<PackRecord, CatalogError> {
        let current_author = vec_to_pubkey(self.current_author)?;
        Ok(PackRecord {
            name: self.name,
            current_author,
            tags: self.tags,
            description: self.description,
            created_at: self.created_at,
            latest_version: self.latest_version,
            total_downloads: self.total_downloads.max(0) as u64,
            extends: self.extends,
        })
    }
}

impl PackVersionRow {
    /// Convert this database row into a [`PackVersionRecord`].
    ///
    /// `schema_version` is `i32` in the DB and `u32` in the domain; negative
    /// values (impossible via the application layer) would produce a
    /// `BackendError`.
    ///
    /// `status` is deserialised from the stored JSONB object.
    pub(crate) fn into_record(self) -> Result<PackVersionRecord, CatalogError> {
        let content_hash = vec_to_hash(self.content_hash)?;
        let author_pubkey = vec_to_pubkey(self.author_pubkey)?;
        let parent_hash = self.parent_hash.map(vec_to_hash).transpose()?;
        let schema_version = u32::try_from(self.schema_version).map_err(|_| {
            CatalogError::BackendError(Box::new(std::io::Error::other(
                "schema_version in DB is negative",
            )))
        })?;
        let size_bytes = u64::try_from(self.size_bytes).map_err(|_| {
            CatalogError::BackendError(Box::new(std::io::Error::other(format!(
                "size_bytes from DB is negative: {}",
                self.size_bytes
            ))))
        })?;
        let status: PackStatus = serde_json::from_value(self.status)
            .map_err(|e| CatalogError::BackendError(Box::new(e)))?;
        let capability_manifest_json = serde_json::to_string(&self.capability_manifest_json)
            .map_err(|e| CatalogError::BackendError(Box::new(e)))?;
        Ok(PackVersionRecord {
            pack_name: self.pack_name,
            version: self.version,
            content_hash,
            signature: self.signature,
            author_pubkey,
            parent_hash,
            capability_manifest_json,
            schema_version,
            license: self.license,
            published_at: self.published_at,
            status,
            size_bytes,
        })
    }
}
