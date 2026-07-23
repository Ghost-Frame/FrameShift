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
    AccountRecord, AccountStatus, AuthorRecord, CatalogError, Ed25519PublicKey, MembershipState,
    OauthLink, ObjectHash, PackRecord, PackStatus, PackVersionRecord, PublisherKeyRecord,
    PublisherKeyState, PublisherMembershipRecord, PublisherModerationStatus,
    PublisherProfileRecord, PublisherRole,
};
use uuid::Uuid;

use crate::schema::{
    accounts, authors, handles, pack_downloads, pack_versions, packs, publisher_audit_events,
    publisher_keys, publisher_memberships, publisher_profiles,
};

/// Queryable account row mapped from the `accounts` table.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct AccountRow {
    /// Internal account identifier.
    pub id: Uuid,
    /// Canonical OIDC issuer.
    pub issuer: String,
    /// Issuer-scoped OIDC subject.
    pub subject: String,
    /// Optional profile email.
    pub email: Option<String>,
    /// Optional account display name.
    pub display_name: Option<String>,
    /// Account lifecycle state string.
    pub status: String,
    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent account update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Insertable account row used by account creation.
#[derive(Debug, Insertable)]
#[diesel(table_name = accounts)]
pub(crate) struct NewAccountRow {
    /// Internal account identifier.
    pub id: Uuid,
    /// Canonical OIDC issuer.
    pub issuer: String,
    /// Issuer-scoped OIDC subject.
    pub subject: String,
    /// Optional profile email.
    pub email: Option<String>,
    /// Optional account display name.
    pub display_name: Option<String>,
    /// Account lifecycle state string.
    pub status: String,
    /// Account creation timestamp supplied by the caller.
    pub created_at: DateTime<Utc>,
    /// Initial account update timestamp supplied by the caller.
    pub updated_at: DateTime<Utc>,
}

/// Queryable public publisher profile row.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = publisher_profiles)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublisherProfileRow {
    /// Internal publisher identifier.
    pub id: Uuid,
    /// Normalized publisher handle.
    pub handle: String,
    /// Public display name.
    pub display_name: String,
    /// Optional public biography.
    pub biography: Option<String>,
    /// Moderation state string.
    pub moderation_status: String,
    /// Profile creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent profile update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Insertable public publisher profile row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publisher_profiles)]
pub(crate) struct NewPublisherProfileRow {
    /// Internal publisher identifier.
    pub id: Uuid,
    /// Normalized publisher handle.
    pub handle: String,
    /// Public display name.
    pub display_name: String,
    /// Optional public biography.
    pub biography: Option<String>,
    /// Moderation state string.
    pub moderation_status: String,
    /// Profile creation timestamp supplied by the caller.
    pub created_at: DateTime<Utc>,
    /// Initial profile update timestamp supplied by the caller.
    pub updated_at: DateTime<Utc>,
}

/// Queryable account-to-publisher membership row.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = publisher_memberships)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublisherMembershipRow {
    /// Account holding the membership.
    pub account_id: Uuid,
    /// Publisher receiving the membership.
    pub publisher_id: Uuid,
    /// Role string.
    pub role: String,
    /// Membership state string.
    pub state: String,
    /// Membership creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent membership update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Insertable account-to-publisher membership row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publisher_memberships)]
pub(crate) struct NewPublisherMembershipRow {
    /// Account holding the membership.
    pub account_id: Uuid,
    /// Publisher receiving the membership.
    pub publisher_id: Uuid,
    /// Role string.
    pub role: String,
    /// Membership state string.
    pub state: String,
    /// Membership creation timestamp supplied by the caller.
    pub created_at: DateTime<Utc>,
    /// Initial membership update timestamp supplied by the caller.
    pub updated_at: DateTime<Utc>,
}

/// Queryable enrolled publisher key row.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = publisher_keys)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublisherKeyRow {
    /// Internal key identifier.
    pub id: Uuid,
    /// Publisher owning the key.
    pub publisher_id: Uuid,
    /// Raw Ed25519 public key bytes.
    pub public_key: Vec<u8>,
    /// User-visible key label.
    pub label: String,
    /// Key lifecycle state string.
    pub state: String,
    /// Key enrollment timestamp.
    pub created_at: DateTime<Utc>,
    /// Optional key revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Optional most recent successful use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Insertable enrolled publisher key row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publisher_keys)]
pub(crate) struct NewPublisherKeyRow {
    /// Internal key identifier.
    pub id: Uuid,
    /// Publisher owning the key.
    pub publisher_id: Uuid,
    /// Raw Ed25519 public key bytes.
    pub public_key: Vec<u8>,
    /// User-visible key label.
    pub label: String,
    /// Key lifecycle state string.
    pub state: String,
    /// Key enrollment timestamp supplied by the caller.
    pub created_at: DateTime<Utc>,
    /// Optional key revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Optional most recent successful use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Insertable immutable publisher audit event row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publisher_audit_events)]
pub(crate) struct NewPublisherAuditEventRow {
    /// Internal event identifier.
    pub id: Uuid,
    /// Optional account responsible for the event.
    pub actor_account_id: Option<Uuid>,
    /// Publisher affected by the event.
    pub publisher_id: Uuid,
    /// Stable action name.
    pub action: String,
    /// Optional affected publisher key.
    pub target_key_id: Option<Uuid>,
    /// Optional affected pack version.
    pub target_version: Option<String>,
    /// Optional request correlation identifier.
    pub request_id: Option<Uuid>,
    /// Event timestamp supplied by the caller.
    pub created_at: DateTime<Utc>,
    /// Sanitized structured metadata.
    pub metadata: JsonValue,
}

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
    /// Nullable publisher owner during the compatibility migration.
    pub publisher_id: Option<Uuid>,
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
    /// Nullable publisher owner during the compatibility migration.
    pub publisher_id: Option<Uuid>,
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
    /// Nullable enrolled publisher key during the compatibility migration.
    pub publisher_key_id: Option<Uuid>,
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
    /// Nullable enrolled publisher key during the compatibility migration.
    pub publisher_key_id: Option<Uuid>,
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

/// Decode a serde string enum stored in a PostgreSQL TEXT column.
fn parse_text_enum<T>(value: String, kind: &str) -> Result<T, CatalogError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(JsonValue::String(value.clone())).map_err(|error| {
        CatalogError::BackendError(Box::new(std::io::Error::other(format!(
            "invalid {kind} value in DB: {value}: {error}"
        ))))
    })
}

/// Encode a serde string enum for a PostgreSQL TEXT column.
pub(crate) fn encode_text_enum<T>(value: T) -> Result<String, CatalogError>
where
    T: serde::Serialize,
{
    match serde_json::to_value(value)
        .map_err(|error| CatalogError::BackendError(Box::new(error)))?
    {
        JsonValue::String(value) => Ok(value),
        other => Err(CatalogError::BackendError(Box::new(std::io::Error::other(
            format!("expected string enum serialization, got {other}"),
        )))),
    }
}

/// Conversion helpers for account rows.
impl AccountRow {
    /// Convert this database row into an [`AccountRecord`].
    pub(crate) fn into_record(self) -> Result<AccountRecord, CatalogError> {
        Ok(AccountRecord {
            id: self.id,
            issuer: self.issuer,
            subject: self.subject,
            email: self.email,
            display_name: self.display_name,
            status: parse_text_enum::<AccountStatus>(self.status, "account status")?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Conversion helpers for publisher profile rows.
impl PublisherProfileRow {
    /// Convert this database row into a [`PublisherProfileRecord`].
    pub(crate) fn into_record(self) -> Result<PublisherProfileRecord, CatalogError> {
        Ok(PublisherProfileRecord {
            id: self.id,
            handle: self.handle,
            display_name: self.display_name,
            biography: self.biography,
            moderation_status: parse_text_enum::<PublisherModerationStatus>(
                self.moderation_status,
                "publisher moderation status",
            )?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Conversion helpers for publisher membership rows.
impl PublisherMembershipRow {
    /// Convert this database row into a [`PublisherMembershipRecord`].
    pub(crate) fn into_record(self) -> Result<PublisherMembershipRecord, CatalogError> {
        Ok(PublisherMembershipRecord {
            account_id: self.account_id,
            publisher_id: self.publisher_id,
            role: parse_text_enum::<PublisherRole>(self.role, "publisher role")?,
            state: parse_text_enum::<MembershipState>(self.state, "membership state")?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Conversion helpers for publisher key rows.
impl PublisherKeyRow {
    /// Convert this database row into a [`PublisherKeyRecord`].
    pub(crate) fn into_record(self) -> Result<PublisherKeyRecord, CatalogError> {
        Ok(PublisherKeyRecord {
            id: self.id,
            publisher_id: self.publisher_id,
            public_key: vec_to_pubkey(self.public_key)?,
            label: self.label,
            state: parse_text_enum::<PublisherKeyState>(self.state, "publisher key state")?,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
            last_used_at: self.last_used_at,
        })
    }
}

/// Converts persisted author rows into catalog domain records.
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

/// Converts persisted pack rows into catalog domain records.
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
            publisher_id: self.publisher_id,
            tags: self.tags,
            description: self.description,
            created_at: self.created_at,
            latest_version: self.latest_version,
            total_downloads: self.total_downloads.max(0) as u64,
            extends: self.extends,
        })
    }
}

/// Converts persisted pack-version rows into catalog domain records.
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
            publisher_key_id: self.publisher_key_id,
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
