//! Transactional publisher ownership backfill for legacy catalog rows.
//!
//! The operator supplies a private, fully enumerated JSON manifest. Validation
//! proves that every pack and version is represented exactly once before any
//! database mutation is attempted. Dry-run mode is the default at the binary
//! boundary; apply mode uses the same validation path and one database
//! transaction.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Timelike as _, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::models::{
    AccountRow, AuthorRow, HandleRow, NewPublisherAuditEventRow, NewPublisherKeyRow,
    NewPublisherMembershipRow, NewPublisherProfileRow, PackRow, PackVersionRow, PublisherKeyRow,
    PublisherMembershipRow, PublisherProfileRow,
};
use crate::pool::{build_pool, PgPool};
use crate::schema::{
    accounts, authors, handles, pack_versions, packs, publisher_audit_events, publisher_keys,
    publisher_memberships, publisher_profiles,
};
use crate::{PostgresCatalog, PostgresCatalogConfig};

/// Manifest schema version accepted by this implementation.
pub const OWNERSHIP_BACKFILL_SCHEMA_VERSION: u32 = 1;

/// Stable audit action emitted once for each migrated publisher.
const OWNERSHIP_BACKFILL_AUDIT_ACTION: &str = "publisher.ownership_backfilled";

/// Operator-selected execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipBackfillMode {
    /// Validate the manifest and live catalog without changing database rows.
    DryRun,
    /// Validate and apply all missing ownership links atomically.
    Apply,
}

/// Publisher moderation state used when bootstrapping a missing profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipManifestModerationStatus {
    /// Publisher awaits moderation review.
    Pending,
    /// Publisher is approved for public discovery.
    Approved,
    /// Publisher is temporarily suspended.
    Suspended,
    /// Publisher application was rejected.
    Rejected,
}

/// String conversion for publisher moderation bootstrap values.
impl OwnershipManifestModerationStatus {
    /// Return the database text representation.
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Suspended => "suspended",
            Self::Rejected => "rejected",
        }
    }
}

/// Publisher key lifecycle state used when bootstrapping a missing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipManifestKeyState {
    /// Key may authorize new writes.
    Active,
    /// Key is retained only for historical verification.
    Revoked,
}

/// String conversion for publisher key bootstrap values.
impl OwnershipManifestKeyState {
    /// Return the database text representation.
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

/// One publisher key included in the private migration manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipManifestKey {
    /// Stable key UUID.
    pub id: Uuid,
    /// Exact 32-byte Ed25519 public key encoded as hexadecimal.
    pub public_key: String,
    /// Operator-reviewed user-visible key label.
    pub label: String,
    /// Key lifecycle state to preserve or bootstrap.
    pub state: OwnershipManifestKeyState,
    /// Original key enrollment time.
    pub created_at: DateTime<Utc>,
    /// Revocation time, present exactly when the key is revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// One publisher profile included in the private migration manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipManifestPublisher {
    /// Stable publisher UUID.
    pub id: Uuid,
    /// Exact normalized public publisher handle.
    pub handle: String,
    /// Existing account that will own the publisher membership.
    pub owner_account_id: Uuid,
    /// Public profile display name.
    pub display_name: String,
    /// Optional public profile biography.
    pub biography: Option<String>,
    /// Profile moderation state.
    pub moderation_status: OwnershipManifestModerationStatus,
    /// Original profile and membership bootstrap time.
    pub created_at: DateTime<Utc>,
    /// Stable audit event UUID for this publisher migration.
    pub audit_event_id: Uuid,
    /// Stable audit event creation time.
    pub audit_created_at: DateTime<Utc>,
    /// Exact publisher keys authorized by the manifest.
    pub keys: Vec<OwnershipManifestKey>,
}

/// One pack head included in the private migration manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipManifestPack {
    /// Exact pack name.
    pub name: String,
    /// Stable publisher UUID that owns the pack.
    pub publisher_id: Uuid,
    /// Expected legacy `current_author` bytes encoded as hexadecimal.
    pub expected_current_author: String,
}

/// One historical pack version included in the private migration manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipManifestVersion {
    /// Exact parent pack name.
    pub pack_name: String,
    /// Exact version identifier.
    pub version: String,
    /// Stable publisher key UUID that signed this version.
    pub publisher_key_id: Uuid,
    /// Expected historical signer bytes encoded as hexadecimal.
    pub expected_author_pubkey: String,
    /// Expected immutable artifact content hash encoded as hexadecimal.
    pub expected_content_hash: String,
}

/// Fully enumerated private migration manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipBackfillManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Exact number of pack rows expected in the live catalog.
    pub expected_pack_count: u64,
    /// Exact number of pack version rows expected in the live catalog.
    pub expected_version_count: u64,
    /// Publisher profiles and keys needed by the mapped catalog.
    pub publishers: Vec<OwnershipManifestPublisher>,
    /// Complete mapping of every pack head.
    pub packs: Vec<OwnershipManifestPack>,
    /// Complete mapping of every historical pack version.
    pub versions: Vec<OwnershipManifestVersion>,
}

/// Exact preflight census for one dry-run or apply operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnershipBackfillCensus {
    /// Deterministic ownership counts for each publisher in UUID order.
    pub publishers: Vec<OwnershipBackfillPublisherCensus>,
    /// Number of packs found in the database.
    pub catalog_packs: u64,
    /// Number of versions found in the database.
    pub catalog_versions: u64,
    /// Number of publishers represented by the manifest.
    pub manifest_publishers: u64,
    /// Number of publisher keys represented by the manifest.
    pub manifest_keys: u64,
    /// Existing publisher profiles that exactly match bootstrap metadata.
    pub publisher_profiles_existing: u64,
    /// Missing publisher profiles that apply mode would create.
    pub publisher_profiles_to_create: u64,
    /// Existing owner memberships that exactly match the manifest.
    pub owner_memberships_existing: u64,
    /// Missing owner memberships that apply mode would create.
    pub owner_memberships_to_create: u64,
    /// Existing publisher keys that exactly match bootstrap metadata.
    pub publisher_keys_existing: u64,
    /// Missing publisher keys that apply mode would create.
    pub publisher_keys_to_create: u64,
    /// Existing migration audit rows that exactly match the manifest.
    pub audit_events_existing: u64,
    /// Missing migration audit rows that apply mode would create.
    pub audit_events_to_create: u64,
    /// Pack heads already linked to their expected publisher.
    pub packs_already_linked: u64,
    /// Pack heads with a nullable publisher link ready for update.
    pub packs_to_update: u64,
    /// Versions already linked to their expected publisher key.
    pub versions_already_linked: u64,
    /// Versions with a nullable publisher key link ready for update.
    pub versions_to_update: u64,
}

/// Exact preflight census for one publisher represented by the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnershipBackfillPublisherCensus {
    /// Stable publisher UUID.
    pub publisher_id: Uuid,
    /// Exact normalized publisher handle.
    pub handle: String,
    /// Manifest keys assigned to this publisher.
    pub manifest_keys: u64,
    /// Manifest packs assigned to this publisher.
    pub mapped_packs: u64,
    /// Manifest versions assigned to this publisher.
    pub mapped_versions: u64,
    /// Assigned pack heads already linked to this publisher.
    pub packs_already_linked: u64,
    /// Assigned pack heads awaiting their publisher link.
    pub packs_to_update: u64,
    /// Assigned versions already linked to this publisher's keys.
    pub versions_already_linked: u64,
    /// Assigned versions awaiting their publisher key link.
    pub versions_to_update: u64,
}

/// Exact row counts mutated by one operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OwnershipBackfillApplied {
    /// Publisher profiles inserted by this operation.
    pub publisher_profiles: u64,
    /// Owner memberships inserted by this operation.
    pub owner_memberships: u64,
    /// Publisher keys inserted by this operation.
    pub publisher_keys: u64,
    /// Migration audit events inserted by this operation.
    pub audit_events: u64,
    /// Pack heads linked by this operation.
    pub packs: u64,
    /// Pack versions linked by this operation.
    pub versions: u64,
}

/// JSON-safe result emitted by dry-run and apply modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnershipBackfillReport {
    /// Execution mode used for this operation.
    pub mode: OwnershipBackfillMode,
    /// SHA-256 of the exact manifest bytes reviewed by the operator.
    pub manifest_sha256: String,
    /// Exact live and planned row census.
    pub census: OwnershipBackfillCensus,
    /// Exact mutations, all zero during dry-run.
    pub applied: OwnershipBackfillApplied,
}

/// Fail-closed ownership migration error.
#[derive(Debug, thiserror::Error)]
pub enum OwnershipBackfillError {
    /// The manifest is internally incomplete, ambiguous, or malformed.
    #[error("manifest validation failed: {0}")]
    Manifest(String),
    /// The live catalog does not exactly match the reviewed manifest.
    #[error("catalog state does not match manifest: {0}")]
    CatalogState(String),
    /// Apply mode did not receive the exact reviewed manifest digest.
    #[error("apply requires the exact manifest SHA-256 confirmation")]
    MissingConfirmation,
    /// The supplied apply confirmation does not match the exact manifest bytes.
    #[error("manifest SHA-256 confirmation does not match")]
    ConfirmationMismatch,
    /// A digest confirmation was supplied to mutation-free dry-run mode.
    #[error("manifest SHA-256 confirmation is only valid in apply mode")]
    UnexpectedConfirmation,
    /// A database connection could not be checked out.
    #[error("database connection unavailable")]
    ConnectionUnavailable,
    /// A database statement failed inside the migration transaction.
    #[error("database operation failed")]
    Database(#[source] diesel::result::Error),
}

/// Validated publisher bootstrap data with decoded key bytes.
#[derive(Debug, Clone)]
struct PreparedPublisher {
    /// Stable publisher UUID.
    id: Uuid,
    /// Exact normalized handle.
    handle: String,
    /// Existing owner account UUID.
    owner_account_id: Uuid,
    /// Public display name.
    display_name: String,
    /// Optional public biography.
    biography: Option<String>,
    /// Database moderation state.
    moderation_status: &'static str,
    /// Stable bootstrap time.
    created_at: DateTime<Utc>,
    /// Stable migration audit UUID.
    audit_event_id: Uuid,
    /// Stable migration audit time.
    audit_created_at: DateTime<Utc>,
}

/// Validated publisher key bootstrap data with decoded bytes.
#[derive(Debug, Clone)]
struct PreparedKey {
    /// Stable key UUID.
    id: Uuid,
    /// Owning publisher UUID.
    publisher_id: Uuid,
    /// Exact Ed25519 public key bytes.
    public_key: [u8; 32],
    /// Operator-reviewed label.
    label: String,
    /// Database key lifecycle state.
    state: &'static str,
    /// Original enrollment time.
    created_at: DateTime<Utc>,
    /// Optional original revocation time.
    revoked_at: Option<DateTime<Utc>>,
}

/// Validated pack ownership mapping with decoded signer bytes.
#[derive(Debug, Clone)]
struct PreparedPack {
    /// Exact pack name.
    name: String,
    /// Stable owner publisher UUID.
    publisher_id: Uuid,
    /// Expected legacy head signer bytes.
    expected_current_author: [u8; 32],
}

/// Validated historical version mapping with decoded evidence.
#[derive(Debug, Clone)]
struct PreparedVersion {
    /// Exact parent pack name.
    pack_name: String,
    /// Exact version identifier.
    version: String,
    /// Stable signer key UUID.
    publisher_key_id: Uuid,
    /// Expected immutable signer bytes.
    expected_author_pubkey: [u8; 32],
    /// Expected immutable artifact hash.
    expected_content_hash: [u8; 32],
}

/// Fully validated and indexed manifest used by database preflight.
#[derive(Debug, Clone)]
struct PreparedManifest {
    /// Exact manifest byte digest.
    manifest_sha256: String,
    /// Exact expected pack count.
    expected_pack_count: u64,
    /// Exact expected version count.
    expected_version_count: u64,
    /// Publisher entries keyed by stable UUID.
    publishers: BTreeMap<Uuid, PreparedPublisher>,
    /// Key entries keyed by stable UUID.
    keys: BTreeMap<Uuid, PreparedKey>,
    /// Key UUIDs keyed by exact public key bytes.
    key_ids_by_public_key: BTreeMap<[u8; 32], Uuid>,
    /// Pack entries keyed by exact name.
    packs: BTreeMap<String, PreparedPack>,
    /// Version entries keyed by exact pack and version.
    versions: BTreeMap<(String, String), PreparedVersion>,
}

/// Validate a private manifest without connecting to Postgres.
impl OwnershipBackfillManifest {
    /// Validate structure, complete internal references, and exact byte widths.
    pub fn validate(&self) -> Result<(), OwnershipBackfillError> {
        self.prepare(&"0".repeat(64)).map(|_| ())
    }

    /// Decode and index a structurally valid manifest.
    fn prepare(&self, manifest_sha256: &str) -> Result<PreparedManifest, OwnershipBackfillError> {
        validate_sha256(manifest_sha256)?;
        if self.schema_version != OWNERSHIP_BACKFILL_SCHEMA_VERSION {
            return Err(manifest_error(format!(
                "unsupported schema_version {}; expected {}",
                self.schema_version, OWNERSHIP_BACKFILL_SCHEMA_VERSION
            )));
        }
        if self.expected_pack_count != self.packs.len() as u64 {
            return Err(manifest_error(format!(
                "expected_pack_count {} does not equal {} manifest pack entries",
                self.expected_pack_count,
                self.packs.len()
            )));
        }
        if self.expected_version_count != self.versions.len() as u64 {
            return Err(manifest_error(format!(
                "expected_version_count {} does not equal {} manifest version entries",
                self.expected_version_count,
                self.versions.len()
            )));
        }

        let mut publishers = BTreeMap::new();
        let mut publisher_ids_by_handle = BTreeMap::new();
        let mut audit_ids = BTreeSet::new();
        let mut keys = BTreeMap::new();
        let mut key_ids_by_public_key = BTreeMap::new();

        for publisher in &self.publishers {
            validate_handle(&publisher.handle)?;
            validate_non_blank("publisher display_name", &publisher.display_name)?;
            validate_timestamp("publisher created_at", publisher.created_at)?;
            validate_timestamp("publisher audit_created_at", publisher.audit_created_at)?;
            if !audit_ids.insert(publisher.audit_event_id) {
                return Err(manifest_error(format!(
                    "duplicate audit_event_id {}",
                    publisher.audit_event_id
                )));
            }
            if publisher.keys.is_empty() {
                return Err(manifest_error(format!(
                    "publisher {} has no mapped keys",
                    publisher.id
                )));
            }
            if publisher_ids_by_handle
                .insert(publisher.handle.clone(), publisher.id)
                .is_some()
            {
                return Err(manifest_error(format!(
                    "duplicate publisher handle {}",
                    publisher.handle
                )));
            }
            let prepared_publisher = PreparedPublisher {
                id: publisher.id,
                handle: publisher.handle.clone(),
                owner_account_id: publisher.owner_account_id,
                display_name: publisher.display_name.clone(),
                biography: publisher.biography.clone(),
                moderation_status: publisher.moderation_status.as_str(),
                created_at: publisher.created_at,
                audit_event_id: publisher.audit_event_id,
                audit_created_at: publisher.audit_created_at,
            };
            if publishers
                .insert(publisher.id, prepared_publisher)
                .is_some()
            {
                return Err(manifest_error(format!(
                    "duplicate publisher id {}",
                    publisher.id
                )));
            }

            for key in &publisher.keys {
                validate_non_blank("publisher key label", &key.label)?;
                validate_timestamp("publisher key created_at", key.created_at)?;
                if let Some(revoked_at) = key.revoked_at {
                    validate_timestamp("publisher key revoked_at", revoked_at)?;
                    if revoked_at < key.created_at {
                        return Err(manifest_error(format!(
                            "publisher key {} was revoked before it was created",
                            key.id
                        )));
                    }
                }
                match (key.state, key.revoked_at) {
                    (OwnershipManifestKeyState::Active, None)
                    | (OwnershipManifestKeyState::Revoked, Some(_)) => {}
                    _ => {
                        return Err(manifest_error(format!(
                            "publisher key {} has inconsistent state and revoked_at",
                            key.id
                        )));
                    }
                }
                let public_key =
                    decode_exact_hex::<32>("publisher key public_key", &key.public_key)?;
                let prepared_key = PreparedKey {
                    id: key.id,
                    publisher_id: publisher.id,
                    public_key,
                    label: key.label.clone(),
                    state: key.state.as_str(),
                    created_at: key.created_at,
                    revoked_at: key.revoked_at,
                };
                if keys.insert(key.id, prepared_key).is_some() {
                    return Err(manifest_error(format!(
                        "duplicate publisher key id {}",
                        key.id
                    )));
                }
                if let Some(existing_id) = key_ids_by_public_key.insert(public_key, key.id) {
                    return Err(manifest_error(format!(
                        "publisher keys {} and {} use the same public key",
                        existing_id, key.id
                    )));
                }
            }
        }

        let mut packs = BTreeMap::new();
        for pack in &self.packs {
            validate_non_blank("pack name", &pack.name)?;
            let publisher = publishers.get(&pack.publisher_id).ok_or_else(|| {
                manifest_error(format!(
                    "pack {} references unknown publisher {}",
                    pack.name, pack.publisher_id
                ))
            })?;
            let expected_current_author = decode_exact_hex::<32>(
                "pack expected_current_author",
                &pack.expected_current_author,
            )?;
            let current_key_id = key_ids_by_public_key
                .get(&expected_current_author)
                .ok_or_else(|| {
                    manifest_error(format!(
                        "pack {} current_author is not a mapped publisher key",
                        pack.name
                    ))
                })?;
            let current_key = keys.get(current_key_id).ok_or_else(|| {
                manifest_error(format!(
                    "pack {} current_author key index is inconsistent",
                    pack.name
                ))
            })?;
            if current_key.publisher_id != publisher.id {
                return Err(manifest_error(format!(
                    "pack {} current_author belongs to publisher {}, not {}",
                    pack.name, current_key.publisher_id, publisher.id
                )));
            }
            let prepared_pack = PreparedPack {
                name: pack.name.clone(),
                publisher_id: pack.publisher_id,
                expected_current_author,
            };
            if packs.insert(pack.name.clone(), prepared_pack).is_some() {
                return Err(manifest_error(format!(
                    "duplicate pack mapping {}",
                    pack.name
                )));
            }
        }

        let mut versions = BTreeMap::new();
        for version in &self.versions {
            validate_non_blank("version pack_name", &version.pack_name)?;
            validate_non_blank("version", &version.version)?;
            let pack = packs.get(&version.pack_name).ok_or_else(|| {
                manifest_error(format!(
                    "version {}@{} references an unmapped pack",
                    version.pack_name, version.version
                ))
            })?;
            let key = keys.get(&version.publisher_key_id).ok_or_else(|| {
                manifest_error(format!(
                    "version {}@{} references unknown key {}",
                    version.pack_name, version.version, version.publisher_key_id
                ))
            })?;
            if key.publisher_id != pack.publisher_id {
                return Err(manifest_error(format!(
                    "version {}@{} key belongs to publisher {}, not {}",
                    version.pack_name, version.version, key.publisher_id, pack.publisher_id
                )));
            }
            let expected_author_pubkey = decode_exact_hex::<32>(
                "version expected_author_pubkey",
                &version.expected_author_pubkey,
            )?;
            if expected_author_pubkey != key.public_key {
                return Err(manifest_error(format!(
                    "version {}@{} author_pubkey does not match key {}",
                    version.pack_name, version.version, key.id
                )));
            }
            let expected_content_hash = decode_exact_hex::<32>(
                "version expected_content_hash",
                &version.expected_content_hash,
            )?;
            let prepared_version = PreparedVersion {
                pack_name: version.pack_name.clone(),
                version: version.version.clone(),
                publisher_key_id: version.publisher_key_id,
                expected_author_pubkey,
                expected_content_hash,
            };
            let version_id = (version.pack_name.clone(), version.version.clone());
            if versions.insert(version_id, prepared_version).is_some() {
                return Err(manifest_error(format!(
                    "duplicate version mapping {}@{}",
                    version.pack_name, version.version
                )));
            }
        }

        if let Some(publisher) = publishers
            .values()
            .find(|publisher| !packs.values().any(|pack| pack.publisher_id == publisher.id))
        {
            return Err(manifest_error(format!(
                "publisher {} is not referenced by any mapped pack",
                publisher.id
            )));
        }
        Ok(PreparedManifest {
            manifest_sha256: manifest_sha256.to_ascii_lowercase(),
            expected_pack_count: self.expected_pack_count,
            expected_version_count: self.expected_version_count,
            publishers,
            keys,
            key_ids_by_public_key,
            packs,
            versions,
        })
    }
}

/// Build a manifest validation error.
fn manifest_error(message: String) -> OwnershipBackfillError {
    OwnershipBackfillError::Manifest(message)
}

/// Validate that a human-readable string is non-blank.
fn validate_non_blank(kind: &str, value: &str) -> Result<(), OwnershipBackfillError> {
    if value.trim().is_empty() {
        return Err(manifest_error(format!("{kind} must not be blank")));
    }
    Ok(())
}

/// Validate the normalized publisher handle shape enforced by Postgres.
fn validate_handle(handle: &str) -> Result<(), OwnershipBackfillError> {
    let bytes = handle.as_bytes();
    let valid_edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let valid_middle = |byte: u8| valid_edge(byte) || byte == b'_' || byte == b'-';
    if !(3..=64).contains(&bytes.len())
        || !valid_edge(bytes[0])
        || !valid_edge(bytes[bytes.len() - 1])
        || !bytes.iter().copied().all(valid_middle)
    {
        return Err(manifest_error(format!(
            "publisher handle {handle:?} is not normalized"
        )));
    }
    Ok(())
}

/// Require timestamps that Postgres can round-trip without precision loss.
fn validate_timestamp(kind: &str, timestamp: DateTime<Utc>) -> Result<(), OwnershipBackfillError> {
    if timestamp.nanosecond() % 1_000 != 0 {
        return Err(manifest_error(format!(
            "{kind} must use microsecond precision or coarser"
        )));
    }
    Ok(())
}

/// Decode an exact-width hexadecimal field.
fn decode_exact_hex<const N: usize>(
    kind: &str,
    value: &str,
) -> Result<[u8; N], OwnershipBackfillError> {
    let decoded = hex::decode(value)
        .map_err(|_| manifest_error(format!("{kind} must be valid hexadecimal")))?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        manifest_error(format!(
            "{kind} must decode to {N} bytes, got {}",
            bytes.len()
        ))
    })
}

/// Validate a manifest SHA-256 string supplied by the operator boundary.
fn validate_sha256(value: &str) -> Result<(), OwnershipBackfillError> {
    decode_exact_hex::<32>("manifest_sha256", value).map(|_| ())
}

/// Queryable immutable publisher audit row used for idempotency validation.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = publisher_audit_events)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct OwnershipAuditRow {
    /// Stable audit event UUID.
    id: Uuid,
    /// Existing account responsible for the migration.
    actor_account_id: Option<Uuid>,
    /// Publisher affected by the migration.
    publisher_id: Uuid,
    /// Stable audit action.
    action: String,
    /// Optional target key.
    target_key_id: Option<Uuid>,
    /// Optional target version.
    target_version: Option<String>,
    /// Optional request correlation UUID.
    request_id: Option<Uuid>,
    /// Stable audit creation time.
    created_at: DateTime<Utc>,
    /// Sanitized migration metadata.
    metadata: JsonValue,
}

/// Live database rows captured while all migration-related writers are locked.
#[derive(Debug)]
struct DatabaseSnapshot {
    /// Accounts keyed by stable UUID.
    accounts: BTreeMap<Uuid, AccountRow>,
    /// Publisher profiles keyed by stable UUID.
    publishers: BTreeMap<Uuid, PublisherProfileRow>,
    /// Publisher UUIDs keyed by exact handle.
    publisher_ids_by_handle: BTreeMap<String, Uuid>,
    /// Owner memberships keyed by account and publisher UUID.
    memberships: BTreeMap<(Uuid, Uuid), PublisherMembershipRow>,
    /// Publisher keys keyed by stable UUID.
    keys: BTreeMap<Uuid, PublisherKeyRow>,
    /// Publisher key UUIDs keyed by exact public key bytes.
    key_ids_by_public_key: BTreeMap<Vec<u8>, Uuid>,
    /// Publisher audit events keyed by stable UUID.
    audit_events: BTreeMap<Uuid, OwnershipAuditRow>,
    /// Legacy author keys keyed by exact handle.
    authors_by_handle: BTreeMap<String, AuthorRow>,
    /// Legacy author handles keyed by exact public key bytes.
    author_handles_by_public_key: BTreeMap<Vec<u8>, String>,
    /// Legacy handle rows keyed by exact handle.
    handles_by_handle: BTreeMap<String, HandleRow>,
    /// Pack heads keyed by exact name.
    packs: BTreeMap<String, PackRow>,
    /// Pack versions keyed by exact pack and version.
    versions: BTreeMap<(String, String), PackVersionRow>,
}

/// Immutable signer and artifact evidence compared before transaction commit.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoricalEvidence {
    /// Pack head signer bytes keyed by pack name.
    pack_current_authors: BTreeMap<String, Vec<u8>>,
    /// Version signer, hash, signature, and parent hash bytes keyed by identity.
    versions: BTreeMap<(String, String), VersionEvidence>,
}

/// Immutable evidence fields for one historical pack version.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionEvidence {
    /// Raw historical signer bytes.
    author_pubkey: Vec<u8>,
    /// Raw immutable content hash.
    content_hash: Vec<u8>,
    /// Raw historical signature.
    signature: Vec<u8>,
    /// Optional raw parent content hash.
    parent_hash: Option<Vec<u8>>,
}

/// Exact mutation plan derived from a locked live snapshot.
#[derive(Debug)]
struct OwnershipMutationPlan {
    /// Exact preflight census.
    census: OwnershipBackfillCensus,
    /// Missing publisher profile UUIDs.
    publisher_profiles_to_create: Vec<Uuid>,
    /// Missing owner membership identity pairs.
    owner_memberships_to_create: Vec<(Uuid, Uuid)>,
    /// Missing publisher key UUIDs.
    publisher_keys_to_create: Vec<Uuid>,
    /// Missing publisher migration audit UUIDs.
    audit_events_to_create: Vec<Uuid>,
    /// Pack names whose nullable publisher ID must be linked.
    packs_to_update: Vec<String>,
    /// Version identities whose nullable publisher key ID must be linked.
    versions_to_update: Vec<(String, String)>,
}

/// Transaction error that preserves fail-closed manifest failures across rollback.
#[derive(Debug)]
enum OwnershipTransactionError {
    /// Manifest or catalog mismatch requiring rollback.
    Ownership(OwnershipBackfillError),
    /// Raw Diesel failure requiring rollback.
    Diesel(diesel::result::Error),
}

/// Diesel error conversion required by `AsyncConnection::transaction`.
impl From<diesel::result::Error> for OwnershipTransactionError {
    /// Preserve a raw Diesel error until the transaction has rolled back.
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

/// Convert a catalog state mismatch into a fail-closed public error.
fn catalog_state_error(message: String) -> OwnershipBackfillError {
    OwnershipBackfillError::CatalogState(message)
}

/// Build a transaction-scoped catalog state failure.
fn transaction_state_error(message: String) -> OwnershipTransactionError {
    OwnershipTransactionError::Ownership(catalog_state_error(message))
}

/// Generate deterministic audit metadata from the reviewed manifest.
fn audit_metadata(manifest: &PreparedManifest) -> JsonValue {
    json!({
        "expected_pack_count": manifest.expected_pack_count,
        "expected_version_count": manifest.expected_version_count,
        "manifest_sha256": manifest.manifest_sha256,
        "schema_version": OWNERSHIP_BACKFILL_SCHEMA_VERSION,
    })
}

/// Load every table needed for migration preflight from one locked connection.
async fn load_snapshot(
    connection: &mut AsyncPgConnection,
) -> Result<DatabaseSnapshot, diesel::result::Error> {
    let account_rows = accounts::table
        .select(AccountRow::as_select())
        .load(connection)
        .await?;
    let publisher_rows = publisher_profiles::table
        .select(PublisherProfileRow::as_select())
        .load(connection)
        .await?;
    let membership_rows = publisher_memberships::table
        .select(PublisherMembershipRow::as_select())
        .load(connection)
        .await?;
    let key_rows = publisher_keys::table
        .select(PublisherKeyRow::as_select())
        .load(connection)
        .await?;
    let audit_rows = publisher_audit_events::table
        .select(OwnershipAuditRow::as_select())
        .load(connection)
        .await?;
    let author_rows = authors::table
        .select(AuthorRow::as_select())
        .load(connection)
        .await?;
    let handle_rows = handles::table
        .select(HandleRow::as_select())
        .load(connection)
        .await?;
    let pack_rows = packs::table
        .select(PackRow::as_select())
        .load(connection)
        .await?;
    let version_rows = pack_versions::table
        .select(PackVersionRow::as_select())
        .load(connection)
        .await?;

    let publisher_ids_by_handle = publisher_rows
        .iter()
        .map(|row| (row.handle.clone(), row.id))
        .collect();
    let key_ids_by_public_key = key_rows
        .iter()
        .map(|row| (row.public_key.clone(), row.id))
        .collect();
    let author_handles_by_public_key = author_rows
        .iter()
        .map(|row| (row.pubkey.clone(), row.handle.clone()))
        .collect();

    Ok(DatabaseSnapshot {
        accounts: account_rows.into_iter().map(|row| (row.id, row)).collect(),
        publishers: publisher_rows
            .into_iter()
            .map(|row| (row.id, row))
            .collect(),
        publisher_ids_by_handle,
        memberships: membership_rows
            .into_iter()
            .map(|row| ((row.account_id, row.publisher_id), row))
            .collect(),
        keys: key_rows.into_iter().map(|row| (row.id, row)).collect(),
        key_ids_by_public_key,
        audit_events: audit_rows.into_iter().map(|row| (row.id, row)).collect(),
        authors_by_handle: author_rows
            .into_iter()
            .map(|row| (row.handle.clone(), row))
            .collect(),
        author_handles_by_public_key,
        handles_by_handle: handle_rows
            .into_iter()
            .map(|row| (row.handle.clone(), row))
            .collect(),
        packs: pack_rows
            .into_iter()
            .map(|row| (row.name.clone(), row))
            .collect(),
        versions: version_rows
            .into_iter()
            .map(|row| ((row.pack_name.clone(), row.version.clone()), row))
            .collect(),
    })
}

/// Capture immutable signer, hash, and signature evidence from a live snapshot.
fn historical_evidence(snapshot: &DatabaseSnapshot) -> HistoricalEvidence {
    HistoricalEvidence {
        pack_current_authors: snapshot
            .packs
            .iter()
            .map(|(name, row)| (name.clone(), row.current_author.clone()))
            .collect(),
        versions: snapshot
            .versions
            .iter()
            .map(|(identity, row)| {
                (
                    identity.clone(),
                    VersionEvidence {
                        author_pubkey: row.author_pubkey.clone(),
                        content_hash: row.content_hash.clone(),
                        signature: row.signature.clone(),
                        parent_hash: row.parent_hash.clone(),
                    },
                )
            })
            .collect(),
    }
}

/// Validate one existing publisher profile against bootstrap metadata.
fn validate_existing_publisher(
    expected: &PreparedPublisher,
    actual: &PublisherProfileRow,
) -> Result<(), OwnershipBackfillError> {
    if actual.id != expected.id
        || actual.handle != expected.handle
        || actual.display_name != expected.display_name
        || actual.biography != expected.biography
        || actual.moderation_status != expected.moderation_status
        || actual.created_at != expected.created_at
    {
        return Err(catalog_state_error(format!(
            "publisher {} does not exactly match bootstrap metadata",
            expected.id
        )));
    }
    Ok(())
}

/// Validate one existing publisher key against bootstrap metadata.
fn validate_existing_key(
    expected: &PreparedKey,
    actual: &PublisherKeyRow,
) -> Result<(), OwnershipBackfillError> {
    if actual.id != expected.id
        || actual.publisher_id != expected.publisher_id
        || actual.public_key.as_slice() != expected.public_key.as_slice()
        || actual.label != expected.label
        || actual.state != expected.state
        || actual.created_at != expected.created_at
        || actual.revoked_at != expected.revoked_at
    {
        return Err(catalog_state_error(format!(
            "publisher key {} does not exactly match bootstrap metadata",
            expected.id
        )));
    }
    Ok(())
}

/// Validate one existing migration audit event for safe idempotency.
fn validate_existing_audit(
    expected: &PreparedPublisher,
    manifest: &PreparedManifest,
    actual: &OwnershipAuditRow,
) -> Result<(), OwnershipBackfillError> {
    if actual.id != expected.audit_event_id
        || actual.actor_account_id.is_some()
        || actual.publisher_id != expected.id
        || actual.action != OWNERSHIP_BACKFILL_AUDIT_ACTION
        || actual.target_key_id.is_some()
        || actual.target_version.is_some()
        || actual.request_id.is_some()
        || actual.created_at != expected.audit_created_at
        || actual.metadata != audit_metadata(manifest)
    {
        return Err(catalog_state_error(format!(
            "audit event {} does not exactly match migration metadata",
            expected.audit_event_id
        )));
    }
    Ok(())
}

/// Require safe coexistence between one publisher and any legacy handle rows.
fn validate_legacy_handle_coexistence(
    publisher: &PreparedPublisher,
    manifest: &PreparedManifest,
    snapshot: &DatabaseSnapshot,
) -> Result<(), OwnershipBackfillError> {
    let matches_mapped_key = |bytes: &[u8]| {
        let Ok(public_key) = <[u8; 32]>::try_from(bytes) else {
            return false;
        };
        manifest
            .key_ids_by_public_key
            .get(&public_key)
            .and_then(|key_id| manifest.keys.get(key_id))
            .is_some_and(|key| key.publisher_id == publisher.id)
    };

    let owns_unlinked_pack = manifest
        .packs
        .values()
        .filter(|pack| pack.publisher_id == publisher.id)
        .any(|pack| {
            snapshot
                .packs
                .get(&pack.name)
                .is_some_and(|actual| actual.publisher_id.is_none())
        });
    let owns_unlinked_version = manifest
        .versions
        .values()
        .filter(|version| {
            manifest
                .keys
                .get(&version.publisher_key_id)
                .is_some_and(|key| key.publisher_id == publisher.id)
        })
        .any(|version| {
            snapshot
                .versions
                .get(&(version.pack_name.clone(), version.version.clone()))
                .is_some_and(|actual| actual.publisher_key_id.is_none())
        });
    let author = snapshot.authors_by_handle.get(&publisher.handle);
    if (owns_unlinked_pack || owns_unlinked_version) && author.is_none() {
        return Err(catalog_state_error(format!(
            "migration publisher {} has no matching legacy author handle",
            publisher.handle
        )));
    }
    if let Some(author) = author {
        if !matches_mapped_key(&author.pubkey) {
            return Err(catalog_state_error(format!(
                "legacy author handle {} has an unmapped or foreign key",
                publisher.handle
            )));
        }
    }
    if let Some(handle) = snapshot.handles_by_handle.get(&publisher.handle) {
        if !matches_mapped_key(&handle.pubkey) {
            return Err(catalog_state_error(format!(
                "legacy handle {} has an unmapped or foreign key",
                publisher.handle
            )));
        }
    }
    if let Some((key, legacy_handle)) = manifest
        .keys
        .values()
        .filter(|key| key.publisher_id == publisher.id)
        .find_map(|key| {
            snapshot
                .author_handles_by_public_key
                .get(key.public_key.as_slice())
                .filter(|legacy_handle| *legacy_handle != &publisher.handle)
                .map(|legacy_handle| (key, legacy_handle))
        })
    {
        return Err(catalog_state_error(format!(
            "publisher key {} belongs to legacy author handle {}, not {}",
            key.id, legacy_handle, publisher.handle
        )));
    }
    Ok(())
}

/// Require historical signer bytes to resolve to the publisher's exact legacy handle.
fn validate_legacy_signer_handle(
    kind: &str,
    identity: &str,
    signer: &[u8],
    expected_handle: &str,
    snapshot: &DatabaseSnapshot,
) -> Result<(), OwnershipBackfillError> {
    let actual_handle = snapshot
        .author_handles_by_public_key
        .get(signer)
        .ok_or_else(|| {
            catalog_state_error(format!(
                "{kind} {identity} signer has no legacy author record"
            ))
        })?;
    if actual_handle != expected_handle {
        return Err(catalog_state_error(format!(
            "{kind} {identity} signer belongs to legacy handle {actual_handle}, not {expected_handle}"
        )));
    }
    Ok(())
}

/// Build an exact, mutation-free plan from a locked database snapshot.
fn build_mutation_plan(
    manifest: &PreparedManifest,
    snapshot: &DatabaseSnapshot,
) -> Result<OwnershipMutationPlan, OwnershipBackfillError> {
    if snapshot.packs.len() as u64 != manifest.expected_pack_count {
        return Err(catalog_state_error(format!(
            "catalog has {} packs; manifest expects {}",
            snapshot.packs.len(),
            manifest.expected_pack_count
        )));
    }
    if snapshot.versions.len() as u64 != manifest.expected_version_count {
        return Err(catalog_state_error(format!(
            "catalog has {} versions; manifest expects {}",
            snapshot.versions.len(),
            manifest.expected_version_count
        )));
    }
    if let Some(name) = snapshot
        .packs
        .keys()
        .find(|name| !manifest.packs.contains_key(*name))
    {
        return Err(catalog_state_error(format!(
            "catalog pack {name} is absent from the manifest"
        )));
    }
    if let Some(identity) = snapshot
        .versions
        .keys()
        .find(|identity| !manifest.versions.contains_key(*identity))
    {
        return Err(catalog_state_error(format!(
            "catalog version {}@{} is absent from the manifest",
            identity.0, identity.1
        )));
    }

    let mut publisher_profiles_to_create = Vec::new();
    let mut owner_memberships_to_create = Vec::new();
    let mut publisher_keys_to_create = Vec::new();
    let mut audit_events_to_create = Vec::new();
    let mut packs_to_update = Vec::new();
    let mut versions_to_update = Vec::new();

    for publisher in manifest.publishers.values() {
        let account = snapshot
            .accounts
            .get(&publisher.owner_account_id)
            .ok_or_else(|| {
                catalog_state_error(format!(
                    "owner account {} does not exist",
                    publisher.owner_account_id
                ))
            })?;
        if account.status != "active" {
            return Err(catalog_state_error(format!(
                "owner account {} is not active",
                publisher.owner_account_id
            )));
        }
        validate_legacy_handle_coexistence(publisher, manifest, snapshot)?;

        match snapshot.publishers.get(&publisher.id) {
            Some(actual) => validate_existing_publisher(publisher, actual)?,
            None => {
                if let Some(existing_id) = snapshot.publisher_ids_by_handle.get(&publisher.handle) {
                    return Err(catalog_state_error(format!(
                        "publisher handle {} already belongs to {}",
                        publisher.handle, existing_id
                    )));
                }
                publisher_profiles_to_create.push(publisher.id);
            }
        }
        if let Some(existing_id) = snapshot
            .publisher_ids_by_handle
            .get(&publisher.handle)
            .filter(|existing_id| **existing_id != publisher.id)
        {
            return Err(catalog_state_error(format!(
                "publisher handle {} conflicts with publisher {}",
                publisher.handle, existing_id
            )));
        }

        let membership_identity = (publisher.owner_account_id, publisher.id);
        if let Some(foreign_owner) = snapshot.memberships.values().find(|membership| {
            membership.publisher_id == publisher.id
                && membership.account_id != publisher.owner_account_id
                && membership.role == "owner"
                && membership.state == "active"
        }) {
            return Err(catalog_state_error(format!(
                "publisher {} already has active owner account {}",
                publisher.id, foreign_owner.account_id
            )));
        }
        match snapshot.memberships.get(&membership_identity) {
            Some(membership)
                if membership.role == "owner"
                    && membership.state == "active"
                    && membership.created_at == publisher.created_at => {}
            Some(_) => {
                return Err(catalog_state_error(format!(
                    "owner membership {} -> {} does not exactly match bootstrap metadata",
                    publisher.owner_account_id, publisher.id
                )));
            }
            None => owner_memberships_to_create.push(membership_identity),
        }

        match snapshot.audit_events.get(&publisher.audit_event_id) {
            Some(actual) => validate_existing_audit(publisher, manifest, actual)?,
            None => audit_events_to_create.push(publisher.audit_event_id),
        }
    }

    if let Some(unmapped_key) = snapshot.keys.values().find(|key| {
        manifest.publishers.contains_key(&key.publisher_id) && !manifest.keys.contains_key(&key.id)
    }) {
        return Err(catalog_state_error(format!(
            "publisher {} has unmanifested key {}",
            unmapped_key.publisher_id, unmapped_key.id
        )));
    }
    for key in manifest.keys.values() {
        let by_id = snapshot.keys.get(&key.id);
        let by_bytes = snapshot
            .key_ids_by_public_key
            .get(key.public_key.as_slice());
        match (by_id, by_bytes) {
            (None, None) => publisher_keys_to_create.push(key.id),
            (Some(actual), Some(existing_id)) if *existing_id == key.id => {
                validate_existing_key(key, actual)?;
            }
            (Some(_), Some(existing_id)) => {
                return Err(catalog_state_error(format!(
                    "publisher key {} bytes belong to key {}",
                    key.id, existing_id
                )));
            }
            (Some(_), None) => {
                return Err(catalog_state_error(format!(
                    "publisher key id {} exists with different bytes",
                    key.id
                )));
            }
            (None, Some(existing_id)) => {
                return Err(catalog_state_error(format!(
                    "publisher key bytes for {} already belong to key {}",
                    key.id, existing_id
                )));
            }
        }
    }
    if let Some(key_id) = publisher_keys_to_create.iter().find(|key_id| {
        manifest.keys.get(*key_id).is_some_and(|key| {
            !manifest
                .packs
                .values()
                .any(|pack| pack.expected_current_author == key.public_key)
                && !manifest
                    .versions
                    .values()
                    .any(|version| version.publisher_key_id == key.id)
        })
    }) {
        return Err(catalog_state_error(format!(
            "new publisher key {key_id} is not referenced by any mapped pack or version"
        )));
    }

    for pack in manifest.packs.values() {
        let actual = snapshot.packs.get(&pack.name).ok_or_else(|| {
            catalog_state_error(format!("manifest pack {} does not exist", pack.name))
        })?;
        if actual.current_author.as_slice() != pack.expected_current_author.as_slice() {
            return Err(catalog_state_error(format!(
                "pack {} current_author does not match the manifest",
                pack.name
            )));
        }
        let publisher = manifest.publishers.get(&pack.publisher_id).ok_or_else(|| {
            catalog_state_error(format!(
                "pack {} references absent prepared publisher {}",
                pack.name, pack.publisher_id
            ))
        })?;
        match actual.publisher_id {
            None => {
                validate_legacy_signer_handle(
                    "pack",
                    &pack.name,
                    &actual.current_author,
                    &publisher.handle,
                    snapshot,
                )?;
                packs_to_update.push(pack.name.clone());
            }
            Some(existing_id) if existing_id == pack.publisher_id => {}
            Some(existing_id) => {
                return Err(catalog_state_error(format!(
                    "pack {} is already linked to conflicting publisher {}",
                    pack.name, existing_id
                )));
            }
        }
    }

    for version in manifest.versions.values() {
        let identity = (version.pack_name.clone(), version.version.clone());
        let actual = snapshot.versions.get(&identity).ok_or_else(|| {
            catalog_state_error(format!(
                "manifest version {}@{} does not exist",
                version.pack_name, version.version
            ))
        })?;
        if actual.author_pubkey.as_slice() != version.expected_author_pubkey.as_slice() {
            return Err(catalog_state_error(format!(
                "version {}@{} author_pubkey does not match the manifest",
                version.pack_name, version.version
            )));
        }
        if actual.content_hash.as_slice() != version.expected_content_hash.as_slice() {
            return Err(catalog_state_error(format!(
                "version {}@{} content_hash does not match the manifest",
                version.pack_name, version.version
            )));
        }
        let key = manifest
            .keys
            .get(&version.publisher_key_id)
            .ok_or_else(|| {
                catalog_state_error(format!(
                    "version {}@{} references absent prepared key {}",
                    version.pack_name, version.version, version.publisher_key_id
                ))
            })?;
        let publisher = manifest.publishers.get(&key.publisher_id).ok_or_else(|| {
            catalog_state_error(format!(
                "version {}@{} key references absent prepared publisher {}",
                version.pack_name, version.version, key.publisher_id
            ))
        })?;
        match actual.publisher_key_id {
            None => {
                validate_legacy_signer_handle(
                    "version",
                    &format!("{}@{}", version.pack_name, version.version),
                    &actual.author_pubkey,
                    &publisher.handle,
                    snapshot,
                )?;
                versions_to_update.push(identity);
            }
            Some(existing_id) if existing_id == version.publisher_key_id => {}
            Some(existing_id) => {
                return Err(catalog_state_error(format!(
                    "version {}@{} is already linked to conflicting key {}",
                    version.pack_name, version.version, existing_id
                )));
            }
        }
    }

    let publisher_census = manifest
        .publishers
        .values()
        .map(|publisher| {
            let manifest_keys = manifest
                .keys
                .values()
                .filter(|key| key.publisher_id == publisher.id)
                .count();
            let mapped_packs = manifest
                .packs
                .values()
                .filter(|pack| pack.publisher_id == publisher.id)
                .count();
            let mapped_versions = manifest
                .versions
                .values()
                .filter(|version| {
                    manifest
                        .keys
                        .get(&version.publisher_key_id)
                        .is_some_and(|key| key.publisher_id == publisher.id)
                })
                .count();
            let publisher_packs_to_update = packs_to_update
                .iter()
                .filter(|name| {
                    manifest
                        .packs
                        .get(name.as_str())
                        .is_some_and(|pack| pack.publisher_id == publisher.id)
                })
                .count();
            let publisher_versions_to_update = versions_to_update
                .iter()
                .filter(|identity| {
                    manifest
                        .versions
                        .get(*identity)
                        .and_then(|version| manifest.keys.get(&version.publisher_key_id))
                        .is_some_and(|key| key.publisher_id == publisher.id)
                })
                .count();
            OwnershipBackfillPublisherCensus {
                publisher_id: publisher.id,
                handle: publisher.handle.clone(),
                manifest_keys: manifest_keys as u64,
                mapped_packs: mapped_packs as u64,
                mapped_versions: mapped_versions as u64,
                packs_already_linked: (mapped_packs - publisher_packs_to_update) as u64,
                packs_to_update: publisher_packs_to_update as u64,
                versions_already_linked: (mapped_versions - publisher_versions_to_update) as u64,
                versions_to_update: publisher_versions_to_update as u64,
            }
        })
        .collect();
    let census = OwnershipBackfillCensus {
        publishers: publisher_census,
        catalog_packs: snapshot.packs.len() as u64,
        catalog_versions: snapshot.versions.len() as u64,
        manifest_publishers: manifest.publishers.len() as u64,
        manifest_keys: manifest.keys.len() as u64,
        publisher_profiles_existing: (manifest.publishers.len()
            - publisher_profiles_to_create.len()) as u64,
        publisher_profiles_to_create: publisher_profiles_to_create.len() as u64,
        owner_memberships_existing: (manifest.publishers.len() - owner_memberships_to_create.len())
            as u64,
        owner_memberships_to_create: owner_memberships_to_create.len() as u64,
        publisher_keys_existing: (manifest.keys.len() - publisher_keys_to_create.len()) as u64,
        publisher_keys_to_create: publisher_keys_to_create.len() as u64,
        audit_events_existing: (manifest.publishers.len() - audit_events_to_create.len()) as u64,
        audit_events_to_create: audit_events_to_create.len() as u64,
        packs_already_linked: (manifest.packs.len() - packs_to_update.len()) as u64,
        packs_to_update: packs_to_update.len() as u64,
        versions_already_linked: (manifest.versions.len() - versions_to_update.len()) as u64,
        versions_to_update: versions_to_update.len() as u64,
    };

    Ok(OwnershipMutationPlan {
        census,
        publisher_profiles_to_create,
        owner_memberships_to_create,
        publisher_keys_to_create,
        audit_events_to_create,
        packs_to_update,
        versions_to_update,
    })
}

/// Apply a validated mutation plan using column-limited inserts and updates.
async fn apply_mutation_plan(
    connection: &mut AsyncPgConnection,
    manifest: &PreparedManifest,
    plan: &OwnershipMutationPlan,
) -> Result<OwnershipBackfillApplied, OwnershipTransactionError> {
    let mut applied = OwnershipBackfillApplied::default();

    for publisher_id in &plan.publisher_profiles_to_create {
        let publisher = manifest.publishers.get(publisher_id).ok_or_else(|| {
            transaction_state_error(format!(
                "planned publisher {publisher_id} is absent from prepared manifest"
            ))
        })?;
        let inserted = diesel::insert_into(publisher_profiles::table)
            .values(NewPublisherProfileRow {
                id: publisher.id,
                handle: publisher.handle.clone(),
                display_name: publisher.display_name.clone(),
                biography: publisher.biography.clone(),
                moderation_status: publisher.moderation_status.to_string(),
                created_at: publisher.created_at,
                updated_at: publisher.created_at,
            })
            .execute(connection)
            .await?;
        require_exact_mutation("publisher profile insert", publisher.id, inserted)?;
        applied.publisher_profiles += inserted as u64;
    }

    for (account_id, publisher_id) in &plan.owner_memberships_to_create {
        let publisher = manifest.publishers.get(publisher_id).ok_or_else(|| {
            transaction_state_error(format!(
                "planned membership publisher {publisher_id} is absent from prepared manifest"
            ))
        })?;
        let inserted = diesel::insert_into(publisher_memberships::table)
            .values(NewPublisherMembershipRow {
                account_id: *account_id,
                publisher_id: *publisher_id,
                role: "owner".to_string(),
                state: "active".to_string(),
                created_at: publisher.created_at,
                updated_at: publisher.created_at,
            })
            .execute(connection)
            .await?;
        require_exact_mutation(
            "owner membership insert",
            format!("{account_id}->{publisher_id}"),
            inserted,
        )?;
        applied.owner_memberships += inserted as u64;
    }

    for key_id in &plan.publisher_keys_to_create {
        let key = manifest.keys.get(key_id).ok_or_else(|| {
            transaction_state_error(format!(
                "planned key {key_id} is absent from prepared manifest"
            ))
        })?;
        let inserted = diesel::insert_into(publisher_keys::table)
            .values(NewPublisherKeyRow {
                id: key.id,
                publisher_id: key.publisher_id,
                public_key: key.public_key.to_vec(),
                label: key.label.clone(),
                state: key.state.to_string(),
                created_at: key.created_at,
                revoked_at: key.revoked_at,
                last_used_at: None,
            })
            .execute(connection)
            .await?;
        require_exact_mutation("publisher key insert", key.id, inserted)?;
        applied.publisher_keys += inserted as u64;
    }

    for pack_name in &plan.packs_to_update {
        let pack = manifest.packs.get(pack_name).ok_or_else(|| {
            transaction_state_error(format!(
                "planned pack {pack_name} is absent from prepared manifest"
            ))
        })?;
        let updated = diesel::update(
            packs::table
                .filter(packs::name.eq(pack_name))
                .filter(packs::publisher_id.is_null()),
        )
        .set(packs::publisher_id.eq(Some(pack.publisher_id)))
        .execute(connection)
        .await?;
        require_exact_mutation("pack ownership update", pack_name, updated)?;
        applied.packs += updated as u64;
    }

    for (pack_name, version_name) in &plan.versions_to_update {
        let identity = (pack_name.clone(), version_name.clone());
        let version = manifest.versions.get(&identity).ok_or_else(|| {
            transaction_state_error(format!(
                "planned version {pack_name}@{version_name} is absent from prepared manifest"
            ))
        })?;
        let updated = diesel::update(
            pack_versions::table
                .filter(pack_versions::pack_name.eq(pack_name))
                .filter(pack_versions::version.eq(version_name))
                .filter(pack_versions::publisher_key_id.is_null()),
        )
        .set(pack_versions::publisher_key_id.eq(Some(version.publisher_key_id)))
        .execute(connection)
        .await?;
        require_exact_mutation(
            "version ownership update",
            format!("{pack_name}@{version_name}"),
            updated,
        )?;
        applied.versions += updated as u64;
    }

    let metadata = audit_metadata(manifest);
    for audit_id in &plan.audit_events_to_create {
        let publisher = manifest
            .publishers
            .values()
            .find(|publisher| publisher.audit_event_id == *audit_id)
            .ok_or_else(|| {
                transaction_state_error(format!(
                    "planned audit event {audit_id} has no prepared publisher"
                ))
            })?;
        let inserted = diesel::insert_into(publisher_audit_events::table)
            .values(NewPublisherAuditEventRow {
                id: publisher.audit_event_id,
                actor_account_id: None,
                publisher_id: publisher.id,
                action: OWNERSHIP_BACKFILL_AUDIT_ACTION.to_string(),
                target_key_id: None,
                target_version: None,
                request_id: None,
                created_at: publisher.audit_created_at,
                metadata: metadata.clone(),
            })
            .execute(connection)
            .await?;
        require_exact_mutation("audit event insert", audit_id, inserted)?;
        applied.audit_events += inserted as u64;
    }

    Ok(applied)
}

/// Require one exact row mutation or force the transaction to roll back.
fn require_exact_mutation(
    kind: &str,
    identity: impl std::fmt::Display,
    affected: usize,
) -> Result<(), OwnershipTransactionError> {
    if affected != 1 {
        return Err(OwnershipTransactionError::Ownership(catalog_state_error(
            format!("{kind} for {identity} affected {affected} rows instead of one"),
        )));
    }
    Ok(())
}

/// Confirm that apply mode left no missing links and changed no evidence bytes.
fn verify_applied_snapshot(
    manifest: &PreparedManifest,
    before_evidence: &HistoricalEvidence,
    after: &DatabaseSnapshot,
) -> Result<(), OwnershipBackfillError> {
    if historical_evidence(after) != *before_evidence {
        return Err(catalog_state_error(
            "historical signer, hash, signature, or parent hash evidence changed".to_string(),
        ));
    }
    let remaining = build_mutation_plan(manifest, after)?;
    let no_missing_rows = remaining.publisher_profiles_to_create.is_empty()
        && remaining.owner_memberships_to_create.is_empty()
        && remaining.publisher_keys_to_create.is_empty()
        && remaining.audit_events_to_create.is_empty()
        && remaining.packs_to_update.is_empty()
        && remaining.versions_to_update.is_empty();
    if !no_missing_rows {
        return Err(catalog_state_error(
            "post-apply verification found unapplied ownership rows".to_string(),
        ));
    }
    Ok(())
}

/// Execute one dry-run or apply operation while relevant writers are locked.
async fn execute_locked_backfill(
    connection: &mut AsyncPgConnection,
    manifest: &PreparedManifest,
    mode: OwnershipBackfillMode,
) -> Result<OwnershipBackfillReport, OwnershipTransactionError> {
    diesel::sql_query(
        "LOCK TABLE pack_versions, authors, handles, publisher_profiles, accounts, \
         publisher_memberships, publisher_keys, publisher_audit_events, \
         packs IN SHARE ROW EXCLUSIVE MODE",
    )
    .execute(connection)
    .await?;

    let before = load_snapshot(connection).await?;
    let before_evidence = historical_evidence(&before);
    let plan =
        build_mutation_plan(manifest, &before).map_err(OwnershipTransactionError::Ownership)?;
    let applied = match mode {
        OwnershipBackfillMode::DryRun => OwnershipBackfillApplied::default(),
        OwnershipBackfillMode::Apply => {
            let applied = apply_mutation_plan(connection, manifest, &plan).await?;
            let after = load_snapshot(connection).await?;
            verify_applied_snapshot(manifest, &before_evidence, &after)
                .map_err(OwnershipTransactionError::Ownership)?;
            applied
        }
    };

    Ok(OwnershipBackfillReport {
        mode,
        manifest_sha256: manifest.manifest_sha256.clone(),
        census: plan.census,
        applied,
    })
}

/// Execute a prepared backfill through an existing Postgres connection pool.
async fn run_with_pool(
    pool: &PgPool,
    manifest: &OwnershipBackfillManifest,
    manifest_sha256: &str,
    mode: OwnershipBackfillMode,
) -> Result<OwnershipBackfillReport, OwnershipBackfillError> {
    let prepared = manifest.prepare(manifest_sha256)?;
    let mut connection = pool
        .get()
        .await
        .map_err(|_| OwnershipBackfillError::ConnectionUnavailable)?;

    use diesel_async::AsyncConnection as _;
    let result = connection
        .transaction::<OwnershipBackfillReport, OwnershipTransactionError, _>(
            async move |connection| execute_locked_backfill(connection, &prepared, mode).await,
        )
        .await;

    match result {
        Ok(report) => Ok(report),
        Err(OwnershipTransactionError::Ownership(error)) => Err(error),
        Err(OwnershipTransactionError::Diesel(error)) => {
            Err(OwnershipBackfillError::Database(error))
        }
    }
}

/// Parse exact manifest bytes and enforce the apply confirmation boundary.
fn prepare_operator_input(
    manifest_bytes: &[u8],
    confirmation: Option<&str>,
    mode: OwnershipBackfillMode,
) -> Result<(OwnershipBackfillManifest, String), OwnershipBackfillError> {
    let manifest_sha256 = hex::encode(Sha256::digest(manifest_bytes));
    match (mode, confirmation) {
        (OwnershipBackfillMode::Apply, None) => {
            return Err(OwnershipBackfillError::MissingConfirmation);
        }
        (OwnershipBackfillMode::Apply, Some(confirmation))
            if !confirmation.eq_ignore_ascii_case(&manifest_sha256) =>
        {
            return Err(OwnershipBackfillError::ConfirmationMismatch);
        }
        (OwnershipBackfillMode::DryRun, Some(_)) => {
            return Err(OwnershipBackfillError::UnexpectedConfirmation);
        }
        _ => {}
    }
    let manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| manifest_error(format!("manifest JSON is invalid: {error}")))?;
    Ok((manifest, manifest_sha256))
}

/// Run the ownership backfill without implicitly applying schema migrations.
///
/// This is the operator binary boundary. It opens a pool against an already
/// migrated catalog, so dry-run mode never mutates the schema as a side effect
/// of connecting. Apply confirmation is checked against the SHA-256 of the
/// exact supplied bytes inside this boundary.
pub async fn run_ownership_backfill(
    config: &PostgresCatalogConfig,
    manifest_bytes: &[u8],
    confirmation: Option<&str>,
    mode: OwnershipBackfillMode,
) -> Result<OwnershipBackfillReport, OwnershipBackfillError> {
    let (manifest, manifest_sha256) = prepare_operator_input(manifest_bytes, confirmation, mode)?;
    let pool = build_pool(config)
        .await
        .map_err(|_| OwnershipBackfillError::ConnectionUnavailable)?;
    run_with_pool(&pool, &manifest, &manifest_sha256, mode).await
}

/// Operator-only ownership backfill methods for the Postgres catalog.
impl PostgresCatalog {
    /// Validate and optionally apply a complete ownership migration manifest.
    ///
    /// The exact manifest SHA-256 is recomputed from `manifest_bytes` and
    /// embedded in every new audit row. Apply mode requires the same digest as
    /// `confirmation`, inserts only missing bootstrap rows, updates only
    /// nullable ownership columns, re-reads the catalog, and compares
    /// historical evidence before committing.
    pub async fn run_ownership_backfill(
        &self,
        manifest_bytes: &[u8],
        confirmation: Option<&str>,
        mode: OwnershipBackfillMode,
    ) -> Result<OwnershipBackfillReport, OwnershipBackfillError> {
        let (manifest, manifest_sha256) =
            prepare_operator_input(manifest_bytes, confirmation, mode)?;
        run_with_pool(self.pool(), &manifest, &manifest_sha256, mode).await
    }
}

/// Pure ownership manifest validation tests.
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a deterministic Postgres-safe timestamp for pure tests.
    fn test_time() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("test timestamp must be valid")
    }

    /// Build one publisher manifest entry with one deterministic key.
    fn test_publisher(id_seed: u128, key_seed: u8) -> OwnershipManifestPublisher {
        OwnershipManifestPublisher {
            id: Uuid::from_u128(id_seed),
            handle: format!("pub{id_seed}"),
            owner_account_id: Uuid::from_u128(id_seed + 100),
            display_name: format!("Publisher {id_seed}"),
            biography: None,
            moderation_status: OwnershipManifestModerationStatus::Approved,
            created_at: test_time(),
            audit_event_id: Uuid::from_u128(id_seed + 200),
            audit_created_at: test_time(),
            keys: vec![OwnershipManifestKey {
                id: Uuid::from_u128(id_seed + 300),
                public_key: hex::encode([key_seed; 32]),
                label: "migration key".to_string(),
                state: OwnershipManifestKeyState::Active,
                created_at: test_time(),
                revoked_at: None,
            }],
        }
    }

    /// Build one internally complete manifest.
    fn test_manifest() -> OwnershipBackfillManifest {
        let publisher = test_publisher(1, 7);
        OwnershipBackfillManifest {
            schema_version: OWNERSHIP_BACKFILL_SCHEMA_VERSION,
            expected_pack_count: 1,
            expected_version_count: 1,
            publishers: vec![publisher.clone()],
            packs: vec![OwnershipManifestPack {
                name: "mapped-pack".to_string(),
                publisher_id: publisher.id,
                expected_current_author: hex::encode([7_u8; 32]),
            }],
            versions: vec![OwnershipManifestVersion {
                pack_name: "mapped-pack".to_string(),
                version: "1.0.0".to_string(),
                publisher_key_id: publisher.keys[0].id,
                expected_author_pubkey: hex::encode([7_u8; 32]),
                expected_content_hash: hex::encode([9_u8; 32]),
            }],
        }
    }

    /// Empty catalogs accept an exactly empty manifest.
    #[test]
    fn empty_manifest_is_valid() {
        let manifest = OwnershipBackfillManifest {
            schema_version: OWNERSHIP_BACKFILL_SCHEMA_VERSION,
            expected_pack_count: 0,
            expected_version_count: 0,
            publishers: vec![],
            packs: vec![],
            versions: vec![],
        };
        manifest.validate().expect("empty manifest must validate");
    }

    /// Duplicate pack identities are rejected before any database work.
    #[test]
    fn duplicate_pack_mapping_is_rejected() {
        let mut manifest = test_manifest();
        manifest.expected_pack_count = 2;
        manifest.packs.push(manifest.packs[0].clone());
        let error = manifest
            .validate()
            .expect_err("duplicate pack must be rejected");
        assert!(error.to_string().contains("duplicate pack mapping"));
    }

    /// A version cannot point at a key owned by another publisher.
    #[test]
    fn cross_publisher_version_key_is_rejected() {
        let mut manifest = test_manifest();
        let second = test_publisher(2, 8);
        manifest.publishers.push(second.clone());
        manifest.versions[0].publisher_key_id = second.keys[0].id;
        manifest.versions[0].expected_author_pubkey = second.keys[0].public_key.clone();
        let error = manifest
            .validate()
            .expect_err("cross-publisher key must be rejected");
        assert!(error.to_string().contains("key belongs to publisher"));
    }

    /// Exact expected counts must agree with the manifest census.
    #[test]
    fn incorrect_manifest_census_is_rejected() {
        let mut manifest = test_manifest();
        manifest.expected_version_count = 2;
        let error = manifest
            .validate()
            .expect_err("count mismatch must be rejected");
        assert!(error.to_string().contains("expected_version_count"));
    }

    /// Current pack signers must be exact mapped publisher keys.
    #[test]
    fn unmapped_current_author_is_rejected() {
        let mut manifest = test_manifest();
        manifest.packs[0].expected_current_author = hex::encode([11_u8; 32]);
        let error = manifest
            .validate()
            .expect_err("unmapped current author must be rejected");
        assert!(error.to_string().contains("not a mapped publisher key"));
    }

    /// Publishers without mapped catalog rows cannot be bootstrapped by backfill.
    #[test]
    fn unreferenced_publisher_is_rejected() {
        let mut manifest = test_manifest();
        manifest.publishers.push(test_publisher(2, 8));
        let error = manifest
            .validate()
            .expect_err("unreferenced publisher must be rejected");
        assert!(error
            .to_string()
            .contains("not referenced by any mapped pack"));
    }

    /// Structurally valid manifests can census an existing unused rotation key.
    #[test]
    fn unreferenced_publisher_key_is_structurally_valid() {
        let mut manifest = test_manifest();
        manifest.publishers[0].keys.push(OwnershipManifestKey {
            id: Uuid::from_u128(999),
            public_key: hex::encode([8_u8; 32]),
            label: "unused key".to_string(),
            state: OwnershipManifestKeyState::Active,
            created_at: test_time(),
            revoked_at: None,
        });
        manifest
            .validate()
            .expect("existing unused key must remain representable");
    }

    /// Revoked key metadata must carry a revocation timestamp.
    #[test]
    fn inconsistent_key_state_is_rejected() {
        let mut manifest = test_manifest();
        manifest.publishers[0].keys[0].state = OwnershipManifestKeyState::Revoked;
        let error = manifest
            .validate()
            .expect_err("revoked key without timestamp must be rejected");
        assert!(error.to_string().contains("inconsistent state"));
    }

    /// A revoked key cannot predate its own enrollment.
    #[test]
    fn revocation_before_creation_is_rejected() {
        let mut manifest = test_manifest();
        manifest.publishers[0].keys[0].state = OwnershipManifestKeyState::Revoked;
        manifest.publishers[0].keys[0].revoked_at = DateTime::from_timestamp(1_699_999_999, 0);
        let error = manifest
            .validate()
            .expect_err("revocation before creation must be rejected");
        assert!(error.to_string().contains("revoked before it was created"));
    }

    /// Apply mode confirms the digest of exact input bytes inside the core API.
    #[test]
    fn apply_confirmation_is_bound_to_exact_manifest_bytes() {
        let bytes = serde_json::to_vec(&test_manifest()).expect("manifest must serialize");
        let digest = hex::encode(Sha256::digest(&bytes));
        prepare_operator_input(&bytes, Some(&digest), OwnershipBackfillMode::Apply)
            .expect("exact digest must pass");

        let missing = prepare_operator_input(&bytes, None, OwnershipBackfillMode::Apply)
            .expect_err("missing apply confirmation must fail");
        assert!(matches!(
            missing,
            OwnershipBackfillError::MissingConfirmation
        ));

        let mismatch =
            prepare_operator_input(&bytes, Some(&"0".repeat(64)), OwnershipBackfillMode::Apply)
                .expect_err("mismatched apply confirmation must fail");
        assert!(matches!(
            mismatch,
            OwnershipBackfillError::ConfirmationMismatch
        ));

        let unexpected =
            prepare_operator_input(&bytes, Some(&digest), OwnershipBackfillMode::DryRun)
                .expect_err("dry-run confirmation must fail");
        assert!(matches!(
            unexpected,
            OwnershipBackfillError::UnexpectedConfirmation
        ));
    }
}
