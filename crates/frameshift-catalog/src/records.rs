//! Catalog record types.
//!
//! These structs represent the canonical data shapes stored and returned by
//! [`crate::backend::CatalogBackend`] implementations. They are plain Rust
//! types with serde derives -- no database-specific code or annotations.

use chrono::{DateTime, Utc};

use crate::identity::Ed25519PublicKey;
use crate::status::PackStatus;
use frameshift_pack::ObjectHash;
use uuid::Uuid;

/// Lifecycle state for an OIDC-backed FrameShift account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// The account may authenticate and perform authorized operations.
    Active,
    /// The account is temporarily denied access by an operator action.
    Suspended,
    /// The account is permanently disabled while its audit history is retained.
    Disabled,
}

/// A user account identified by an exact OIDC issuer and subject pair.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountRecord {
    /// Internal stable account identifier.
    pub id: Uuid,
    /// Canonical OIDC issuer URL from the validated token.
    pub issuer: String,
    /// Issuer-scoped OIDC subject identifier from the validated token.
    pub subject: String,
    /// Optional email claim retained only as mutable profile metadata.
    pub email: Option<String>,
    /// Optional user-selected display name.
    pub display_name: Option<String>,
    /// Current account lifecycle state.
    pub status: AccountStatus,
    /// UTC timestamp when the account was created.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of the most recent account update.
    pub updated_at: DateTime<Utc>,
}

/// Moderation state for a public publisher profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherModerationStatus {
    /// The profile exists but public publication still requires review.
    Pending,
    /// The profile is approved for the configured publication policy.
    Approved,
    /// The profile is temporarily prevented from publishing.
    Suspended,
    /// The profile was rejected but remains available to the audit trail.
    Rejected,
}

/// Public identity and moderation state for an artifact publisher.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublisherProfileRecord {
    /// Internal stable publisher identifier.
    pub id: Uuid,
    /// Unique lowercase public handle.
    pub handle: String,
    /// Public publisher display name.
    pub display_name: String,
    /// Optional bounded public biography.
    pub biography: Option<String>,
    /// Current moderation state.
    pub moderation_status: PublisherModerationStatus,
    /// UTC timestamp when the profile was created.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of the most recent profile update.
    pub updated_at: DateTime<Utc>,
}

/// Authorization role assigned through a publisher membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherRole {
    /// Full publisher ownership authority.
    Owner,
}

/// Lifecycle state for a publisher membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    /// The account currently holds the membership role.
    Active,
    /// The membership has been revoked but remains auditable.
    Revoked,
}

/// An account's role within one publisher profile.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublisherMembershipRecord {
    /// Account holding the membership.
    pub account_id: Uuid,
    /// Publisher to which the membership grants access.
    pub publisher_id: Uuid,
    /// Authorization role held by the account.
    pub role: PublisherRole,
    /// Current membership lifecycle state.
    pub state: MembershipState,
    /// UTC timestamp when the membership was created.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of the most recent membership update.
    pub updated_at: DateTime<Utc>,
}

/// Lifecycle state for an enrolled publisher signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherKeyState {
    /// The key may authorize new publisher writes.
    Active,
    /// The key may verify historical evidence but cannot authorize new writes.
    Revoked,
}

/// A public Ed25519 key enrolled to a publisher profile.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublisherKeyRecord {
    /// Internal stable key identifier.
    pub id: Uuid,
    /// Publisher that owns the key.
    pub publisher_id: Uuid,
    /// Raw public key used to verify proof-of-possession and signed requests.
    pub public_key: Ed25519PublicKey,
    /// User-visible device or purpose label.
    pub label: String,
    /// Current key lifecycle state.
    pub state: PublisherKeyState,
    /// UTC timestamp when the key was enrolled.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp when the key was revoked, when applicable.
    pub revoked_at: Option<DateTime<Utc>>,
    /// UTC timestamp of the most recent successful use, when known.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Immutable audit event for security-sensitive publisher operations.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PublisherAuditEventRecord {
    /// Internal stable audit event identifier.
    pub id: Uuid,
    /// Account responsible for the action, when an account initiated it.
    pub actor_account_id: Option<Uuid>,
    /// Publisher affected by the action.
    pub publisher_id: Uuid,
    /// Stable action name suitable for filtering.
    pub action: String,
    /// Optional publisher key affected by the action.
    pub target_key_id: Option<Uuid>,
    /// Optional pack version affected by the action.
    pub target_version: Option<String>,
    /// Request correlation identifier from the HTTP boundary.
    pub request_id: Option<Uuid>,
    /// UTC timestamp when the event was recorded.
    pub created_at: DateTime<Utc>,
    /// Sanitized structured metadata that must not contain credentials.
    pub metadata: serde_json::Value,
}

/// A registered marketplace author.
///
/// Authors are identified by their Ed25519 public key (`pubkey`). The `handle`
/// is a human-readable unique alias that maps to the pubkey. Handles can be
/// updated via [`crate::backend::CatalogBackend::set_handle_pubkey`], but each
/// handle may only point to one key at a time.
///
/// # Invariants
///
/// - `handle` is unique across all `AuthorRecord`s in the catalog.
/// - `display_name` is `None` if the author did not supply one; an empty string
///   MUST NOT be stored (backends reject it with `CatalogError::Validation`).
/// - `oauth_links` may be empty; this is valid and serializes as `[]`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuthorRecord {
    /// The author's Ed25519 public key, used as the primary identifier.
    pub pubkey: Ed25519PublicKey,

    /// The author's unique human-readable handle (e.g. `"alice"`).
    ///
    /// Must be unique within the catalog. Maximum length and allowed characters
    /// are enforced at the HTTP layer, not by this type.
    pub handle: String,

    /// Optional display name chosen by the author.
    ///
    /// `None` means the author did not supply a display name. Empty strings
    /// are rejected at registration time -- callers must pass `None`.
    pub display_name: Option<String>,

    /// UTC timestamp when this author record was first created.
    pub created_at: DateTime<Utc>,

    /// OAuth provider links associated with this author.
    ///
    /// May be empty. Each entry identifies a linked OAuth identity (e.g.
    /// GitHub, Google).
    pub oauth_links: Vec<OauthLink>,
}

/// A linked OAuth identity for an author.
///
/// Records that the author authenticated with `provider` (e.g. `"github"`)
/// using the OAuth subject identifier `subject` (e.g. a numeric user ID).
///
/// # Usage
///
/// `OauthLink` records are informational -- the catalog does not use them for
/// access control. The HTTP layer is responsible for verifying OAuth tokens
/// before creating these records.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OauthLink {
    /// The OAuth provider name (e.g. `"github"`, `"google"`).
    pub provider: String,

    /// The provider-assigned subject identifier for this author.
    ///
    /// Typically a numeric or UUID string that uniquely identifies the user
    /// within the provider's system.
    pub subject: String,

    /// UTC timestamp when the OAuth link was established.
    pub linked_at: DateTime<Utc>,
}

/// Top-level pack record representing a named persona pack in the catalog.
///
/// A `PackRecord` is the mutable "head" entry for a pack -- it tracks the
/// latest published version and the total download count. Immutable version
/// history is stored in [`PackVersionRecord`].
///
/// # Invariants
///
/// - `name` is unique within the catalog.
/// - `latest_version` is `None` until at least one version has been published,
///   is updated atomically when a new version is registered, and is
///   recomputed (possibly back to `None`) whenever a version is tombstoned --
///   see [`crate::backend::CatalogBackend::tombstone_pack`]'s recompute
///   contract.
/// - `total_downloads` is a monotonically increasing counter; it is never
///   decremented even if a version is tombstoned.
/// - `tags` may be empty; duplicates within the vec are discouraged but not
///   enforced at this layer.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PackRecord {
    /// The unique name of this pack (e.g. `"my-persona"`).
    ///
    /// Names are enforced as globally unique by the catalog backend.
    pub name: String,

    /// The public key of the current pack author/owner.
    ///
    /// May differ from the original creator if ownership was transferred.
    pub current_author: Ed25519PublicKey,

    /// Optional publisher profile that owns the pack after identity backfill.
    ///
    /// `None` preserves the legacy author-key ownership path during migration.
    pub publisher_id: Option<Uuid>,

    /// Tags associated with this pack for search and discovery.
    ///
    /// Example: `["roleplay", "assistant", "creative"]`.
    pub tags: Vec<String>,

    /// Short human-readable description of the pack's purpose.
    pub description: String,

    /// UTC timestamp when this pack was first created in the catalog.
    pub created_at: DateTime<Utc>,

    /// The semver string of the newest `PackStatus::Active` version.
    ///
    /// `None` until the first version is registered, and also `None` again if
    /// every version is later tombstoned. Updated atomically by
    /// `register_pack_version` on publish and recomputed by `tombstone_pack`
    /// on takedown (see that method's doc for the recompute contract). This
    /// field, not any per-version status, is what `search_packs` uses to
    /// decide whether a pack is currently installable.
    pub latest_version: Option<String>,

    /// Cumulative download count across all versions of this pack.
    ///
    /// Incremented by [`crate::backend::CatalogBackend::increment_download_counter`].
    /// Never decremented.
    pub total_downloads: u64,

    /// Base persona pack name from the manifest `extends` field.
    ///
    /// `None` for root packs that do not extend another pack.
    /// Format is the raw value from the pack manifest (e.g. `"base@^1.0"`).
    pub extends: Option<String>,
}

/// An immutable record of a specific published version of a pack.
///
/// Each `PackVersionRecord` is an append-only entry. Once registered, a version
/// record is never mutated except to update its `status` field (which can only
/// transition from `Active` to `Tombstone`).
///
/// # Invariants
///
/// - `(pack_name, version)` is unique within the catalog.
/// - `signature` MUST be exactly 64 bytes (Ed25519 signature length). Backends
///   MUST reject registration of records with other lengths with
///   `CatalogError::InvalidArgument`.
/// - `parent_hash` references the `content_hash` of the previous version in
///   the pack's history chain, or `None` for the first version. The catalog
///   does NOT validate that the referenced hash exists -- transparency log
///   infrastructure handles lineage validation.
/// - `schema_version` identifies the pack schema used at publication time,
///   allowing future readers to apply the correct parsing logic.
/// - `status` starts as `PackStatus::Active` and can only be set to
///   `PackStatus::Tombstone` via `tombstone_pack`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PackVersionRecord {
    /// The name of the parent pack this version belongs to.
    pub pack_name: String,

    /// The semver version string for this release (e.g. `"1.2.0"`).
    pub version: String,

    /// The content-addressed hash of the pack's canonical byte content.
    ///
    /// Computed by the pack tooling (SHA-256 of the canonical pack serialization).
    /// Used for content-addressed retrieval from the object store.
    pub content_hash: ObjectHash,

    /// The Ed25519 signature over the canonical pack content.
    ///
    /// Must be exactly 64 bytes. Verified against `author_pubkey` by callers;
    /// the catalog stores it verbatim without re-verifying.
    #[serde(with = "crate::serde_helpers::bytes_as_b64")]
    pub signature: Vec<u8>,

    /// The Ed25519 public key of the author who published this version.
    pub author_pubkey: Ed25519PublicKey,

    /// Optional enrolled publisher key associated with this version.
    ///
    /// Historical `author_pubkey` bytes remain immutable even when this link is set.
    pub publisher_key_id: Option<Uuid>,

    /// The content hash of the previous version in this pack's history chain.
    ///
    /// `None` for the first version of a pack. Subsequent versions SHOULD set
    /// this to the `content_hash` of the previous version to form a verifiable
    /// hash chain. The catalog does NOT enforce that the referenced hash exists.
    pub parent_hash: Option<ObjectHash>,

    /// The capability manifest as a JSON string.
    ///
    /// Describes what capabilities this pack requests (e.g. network access,
    /// file system access). The schema is defined by the pack runtime; the
    /// catalog stores it opaquely.
    pub capability_manifest_json: String,

    /// The schema version of the pack format used at publication time.
    ///
    /// Monotonically increasing integer. Readers use this to select the correct
    /// deserialization path.
    pub schema_version: u32,

    /// The SPDX license identifier for this pack (e.g. `"MIT"`, `"Apache-2.0"`).
    pub license: String,

    /// UTC timestamp when this version was published.
    pub published_at: DateTime<Utc>,

    /// The publication status of this version.
    ///
    /// Starts as `PackStatus::Active`. Can only transition to
    /// `PackStatus::Tombstone` via `tombstone_pack`.
    pub status: PackStatus,

    /// The size of the pack content in bytes.
    ///
    /// Reflects the size of the packed artifact as stored in the object store.
    pub size_bytes: u64,
}

#[cfg(test)]
/// Unit tests for catalog record serde roundtrips.
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    /// OauthLink serde JSON roundtrip preserves all fields.
    fn oauth_link_serde_roundtrip() {
        let link = OauthLink {
            provider: "github".to_string(),
            subject: "12345".to_string(),
            linked_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
        };
        let json = serde_json::to_string(&link).expect("serialize");
        let back: OauthLink = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(link, back);
    }

    #[test]
    /// AuthorRecord with empty oauth_links serializes as `[]` and roundtrips correctly.
    fn author_record_empty_oauth_links_roundtrip() {
        let record = AuthorRecord {
            pubkey: Ed25519PublicKey([0u8; 32]),
            handle: "bob".to_string(),
            display_name: None,
            created_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            oauth_links: vec![],
        };
        let json = serde_json::to_string(&record).expect("serialize");
        assert!(json.contains(r#""oauth_links":[]"#));
        let back: AuthorRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }
}
