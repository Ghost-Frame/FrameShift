//! Catalog record types.
//!
//! These structs represent the canonical data shapes stored and returned by
//! [`crate::backend::CatalogBackend`] implementations. They are plain Rust
//! types with serde derives -- no database-specific code or annotations.

use chrono::{DateTime, Utc};

use crate::identity::Ed25519PublicKey;
use crate::status::PackStatus;
use frameshift_pack::ObjectHash;

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
///   and is updated atomically when a new version is registered.
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

    /// Tags associated with this pack for search and discovery.
    ///
    /// Example: `["roleplay", "assistant", "creative"]`.
    pub tags: Vec<String>,

    /// Short human-readable description of the pack's purpose.
    pub description: String,

    /// UTC timestamp when this pack was first created in the catalog.
    pub created_at: DateTime<Utc>,

    /// The semver string of the most-recently published version.
    ///
    /// `None` until the first version is registered. Updated atomically by
    /// `register_pack_version`.
    pub latest_version: Option<String>,

    /// Cumulative download count across all versions of this pack.
    ///
    /// Incremented by [`crate::backend::CatalogBackend::increment_download_counter`].
    /// Never decremented.
    pub total_downloads: u64,
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
