//! Pack status and tombstone types.
//!
//! A pack version transitions from [`PackStatus::Active`] to
//! [`PackStatus::Tombstone`] when it is removed from public availability.
//! Tombstoned versions remain in the store (content-addressed retrieval still
//! works by hash) but are excluded from search results unless the caller
//! explicitly opts in.

use chrono::{DateTime, Utc};

/// The publication status of a pack version.
///
/// Variants are serialized with an internal `kind` tag (serde
/// `tag = "kind", rename_all = "kebab-case"`):
///
/// - Active: `{"kind":"active"}`
/// - Tombstone: `{"kind":"tombstone","reason":"author-request","recorded_at":"..."}`
///
/// # Invariants
///
/// Once a version is tombstoned it MUST NOT transition back to `Active`. The
/// catalog backend is responsible for enforcing this in `tombstone_pack`.
///
/// # Usage
///
/// Callers checking whether a version is visible should match on this enum.
/// Search backends SHOULD exclude `Tombstone` versions from results by default.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PackStatus {
    /// The pack version is publicly available.
    Active,

    /// The pack version has been removed from public availability.
    ///
    /// The version record is retained for auditability and content-addressed
    /// retrieval, but search indexers SHOULD exclude it.
    Tombstone {
        /// The reason the version was tombstoned.
        reason: TombstoneReason,
        /// The UTC timestamp when the tombstone was recorded.
        ///
        /// Unix epoch is not used here -- the full `DateTime<Utc>` is stored
        /// so that serialized records are human-readable.
        recorded_at: DateTime<Utc>,
    },
}

/// The reason a pack version was tombstoned.
///
/// The set of reasons is intentionally small and closed. If a new takedown
/// category emerges, add a variant here and update all match arms.
///
/// Serializes as lowercase kebab-case JSON strings:
/// - `AuthorRequest` -> `"author-request"`
/// - `TosViolation` -> `"tos-violation"`
/// - `Dmca` -> `"dmca"`
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TombstoneReason {
    /// The pack author requested removal.
    AuthorRequest,

    /// The pack violated the platform terms of service.
    TosViolation,

    /// The pack was removed in response to a DMCA takedown notice.
    Dmca,
}

/// A record describing when and why a pack version was tombstoned.
///
/// This is passed to [`crate::backend::CatalogBackend::tombstone_pack`] by the
/// caller. The backend stores it and reflects it back in the `Tombstone` variant
/// of [`PackStatus`].
///
/// # Usage
///
/// Build a `TombstoneRecord` with the reason and current UTC time, then pass it
/// to `tombstone_pack`. The backend is responsible for ensuring the transition
/// is idempotent (re-tombstoning with the same reason is a no-op; re-tombstoning
/// with a different reason is a `Conflict`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TombstoneRecord {
    /// The reason for the tombstone.
    pub reason: TombstoneReason,

    /// The UTC timestamp when the tombstone was recorded.
    ///
    /// Callers should pass the current UTC time. Backends MUST persist this
    /// value as-supplied and MUST NOT overwrite it with server time.
    pub recorded_at: DateTime<Utc>,
}

#[cfg(test)]
/// Unit tests for PackStatus and TombstoneReason serde behavior.
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    /// Return a fixed UTC timestamp for use in tests.
    fn fixed_ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()
    }

    #[test]
    /// Active variant serializes to `{"kind":"active"}`.
    fn pack_status_active_serializes_correctly() {
        let json = serde_json::to_string(&PackStatus::Active).expect("serialize");
        assert_eq!(json, r#"{"kind":"active"}"#);
    }

    #[test]
    /// Tombstone variant serializes with kind, reason, and recorded_at fields.
    fn pack_status_tombstone_serializes_correctly() {
        let ts = PackStatus::Tombstone {
            reason: TombstoneReason::AuthorRequest,
            recorded_at: fixed_ts(),
        };
        let json = serde_json::to_string(&ts).expect("serialize");
        assert!(
            json.contains(r#""kind":"tombstone""#),
            "missing kind: {json}"
        );
        assert!(
            json.contains(r#""reason":"author-request""#),
            "missing reason: {json}"
        );
        assert!(json.contains("recorded_at"), "missing recorded_at: {json}");
    }

    #[test]
    /// PackStatus::Active roundtrip locks the `{"kind":"active"}` wire shape.
    fn pack_status_active_roundtrip() {
        let original = PackStatus::Active;
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, r#"{"kind":"active"}"#);
        let back: PackStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, back);
    }

    #[test]
    /// PackStatus::Tombstone roundtrip preserves reason and recorded_at.
    fn pack_status_tombstone_roundtrip() {
        let original = PackStatus::Tombstone {
            reason: TombstoneReason::Dmca,
            recorded_at: fixed_ts(),
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let back: PackStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, back);
    }

    #[test]
    /// TombstoneReason serializes as lowercase kebab-case for every variant.
    fn tombstone_reason_serializes_as_kebab_case() {
        assert_eq!(
            serde_json::to_string(&TombstoneReason::AuthorRequest).expect("serialize"),
            r#""author-request""#
        );
        assert_eq!(
            serde_json::to_string(&TombstoneReason::TosViolation).expect("serialize"),
            r#""tos-violation""#
        );
        assert_eq!(
            serde_json::to_string(&TombstoneReason::Dmca).expect("serialize"),
            r#""dmca""#
        );
    }
}
