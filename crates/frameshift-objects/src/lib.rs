//! Content-addressed pack object store trait and canonical types.
//!
//! This crate defines the [`PackStore`] async trait and the supporting types
//! ([`ObjectStoreError`], [`ObjectStoreHealth`]) used by all frameshift
//! object-store adapters. It contains no I/O, no async runtime initialization,
//! and no filesystem or network code -- only the public contract.
//!
//! # Object addressing
//!
//! Objects are addressed by [`ObjectHash`], which is re-exported from
//! `frameshift-pack`. This re-export ensures that every layer of the workspace
//! (packing, signing, catalog, and object stores) agrees on the same type and
//! the same bytes-to-hash function (SHA-256).
//!
//! # Usage
//!
//! ```rust,ignore
//! use frameshift_objects::{PackStore, ObjectHash, ObjectStoreError};
//! use std::sync::Arc;
//!
//! async fn store_bytes(store: &Arc<dyn PackStore>, data: &[u8]) {
//!     let hash = ObjectHash::of(data);
//!     store.put(&hash, data).await.expect("store succeeded");
//! }
//! ```
//!
//! # Adapter crates
//!
//! Concrete implementations live in sibling crates (e.g.
//! `frameshift-objects-fs` for the filesystem adapter). This crate only
//! defines the interface.

mod error;
mod health;
mod store;

/// Re-export of [`frameshift_pack::ObjectHash`].
///
/// Single source of truth for the 32-byte SHA-256 content-addressing hash
/// used across the frameshift workspace. All adapters and callers should
/// import [`ObjectHash`] from this crate to avoid version skew.
pub use frameshift_pack::ObjectHash;

pub use error::ObjectStoreError;
pub use health::ObjectStoreHealth;
pub use store::PackStore;

#[cfg(test)]
mod tests {
    use super::*;

    // --- ObjectStoreError Display tests ---

    #[test]
    fn error_not_found_display() {
        let hash = ObjectHash::of(b"not-here");
        let e = ObjectStoreError::NotFound { hash };
        assert!(e.to_string().starts_with("object not found:"));
    }

    #[test]
    fn error_already_exists_display() {
        let hash = ObjectHash::of(b"dup");
        let e = ObjectStoreError::AlreadyExists { hash };
        assert!(e.to_string().starts_with("object already exists:"));
    }

    #[test]
    fn error_hash_mismatch_display() {
        let expected = ObjectHash::of(b"expected");
        let actual = ObjectHash::of(b"actual");
        let e = ObjectStoreError::HashMismatch { expected, actual };
        let s = e.to_string();
        assert!(s.contains("hash mismatch"), "unexpected: {s}");
        assert!(s.contains("expected"));
        assert!(s.contains("actual"));
    }

    #[test]
    fn error_backend_error_display() {
        let inner: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("disk full"));
        let e = ObjectStoreError::BackendError(inner);
        assert!(e.to_string().contains("backend error"));
    }

    #[test]
    fn error_quota_exceeded_display() {
        let e = ObjectStoreError::QuotaExceeded {
            used_bytes: 900,
            max_bytes: 1000,
        };
        let s = e.to_string();
        assert!(s.contains("quota exceeded"), "unexpected: {s}");
        assert!(s.contains("900"));
        assert!(s.contains("1000"));
    }

    // --- ObjectStoreHealth construction and Debug ---

    #[test]
    fn health_constructs_and_debugs() {
        let h = ObjectStoreHealth {
            healthy: true,
            total_objects: Some(0),
            total_bytes: Some(0),
            detail: "fresh".into(),
        };
        assert!(h.healthy);
        assert_eq!(h.total_objects, Some(0));
        assert_eq!(h.total_bytes, Some(0));
        assert_eq!(h.detail, "fresh");
        // Debug should not panic and should include the healthy field.
        let debug = format!("{h:?}");
        assert!(debug.contains("healthy: true"), "debug was: {debug}");
    }

    #[test]
    fn health_none_counters() {
        // Adapters that cannot cheaply count should be able to return None.
        let h = ObjectStoreHealth {
            healthy: false,
            total_objects: None,
            total_bytes: None,
            detail: "connection pool exhausted".into(),
        };
        assert!(!h.healthy);
        assert!(h.total_objects.is_none());
        assert!(h.total_bytes.is_none());
    }
}
