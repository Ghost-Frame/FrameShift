//! Quota tracking for the filesystem object store.
//!
//! [`QuotaCounter`] wraps an [`AtomicU64`] so that the running byte total can
//! be observed and mutated from concurrent tasks without locking. On store
//! initialization the counter is seeded by a filesystem scan (see
//! [`QuotaCounter::scan`]); after that every successful `put` increments it
//! and every successful `delete` decrements it.
//!
//! # Accuracy
//!
//! The counter is a best-effort approximation under concurrent writes. Two
//! callers that both pass the quota gate before either commits may together
//! exceed `max_bytes` by up to one object's size. This is documented as an
//! accepted race in the store spec. The invariant that NO partial write
//! becomes observable is upheld regardless.

use std::{
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use frameshift_objects::ObjectStoreError;

/// Running byte-total counter for the object store.
///
/// Internally backed by an [`AtomicU64`] so all operations are lock-free.
/// The counter represents the sum of the on-disk sizes of all stored objects
/// as last seen by the running process. It is seeded by [`QuotaCounter::scan`]
/// on store initialization and updated by callers after each mutation.
pub struct QuotaCounter {
    /// Current total bytes held by the store.
    bytes: AtomicU64,
}

/// Inherent methods for constructing and operating on a [`QuotaCounter`].
impl QuotaCounter {
    /// Create a zeroed counter.
    ///
    /// Call [`QuotaCounter::scan`] immediately after construction to seed the
    /// counter from the existing on-disk tree.
    pub fn new() -> Self {
        Self {
            bytes: AtomicU64::new(0),
        }
    }

    /// Recursively scan `root` and sum the `metadata().len()` of every file
    /// found, seeding the counter with the result.
    ///
    /// Only regular files are counted; directories, symlinks, and other
    /// special files are skipped. The scan is synchronous and intended to be
    /// called once from within `tokio::task::spawn_blocking` during
    /// [`crate::FsPackStore::new`].
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::BackendError`] -- an I/O error was encountered
    ///   while reading the directory tree.
    pub fn scan(root: &Path) -> Result<Self, ObjectStoreError> {
        let total = scan_bytes(root)?;
        Ok(Self {
            bytes: AtomicU64::new(total),
        })
    }

    /// Return the current byte total with `Relaxed` ordering.
    ///
    /// Suitable for informational reads (e.g. the `health()` method).
    /// For quota enforcement use [`QuotaCounter::load`] with `Acquire`.
    pub fn get(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Return the current byte total with `Acquire` ordering.
    ///
    /// Use this when the loaded value will gate a subsequent write to ensure
    /// that any prior `fetch_add` or `fetch_sub` is visible.
    pub fn load(&self) -> u64 {
        self.bytes.load(Ordering::Acquire)
    }

    /// Add `n` bytes to the counter.
    ///
    /// Uses `AcqRel` ordering so that the increment is visible to concurrent
    /// `load` calls after this returns.
    pub fn add(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::AcqRel);
    }

    /// Subtract `n` bytes from the counter.
    ///
    /// Uses `AcqRel` ordering. Saturates at zero to avoid underflow if the
    /// counter is somehow behind the on-disk reality (e.g. manual deletion
    /// outside the store).
    pub fn sub(&self, n: u64) {
        // Use a CAS loop so we can saturate at zero without wrapping.
        loop {
            let current = self.bytes.load(Ordering::Acquire);
            let next = current.saturating_sub(n);
            match self
                .bytes
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(_) => continue,
            }
        }
    }

    /// Check whether adding `additional` bytes would exceed `max_bytes`.
    ///
    /// Returns an error if the quota would be exceeded; returns `Ok(current)`
    /// (the bytes currently in use before the prospective add) otherwise.
    ///
    /// This is a non-atomic read-then-decide: two concurrent callers may both
    /// pass the gate and together exceed the quota by up to one object. This
    /// race is documented in the spec as accepted behaviour.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::QuotaExceeded`] -- `current + additional > max_bytes`.
    pub fn check(&self, additional: u64, max_bytes: u64) -> Result<u64, ObjectStoreError> {
        let current = self.bytes.load(Ordering::Acquire);
        if current.saturating_add(additional) > max_bytes {
            Err(ObjectStoreError::QuotaExceeded {
                used_bytes: current,
                max_bytes,
            })
        } else {
            Ok(current)
        }
    }
}

/// [`Default`] impl for [`QuotaCounter`]: returns a zeroed counter via [`QuotaCounter::new`].
impl Default for QuotaCounter {
    /// Create a zeroed [`QuotaCounter`]. Equivalent to [`QuotaCounter::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Walk `root` recursively and sum the lengths of all regular files.
///
/// Directories, symlinks, and other non-regular-file entries are skipped
/// silently. Returns `0` if `root` does not exist.
///
/// # Errors
///
/// - [`ObjectStoreError::BackendError`] -- an I/O error occurred while
///   reading any directory entry or its metadata.
fn scan_bytes(root: &Path) -> Result<u64, ObjectStoreError> {
    if !root.exists() {
        return Ok(0);
    }
    let mut total: u64 = 0;
    scan_dir(root, &mut total)?;
    Ok(total)
}

/// Recursively accumulate file sizes starting at `dir`.
///
/// # Errors
///
/// - [`ObjectStoreError::BackendError`] -- an I/O error occurred while
///   reading any directory entry or its metadata.
fn scan_dir(dir: &Path, total: &mut u64) -> Result<(), ObjectStoreError> {
    let read_dir = std::fs::read_dir(dir).map_err(io_err)?;
    for entry in read_dir {
        let entry = entry.map_err(io_err)?;
        let meta = entry.metadata().map_err(io_err)?;
        if meta.is_file() {
            *total = total.saturating_add(meta.len());
        } else if meta.is_dir() {
            scan_dir(&entry.path(), total)?;
        }
        // symlinks and other types are intentionally skipped
    }
    Ok(())
}

/// Convert an [`std::io::Error`] into [`ObjectStoreError::BackendError`].
fn io_err(e: std::io::Error) -> ObjectStoreError {
    ObjectStoreError::BackendError(Box::new(e))
}

#[cfg(test)]
/// Unit tests for [`QuotaCounter`] atomic arithmetic and quota checking.
mod tests {
    use super::*;

    /// New counter starts at zero.
    #[test]
    fn zero_counter() {
        let c = QuotaCounter::new();
        assert_eq!(c.get(), 0);
    }

    /// `add` increments and `sub` decrements the counter correctly.
    #[test]
    fn add_and_sub() {
        let c = QuotaCounter::new();
        c.add(100);
        assert_eq!(c.get(), 100);
        c.sub(40);
        assert_eq!(c.get(), 60);
    }

    /// `sub` saturates at zero rather than wrapping.
    #[test]
    fn sub_saturates_at_zero() {
        let c = QuotaCounter::new();
        c.add(10);
        c.sub(999);
        assert_eq!(c.get(), 0);
    }

    /// `check` returns Ok when the prospective total fits within the quota.
    #[test]
    fn check_passes_when_under_quota() {
        let c = QuotaCounter::new();
        c.add(500);
        assert!(c.check(100, 1000).is_ok());
    }

    /// `check` returns `QuotaExceeded` when the prospective total exceeds max.
    #[test]
    fn check_fails_when_over_quota() {
        let c = QuotaCounter::new();
        c.add(900);
        let err = c.check(200, 1000).unwrap_err();
        assert!(matches!(
            err,
            ObjectStoreError::QuotaExceeded {
                used_bytes: 900,
                max_bytes: 1000
            }
        ));
    }
}
