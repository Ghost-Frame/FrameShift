//! [`FsPackStore`] -- the filesystem-backed [`PackStore`] implementation.
//!
//! Objects are stored in a two-level content-addressed shard tree rooted at a
//! configurable directory. The layout is:
//!
//! ```text
//! {root}/
//!   {aa}/
//!     {bb}/
//!       {hex}     <- 64-char lowercase hex filename, file contains raw bytes
//! ```
//!
//! where `aa` = first byte of hash as two hex digits, `bb` = second byte, and
//! `hex` is the full 64-character digest.
//!
//! # Atomic writes
//!
//! All `put` operations write to a [`tempfile::NamedTempFile`] created in the
//! same shard directory as the target, then call `persist()` to rename it into
//! place. On POSIX systems `rename(2)` is atomic, so readers always observe
//! either the old file (absent) or the complete new file -- never a partial
//! write.
//!
//! # Concurrency
//!
//! All blocking `std::fs` operations run inside `tokio::task::spawn_blocking`
//! to avoid starving the async executor. Quota enforcement uses an
//! [`AtomicU64`] backed by [`crate::quota::QuotaCounter`] for lock-free
//! read-modify operations.
//!
//! # Platform note
//!
//! Case-insensitive filesystems (e.g. HFS+ on macOS) can theoretically
//! collide on different hex strings that differ only in case. This adapter
//! always writes lowercase hex; mixed-case collisions are not supported and
//! are documented as a known limitation.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
    sync::atomic::AtomicU64,
};

use async_trait::async_trait;
use frameshift_objects::{ObjectHash, ObjectStoreError, ObjectStoreHealth, PackStore};
use tracing::{debug, warn};

use crate::{
    path::{hash_from_filename, object_path, shard_aa, shard_aabb},
    quota::QuotaCounter,
};

/// Configuration for [`FsPackStore`].
///
/// All fields are set at construction time and are immutable for the lifetime
/// of the store. To change configuration, construct a new [`FsPackStore`].
#[derive(Debug, Clone)]
pub struct FsPackStoreConfig {
    /// Root directory for the content-addressed object tree.
    ///
    /// The store creates this directory (and any missing parents) on
    /// initialization if it does not exist.
    pub root: PathBuf,

    /// When `true`, `get()` re-hashes the bytes after reading and returns
    /// [`ObjectStoreError::BackendError`] if the on-disk bytes do not match
    /// the expected hash.
    ///
    /// This guards against silent disk corruption at the cost of one SHA-256
    /// per read. Recommended for production use; optional to allow benchmarking
    /// without the overhead.
    pub verify_on_read: bool,

    /// Maximum total bytes the store may hold across all objects.
    ///
    /// `None` means no quota is enforced. When `Some(n)`, a `put` that would
    /// push the running total past `n` returns
    /// [`ObjectStoreError::QuotaExceeded`] without writing any bytes.
    ///
    /// The quota counter is seeded on startup by a full directory scan and is
    /// updated incrementally after each `put` and `delete`. Under concurrent
    /// puts two callers may simultaneously pass the gate and together exceed the
    /// limit by at most one object's size; this race is accepted and documented.
    pub max_bytes: Option<u64>,

    /// When `true`, `put()` calls `sync_all()` on the tempfile before the
    /// atomic rename and also `sync_all()` on the parent directory after the
    /// rename.
    ///
    /// This ensures durability across power failures at the cost of two
    /// additional `fsync(2)` calls per write. Disable for higher throughput
    /// in scenarios where durability can be provided at a higher layer.
    pub fsync_on_put: bool,
}

/// Filesystem-backed content-addressed object store.
///
/// Implements [`PackStore`] by storing objects in a sharded directory tree
/// under [`FsPackStoreConfig::root`]. Use [`FsPackStore::new`] to construct;
/// use `Arc<FsPackStore>` or `Arc<dyn PackStore>` for shared ownership across
/// async tasks.
///
/// # Thread safety
///
/// `FsPackStore` is `Send + Sync`. The quota counter uses atomic operations;
/// all blocking I/O is wrapped in `tokio::task::spawn_blocking`.
pub struct FsPackStore {
    /// Immutable configuration for this store instance.
    config: FsPackStoreConfig,
    /// Running total of bytes held by this store instance.
    ///
    /// Seeded by a scan on construction; incremented on `put` success;
    /// decremented on `delete` success.
    current_bytes: AtomicU64,
}

/// Inherent methods for [`FsPackStore`]: construction and introspection.
impl FsPackStore {
    /// Create a new [`FsPackStore`] from the given configuration.
    ///
    /// # Procedure
    ///
    /// 1. Create `config.root` (and any missing parents) if it does not exist.
    /// 2. Verify that the root is writable by attempting to create a temporary
    ///    file inside it. Returns [`ObjectStoreError::BackendError`] if the
    ///    directory is not writable.
    /// 3. Scan the existing object tree to seed the running byte counter.
    ///    This scan is synchronous and may be slow on very large stores. A
    ///    sidecar-persisted counter is a noted follow-up improvement.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::BackendError`] -- the root directory could not be
    ///   created, is not writable, or the initial scan failed.
    pub async fn new(config: FsPackStoreConfig) -> Result<Self, ObjectStoreError> {
        let root = config.root.clone();
        let counter = tokio::task::spawn_blocking(move || {
            // Create root if missing.
            std::fs::create_dir_all(&root).map_err(io_err)?;

            // Verify writability: try to create a tempfile in root.
            tempfile::NamedTempFile::new_in(&root).map_err(io_err)?;

            // Seed the byte counter from a recursive scan.
            QuotaCounter::scan(&root)
        })
        .await
        .map_err(join_err)??;

        let bytes = counter.get();
        Ok(Self {
            config,
            current_bytes: AtomicU64::new(bytes),
        })
    }

    /// Return a reference to the store's root directory path.
    pub fn root(&self) -> &Path {
        &self.config.root
    }

    /// Return the current byte total tracked by the running quota counter.
    ///
    /// This is a best-effort snapshot; it may lag slightly under concurrent
    /// mutations.
    pub fn current_bytes(&self) -> u64 {
        use std::sync::atomic::Ordering;
        self.current_bytes.load(Ordering::Relaxed)
    }

    /// Access the quota counter as a [`QuotaCounter`] view.
    ///
    /// [`QuotaCounter`] wraps the raw [`AtomicU64`] with convenience methods
    /// (`add`, `sub`, `check`). This method re-borrows the underlying atomic
    /// using a pointer cast so that `FsPackStore` owns the `AtomicU64` directly
    /// (avoiding a second allocation) while still exposing the richer API.
    fn quota(&self) -> QuotaView<'_> {
        QuotaView {
            inner: &self.current_bytes,
        }
    }
}

/// A borrowed view of the quota `AtomicU64` with `QuotaCounter`-like methods.
///
/// This avoids allocating a separate `QuotaCounter` struct while still giving
/// `store.rs` a clean API for quota operations.
struct QuotaView<'a> {
    /// Reference to the store's quota atomic.
    inner: &'a AtomicU64,
}

/// Quota-operation methods on the borrowed atomic counter view.
impl QuotaView<'_> {
    /// Return current bytes with `Acquire` ordering.
    fn load(&self) -> u64 {
        use std::sync::atomic::Ordering;
        self.inner.load(Ordering::Acquire)
    }

    /// Add `n` bytes with `AcqRel` ordering.
    fn add(&self, n: u64) {
        use std::sync::atomic::Ordering;
        self.inner.fetch_add(n, Ordering::AcqRel);
    }

    /// Subtract `n` bytes with `AcqRel` ordering, saturating at zero.
    fn sub(&self, n: u64) {
        use std::sync::atomic::Ordering;
        loop {
            let current = self.inner.load(Ordering::Acquire);
            let next = current.saturating_sub(n);
            match self
                .inner
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(_) => continue,
            }
        }
    }

    /// Return `QuotaExceeded` if `current + additional > max_bytes`.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::QuotaExceeded`] when the quota would be exceeded.
    fn check(&self, additional: u64, max_bytes: u64) -> Result<(), ObjectStoreError> {
        let current = self.load();
        if current.saturating_add(additional) > max_bytes {
            Err(ObjectStoreError::QuotaExceeded {
                used_bytes: current,
                max_bytes,
            })
        } else {
            Ok(())
        }
    }
}

/// Outcome of the blocking section of [`PackStore::put`].
///
/// Exists so the post-await quota counter update can distinguish a fresh
/// write (counter must increment) from an idempotent hit on an existing
/// matching object (counter must NOT increment, otherwise repeated puts of
/// the same object inflate the byte total and eventually fire spurious
/// [`ObjectStoreError::QuotaExceeded`] returns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PutOutcome {
    /// The bytes were written and persisted via atomic rename.
    Wrote,
    /// The target path already held an object with matching bytes; no write
    /// occurred and the quota counter remains unchanged.
    AlreadyPresent,
}

/// [`PackStore`] implementation for [`FsPackStore`].
///
/// All six trait methods (`put`, `get`, `exists`, `delete`, `list_prefix`,
/// `health`) are implemented here. Each method dispatches blocking filesystem
/// work to `tokio::task::spawn_blocking` and then updates in-memory state
/// (quota counter) after the blocking call returns.
#[async_trait]
impl PackStore for FsPackStore {
    /// Store `bytes` under the content address `hash`.
    ///
    /// # Procedure
    ///
    /// 1. Compute `ObjectHash::of(bytes)` and compare to `hash`. On mismatch,
    ///    return [`ObjectStoreError::HashMismatch`] WITHOUT touching the
    ///    filesystem. This is the verify-on-write invariant.
    /// 2. Resolve the target path `{root}/{aa}/{bb}/{hex}`. If a file already
    ///    exists at that path, read its bytes, compute SHA-256, and compare.
    ///    - Match: return `Ok(())` (idempotent -- same bytes already stored).
    ///    - Mismatch: return [`ObjectStoreError::HashMismatch`] -- adversarial
    ///      input; a different payload is claiming the same hash key.
    /// 3. Check the quota counter. If `max_bytes` is set and the running total
    ///    plus the new object's size would exceed it, return
    ///    [`ObjectStoreError::QuotaExceeded`] without writing.
    /// 4. Create the shard directories (`{root}/{aa}/{bb}/`) if they do not
    ///    exist using `std::fs::create_dir_all`.
    /// 5. Open a [`tempfile::NamedTempFile`] in the SAME shard directory as the
    ///    target. Creating the temp file in the same directory is the critical
    ///    invariant that makes the subsequent rename atomic on POSIX: `rename(2)`
    ///    is atomic only when source and destination are on the same filesystem
    ///    mount, and keeping them in the same directory guarantees this.
    /// 6. Write all bytes to the temp file. If `fsync_on_put` is set, call
    ///    `sync_all()` on the file before renaming to flush data to stable
    ///    storage.
    /// 7. Call `NamedTempFile::persist(&final_path)` to rename the temp file
    ///    over the target. On POSIX this is a single `rename(2)` syscall,
    ///    which is atomic: concurrent readers observe either the previous state
    ///    (absent) or the fully written file -- never a partial write.
    /// 8. If `fsync_on_put` is set, open the parent directory and call
    ///    `sync_all()` on it. This flushes the directory entry to stable storage
    ///    so the rename survives a power failure.
    /// 9. Increment the quota counter by `bytes.len()`.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::HashMismatch`] -- `SHA-256(bytes) != hash`, or an
    ///   existing object at the same path has different content.
    /// - [`ObjectStoreError::QuotaExceeded`] -- writing would exceed `max_bytes`.
    /// - [`ObjectStoreError::BackendError`] -- I/O failure at any step.
    async fn put(&self, hash: &ObjectHash, bytes: &[u8]) -> Result<(), ObjectStoreError> {
        // Step 1: verify-on-write (hash the caller's bytes before any I/O).
        let computed = ObjectHash::of(bytes);
        if computed != *hash {
            return Err(ObjectStoreError::HashMismatch {
                expected: *hash,
                actual: computed,
            });
        }

        // Step 3: quota pre-check (before any I/O).
        let len = bytes.len() as u64;
        if let Some(max) = self.config.max_bytes {
            self.quota().check(len, max)?;
        }

        let final_path = object_path(&self.config.root, hash);
        let bytes_owned = bytes.to_vec();
        let hash_owned = *hash;
        let fsync = self.config.fsync_on_put;

        // All blocking I/O in spawn_blocking.  The closure returns a
        // [`PutOutcome`] so the post-await quota update can distinguish the
        // idempotent-hit branch (no new bytes consumed) from the wrote-bytes
        // branch.  Conflating the two would double-count storage and produce
        // spurious [`ObjectStoreError::QuotaExceeded`] returns after enough
        // idempotent re-puts of an already-stored object.
        let outcome = tokio::task::spawn_blocking(move || {
            // Step 2: idempotency check -- if the file exists, verify its content.
            if let Ok(meta) = std::fs::symlink_metadata(&final_path) {
                if meta.file_type().is_symlink() {
                    // We do not follow symlinks; treat as non-existent to avoid
                    // overwriting through an attacker-controlled symlink.
                    return Err(ObjectStoreError::BackendError(
                        "unexpected symlink at object path".into(),
                    ));
                }
                // Regular file exists -- read and compare.
                let existing = std::fs::read(&final_path).map_err(io_err)?;
                let existing_hash = ObjectHash::of(&existing);
                if existing_hash == hash_owned {
                    debug!(hash = %hash_owned, "put: object already exists, idempotent");
                    return Ok(PutOutcome::AlreadyPresent);
                } else {
                    warn!(
                        hash = %hash_owned,
                        existing_hash = %existing_hash,
                        "put: existing object has different content -- adversarial input"
                    );
                    return Err(ObjectStoreError::HashMismatch {
                        expected: hash_owned,
                        actual: existing_hash,
                    });
                }
            }

            // Step 4: create shard directories.
            let parent = final_path.parent().ok_or_else(|| {
                ObjectStoreError::BackendError("object path has no parent".into())
            })?;
            std::fs::create_dir_all(parent).map_err(io_err)?;

            // Step 5+6: write to a named temp file in the same directory.
            let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(io_err)?;
            tmp.write_all(&bytes_owned).map_err(io_err)?;

            // Step 6 (conditional fsync of data).
            if fsync {
                tmp.as_file().sync_all().map_err(io_err)?;
            }

            // Step 7: atomic rename.
            tmp.persist(&final_path).map_err(|e| io_err(e.error))?;

            // Step 8 (conditional fsync of parent directory entry).
            if fsync {
                let dir = std::fs::File::open(parent).map_err(io_err)?;
                dir.sync_all().map_err(io_err)?;
            }

            Ok::<PutOutcome, ObjectStoreError>(PutOutcome::Wrote)
        })
        .await
        .map_err(join_err)??;

        // Step 9: update quota counter ONLY when bytes were actually written.
        match outcome {
            PutOutcome::Wrote => {
                self.quota().add(len);
                debug!(hash = %hash, bytes = len, "put: object stored");
            }
            PutOutcome::AlreadyPresent => {
                debug!(hash = %hash, "put: object already present, quota unchanged");
            }
        }
        Ok(())
    }

    /// Retrieve the bytes stored under `hash`.
    ///
    /// # Procedure
    ///
    /// 1. Resolve the target path `{root}/{aa}/{bb}/{hex}`.
    /// 2. Read the file. If absent, return [`ObjectStoreError::NotFound`].
    /// 3. If `verify_on_read` is set in the config, compute `SHA-256(bytes)`
    ///    and compare it to `hash`. On mismatch, return
    ///    [`ObjectStoreError::BackendError`] with a message of the form
    ///    `"object corrupted at {path}: expected {hash}, got {computed}"`. This
    ///    guards against silent disk corruption.
    /// 4. Return the raw bytes.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::NotFound`] -- no object file exists at the path.
    /// - [`ObjectStoreError::BackendError`] -- I/O failure, or `verify_on_read`
    ///   is enabled and the stored bytes do not match the key.
    async fn get(&self, hash: &ObjectHash) -> Result<Vec<u8>, ObjectStoreError> {
        let path = object_path(&self.config.root, hash);
        let hash_owned = *hash;
        let verify = self.config.verify_on_read;

        tokio::task::spawn_blocking(move || match std::fs::read(&path) {
            Ok(bytes) => {
                if verify {
                    let computed = ObjectHash::of(&bytes);
                    if computed != hash_owned {
                        return Err(ObjectStoreError::BackendError(
                            format!(
                                "object corrupted at {}: expected {}, got {}",
                                path.display(),
                                hash_owned,
                                computed
                            )
                            .into(),
                        ));
                    }
                }
                Ok(bytes)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ObjectStoreError::NotFound { hash: hash_owned })
            }
            Err(e) => Err(io_err(e)),
        })
        .await
        .map_err(join_err)?
    }

    /// Return `true` if an object exists for `hash`, `false` if not.
    ///
    /// # Procedure
    ///
    /// 1. Resolve the target path `{root}/{aa}/{bb}/{hex}`.
    /// 2. Call `std::fs::symlink_metadata` (does NOT follow symlinks).
    ///    - If the call succeeds and the entry is a regular file: `Ok(true)`.
    ///    - If the call succeeds and the entry is a symlink: `Ok(false)`. Symlinks
    ///      are rejected to prevent an attacker from planting a symlink that
    ///      makes the store believe a non-existent object exists, potentially
    ///      redirecting a subsequent `get` to arbitrary filesystem content.
    ///    - If the call fails with `NotFound`: `Ok(false)`.
    ///    - Any other I/O error: `Err(BackendError(...))`.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::BackendError`] -- an I/O error occurred that was
    ///   not a simple "not found".
    async fn exists(&self, hash: &ObjectHash) -> Result<bool, ObjectStoreError> {
        let path = object_path(&self.config.root, hash);

        tokio::task::spawn_blocking(move || match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                // Reject symlinks to prevent TOCTOU / symlink-following attacks.
                if meta.file_type().is_symlink() {
                    Ok(false)
                } else {
                    Ok(meta.is_file())
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_err(e)),
        })
        .await
        .map_err(join_err)?
    }

    /// Remove the object at `hash` from the store.
    ///
    /// # Procedure
    ///
    /// 1. Resolve the target path `{root}/{aa}/{bb}/{hex}`.
    /// 2. Call `std::fs::remove_file`. If absent, return
    ///    [`ObjectStoreError::NotFound`].
    /// 3. Subtract the deleted file's byte count from the quota counter.
    ///
    /// # Notes
    ///
    /// On POSIX, if another task holds the file open for reading while `delete`
    /// is called, the file remains readable until the last handle closes, but
    /// `exists()` returns `Ok(false)` immediately after the `remove_file` call.
    /// This is standard POSIX unlink semantics and is not a bug.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::NotFound`] -- no object exists at `hash`.
    /// - [`ObjectStoreError::BackendError`] -- an I/O error occurred.
    async fn delete(&self, hash: &ObjectHash) -> Result<(), ObjectStoreError> {
        let path = object_path(&self.config.root, hash);
        let hash_owned = *hash;

        let file_len = tokio::task::spawn_blocking(move || {
            // Read the file size before deleting so we can update the counter.
            let len = match std::fs::metadata(&path) {
                Ok(meta) => meta.len(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(ObjectStoreError::NotFound { hash: hash_owned });
                }
                Err(e) => return Err(io_err(e)),
            };

            match std::fs::remove_file(&path) {
                Ok(()) => Ok(len),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Err(ObjectStoreError::NotFound { hash: hash_owned })
                }
                Err(e) => Err(io_err(e)),
            }
        })
        .await
        .map_err(join_err)??;

        self.quota().sub(file_len);
        debug!(hash = %hash, bytes = file_len, "delete: object removed");
        Ok(())
    }

    /// List object hashes whose byte representation begins with `prefix`.
    ///
    /// # Procedure
    ///
    /// 1. If `prefix.len() > 32`, return `Ok(vec![])` immediately -- no hash
    ///    can match a prefix longer than the hash itself.
    /// 2. Determine which shard directories to walk:
    ///    - `prefix.len() == 0`: walk all `{aa}` subdirectories under `root`.
    ///    - `prefix.len() >= 1`: walk only `{root}/{aa}` for the matching first
    ///      byte, limiting the walk to 1/256 of the tree.
    ///    - `prefix.len() >= 2`: walk only `{root}/{aa}/{bb}` for the matching
    ///      first two bytes, limiting to 1/65536 of the tree.
    /// 3. For each leaf file in the determined shard(s), attempt to parse the
    ///    filename as a 64-hex-character [`ObjectHash`]. Entries that do not
    ///    parse as valid hashes are silently skipped.
    /// 4. Compare the parsed hash's byte representation against `prefix` using
    ///    a byte-slice prefix match. Hashes that do not start with `prefix` are
    ///    skipped.
    /// 5. Accumulate matching hashes up to `limit` and return.
    ///
    /// Shard directories that do not exist are treated as empty (returning no
    /// hashes from that shard), not as errors.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::BackendError`] -- an I/O error occurred while
    ///   reading a directory.
    async fn list_prefix(
        &self,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<ObjectHash>, ObjectStoreError> {
        if prefix.len() > 32 {
            return Ok(vec![]);
        }

        let root = self.config.root.clone();
        let prefix_owned = prefix.to_vec();

        tokio::task::spawn_blocking(move || list_prefix_blocking(&root, &prefix_owned, limit))
            .await
            .map_err(join_err)?
    }

    /// Return a health snapshot for this store.
    ///
    /// # Procedure
    ///
    /// 1. Check that the root directory exists using `std::fs::metadata`.
    /// 2. Attempt to create and immediately drop a [`tempfile::NamedTempFile`]
    ///    in the root to verify writability.
    /// 3. Return [`ObjectStoreHealth`] with the current quota counter values.
    ///    The counters come from the running atomic counter (not a full scan),
    ///    so they are O(1) to compute.
    ///
    /// # Errors
    ///
    /// - [`ObjectStoreError::BackendError`] -- the root directory does not
    ///   exist or is not writable.
    async fn health(&self) -> Result<ObjectStoreHealth, ObjectStoreError> {
        let root = self.config.root.clone();
        let current = self.current_bytes();

        let (healthy, detail) = tokio::task::spawn_blocking(move || {
            // Check existence.
            if !root.exists() {
                return (false, format!("root directory missing: {}", root.display()));
            }
            // Check writability.
            match tempfile::NamedTempFile::new_in(&root) {
                Ok(_) => (true, format!("healthy, root: {}", root.display())),
                Err(e) => (false, format!("root not writable: {e}")),
            }
        })
        .await
        .map_err(join_err)?;

        Ok(ObjectStoreHealth {
            healthy,
            total_objects: None, // would require a scan; use None for O(1) health check
            total_bytes: Some(current),
            detail,
        })
    }
}

/// Synchronous prefix-listing walk, suitable for `spawn_blocking`.
///
/// Walks the relevant shard directories and collects up to `limit` hashes
/// whose bytes begin with `prefix`. Shard directories that do not exist are
/// treated as empty (no error).
///
/// # Errors
///
/// - [`ObjectStoreError::BackendError`] -- a `read_dir` or `DirEntry::metadata`
///   call returned an unexpected I/O error.
fn list_prefix_blocking(
    root: &Path,
    prefix: &[u8],
    limit: usize,
) -> Result<Vec<ObjectHash>, ObjectStoreError> {
    let mut results = Vec::new();

    if prefix.is_empty() {
        // Walk all shards.
        for aa in 0u8..=255 {
            let aa_dir = shard_aa(root, aa);
            if !aa_dir.exists() {
                continue;
            }
            for bb in 0u8..=255 {
                let bb_dir = shard_aabb(root, aa, bb);
                collect_from_dir(&bb_dir, prefix, &mut results, limit)?;
                if results.len() >= limit {
                    return Ok(results);
                }
            }
            if results.len() >= limit {
                return Ok(results);
            }
        }
    } else {
        // First byte is known.
        let aa_dir = shard_aa(root, prefix[0]);
        if prefix.len() >= 2 {
            // First two bytes are known.
            let bb_dir = shard_aabb(root, prefix[0], prefix[1]);
            collect_from_dir(&bb_dir, prefix, &mut results, limit)?;
        } else {
            // Only first byte is known; walk all `bb` sub-shards.
            if aa_dir.exists() {
                for bb in 0u8..=255 {
                    let bb_dir = shard_aabb(root, prefix[0], bb);
                    collect_from_dir(&bb_dir, prefix, &mut results, limit)?;
                    if results.len() >= limit {
                        return Ok(results);
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Collect matching hashes from a single leaf shard directory.
///
/// Reads all entries in `dir`, attempts to parse each filename as a
/// 64-hex [`ObjectHash`], and adds those whose byte representation starts with
/// `prefix` to `results`, stopping when `results.len() >= limit`.
///
/// If `dir` does not exist, returns without error (treated as an empty shard).
///
/// # Errors
///
/// - [`ObjectStoreError::BackendError`] -- a `read_dir` or `DirEntry` call
///   returned an unexpected I/O error.
fn collect_from_dir(
    dir: &Path,
    prefix: &[u8],
    results: &mut Vec<ObjectHash>,
    limit: usize,
) -> Result<(), ObjectStoreError> {
    if results.len() >= limit {
        return Ok(());
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_err(e)),
    };

    for entry in entries {
        let entry = entry.map_err(io_err)?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Some(hash) = hash_from_filename(&name_str) {
            if hash.as_bytes().starts_with(prefix) {
                results.push(hash);
                if results.len() >= limit {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

/// Convert an [`std::io::Error`] into [`ObjectStoreError::BackendError`].
fn io_err(e: std::io::Error) -> ObjectStoreError {
    ObjectStoreError::BackendError(Box::new(e))
}

/// Convert a [`tokio::task::JoinError`] into [`ObjectStoreError::BackendError`].
fn join_err(e: tokio::task::JoinError) -> ObjectStoreError {
    ObjectStoreError::BackendError(Box::new(e))
}
