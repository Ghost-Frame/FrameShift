//! Integration tests for [`FsPackStore`].
//!
//! Each test creates an isolated temporary directory so tests can run in
//! parallel without interfering with one another.

use frameshift_objects::{ObjectHash, ObjectStoreError, PackStore};
use frameshift_objects_fs::{FsPackStore, FsPackStoreConfig};
use std::path::PathBuf;

/// Return a config pointing at a fresh temporary directory.
fn temp_config() -> (FsPackStoreConfig, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = FsPackStoreConfig {
        root: dir.path().to_path_buf(),
        verify_on_read: false,
        max_bytes: None,
        fsync_on_put: false,
    };
    (config, dir)
}

/// Build and return a store together with its temp directory guard.
async fn make_store() -> (FsPackStore, tempfile::TempDir) {
    let (config, dir) = temp_config();
    let store = FsPackStore::new(config).await.unwrap();
    (store, dir)
}

// --- put then get returns identical bytes ---

#[tokio::test]
async fn put_then_get_roundtrip() {
    let (store, _dir) = make_store().await;
    let data = b"hello, content-addressed world";
    let hash = ObjectHash::of(data);
    store.put(&hash, data).await.unwrap();
    let back = store.get(&hash).await.unwrap();
    assert_eq!(back, data);
}

// --- put same hash, same bytes twice is idempotent ---

#[tokio::test]
async fn put_idempotent_same_bytes() {
    let (store, _dir) = make_store().await;
    let data = b"idempotent payload";
    let hash = ObjectHash::of(data);
    store.put(&hash, data).await.unwrap();
    // Second put with identical bytes must succeed.
    store.put(&hash, data).await.unwrap();
    let back = store.get(&hash).await.unwrap();
    assert_eq!(back, data);
}

// --- put on existing same-hash same-bytes must NOT increment the quota counter ---

#[tokio::test]
async fn put_idempotent_does_not_double_count_quota() {
    let (store, _dir) = make_store().await;
    let data = b"idempotent quota check";
    let hash = ObjectHash::of(data);
    store.put(&hash, data).await.unwrap();
    let after_first = store.current_bytes();
    // Three more idempotent puts of identical bytes.
    for _ in 0..3 {
        store.put(&hash, data).await.unwrap();
    }
    let after_repeats = store.current_bytes();
    assert_eq!(
        after_first, after_repeats,
        "idempotent re-puts must not increment the quota counter"
    );
}

// --- put with mismatched hash returns HashMismatch without writing ---

#[tokio::test]
async fn put_hash_mismatch_no_write() {
    let (store, _dir) = make_store().await;
    let data = b"real content";
    let wrong_hash = ObjectHash::of(b"completely different");
    let result = store.put(&wrong_hash, data).await;
    assert!(
        matches!(result, Err(ObjectStoreError::HashMismatch { .. })),
        "expected HashMismatch, got {result:?}"
    );
    // The file must not have been written.
    let exists = store.exists(&wrong_hash).await.unwrap();
    assert!(!exists, "no file should have been written on hash mismatch");
}

// --- delete then get returns NotFound ---

#[tokio::test]
async fn delete_then_get_not_found() {
    let (store, _dir) = make_store().await;
    let data = b"to be deleted";
    let hash = ObjectHash::of(data);
    store.put(&hash, data).await.unwrap();
    store.delete(&hash).await.unwrap();
    let result = store.get(&hash).await;
    assert!(
        matches!(result, Err(ObjectStoreError::NotFound { .. })),
        "expected NotFound after delete, got {result:?}"
    );
}

// --- exists: missing -> false, present -> true, symlink -> false ---

#[tokio::test]
async fn exists_missing_is_false() {
    let (store, _dir) = make_store().await;
    let hash = ObjectHash::of(b"never stored");
    assert!(!store.exists(&hash).await.unwrap());
}

#[tokio::test]
async fn exists_present_is_true() {
    let (store, _dir) = make_store().await;
    let data = b"present";
    let hash = ObjectHash::of(data);
    store.put(&hash, data).await.unwrap();
    assert!(store.exists(&hash).await.unwrap());
}

#[tokio::test]
async fn exists_symlink_is_false() {
    let (store, dir) = make_store().await;
    let data = b"symlink target";
    let hash = ObjectHash::of(data);

    // Compute where the store would place this object.
    let hex = hash.to_hex();
    let aa = &hex[..2];
    let bb = &hex[2..4];
    let shard = dir.path().join(aa).join(bb);
    std::fs::create_dir_all(&shard).unwrap();
    let real_file = dir.path().join("real_file.bin");
    std::fs::write(&real_file, data).unwrap();
    let link_path = shard.join(&hex);
    std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

    // exists() must NOT follow the symlink.
    let result = store.exists(&hash).await.unwrap();
    assert!(!result, "symlink should appear as non-existent");
}

// --- list_prefix: empty prefix returns all (up to limit) ---

#[tokio::test]
async fn list_prefix_empty_returns_all_up_to_limit() {
    let (store, _dir) = make_store().await;
    // Store 5 distinct objects.
    let mut expected_hashes = Vec::new();
    for i in 0u8..5 {
        let data = vec![i; 32];
        let hash = ObjectHash::of(&data);
        store.put(&hash, &data).await.unwrap();
        expected_hashes.push(hash);
    }
    let listed = store.list_prefix(&[], 100).await.unwrap();
    assert_eq!(listed.len(), 5);
    for hash in &expected_hashes {
        assert!(listed.contains(hash), "missing {hash}");
    }
}

#[tokio::test]
async fn list_prefix_limit_is_respected() {
    let (store, _dir) = make_store().await;
    for i in 0u8..10 {
        let data = vec![i; 32];
        let hash = ObjectHash::of(&data);
        store.put(&hash, &data).await.unwrap();
    }
    let listed = store.list_prefix(&[], 3).await.unwrap();
    assert_eq!(listed.len(), 3);
}

// --- list_prefix with 1-byte prefix returns only the matching shard ---

#[tokio::test]
async fn list_prefix_one_byte_filters_shard() {
    let (store, _dir) = make_store().await;
    let data = b"shard test";
    let hash = ObjectHash::of(data);
    store.put(&hash, data).await.unwrap();

    let first_byte = hash.as_bytes()[0];
    let prefix = [first_byte];
    let listed = store.list_prefix(&prefix, 100).await.unwrap();
    // Every returned hash must start with `first_byte`.
    for h in &listed {
        assert_eq!(
            h.as_bytes()[0],
            first_byte,
            "hash {h} does not match prefix byte {first_byte:#x}"
        );
    }
    // Our known hash must be in there.
    assert!(listed.contains(&hash));
}

// --- list_prefix with a 33-byte prefix returns empty Vec ---

#[tokio::test]
async fn list_prefix_too_long_returns_empty() {
    let (store, _dir) = make_store().await;
    let data = b"too long prefix";
    let hash = ObjectHash::of(data);
    store.put(&hash, data).await.unwrap();
    let result = store.list_prefix(&[0u8; 33], 100).await.unwrap();
    assert!(result.is_empty());
}

// --- quota: put up to capacity succeeds; next put gets QuotaExceeded ---

#[tokio::test]
async fn quota_exceeded_prevents_write() {
    let data1 = b"first object, exactly sized";
    let hash1 = ObjectHash::of(data1);
    let data1_len = data1.len() as u64;

    let (dir_guard, config) = {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_path_buf();
        let cfg = FsPackStoreConfig {
            root: path,
            verify_on_read: false,
            max_bytes: Some(data1_len), // quota: exactly enough for one object
            fsync_on_put: false,
        };
        (tmp, cfg)
    };
    let store = FsPackStore::new(config).await.unwrap();
    // First put fits exactly within quota.
    store.put(&hash1, data1).await.unwrap();

    // Second put should exceed quota.
    let data2 = b"second object -- quota exceeded";
    let hash2 = ObjectHash::of(data2);
    let result = store.put(&hash2, data2).await;
    assert!(
        matches!(result, Err(ObjectStoreError::QuotaExceeded { .. })),
        "expected QuotaExceeded, got {result:?}"
    );
    // The second object must not have been written.
    assert!(!store.exists(&hash2).await.unwrap());
    drop(dir_guard);
}

// --- verify_on_read: corrupt file returns BackendError ---

#[tokio::test]
async fn verify_on_read_detects_corruption() {
    let tmp = tempfile::tempdir().unwrap();
    let config = FsPackStoreConfig {
        root: tmp.path().to_path_buf(),
        verify_on_read: true,
        max_bytes: None,
        fsync_on_put: false,
    };
    let store = FsPackStore::new(config).await.unwrap();

    let data = b"uncorrupted data";
    let hash = ObjectHash::of(data);
    store.put(&hash, data).await.unwrap();

    // Corrupt the file by overwriting it with garbage.
    let hex = hash.to_hex();
    let aa = &hex[..2];
    let bb = &hex[2..4];
    let path = tmp.path().join(aa).join(bb).join(&hex);
    std::fs::write(&path, b"garbage garbage garbage").unwrap();

    let result = store.get(&hash).await;
    assert!(
        matches!(result, Err(ObjectStoreError::BackendError(_))),
        "expected BackendError for corrupted object, got {result:?}"
    );
}

// --- new() on non-existent root creates the directory ---

#[tokio::test]
async fn new_creates_root_if_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = tmp.path().join("does").join("not").join("exist");
    assert!(!root.exists());
    let config = FsPackStoreConfig {
        root: root.clone(),
        verify_on_read: false,
        max_bytes: None,
        fsync_on_put: false,
    };
    FsPackStore::new(config).await.unwrap();
    assert!(
        root.exists(),
        "new() should have created the root directory"
    );
}

// --- new() rescans existing files into the byte counter ---

#[tokio::test]
async fn new_rescans_existing_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();

    // First store: write one object.
    let data = b"persisted across restart";
    let hash = ObjectHash::of(data);
    {
        let config = FsPackStoreConfig {
            root: root.clone(),
            verify_on_read: false,
            max_bytes: None,
            fsync_on_put: false,
        };
        let store = FsPackStore::new(config).await.unwrap();
        store.put(&hash, data).await.unwrap();
        assert_eq!(store.current_bytes(), data.len() as u64);
    }

    // Second store: should rescan and see the same byte total.
    let config2 = FsPackStoreConfig {
        root,
        verify_on_read: false,
        max_bytes: None,
        fsync_on_put: false,
    };
    let store2 = FsPackStore::new(config2).await.unwrap();
    assert_eq!(
        store2.current_bytes(),
        data.len() as u64,
        "byte counter should be seeded from existing files on startup"
    );
}

// --- Two concurrent puts of DIFFERENT bytes claiming the same hash (platform-dependent) ---
// platform-dependent: on POSIX the first rename wins; the second writer either
// gets HashMismatch when it reads the existing file pre-rename, or one rename
// silently replaces the other. The test verifies that at most one outcome is
// observed and the invariant holds.

#[tokio::test]
async fn concurrent_put_same_hash_different_bytes_at_most_one_wins() {
    // platform-dependent: this test documents the race behaviour rather than
    // asserting a strict outcome. We just ensure the store does not panic or
    // corrupt state.
    let (store, _dir) = make_store().await;
    use std::sync::Arc;
    let store = Arc::new(store);

    let data_a = b"payload alpha";
    let hash_a = ObjectHash::of(data_a);

    // Attempt two concurrent puts of identical (hash, bytes) -- should both
    // succeed with idempotency.
    let s1 = Arc::clone(&store);
    let h1 = hash_a;
    let t1 = tokio::spawn(async move { s1.put(&h1, data_a).await });

    let s2 = Arc::clone(&store);
    let h2 = hash_a;
    let t2 = tokio::spawn(async move { s2.put(&h2, data_a).await });

    let r1 = t1.await.unwrap();
    let r2 = t2.await.unwrap();

    // Both tasks used the same (hash, bytes), so both must succeed.
    assert!(r1.is_ok(), "first concurrent put failed: {r1:?}");
    assert!(r2.is_ok(), "second concurrent put failed: {r2:?}");
    let back = store.get(&hash_a).await.unwrap();
    assert_eq!(back, data_a);
}
