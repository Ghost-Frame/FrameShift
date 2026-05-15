//! Mock [`PackStore`] implementation for integration tests.
//!
//! [`MockPackStore`] holds blobs in an in-memory `HashMap<ObjectHash, Vec<u8>>`
//! behind an `Arc<RwLock<...>>`. Tests pre-populate the store and verify that
//! the download handler retrieves the correct bytes, or that a missing blob
//! causes a `502 Bad Gateway` response.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use frameshift_objects::{ObjectHash, ObjectStoreError, ObjectStoreHealth, PackStore};

/// In-memory [`PackStore`] for integration tests.
///
/// Pre-populate the store by calling [`MockPackStore::insert`] before wiring
/// it into the router:
///
/// ```rust,ignore
/// let store = MockPackStore::new();
/// let hash = ObjectHash::of(b"bytes");
/// store.insert(hash, b"bytes".to_vec());
/// ```
#[derive(Clone)]
pub struct MockPackStore {
    /// In-memory blob storage, keyed by content hash.
    pub blobs: Arc<RwLock<HashMap<ObjectHash, Vec<u8>>>>,
}

impl MockPackStore {
    /// Create an empty [`MockPackStore`] with no pre-populated blobs.
    pub fn new() -> Self {
        Self {
            blobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Insert a blob into the store under `hash`.
    ///
    /// No hash verification is performed here; test code is trusted to supply
    /// consistent (hash, bytes) pairs.
    pub fn insert(&self, hash: ObjectHash, bytes: Vec<u8>) {
        self.blobs
            .write()
            .expect("MockPackStore lock poisoned")
            .insert(hash, bytes);
    }
}

impl Default for MockPackStore {
    /// Returns an empty [`MockPackStore`].
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PackStore for MockPackStore {
    /// Store `bytes` under `hash`.
    ///
    /// No hash verification in the mock; test code controls correctness.
    async fn put(&self, hash: &ObjectHash, bytes: &[u8]) -> Result<(), ObjectStoreError> {
        self.blobs
            .write()
            .map_err(|e| ObjectStoreError::BackendError(e.to_string().into()))?
            .insert(*hash, bytes.to_vec());
        Ok(())
    }

    /// Retrieve the bytes stored under `hash`, or `NotFound` if absent.
    async fn get(&self, hash: &ObjectHash) -> Result<Vec<u8>, ObjectStoreError> {
        self.blobs
            .read()
            .map_err(|e| ObjectStoreError::BackendError(e.to_string().into()))?
            .get(hash)
            .cloned()
            .ok_or_else(|| ObjectStoreError::NotFound { hash: *hash })
    }

    /// Return `true` if a blob exists for `hash`.
    async fn exists(&self, hash: &ObjectHash) -> Result<bool, ObjectStoreError> {
        Ok(self
            .blobs
            .read()
            .map_err(|e| ObjectStoreError::BackendError(e.to_string().into()))?
            .contains_key(hash))
    }

    /// Remove the blob at `hash`, or return `NotFound` if absent.
    async fn delete(&self, hash: &ObjectHash) -> Result<(), ObjectStoreError> {
        let removed = self
            .blobs
            .write()
            .map_err(|e| ObjectStoreError::BackendError(e.to_string().into()))?
            .remove(hash);
        if removed.is_none() {
            return Err(ObjectStoreError::NotFound { hash: *hash });
        }
        Ok(())
    }

    /// List hashes whose bytes begin with `prefix`, up to `limit`.
    async fn list_prefix(
        &self,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<ObjectHash>, ObjectStoreError> {
        let guard = self
            .blobs
            .read()
            .map_err(|e| ObjectStoreError::BackendError(e.to_string().into()))?;
        let results = guard
            .keys()
            .filter(|h| h.as_bytes().starts_with(prefix))
            .take(limit)
            .copied()
            .collect();
        Ok(results)
    }

    /// Report healthy.
    async fn health(&self) -> Result<ObjectStoreHealth, ObjectStoreError> {
        let count = self
            .blobs
            .read()
            .map_err(|e| ObjectStoreError::BackendError(e.to_string().into()))?
            .len() as u64;
        Ok(ObjectStoreHealth {
            healthy: true,
            total_objects: Some(count),
            total_bytes: None,
            detail: "mock object store is always healthy".to_string(),
        })
    }
}
