//! Mock [`CatalogBackend`] implementation for integration tests.
//!
//! [`MockCatalog`] holds fake data in `Arc<RwLock<...>>` maps so that tests
//! can pre-populate records and assert on the exact responses the handlers
//! produce without touching a real database.
//!
//! # Conflict injection
//!
//! Set `inject_conflict = true` on the inner state to make the next
//! `register_author` call return `CatalogError::Conflict`. This lets tests
//! verify that the handler maps `409` correctly.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::Utc;

use frameshift_catalog::backend::CatalogBackend;
use frameshift_catalog::error::{CatalogError, HealthStatus};
use frameshift_catalog::filters::{PackSearchFilters, PackSearchResult};
use frameshift_catalog::identity::Ed25519PublicKey;
use frameshift_catalog::records::{AuthorRecord, PackRecord, PackVersionRecord};
use frameshift_catalog::status::TombstoneRecord;

/// Shared mutable state for [`MockCatalog`].
///
/// Wrapped in `Arc<RwLock<MockState>>` so that the catalog can be cloned
/// cheaply and mutated from test setup code.
#[derive(Default)]
pub struct MockState {
    /// Registered authors, keyed by base64url-encoded pubkey.
    pub authors: HashMap<String, AuthorRecord>,

    /// Handle -> current owner pubkey mapping (the publish authority).
    ///
    /// `set_handle_pubkey` writes here and `get_handle_pubkey` reads here first,
    /// so handle key rotation is observable in tests. When a handle is absent
    /// from this map, `get_handle_pubkey` falls back to scanning `authors` by
    /// handle (the pre-rotation registration path).
    pub handles: HashMap<String, Ed25519PublicKey>,

    /// Top-level pack records, keyed by pack name.
    pub packs: HashMap<String, PackRecord>,

    /// Pack version records, keyed by `(pack_name, version)`.
    pub versions: HashMap<(String, String), PackVersionRecord>,

    /// When `true`, the next mutating call returns `CatalogError::Conflict`.
    pub inject_conflict: bool,
}

/// In-memory [`CatalogBackend`] for integration tests.
///
/// Pre-populate `state` before passing the catalog to [`crate::router::app`]:
///
/// ```rust,ignore
/// let state = Arc::new(RwLock::new(MockState::default()));
/// // ... insert records ...
/// let catalog = MockCatalog { state };
/// ```
#[derive(Clone)]
pub struct MockCatalog {
    /// The shared mutable fake catalog state.
    pub state: Arc<RwLock<MockState>>,
}

impl MockCatalog {
    /// Create an empty [`MockCatalog`] with no pre-populated records.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(MockState::default())),
        }
    }
}

impl Default for MockCatalog {
    /// Returns an empty [`MockCatalog`].
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CatalogBackend for MockCatalog {
    /// Register an author, enforcing the trait's uniqueness contract.
    ///
    /// - identical `(pubkey, handle)` -> idempotent `Ok(())`.
    /// - handle owned by a different pubkey -> `HandleTaken`.
    /// - pubkey already registered under a different handle -> `Conflict`.
    /// - `inject_conflict` flag -> forced `Conflict` (legacy test hook).
    async fn register_author(&self, record: AuthorRecord) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        if state.inject_conflict {
            state.inject_conflict = false;
            return Err(CatalogError::Conflict {
                kind: "author",
                key: record.handle.clone(),
            });
        }
        // Handle owned by a different key?
        if let Some(existing) = state.authors.values().find(|a| a.handle == record.handle) {
            if existing.pubkey != record.pubkey {
                return Err(CatalogError::HandleTaken {
                    owner: existing.pubkey,
                });
            }
        }
        let key = record.pubkey.to_string();
        // Pubkey already registered under a different handle?
        if let Some(existing) = state.authors.get(&key) {
            if existing.handle != record.handle {
                return Err(CatalogError::Conflict {
                    kind: "author",
                    key: record.pubkey.to_string(),
                });
            }
            // Identical (pubkey, handle): idempotent no-op.
            return Ok(());
        }
        state.authors.insert(key, record);
        Ok(())
    }

    /// Look up an author by public key.
    async fn lookup_author(&self, pubkey: &Ed25519PublicKey) -> Result<AuthorRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        let key = pubkey.to_string();
        state
            .authors
            .get(&key)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "author",
                key,
            })
    }

    /// Look up an author by handle.
    async fn lookup_author_by_handle(&self, handle: &str) -> Result<AuthorRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        state
            .authors
            .values()
            .find(|a| a.handle == handle)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "author",
                key: handle.to_string(),
            })
    }

    /// List authors (returns all stored authors, ignoring pagination).
    async fn list_authors(
        &self,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<AuthorRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        Ok(state.authors.values().cloned().collect())
    }

    /// Register a pack version.
    async fn register_pack_version(&self, record: PackVersionRecord) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        let k = (record.pack_name.clone(), record.version.clone());
        state.versions.insert(k, record);
        Ok(())
    }

    /// Get the top-level pack record.
    async fn get_pack(&self, name: &str) -> Result<PackRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        state
            .packs
            .get(name)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "pack",
                key: name.to_string(),
            })
    }

    /// Get a specific pack version record.
    async fn get_pack_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<PackVersionRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        let k = (name.to_string(), version.to_string());
        state
            .versions
            .get(&k)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "pack_version",
                key: format!("{name}@{version}"),
            })
    }

    /// List all versions for a pack.
    async fn list_pack_versions(&self, name: &str) -> Result<Vec<PackVersionRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        if !state.packs.contains_key(name) {
            return Err(CatalogError::NotFound {
                kind: "pack",
                key: name.to_string(),
            });
        }
        let versions: Vec<_> = state
            .versions
            .values()
            .filter(|v| v.pack_name == name)
            .cloned()
            .collect();
        Ok(versions)
    }

    /// Search packs (returns all stored packs with score 1.0, ignoring filters).
    async fn search_packs(
        &self,
        _filters: &PackSearchFilters,
    ) -> Result<Vec<PackSearchResult>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        let results = state
            .packs
            .values()
            .cloned()
            .map(|pack| PackSearchResult { pack, score: 1.0 })
            .collect();
        Ok(results)
    }

    /// Increment download counter (no-op in mock).
    async fn increment_download_counter(
        &self,
        _name: &str,
        _version: &str,
    ) -> Result<u64, CatalogError> {
        Ok(0)
    }

    /// Tombstone a pack version (no-op in mock).
    async fn tombstone_pack(
        &self,
        _name: &str,
        _version: &str,
        _record: TombstoneRecord,
    ) -> Result<(), CatalogError> {
        Ok(())
    }

    /// Get the public key for a handle.
    ///
    /// Reads the `handles` map first (so rotation via `set_handle_pubkey` is
    /// reflected), then falls back to scanning `authors` by handle for setups
    /// that only pre-populated author records.
    async fn get_handle_pubkey(&self, handle: &str) -> Result<Ed25519PublicKey, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        if let Some(pubkey) = state.handles.get(handle) {
            return Ok(*pubkey);
        }
        state
            .authors
            .values()
            .find(|a| a.handle == handle)
            .map(|a| a.pubkey)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "handle",
                key: handle.to_string(),
            })
    }

    /// Set the public key for a handle (writes the `handles` map).
    async fn set_handle_pubkey(
        &self,
        handle: &str,
        pubkey: Ed25519PublicKey,
    ) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        state.handles.insert(handle.to_string(), pubkey);
        Ok(())
    }

    /// Report healthy.
    async fn health(&self) -> Result<HealthStatus, CatalogError> {
        Ok(HealthStatus {
            healthy: true,
            detail: "mock catalog is always healthy".to_string(),
        })
    }

    /// Set the `extends` field on the pack head record.
    ///
    /// Errors with `NotFound` if the pack is absent; otherwise mutates the
    /// in-memory record in place.
    async fn set_pack_extends(
        &self,
        pack_name: &str,
        extends: Option<&str>,
    ) -> Result<(), CatalogError> {
        let mut state = self.state.write().unwrap();
        match state.packs.get_mut(pack_name) {
            Some(rec) => {
                rec.extends = extends.map(str::to_string);
                Ok(())
            }
            None => Err(CatalogError::NotFound {
                kind: "pack",
                key: pack_name.to_string(),
            }),
        }
    }

    /// Set the `description` and `tags` fields on the pack head record.
    ///
    /// Errors with `NotFound` if the pack is absent; otherwise mutates the
    /// in-memory record in place.
    async fn set_pack_metadata(
        &self,
        name: &str,
        description: &str,
        tags: &[String],
    ) -> Result<(), CatalogError> {
        let mut state = self.state.write().unwrap();
        match state.packs.get_mut(name) {
            Some(rec) => {
                rec.description = description.to_string();
                rec.tags = tags.to_vec();
                Ok(())
            }
            None => Err(CatalogError::NotFound {
                kind: "pack",
                key: name.to_string(),
            }),
        }
    }

    /// Record a download for trending. The mock accepts any call and is a no-op
    /// (trending ranking is exercised by the Postgres adapter integration tests).
    async fn record_download(&self, _pack_name: &str, _version: &str) -> Result<(), CatalogError> {
        Ok(())
    }
}

/// Helper: build a minimal [`AuthorRecord`] for test setup.
///
/// `pubkey_bytes` is the raw 32-byte Ed25519 public key. `handle` is the
/// unique author handle. Marked `#[allow(dead_code)]` because each
/// `tests/*.rs` file is a separate test binary and this helper is only
/// referenced by integration.rs.
#[allow(dead_code)]
pub fn make_author(pubkey_bytes: [u8; 32], handle: &str) -> AuthorRecord {
    AuthorRecord {
        pubkey: Ed25519PublicKey(pubkey_bytes),
        handle: handle.to_string(),
        display_name: None,
        created_at: Utc::now(),
        oauth_links: vec![],
    }
}
