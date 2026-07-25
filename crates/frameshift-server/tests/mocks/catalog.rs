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
use chrono::{DateTime, Utc};

use frameshift_catalog::backend::CatalogBackend;
use frameshift_catalog::error::{CatalogError, HealthStatus};
use frameshift_catalog::filters::{PackSearchFilters, PackSearchResult};
use frameshift_catalog::identity::Ed25519PublicKey;
use frameshift_catalog::records::{
    AccountRecord, AccountStatus, AuthorRecord, MembershipState, PackRecord, PackVersionRecord,
    PlatformRole, PlatformRoleRecord, PlatformRoleState, PublicationIntentRecord,
    PublicationModerationAction, PublicationModerationDecisionRecord,
    PublicationModerationDecisionRequest, PublicationSubmissionRecord,
    PublicationSubmissionRequest, PublicationSubmissionState, PublisherAuditEventRecord,
    PublisherKeyRecord, PublisherKeyState, PublisherMembershipRecord, PublisherProfileRecord,
    PublisherRole,
};
use frameshift_catalog::status::{PackStatus, TombstoneRecord};
// Reuse the exact same version-precedence comparator the Postgres adapter
// uses for `register_pack_version`'s `latest_version` selection, so the
// mock's tombstone head-recompute can never drift from the real ordering.
use frameshift_catalog::PublishQuota;
use frameshift_catalog_postgres::backend::semver_gt;
use frameshift_pack::ObjectHash;

/// Shared mutable state for [`MockCatalog`].
///
/// Wrapped in `Arc<RwLock<MockState>>` so that the catalog can be cloned
/// cheaply and mutated from test setup code.
#[derive(Default)]
pub struct MockState {
    /// OIDC-backed accounts keyed by internal identifier.
    pub accounts: HashMap<uuid::Uuid, AccountRecord>,

    /// Exact OIDC issuer and subject pairs mapped to account identifiers.
    pub account_subjects: HashMap<(String, String), uuid::Uuid>,

    /// Public publisher profiles keyed by internal identifier.
    pub publishers: HashMap<uuid::Uuid, PublisherProfileRecord>,

    /// Normalized publisher handles mapped to publisher identifiers.
    pub publisher_handles: HashMap<String, uuid::Uuid>,

    /// Account-to-publisher memberships keyed by both identifiers.
    pub publisher_memberships: HashMap<(uuid::Uuid, uuid::Uuid), PublisherMembershipRecord>,

    /// Enrolled publisher keys keyed by internal identifier.
    pub publisher_keys: HashMap<uuid::Uuid, PublisherKeyRecord>,

    /// Immutable publisher security audit events.
    pub publisher_audit_events: Vec<PublisherAuditEventRecord>,

    /// Registered authors, keyed by base64url-encoded pubkey.
    pub authors: HashMap<String, AuthorRecord>,

    /// Handle -> current owner pubkey mapping (the publish authority).
    ///
    /// `set_handle_pubkey` writes here and `get_handle_pubkey` reads here first.
    /// When a handle is absent from this map, `get_handle_pubkey` falls back to
    /// scanning `authors` by handle for compatibility with older fixtures.
    pub handles: HashMap<String, Ed25519PublicKey>,

    /// Top-level pack records, keyed by pack name.
    pub packs: HashMap<String, PackRecord>,

    /// Pack version records, keyed by `(pack_name, version)`.
    pub versions: HashMap<(String, String), PackVersionRecord>,

    /// When `true`, the next mutating call returns `CatalogError::Conflict`.
    pub inject_conflict: bool,

    /// Number of `increment_download_counter` calls per `(pack_name, version)`.
    ///
    /// Tests read this to assert that the cumulative download counter was
    /// incremented after a successful download response.
    pub download_counter_increments: HashMap<(String, String), u64>,

    /// Shared signed-request nonce claims keyed by signer and nonce.
    pub signed_request_nonces: HashMap<(String, String), DateTime<Utc>>,

    /// Publication intents keyed by their caller-generated idempotency identifier.
    pub publication_intents: HashMap<uuid::Uuid, PublicationIntentRecord>,

    /// Quarantined publication submissions keyed by stable identifier.
    pub publication_submissions: HashMap<uuid::Uuid, PublicationSubmissionRecord>,

    /// Global platform-role assignments retained for authorization tests.
    pub platform_roles: Vec<PlatformRoleRecord>,

    /// Immutable publication moderation decisions keyed by stable identifier.
    pub publication_moderation_decisions: HashMap<uuid::Uuid, PublicationModerationDecisionRecord>,

    /// Optional persistent backend failure injected into submission creation.
    pub publication_submission_error: Option<String>,

    /// Whether submission creation enforces the durable intent transaction invariants.
    pub enforce_publication_submission_invariants: bool,
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

/// Constructors for the in-memory catalog test double.
impl MockCatalog {
    /// Create an empty [`MockCatalog`] with no pre-populated records.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(MockState::default())),
        }
    }
}

/// Default construction of an empty mock catalog.
impl Default for MockCatalog {
    /// Returns an empty [`MockCatalog`].
    fn default() -> Self {
        Self::new()
    }
}

/// Validate optional audit records before applying an in-memory mutation.
fn validate_audit(
    event: Option<&PublisherAuditEventRecord>,
    publisher_id: Option<uuid::Uuid>,
) -> Result<(), CatalogError> {
    if event.is_some_and(|event| event.action.trim().is_empty() || !event.metadata.is_object()) {
        return Err(CatalogError::Validation(
            "audit action must be non-blank and metadata must be an object".to_string(),
        ));
    }
    if event
        .zip(publisher_id)
        .is_some_and(|(event, publisher_id)| event.publisher_id != publisher_id)
    {
        return Err(CatalogError::InvalidArgument(
            "audit publisher_id must match the mutated publisher".to_string(),
        ));
    }
    Ok(())
}

#[async_trait]
/// In-memory implementation of every catalog operation used by server tests.
impl CatalogBackend for MockCatalog {
    /// Create an account while enforcing ID and OIDC identity uniqueness.
    async fn create_account(&self, record: AccountRecord) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let identity = (record.issuer.clone(), record.subject.clone());
        if state.accounts.contains_key(&record.id) || state.account_subjects.contains_key(&identity)
        {
            return Err(CatalogError::Conflict {
                kind: "account",
                key: format!("{}#{}", record.issuer, record.subject),
            });
        }
        state.account_subjects.insert(identity, record.id);
        state.accounts.insert(record.id, record);
        Ok(())
    }

    /// Retrieve an account by internal identifier.
    async fn get_account(&self, id: uuid::Uuid) -> Result<AccountRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        state
            .accounts
            .get(&id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account",
                key: id.to_string(),
            })
    }

    /// Retrieve an account by exact OIDC issuer and subject.
    async fn get_account_by_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<AccountRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let identity = (issuer.to_string(), subject.to_string());
        let id = state
            .account_subjects
            .get(&identity)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account",
                key: format!("{issuer}#{subject}"),
            })?;
        state
            .accounts
            .get(id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account",
                key: id.to_string(),
            })
    }

    /// Update mutable account profile fields.
    async fn update_account_profile(
        &self,
        id: uuid::Uuid,
        email: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<AccountRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let account = state
            .accounts
            .get_mut(&id)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account",
                key: id.to_string(),
            })?;
        account.email = email.map(str::to_string);
        account.display_name = display_name.map(str::to_string);
        account.updated_at = Utc::now();
        Ok(account.clone())
    }

    /// Atomically create a publisher and its first owner membership in memory.
    async fn create_publisher(
        &self,
        profile: PublisherProfileRecord,
        owner: PublisherMembershipRecord,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<(), CatalogError> {
        validate_audit(audit.as_ref(), Some(profile.id))?;
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if profile.id != owner.publisher_id || !state.accounts.contains_key(&owner.account_id) {
            return Err(CatalogError::Validation(
                "publisher owner membership is invalid".to_string(),
            ));
        }
        if state.publishers.contains_key(&profile.id)
            || state.publisher_handles.contains_key(&profile.handle)
            || state.handles.contains_key(&profile.handle)
            || state
                .authors
                .values()
                .any(|author| author.handle == profile.handle)
        {
            return Err(CatalogError::Conflict {
                kind: "publisher",
                key: profile.handle,
            });
        }
        state
            .publisher_handles
            .insert(profile.handle.clone(), profile.id);
        state
            .publisher_memberships
            .insert((owner.account_id, owner.publisher_id), owner);
        state.publishers.insert(profile.id, profile);
        if let Some(audit) = audit {
            state.publisher_audit_events.push(audit);
        }
        Ok(())
    }

    /// Retrieve a publisher profile by normalized handle.
    async fn get_publisher_by_handle(
        &self,
        handle: &str,
    ) -> Result<PublisherProfileRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let id = state
            .publisher_handles
            .get(handle)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publisher",
                key: handle.to_string(),
            })?;
        state
            .publishers
            .get(id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publisher",
                key: handle.to_string(),
            })
    }

    /// Retrieve a publisher profile by its stable internal identifier.
    async fn get_publisher(&self, id: uuid::Uuid) -> Result<PublisherProfileRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        state
            .publishers
            .get(&id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publisher",
                key: id.to_string(),
            })
    }

    /// Update mutable publisher profile fields.
    async fn update_publisher_profile(
        &self,
        id: uuid::Uuid,
        display_name: &str,
        biography: Option<&str>,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<PublisherProfileRecord, CatalogError> {
        validate_audit(audit.as_ref(), Some(id))?;
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let publisher = state
            .publishers
            .get_mut(&id)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publisher",
                key: id.to_string(),
            })?;
        publisher.display_name = display_name.to_string();
        publisher.biography = biography.map(str::to_string);
        publisher.updated_at = Utc::now();
        let updated = publisher.clone();
        if let Some(audit) = audit {
            state.publisher_audit_events.push(audit);
        }
        Ok(updated)
    }

    /// List all memberships held by one account.
    async fn list_account_memberships(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<Vec<PublisherMembershipRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let mut records: Vec<_> = state
            .publisher_memberships
            .values()
            .filter(|record| record.account_id == account_id)
            .cloned()
            .collect();
        records.sort_by_key(|record| record.created_at);
        Ok(records)
    }

    /// Retrieve one account-to-publisher membership.
    async fn get_publisher_membership(
        &self,
        account_id: uuid::Uuid,
        publisher_id: uuid::Uuid,
    ) -> Result<PublisherMembershipRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        state
            .publisher_memberships
            .get(&(account_id, publisher_id))
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publisher_membership",
                key: format!("{account_id}:{publisher_id}"),
            })
    }

    /// Enroll a public signing key idempotently while enforcing global uniqueness.
    async fn create_publisher_key(
        &self,
        record: PublisherKeyRecord,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<PublisherKeyRecord, CatalogError> {
        validate_audit(audit.as_ref(), Some(record.publisher_id))?;
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if let Some(existing) = state
            .publisher_keys
            .values()
            .find(|existing| existing.public_key == record.public_key)
        {
            if existing.publisher_id == record.publisher_id
                && existing.state == PublisherKeyState::Active
            {
                return Ok(existing.clone());
            }
            return Err(CatalogError::Conflict {
                kind: "publisher_key",
                key: record.public_key.to_string(),
            });
        }
        if state.publisher_keys.contains_key(&record.id) {
            return Err(CatalogError::Conflict {
                kind: "publisher_key",
                key: record.id.to_string(),
            });
        }
        state.publisher_keys.insert(record.id, record.clone());
        if let Some(audit) = audit {
            state.publisher_audit_events.push(audit);
        }
        Ok(record)
    }

    /// List a publisher's enrolled public keys.
    async fn list_publisher_keys(
        &self,
        publisher_id: uuid::Uuid,
    ) -> Result<Vec<PublisherKeyRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let mut records: Vec<_> = state
            .publisher_keys
            .values()
            .filter(|record| record.publisher_id == publisher_id)
            .cloned()
            .collect();
        records.sort_by_key(|record| record.created_at);
        Ok(records)
    }

    /// Retrieve one enrolled publisher key by stable identifier.
    async fn get_publisher_key(&self, id: uuid::Uuid) -> Result<PublisherKeyRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        state
            .publisher_keys
            .get(&id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publisher_key",
                key: id.to_string(),
            })
    }

    /// Revoke a key unless it is the publisher's last active key.
    async fn revoke_publisher_key(
        &self,
        publisher_id: uuid::Uuid,
        key_id: uuid::Uuid,
        revoked_at: DateTime<Utc>,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<PublisherKeyRecord, CatalogError> {
        validate_audit(audit.as_ref(), Some(publisher_id))?;
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let active_count = state
            .publisher_keys
            .values()
            .filter(|record| {
                record.publisher_id == publisher_id && record.state == PublisherKeyState::Active
            })
            .count();
        let key = state
            .publisher_keys
            .get_mut(&key_id)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publisher_key",
                key: key_id.to_string(),
            })?;
        if key.publisher_id != publisher_id {
            return Err(CatalogError::NotFound {
                kind: "publisher_key",
                key: key_id.to_string(),
            });
        }
        if key.state == PublisherKeyState::Revoked {
            return Ok(key.clone());
        }
        if active_count <= 1 {
            return Err(CatalogError::Validation(
                "cannot revoke the last active publisher key".to_string(),
            ));
        }
        key.state = PublisherKeyState::Revoked;
        key.revoked_at = Some(revoked_at);
        let updated = key.clone();
        if let Some(audit) = audit {
            state.publisher_audit_events.push(audit);
        }
        Ok(updated)
    }

    /// Append an immutable publisher audit event.
    async fn append_publisher_audit_event(
        &self,
        event: PublisherAuditEventRecord,
    ) -> Result<(), CatalogError> {
        validate_audit(Some(&event), None)?;
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        state.publisher_audit_events.push(event);
        Ok(())
    }

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
        if state.publisher_handles.contains_key(&record.handle) {
            return Err(CatalogError::Conflict {
                kind: "author",
                key: record.handle,
            });
        }
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

    /// List authors, paginated by `limit`/`offset` and ordered by
    /// `created_at ASC` for a stable order matching the trait's documented
    /// contract (mirrors the real Postgres backend's `ORDER BY created_at`).
    async fn list_authors(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuthorRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        let mut authors: Vec<AuthorRecord> = state.authors.values().cloned().collect();
        authors.sort_by_key(|a| a.created_at);
        let page = authors
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok(page)
    }

    /// Register a pack version.
    async fn register_pack_version_with_quota(
        &self,
        record: PackVersionRecord,
        quota: PublishQuota,
    ) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        let publisher_id = match record.publisher_key_id {
            Some(key_id) => {
                let key = state.publisher_keys.get(&key_id).ok_or_else(|| {
                    CatalogError::Unauthorized {
                        kind: "publisher_key",
                        key: key_id.to_string(),
                    }
                })?;
                if key.state != PublisherKeyState::Active || key.public_key != record.author_pubkey
                {
                    return Err(CatalogError::Unauthorized {
                        kind: "publisher_key",
                        key: key_id.to_string(),
                    });
                }
                Some(key.publisher_id)
            }
            None => None,
        };
        if publisher_id.is_none() {
            let legacy_author = state
                .authors
                .values()
                .find(|author| author.pubkey == record.author_pubkey)
                .ok_or_else(|| CatalogError::NotFound {
                    kind: "author",
                    key: record.author_pubkey.to_string(),
                })?;
            if state.publisher_handles.contains_key(&legacy_author.handle) {
                return Err(CatalogError::Unauthorized {
                    kind: "publisher",
                    key: legacy_author.handle.clone(),
                });
            }
        }
        if let Some(pack) = state.packs.get(&record.pack_name) {
            let ownership_matches = match (pack.publisher_id, publisher_id) {
                (Some(existing), Some(incoming)) => existing == incoming,
                (None, None) => pack.current_author == record.author_pubkey,
                _ => false,
            };
            if !ownership_matches {
                return Err(CatalogError::Unauthorized {
                    kind: "pack",
                    key: record.pack_name.clone(),
                });
            }
        }
        let publisher_key_ids: Vec<_> = publisher_id
            .map(|publisher_id| {
                state
                    .publisher_keys
                    .values()
                    .filter(|key| key.publisher_id == publisher_id)
                    .map(|key| key.id)
                    .collect()
            })
            .unwrap_or_default();
        let existing: Vec<&PackVersionRecord> = state
            .versions
            .values()
            .filter(|version| {
                if publisher_id.is_some() {
                    version
                        .publisher_key_id
                        .is_some_and(|key_id| publisher_key_ids.contains(&key_id))
                } else {
                    version.author_pubkey == record.author_pubkey
                }
            })
            .collect();
        let next_versions = existing.len() as u64 + 1;
        let next_bytes = existing
            .iter()
            .fold(0u64, |total, version| {
                total.saturating_add(version.size_bytes)
            })
            .saturating_add(record.size_bytes);
        if quota
            .max_versions
            .is_some_and(|limit| next_versions > limit)
        {
            return Err(CatalogError::Validation(
                "publisher version quota exceeded".to_string(),
            ));
        }
        if quota.max_bytes.is_some_and(|limit| next_bytes > limit) {
            return Err(CatalogError::Validation(
                "publisher storage quota exceeded".to_string(),
            ));
        }
        let next_total_bytes = state
            .versions
            .values()
            .fold(record.size_bytes, |total, version| {
                total.saturating_add(version.size_bytes)
            });
        if quota
            .max_total_bytes
            .is_some_and(|limit| next_total_bytes > limit)
        {
            return Err(CatalogError::Validation(
                "registry storage quota exceeded".to_string(),
            ));
        }
        let k = (record.pack_name.clone(), record.version.clone());
        if state.versions.contains_key(&k) {
            return Err(CatalogError::Conflict {
                kind: "pack_version",
                key: format!("{}@{}", record.pack_name, record.version),
            });
        }
        let pack_name = record.pack_name.clone();
        let version = record.version.clone();
        let author_pubkey = record.author_pubkey;
        let publisher_key_id = record.publisher_key_id;
        state.versions.insert(k, record);
        let pack = state
            .packs
            .entry(pack_name.clone())
            .or_insert_with(|| PackRecord {
                name: pack_name,
                current_author: author_pubkey,
                publisher_id,
                tags: Vec::new(),
                description: String::new(),
                created_at: Utc::now(),
                latest_version: None,
                total_downloads: 0,
                extends: None,
            });
        if pack
            .latest_version
            .as_deref()
            .is_none_or(|current| semver_gt(&version, current))
        {
            pack.latest_version = Some(version);
        }
        if let Some(key_id) = publisher_key_id {
            if let Some(key) = state.publisher_keys.get_mut(&key_id) {
                key.last_used_at = Some(Utc::now());
            }
        }
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

    /// Return an active version that references `content_hash`.
    async fn get_active_pack_version_by_hash(
        &self,
        content_hash: &ObjectHash,
    ) -> Result<PackVersionRecord, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        state
            .versions
            .values()
            .find(|record| {
                record.content_hash == *content_hash && matches!(record.status, PackStatus::Active)
            })
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "active_pack_version",
                key: content_hash.to_string(),
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

    /// Search packs (returns stored packs with score 1.0, ignoring filters
    /// other than the tombstone-driven `latest_version` exclusion).
    ///
    /// Mirrors the Postgres adapter's `latest_version IS NOT NULL` predicate:
    /// a pack whose head has zero remaining `Active` versions (recomputed by
    /// `tombstone_pack` to `None`) is excluded from every search result set.
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
            .filter(|pack| pack.latest_version.is_some())
            .cloned()
            .map(|pack| PackSearchResult { pack, score: 1.0 })
            .collect();
        Ok(results)
    }

    /// Increment the download counter for a pack version.
    ///
    /// Records the call in `state.download_counter_increments` so tests can
    /// assert that `download_pack_bytes` actually invoked this method.
    async fn increment_download_counter(
        &self,
        name: &str,
        version: &str,
    ) -> Result<u64, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        let key = (name.to_string(), version.to_string());
        let count = state.download_counter_increments.entry(key).or_insert(0);
        *count += 1;
        Ok(*count)
    }

    /// Tombstone a pack version, mirroring the Postgres adapter's documented
    /// choice (`crates/frameshift-catalog-postgres/src/backend.rs`):
    /// re-tombstoning an already-tombstoned version is idempotent
    /// (last-writer-wins on `reason`/`recorded_at`), never `Conflict`.
    /// Returns `NotFound` when the `(name, version)` pair has no version
    /// record, matching the trait's documented contract.
    ///
    /// After flipping the status, recomputes the pack head's `latest_version`
    /// (when a head row exists) to the newest remaining `Active` version using
    /// [`semver_gt`] -- the exact same comparator the Postgres adapter uses
    /// for `register_pack_version` ordering -- or clears it to `None`
    /// when no `Active` version remains. A head that was never seeded (tests
    /// that only call `seed_active_version`-style helpers without inserting a
    /// `PackRecord`) is left absent; there is nothing to recompute.
    async fn tombstone_pack(
        &self,
        name: &str,
        version: &str,
        record: TombstoneRecord,
    ) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        let key = (name.to_string(), version.to_string());
        match state.versions.get_mut(&key) {
            Some(v) => {
                v.status = PackStatus::Tombstone {
                    reason: record.reason,
                    recorded_at: record.recorded_at,
                };
            }
            None => {
                return Err(CatalogError::NotFound {
                    kind: "pack_version",
                    key: format!("{name}@{version}"),
                });
            }
        }

        // Recompute the newest remaining Active version for this pack, the
        // same way the Postgres adapter does inside its transaction.
        let newest_active = state
            .versions
            .values()
            .filter(|v| v.pack_name == name && matches!(v.status, PackStatus::Active))
            .map(|v| v.version.clone())
            .fold(None::<String>, |best, candidate| match best {
                None => Some(candidate),
                Some(cur) if semver_gt(&candidate, &cur) => Some(candidate),
                Some(cur) => Some(cur),
            });

        if let Some(pack) = state.packs.get_mut(name) {
            pack.latest_version = newest_active;
        }

        Ok(())
    }

    /// Get the public key for a handle.
    ///
    /// Reads the `handles` map first, then falls back to scanning `authors` by
    /// handle for setups that only pre-populated author records.
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
        if state.publisher_handles.contains_key(handle) {
            return Err(CatalogError::Conflict {
                kind: "handle",
                key: handle.to_string(),
            });
        }
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

    /// Atomically claim a signed-request nonce in shared mock state.
    async fn claim_signed_request_nonce(
        &self,
        pubkey: &Ed25519PublicKey,
        nonce: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| CatalogError::BackendError(e.to_string().into()))?;
        let now = Utc::now();
        state
            .signed_request_nonces
            .retain(|_, expiry| *expiry >= now);
        let key = (pubkey.to_string(), nonce.to_string());
        if state.signed_request_nonces.contains_key(&key) {
            return Ok(false);
        }
        state.signed_request_nonces.insert(key, expires_at);
        Ok(true)
    }

    /// Create an exact publication intent after validating its identity chain.
    async fn create_publication_intent(
        &self,
        record: PublicationIntentRecord,
    ) -> Result<PublicationIntentRecord, CatalogError> {
        if record.scan_schema_version == 0
            || record.expires_at <= record.created_at
            || record.consumed_at.is_some()
        {
            return Err(CatalogError::InvalidArgument(
                "invalid publication intent".to_string(),
            ));
        }
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let account_is_active = state
            .accounts
            .get(&record.account_id)
            .is_some_and(|account| account.status == AccountStatus::Active);
        let membership_is_active_owner = state
            .publisher_memberships
            .get(&(record.account_id, record.publisher_id))
            .is_some_and(|membership| {
                membership.role == PublisherRole::Owner
                    && membership.state == MembershipState::Active
            });
        let key_is_active_for_publisher = state
            .publisher_keys
            .get(&record.publisher_key_id)
            .is_some_and(|key| {
                key.publisher_id == record.publisher_id && key.state == PublisherKeyState::Active
            });
        if !state.publishers.contains_key(&record.publisher_id)
            || !account_is_active
            || !membership_is_active_owner
            || !key_is_active_for_publisher
        {
            return Err(CatalogError::Unauthorized {
                kind: "publication_intent",
                key: record.id.to_string(),
            });
        }
        if let Some(existing) = state.publication_intents.get(&record.id) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_intent",
                    key: record.id.to_string(),
                })
            };
        }
        state.publication_intents.insert(record.id, record.clone());
        Ok(record)
    }

    /// Retrieve one publication intent by stable identifier.
    async fn get_publication_intent(
        &self,
        id: uuid::Uuid,
    ) -> Result<PublicationIntentRecord, CatalogError> {
        self.state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?
            .publication_intents
            .get(&id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publication_intent",
                key: id.to_string(),
            })
    }

    /// Persist one quarantined submission with exact retry semantics.
    async fn create_publication_submission(
        &self,
        request: PublicationSubmissionRequest,
    ) -> Result<PublicationSubmissionRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if let Some(message) = &state.publication_submission_error {
            return Err(CatalogError::BackendError(
                std::io::Error::other(message.clone()).into(),
            ));
        }
        let exact_retry = |record: &PublicationSubmissionRecord| {
            record.id == request.id
                && record.intent_id == request.intent.id
                && record.account_id == request.intent.account_id
                && record.publisher_id == request.intent.publisher_id
                && record.publisher_key_id == request.intent.publisher_key_id
                && record.archive_hash == request.intent.archive_hash
                && record.manifest_hash == request.intent.manifest_hash
                && record.file_inventory_hash == request.intent.file_inventory_hash
                && record.scan_schema_version == request.intent.scan_schema_version
                && record.scan_report == request.scan_report
                && record.state == PublicationSubmissionState::Quarantined
        };
        if let Some(existing) = state.publication_submissions.get(&request.id) {
            return if exact_retry(existing) {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_submission",
                    key: request.id.to_string(),
                })
            };
        }
        if let Some(existing) = state
            .publication_submissions
            .values()
            .find(|record| record.intent_id == request.intent.id)
        {
            return if exact_retry(existing) {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_submission",
                    key: request.id.to_string(),
                })
            };
        }

        let now = Utc::now();
        if state.enforce_publication_submission_invariants {
            let account_is_active = state
                .accounts
                .get(&request.intent.account_id)
                .is_some_and(|account| account.status == AccountStatus::Active);
            let membership_is_active_owner = state
                .publisher_memberships
                .get(&(request.intent.account_id, request.intent.publisher_id))
                .is_some_and(|membership| {
                    membership.role == PublisherRole::Owner
                        && membership.state == MembershipState::Active
                });
            let key_is_active_for_publisher = state
                .publisher_keys
                .get(&request.intent.publisher_key_id)
                .is_some_and(|key| {
                    key.publisher_id == request.intent.publisher_id
                        && key.state == PublisherKeyState::Active
                });
            let intent_matches = state
                .publication_intents
                .get(&request.intent.id)
                .is_some_and(|intent| {
                    intent.account_id == request.intent.account_id
                        && intent.publisher_id == request.intent.publisher_id
                        && intent.publisher_key_id == request.intent.publisher_key_id
                        && intent.archive_hash == request.intent.archive_hash
                        && intent.manifest_hash == request.intent.manifest_hash
                        && intent.file_inventory_hash == request.intent.file_inventory_hash
                        && intent.scan_schema_version == request.intent.scan_schema_version
                        && intent.consumed_at.is_none()
                        && intent.expires_at > now
                });
            if !account_is_active
                || !membership_is_active_owner
                || !key_is_active_for_publisher
                || !intent_matches
            {
                return Err(CatalogError::Unauthorized {
                    kind: "publication_submission",
                    key: request.id.to_string(),
                });
            }
            state
                .publication_intents
                .get_mut(&request.intent.id)
                .expect("validated publication intent must remain present")
                .consumed_at = Some(now);
        }
        let record = PublicationSubmissionRecord {
            id: request.id,
            intent_id: request.intent.id,
            account_id: request.intent.account_id,
            publisher_id: request.intent.publisher_id,
            publisher_key_id: request.intent.publisher_key_id,
            archive_hash: request.intent.archive_hash,
            manifest_hash: request.intent.manifest_hash,
            file_inventory_hash: request.intent.file_inventory_hash,
            scan_schema_version: request.intent.scan_schema_version,
            scan_report: request.scan_report,
            state: PublicationSubmissionState::Quarantined,
            created_at: now,
            updated_at: now,
        };
        state
            .publication_submissions
            .insert(record.id, record.clone());
        Ok(record)
    }

    /// Retrieve one quarantined publication submission by identifier.
    async fn get_publication_submission(
        &self,
        id: uuid::Uuid,
    ) -> Result<PublicationSubmissionRecord, CatalogError> {
        self.state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?
            .publication_submissions
            .get(&id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publication_submission",
                key: id.to_string(),
            })
    }

    /// List an account's global platform roles in stable role order.
    async fn list_account_platform_roles(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<Vec<PlatformRoleRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let mut roles: Vec<_> = state
            .platform_roles
            .iter()
            .filter(|record| record.account_id == account_id)
            .cloned()
            .collect();
        roles.sort_by_key(|record| match record.role {
            PlatformRole::Administrator => 0,
            PlatformRole::Moderator => 1,
        });
        Ok(roles)
    }

    /// Authorize and atomically apply one publication moderation decision.
    async fn moderate_publication_submission(
        &self,
        request: PublicationModerationDecisionRequest,
    ) -> Result<PublicationModerationDecisionRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let actor_is_active = state
            .accounts
            .get(&request.actor_account_id)
            .is_some_and(|account| account.status == AccountStatus::Active);
        let role_is_active = state.platform_roles.iter().any(|record| {
            record.account_id == request.actor_account_id
                && record.state == PlatformRoleState::Active
                && matches!(
                    record.role,
                    PlatformRole::Moderator | PlatformRole::Administrator
                )
        });
        if !actor_is_active || !role_is_active {
            return Err(CatalogError::Unauthorized {
                kind: "publication_moderation",
                key: request.id.to_string(),
            });
        }

        let submission = state
            .publication_submissions
            .get(&request.submission_id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publication_submission",
                key: request.submission_id.to_string(),
            })?;
        let actor_is_owner = state.publisher_memberships.values().any(|membership| {
            membership.account_id == request.actor_account_id
                && membership.publisher_id == submission.publisher_id
                && membership.role == PublisherRole::Owner
                && membership.state == MembershipState::Active
        });
        if actor_is_owner {
            return Err(CatalogError::Unauthorized {
                kind: "publication_moderation",
                key: request.id.to_string(),
            });
        }

        let exact_retry = |record: &PublicationModerationDecisionRecord| {
            record.id == request.id
                && record.submission_id == request.submission_id
                && record.actor_account_id == request.actor_account_id
                && record.action == request.action
                && record.reason_code == request.reason_code
                && record.private_explanation == request.private_explanation
                && record.request_id == request.request_id
        };
        if let Some(existing) = state.publication_moderation_decisions.get(&request.id) {
            return if exact_retry(existing) {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_moderation_decision",
                    key: request.id.to_string(),
                })
            };
        }
        if let Some(existing) = state
            .publication_moderation_decisions
            .values()
            .find(|record| record.request_id == request.request_id)
        {
            return if exact_retry(existing) {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_moderation_decision",
                    key: request.request_id.to_string(),
                })
            };
        }

        if !matches!(
            submission.state,
            PublicationSubmissionState::Quarantined | PublicationSubmissionState::NeedsReview
        ) {
            return Err(CatalogError::Conflict {
                kind: "publication_submission",
                key: request.submission_id.to_string(),
            });
        }
        let to_state = match request.action {
            PublicationModerationAction::Approve => PublicationSubmissionState::Approved,
            PublicationModerationAction::RequestChanges => PublicationSubmissionState::NeedsReview,
            PublicationModerationAction::Reject => PublicationSubmissionState::Rejected,
        };
        let now = Utc::now();
        let decision = PublicationModerationDecisionRecord {
            id: request.id,
            submission_id: request.submission_id,
            actor_account_id: request.actor_account_id,
            action: request.action,
            from_state: submission.state,
            to_state,
            reason_code: request.reason_code,
            private_explanation: request.private_explanation,
            request_id: request.request_id,
            created_at: now,
        };
        let stored_submission = state
            .publication_submissions
            .get_mut(&request.submission_id)
            .expect("validated publication submission must remain present");
        stored_submission.state = to_state;
        stored_submission.updated_at = now;
        state
            .publication_moderation_decisions
            .insert(decision.id, decision.clone());
        Ok(decision)
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
