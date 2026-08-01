//! The [`CatalogBackend`] async trait and its contract.
//!
//! Adapters (e.g. the Postgres adapter in `frameshift-catalog-postgres`) implement
//! this trait and translate the generic catalog operations into driver-specific
//! calls. The HTTP server depends only on `dyn CatalogBackend`; it never
//! imports adapter crates directly.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use frameshift_pack::ObjectHash;

use crate::error::{CatalogError, HealthStatus};
use crate::filters::{PackSearchFilters, PackSearchResult};
use crate::identity::Ed25519PublicKey;
use crate::records::{
    AccountInviteIssueRequest, AccountInviteRecord, AccountInviteRequestRecord,
    AccountInviteReviewRequest, AccountInviteStatus, AccountPasswordCredentialRecord,
    AccountPasswordRehashRequest, AccountRecord, AccountSessionRecord, AccountStatusChangeRequest,
    AuthorRecord, LocalAccountRegistrationRequest, LocalAccountRegistrationResult, PackRecord,
    PackVersionRecord, PlatformRoleAssignmentRequest, PlatformRoleRecord,
    PlatformRoleRevocationRequest, PublicationAppealCaseRecord, PublicationAppealCursor,
    PublicationAppealRecord, PublicationAppealRequest, PublicationAppealResolutionRecord,
    PublicationAppealResolutionRequest, PublicationIntentClaim, PublicationIntentRecord,
    PublicationLifecycleCursor, PublicationLifecycleDecisionRecord,
    PublicationModerationDecisionRecord, PublicationModerationDecisionRequest,
    PublicationModerationSnapshot, PublicationPromotionRecord, PublicationPromotionRequest,
    PublicationSubmissionRecord, PublicationSubmissionRequest, PublicationTombstoneRequest,
    PublicationWithdrawalRequest, PublisherAuditEventRecord, PublisherKeyRecord,
    PublisherMembershipRecord, PublisherProfileRecord, PublisherSuspensionRequest,
};
use crate::status::TombstoneRecord;

/// Optional per-author limits applied atomically during pack registration.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublishQuota {
    /// Maximum number of versions an author may retain.
    pub max_versions: Option<u64>,
    /// Maximum cumulative archive bytes an author may retain.
    pub max_bytes: Option<u64>,
    /// Maximum cumulative archive bytes retained across all authors.
    pub max_total_bytes: Option<u64>,
}

/// Constructors for publisher quota policies.
impl PublishQuota {
    /// Return an unrestricted quota for trusted internal callers and seeders.
    pub const fn unlimited() -> Self {
        Self {
            max_versions: None,
            max_bytes: None,
            max_total_bytes: None,
        }
    }
}

/// Catalog backend for the persona marketplace.
///
/// Implementations persist authors, packs, pack versions, tag indices, and
/// download counters. All methods are async and return [`CatalogError`] on
/// failure; concrete error mapping (e.g. database-specific failure modes) is
/// the adapter's responsibility.
///
/// # Invariants implementations must uphold
///
/// - `register_author` MUST be idempotent for an identical `(pubkey, handle)`
///   pair: re-registering the same author with the same handle is a no-op that
///   returns `Ok(())`. Re-registering the same pubkey with a different handle,
///   or the same handle with a different pubkey, returns `CatalogError::Conflict`
///   or `CatalogError::HandleTaken` respectively.
/// - `register_pack_version` MUST be transactional: either the version row and
///   the parent pack's `latest_version` field both commit, or neither does.
///   Partial writes are not acceptable.
/// - `search_packs` MUST return a deterministic ordering for results with equal
///   scores, using `name ASC` as the tiebreaker, so that paginated results are
///   stable across requests.
/// - `tombstone_pack` MUST be a one-way transition: `Active` -> `Tombstone`.
///   An attempt to tombstone an already-tombstoned version MAY be treated as a
///   no-op (idempotent) or MAY return `CatalogError::Conflict` -- document the
///   adapter's choice.
/// - `increment_download_counter` for a pack name that does not exist MUST
///   return `CatalogError::NotFound`.
///
/// # Auth boundary
///
/// Most legacy methods do not enforce caller identity. `set_handle_pubkey`,
/// `tombstone_pack`, and similar mutations trust the caller, so the HTTP server
/// must verify Ed25519 signatures before invoking them. New moderation methods
/// explicitly document and enforce their durable account-authority invariants
/// in the backend so authorization, lifecycle mutation, and audit evidence
/// remain atomic.
///
/// # Object safety
///
/// This trait is object-safe when used via `async_trait`. Use
/// `Box<dyn CatalogBackend>` or `Arc<dyn CatalogBackend>` for dynamic dispatch.
#[async_trait]
pub trait CatalogBackend: Send + Sync {
    /// Store one invite application, treating a repeated normalized email as success.
    ///
    /// # Errors
    ///
    /// - `CatalogError::Validation` when the record violates adapter policy.
    /// - `CatalogError::BackendError` for unexpected backend failures.
    async fn create_account_invite_request(
        &self,
        record: AccountInviteRequestRecord,
    ) -> Result<(), CatalogError>;

    /// List invite applications after proving active administrator authority.
    async fn list_account_invite_requests(
        &self,
        actor_account_id: uuid::Uuid,
        status: Option<AccountInviteStatus>,
        limit: u32,
    ) -> Result<Vec<AccountInviteRequestRecord>, CatalogError> {
        let _ = (actor_account_id, status, limit);
        Err(CatalogError::Unauthorized {
            kind: "account_invite_request",
            key: "list".to_string(),
        })
    }

    /// Transition an application between non-issued review states under administrator authority.
    async fn review_account_invite_request(
        &self,
        request: AccountInviteReviewRequest,
    ) -> Result<AccountInviteRequestRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "account_invite_request",
            key: request.request_id.to_string(),
        })
    }

    /// Issue a single-use invitation and mark its application invited atomically.
    async fn issue_account_invite(
        &self,
        request: AccountInviteIssueRequest,
    ) -> Result<AccountInviteRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "account_invite",
            key: request.request_id.to_string(),
        })
    }

    /// Redeem one active invitation into an account, credential, and session atomically.
    async fn register_local_account(
        &self,
        request: LocalAccountRegistrationRequest,
    ) -> Result<LocalAccountRegistrationResult, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "account_invite",
            key: request.account.id.to_string(),
        })
    }

    /// Retrieve a first-party password credential by normalized email.
    async fn get_account_password_credential(
        &self,
        normalized_email: &str,
    ) -> Result<AccountPasswordCredentialRecord, CatalogError> {
        Err(CatalogError::NotFound {
            kind: "account_password_credential",
            key: normalized_email.to_string(),
        })
    }

    /// Replace one verified password hash only if its credential is unchanged.
    ///
    /// Returns `true` when the exact expected credential was upgraded and
    /// `false` when another writer changed or removed it first. Implementations
    /// must not modify `password_changed_at` for this pepper-only migration.
    async fn rehash_account_password_credential(
        &self,
        request: AccountPasswordRehashRequest,
    ) -> Result<bool, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "account_password_credential",
            key: request.account_id.to_string(),
        })
    }

    /// Create a revocable session after successful first-party authentication.
    async fn create_account_session(
        &self,
        record: AccountSessionRecord,
    ) -> Result<(), CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "account_session",
            key: record.id.to_string(),
        })
    }

    /// Resolve one currently active session by its opaque token digest.
    async fn get_active_account_session(
        &self,
        token_digest: &[u8],
        now: DateTime<Utc>,
    ) -> Result<AccountSessionRecord, CatalogError> {
        let _ = (token_digest, now);
        Err(CatalogError::NotFound {
            kind: "account_session",
            key: "opaque-token".to_string(),
        })
    }

    /// Advance one session's last-seen and sliding-expiry timestamps.
    async fn touch_account_session(
        &self,
        session_id: uuid::Uuid,
        last_seen_at: DateTime<Utc>,
        idle_expires_at: DateTime<Utc>,
    ) -> Result<(), CatalogError> {
        let _ = (last_seen_at, idle_expires_at);
        Err(CatalogError::NotFound {
            kind: "account_session",
            key: session_id.to_string(),
        })
    }

    /// Revoke one session owned by the authenticated account.
    async fn revoke_account_session(
        &self,
        session_id: uuid::Uuid,
        account_id: uuid::Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), CatalogError> {
        let _ = (account_id, revoked_at);
        Err(CatalogError::NotFound {
            kind: "account_session",
            key: session_id.to_string(),
        })
    }

    /// Create an OIDC-backed account with a unique `(issuer, subject)` identity.
    ///
    /// # Errors
    ///
    /// - `CatalogError::Conflict` when the account ID or identity pair exists.
    /// - `CatalogError::Validation` when issuer or subject is empty.
    /// - `CatalogError::BackendError` for unexpected backend failures.
    async fn create_account(&self, record: AccountRecord) -> Result<(), CatalogError>;

    /// Retrieve an account by its internal identifier.
    async fn get_account(&self, id: uuid::Uuid) -> Result<AccountRecord, CatalogError>;

    /// Retrieve an account by its exact OIDC issuer and subject pair.
    async fn get_account_by_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<AccountRecord, CatalogError>;

    /// Update mutable account profile fields without changing OIDC identity.
    async fn update_account_profile(
        &self,
        id: uuid::Uuid,
        email: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<AccountRecord, CatalogError>;

    /// Atomically create a publisher, its first owner, and an optional audit event.
    async fn create_publisher(
        &self,
        profile: PublisherProfileRecord,
        owner: PublisherMembershipRecord,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<(), CatalogError>;

    /// Retrieve a public publisher profile by its normalized handle.
    async fn get_publisher_by_handle(
        &self,
        handle: &str,
    ) -> Result<PublisherProfileRecord, CatalogError>;

    /// Retrieve a public publisher profile by its stable internal identifier.
    ///
    /// The default preserves source compatibility for external backends that
    /// cannot produce publisher-linked records yet.
    async fn get_publisher(&self, id: uuid::Uuid) -> Result<PublisherProfileRecord, CatalogError> {
        Err(CatalogError::NotFound {
            kind: "publisher",
            key: id.to_string(),
        })
    }

    /// Atomically update publisher fields and append an optional audit event.
    async fn update_publisher_profile(
        &self,
        id: uuid::Uuid,
        display_name: &str,
        biography: Option<&str>,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<PublisherProfileRecord, CatalogError>;

    /// List all memberships held by one account in stable creation order.
    async fn list_account_memberships(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<Vec<PublisherMembershipRecord>, CatalogError>;

    /// Retrieve the membership joining one account and publisher.
    async fn get_publisher_membership(
        &self,
        account_id: uuid::Uuid,
        publisher_id: uuid::Uuid,
    ) -> Result<PublisherMembershipRecord, CatalogError>;

    /// Atomically enroll a publisher key and append an optional audit event.
    ///
    /// Repeating enrollment for the same active public key and publisher is
    /// idempotent: the original record is returned and no duplicate audit event
    /// is written. Reuse across publishers or after revocation is a conflict.
    async fn create_publisher_key(
        &self,
        record: PublisherKeyRecord,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<PublisherKeyRecord, CatalogError>;

    /// List a publisher's enrolled public keys in stable creation order.
    async fn list_publisher_keys(
        &self,
        publisher_id: uuid::Uuid,
    ) -> Result<Vec<PublisherKeyRecord>, CatalogError>;

    /// Retrieve one enrolled publisher key by its stable identifier.
    ///
    /// The default preserves source compatibility for external backends that
    /// cannot produce publisher-key-linked versions yet.
    async fn get_publisher_key(&self, id: uuid::Uuid) -> Result<PublisherKeyRecord, CatalogError> {
        Err(CatalogError::NotFound {
            kind: "publisher_key",
            key: id.to_string(),
        })
    }

    /// Atomically revoke a publisher key and append an optional audit event.
    async fn revoke_publisher_key(
        &self,
        publisher_id: uuid::Uuid,
        key_id: uuid::Uuid,
        revoked_at: DateTime<Utc>,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<PublisherKeyRecord, CatalogError>;

    /// Append an immutable, sanitized publisher audit event.
    async fn append_publisher_audit_event(
        &self,
        event: PublisherAuditEventRecord,
    ) -> Result<(), CatalogError>;

    /// Create or idempotently retrieve one exact publication intent.
    ///
    /// Backends that do not support the Phase 5 publication workflow fail
    /// closed through this default implementation.
    async fn create_publication_intent(
        &self,
        record: PublicationIntentRecord,
    ) -> Result<PublicationIntentRecord, CatalogError> {
        Err(CatalogError::Validation(format!(
            "publication intents are not supported by this backend: {}",
            record.id
        )))
    }

    /// Retrieve a durable publication intent by its stable identifier.
    ///
    /// The default preserves source compatibility for existing external
    /// backends while preventing an unsupported backend from authorizing use.
    async fn get_publication_intent(
        &self,
        id: uuid::Uuid,
    ) -> Result<PublicationIntentRecord, CatalogError> {
        Err(CatalogError::NotFound {
            kind: "publication_intent",
            key: id.to_string(),
        })
    }

    /// Atomically consume an unexpired intent with an exact identity and hash binding.
    ///
    /// Returns `true` only for the single successful transition. `false`
    /// intentionally combines missing, expired, consumed, inactive, and
    /// mismatched cases so callers cannot accidentally weaken the predicate.
    async fn consume_publication_intent(
        &self,
        _claim: PublicationIntentClaim,
    ) -> Result<bool, CatalogError> {
        Ok(false)
    }

    /// Atomically consume an exact intent and create one quarantined submission.
    ///
    /// Backends that do not support quarantine persistence fail closed. The
    /// operation must not consume the intent unless the submission is committed.
    async fn create_publication_submission(
        &self,
        request: PublicationSubmissionRequest,
    ) -> Result<PublicationSubmissionRecord, CatalogError> {
        Err(CatalogError::Validation(format!(
            "publication submissions are not supported by this backend: {}",
            request.id
        )))
    }

    /// Retrieve one durable publication submission by stable identifier.
    async fn get_publication_submission(
        &self,
        id: uuid::Uuid,
    ) -> Result<PublicationSubmissionRecord, CatalogError> {
        Err(CatalogError::NotFound {
            kind: "publication_submission",
            key: id.to_string(),
        })
    }

    /// Return an aggregate snapshot of unresolved publication review work.
    ///
    /// `None` preserves source compatibility for backends without operational
    /// queue support while preventing zero values from masquerading as a
    /// verified empty queue.
    async fn publication_moderation_snapshot(
        &self,
    ) -> Result<Option<PublicationModerationSnapshot>, CatalogError> {
        Ok(None)
    }

    /// List an account's global platform roles in stable role order.
    ///
    /// The empty default fails closed for backends that have not implemented
    /// the D4 moderation authority model.
    async fn list_account_platform_roles(
        &self,
        _account_id: uuid::Uuid,
    ) -> Result<Vec<PlatformRoleRecord>, CatalogError> {
        Ok(Vec::new())
    }

    /// Grant or reactivate one platform role under administrator authority.
    ///
    /// The actor must be an active account holding an active administrator
    /// role, verified atomically with the write. Granting an already active
    /// role is idempotent, and granting a revoked role reactivates that same
    /// assignment rather than creating a duplicate.
    ///
    /// The denying default fails closed so a backend without an implemented
    /// authority model can never appear to grant platform authority.
    async fn assign_account_platform_role(
        &self,
        request: PlatformRoleAssignmentRequest,
    ) -> Result<PlatformRoleRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "platform_role",
            key: request.account_id.to_string(),
        })
    }

    /// Revoke one platform role under administrator authority.
    ///
    /// The assignment row is retained in the revoked state so the original
    /// grant remains auditable. Revoking the last active administrator is
    /// rejected, because losing every administrator would permanently remove
    /// the platform's ability to moderate, promote, or restore authority.
    ///
    /// The denying default fails closed for unimplemented backends.
    async fn revoke_account_platform_role(
        &self,
        request: PlatformRoleRevocationRequest,
    ) -> Result<PlatformRoleRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "platform_role",
            key: request.account_id.to_string(),
        })
    }

    /// Transition one account's status under administrator authority.
    ///
    /// Suspending or disabling the account that holds the last active
    /// administrator role is rejected for the same coverage reason as role
    /// revocation. Status changes never delete memberships, keys, submissions,
    /// or audit history.
    ///
    /// The denying default fails closed for unimplemented backends.
    async fn set_account_status(
        &self,
        request: AccountStatusChangeRequest,
    ) -> Result<AccountRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "account_status",
            key: request.account_id.to_string(),
        })
    }

    /// Atomically authorize and persist one publication moderation decision.
    ///
    /// Unsupported backends fail closed. Implementations must verify active
    /// moderator or administrator authority, exclude active publisher owners,
    /// update the submission state, and append immutable decision evidence in
    /// one transaction.
    async fn moderate_publication_submission(
        &self,
        request: PublicationModerationDecisionRequest,
    ) -> Result<PublicationModerationDecisionRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "publication_moderation",
            key: request.id.to_string(),
        })
    }

    /// Atomically file one owner-authenticated appeal against an adverse decision.
    ///
    /// Unsupported backends fail closed. Implementations must resolve exact
    /// completed retries before current authorization checks, enforce one
    /// appeal per decision and the 30-day deadline, and bind the appeal to the
    /// original submission and publisher without accepting mutable artifact data.
    async fn file_publication_appeal(
        &self,
        request: PublicationAppealRequest,
    ) -> Result<PublicationAppealRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "publication_appeal",
            key: request.id.to_string(),
        })
    }

    /// Atomically resolve one appeal under active administrator authority.
    ///
    /// Unsupported backends fail closed. A different administrator from the
    /// original decision actor is mandatory when available. An unavoidable
    /// self-resolution requires a retained separation-exception reason.
    async fn resolve_publication_appeal(
        &self,
        request: PublicationAppealResolutionRequest,
    ) -> Result<PublicationAppealResolutionRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "publication_appeal_resolution",
            key: request.id.to_string(),
        })
    }

    /// List one publisher's private appeal cases for an owner or administrator.
    async fn list_publisher_publication_appeals(
        &self,
        actor_account_id: uuid::Uuid,
        publisher_id: uuid::Uuid,
        before: Option<PublicationAppealCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationAppealCaseRecord>, CatalogError> {
        let _ = (before, limit);
        Err(CatalogError::Unauthorized {
            kind: "publication_appeal",
            key: format!("{actor_account_id}:{publisher_id}"),
        })
    }

    /// List global private appeal cases for an active administrator.
    async fn list_administrator_publication_appeals(
        &self,
        actor_account_id: uuid::Uuid,
        before: Option<PublicationAppealCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationAppealCaseRecord>, CatalogError> {
        let _ = (before, limit);
        Err(CatalogError::Unauthorized {
            kind: "publication_appeal",
            key: actor_account_id.to_string(),
        })
    }

    /// Atomically activate one independently approved quarantine submission.
    ///
    /// Unsupported backends fail closed. Implementations must resolve exact
    /// completed retries, enforce current promotion authority and publisher
    /// eligibility, register the active pack version, append immutable
    /// promotion evidence, and transition the submission to `promoted` in one
    /// transaction.
    async fn promote_publication_submission(
        &self,
        request: PublicationPromotionRequest,
        _quota: PublishQuota,
    ) -> Result<PublicationPromotionRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "publication_promotion",
            key: request.id.to_string(),
        })
    }

    /// Atomically withdraw one eligible non-public submission as its publisher owner.
    ///
    /// Unsupported backends fail closed. Implementations must resolve exact
    /// completed retries before current authorization checks, then require an
    /// active account and active owner membership for a new transition.
    async fn withdraw_publication_submission(
        &self,
        request: PublicationWithdrawalRequest,
    ) -> Result<PublicationLifecycleDecisionRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "publication_withdrawal",
            key: request.id.to_string(),
        })
    }

    /// Atomically suspend one publisher profile under active administrator authority.
    ///
    /// Unsupported backends fail closed. The profile mutation and immutable
    /// lifecycle evidence must commit in the same transaction.
    async fn suspend_publisher(
        &self,
        request: PublisherSuspensionRequest,
    ) -> Result<PublicationLifecycleDecisionRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "publisher_suspension",
            key: request.id.to_string(),
        })
    }

    /// Atomically tombstone one public release under active administrator authority.
    ///
    /// Unsupported backends fail closed. Implementations must retain released
    /// catalog and object history while removing the version from every active
    /// resolution path.
    async fn tombstone_publication_release(
        &self,
        request: PublicationTombstoneRequest,
    ) -> Result<PublicationLifecycleDecisionRecord, CatalogError> {
        Err(CatalogError::Unauthorized {
            kind: "publication_tombstone",
            key: request.id.to_string(),
        })
    }

    /// List one publisher's lifecycle evidence after actor authorization.
    ///
    /// Unsupported backends fail closed. Implementations must require an active
    /// publisher owner or active administrator and cap `limit` before querying.
    async fn list_publisher_lifecycle_decisions(
        &self,
        actor_account_id: uuid::Uuid,
        publisher_id: uuid::Uuid,
        before: Option<PublicationLifecycleCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationLifecycleDecisionRecord>, CatalogError> {
        let _ = (before, limit);
        Err(CatalogError::Unauthorized {
            kind: "publication_lifecycle_audit",
            key: format!("{actor_account_id}:{publisher_id}"),
        })
    }

    /// List global lifecycle evidence after active administrator authorization.
    ///
    /// Unsupported backends fail closed. Results must use a deterministic
    /// newest-first order and a bounded limit.
    async fn list_administrator_lifecycle_decisions(
        &self,
        actor_account_id: uuid::Uuid,
        before: Option<PublicationLifecycleCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationLifecycleDecisionRecord>, CatalogError> {
        let _ = (before, limit);
        Err(CatalogError::Unauthorized {
            kind: "publication_lifecycle_audit",
            key: actor_account_id.to_string(),
        })
    }

    /// Register a new author or confirm that an identical author already exists.
    ///
    /// Idempotent for an identical `(pubkey, handle)` pair. Returns
    /// `CatalogError::HandleTaken` if the handle is owned by a different pubkey.
    /// Returns `CatalogError::Conflict` if the pubkey is already registered with
    /// a different handle.
    ///
    /// # Errors
    ///
    /// - `CatalogError::HandleTaken` -- the handle is already owned by another key.
    /// - `CatalogError::Conflict` -- the pubkey is registered with a different handle.
    /// - `CatalogError::Validation` -- `display_name` is `Some("")` (empty string).
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn register_author(&self, record: AuthorRecord) -> Result<(), CatalogError>;

    /// Look up an author by their Ed25519 public key.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"author"`) -- no author with this pubkey.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn lookup_author(&self, pubkey: &Ed25519PublicKey) -> Result<AuthorRecord, CatalogError>;

    /// Look up an author by their unique handle string.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"author"`) -- no author with this handle.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn lookup_author_by_handle(&self, handle: &str) -> Result<AuthorRecord, CatalogError>;

    /// List all registered authors, paginated by `limit` and `offset`.
    ///
    /// Returns an empty `Vec` if `offset` is beyond the total author count.
    /// Order is implementation-defined but MUST be stable (e.g. `created_at ASC`).
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn list_authors(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuthorRecord>, CatalogError>;

    /// Register a new version of a pack.
    ///
    /// The parent pack record is created if it does not yet exist, and its
    /// `latest_version` is updated atomically within the same transaction.
    ///
    /// `record.signature` MUST be exactly 64 bytes; any other length returns
    /// `CatalogError::InvalidArgument`.
    ///
    /// When `record.publisher_key_id` is present, the backend MUST atomically
    /// verify that the referenced key is active, belongs to the same publisher
    /// as the pack head, and equals `record.author_pubkey`. The first version
    /// persists that key's publisher on the parent pack. A revoked key remains
    /// valid historical evidence but MUST NOT authorize a new version.
    ///
    /// # Errors
    ///
    /// - `CatalogError::Conflict` -- `(pack_name, version)` already registered.
    /// - `CatalogError::InvalidArgument` -- `signature` is not 64 bytes.
    /// - `CatalogError::Validation` -- e.g. attempt to publish to a tombstoned pack.
    /// - `CatalogError::Unauthorized` -- the pack already exists and its
    ///   `current_author` does not match `record.author_pubkey` (co-publish
    ///   / name-squat rejection).
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn register_pack_version(&self, record: PackVersionRecord) -> Result<(), CatalogError> {
        self.register_pack_version_with_quota(record, PublishQuota::unlimited())
            .await
    }

    /// Register a version while atomically enforcing author or publisher storage limits.
    async fn register_pack_version_with_quota(
        &self,
        record: PackVersionRecord,
        quota: PublishQuota,
    ) -> Result<(), CatalogError>;

    /// Retrieve the top-level pack record for the given pack name.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack"`) -- no pack with this name.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn get_pack(&self, name: &str) -> Result<PackRecord, CatalogError>;

    /// Retrieve a specific version record for the given pack and version string.
    ///
    /// This method DOES return tombstoned records, with `status` set to
    /// `PackStatus::Tombstone { .. }` so the caller can see exactly what
    /// happened and when. It never hides a version just because it was taken
    /// down -- direct, targeted lookup by `(name, version)` is precisely the
    /// operation an auditor or a consumer chasing a broken dependency needs,
    /// and answering it honestly (rather than returning `NotFound` for a
    /// version that in fact exists) is the deliberate design choice here.
    /// Callers that want to reject serving tombstoned content (e.g. the pack
    /// download route) MUST check `status` themselves after the call.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack_version"`) -- no such version.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn get_pack_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<PackVersionRecord, CatalogError>;

    /// Retrieve one active pack version that references `content_hash`.
    ///
    /// This lookup is the revocation check for content-addressed signed
    /// downloads. Tombstoned versions MUST NOT satisfy the lookup. If several
    /// active versions reference identical bytes, implementations may return
    /// any one of them.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"active_pack_version"`) if no active
    ///   version references the hash.
    /// - `CatalogError::BackendError` for unexpected backend failures.
    async fn get_active_pack_version_by_hash(
        &self,
        content_hash: &ObjectHash,
    ) -> Result<PackVersionRecord, CatalogError>;

    /// List all versions of a pack, ordered by `published_at ASC`.
    ///
    /// Returns an empty `Vec` if the pack has no published versions. Returns
    /// `CatalogError::NotFound` if the pack does not exist at all.
    ///
    /// This method returns EVERY version, including tombstoned ones, with
    /// `status` set to `PackStatus::Tombstone { .. }` on those records. This is
    /// deliberate transparency (the same norm most package registries follow:
    /// a takedown removes a version from discovery/installation, but the
    /// version history itself stays visible so consumers can see what
    /// happened to a version they may already depend on). Callers that want to
    /// hide tombstoned versions from an end-user-facing list must filter on
    /// `status` themselves; this method does not do it for them.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack"`) -- pack does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn list_pack_versions(&self, name: &str) -> Result<Vec<PackVersionRecord>, CatalogError>;

    /// Search for packs matching the given filters.
    ///
    /// Returns results ordered by the sort mode specified in `filters`, with a
    /// deterministic `name ASC` tiebreaker for equal scores.
    ///
    /// Tombstoned content is excluded from results via the pack head's
    /// `latest_version` field: `tombstone_pack` recomputes `latest_version` to
    /// the newest remaining `Active` version every time it tombstones a
    /// version, clearing it to `None` when no `Active` version remains. A pack
    /// with `latest_version == None` (zero `Active` versions) MUST NOT appear
    /// in `search_packs` results. There is no per-version status check inside
    /// this method -- it operates entirely on the pack head, and the head's
    /// `latest_version` is the single source of truth for "is this pack
    /// currently installable." Adapters MUST implement the `latest_version IS
    /// NOT NULL` exclusion (or equivalent) in every code path this method can
    /// take, not just the default/no-filter path.
    ///
    /// Returns an empty `Vec` (not an error) when no packs match.
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn search_packs(
        &self,
        filters: &PackSearchFilters,
    ) -> Result<Vec<PackSearchResult>, CatalogError>;

    /// Increment the download counter for a specific pack version.
    ///
    /// Also increments the parent pack's `total_downloads` field. Returns the
    /// new value of the version-level download counter after incrementing.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack_version"`) -- the pack or version
    ///   does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn increment_download_counter(
        &self,
        name: &str,
        version: &str,
    ) -> Result<u64, CatalogError>;

    /// Mark a specific pack version as tombstoned.
    ///
    /// The version record is retained; only its `status` field transitions from
    /// `PackStatus::Active` to `PackStatus::Tombstone`. Content-addressed
    /// retrieval by hash still works after tombstoning.
    ///
    /// # Head recompute contract
    ///
    /// After flipping the version's status, the implementation MUST recompute
    /// the parent pack's `latest_version` field so that it never points at a
    /// tombstoned version:
    ///
    /// - Find the newest remaining `PackStatus::Active` version for the pack,
    ///   using the SAME version-precedence ordering `register_pack_version`
    ///   uses to decide `latest_version` (true semver precedence, not
    ///   lexicographic or insertion order -- see the adapter's
    ///   `register_pack_version` doc for specifics).
    /// - Set `latest_version` to that version.
    /// - If no `Active` version remains for the pack (this was the last one),
    ///   clear `latest_version` to `None` rather than leaving it pointing at
    ///   the version that was just tombstoned. This is what makes the pack
    ///   disappear from `search_packs` (which excludes packs with
    ///   `latest_version == None`) while still allowing direct lookups
    ///   (`get_pack_version`, `list_pack_versions`) to see it.
    ///
    /// This recompute MUST happen atomically with the status update (same
    /// transaction where the adapter supports transactions), so a reader can
    /// never observe a pack head whose `latest_version` points at a
    /// `Tombstone` version.
    ///
    /// Adapter MUST document whether re-tombstoning an already-tombstoned version
    /// is idempotent or returns `CatalogError::Conflict`.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack_version"`) -- the version does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn tombstone_pack(
        &self,
        name: &str,
        version: &str,
        record: TombstoneRecord,
    ) -> Result<(), CatalogError>;

    /// Retrieve the Ed25519 public key currently mapped to a handle.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"handle"`) -- the handle does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn get_handle_pubkey(&self, handle: &str) -> Result<Ed25519PublicKey, CatalogError>;

    /// Update the public key mapped to an existing handle.
    ///
    /// The caller is responsible for verifying ownership before invoking this
    /// method. The catalog does not verify that the caller controls the new key.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"handle"`) -- the handle does not exist.
    /// - `CatalogError::InvalidArgument` -- the pubkey is structurally invalid
    ///   (e.g. all-zero bytes, if the adapter validates this).
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn set_handle_pubkey(
        &self,
        handle: &str,
        pubkey: Ed25519PublicKey,
    ) -> Result<(), CatalogError>;

    /// Record a single download event for a specific pack version in the audit log.
    ///
    /// Inserts one row into the `pack_downloads` audit table with the current
    /// timestamp. This is the write side of the trending feature; `search_packs`
    /// with `SortMode::Trending` reads from the same table to compute 7-day
    /// download velocity.
    ///
    /// This method is best-effort: callers SHOULD invoke it after a successful
    /// object-store fetch, but a failure here MUST NOT prevent the download from
    /// being served. The recommended pattern is to log and discard the error at
    /// the call site rather than surfacing it to the end user.
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` -- unexpected backend failure (e.g. pool
    ///   exhausted, DB unreachable). The download itself should still be served.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn record_download(&self, pack_name: &str, version: &str) -> Result<(), CatalogError>;

    /// Atomically claim a signed-request nonce for one public key.
    ///
    /// Returns `true` only for the first unexpired claim of `(pubkey, nonce)`.
    /// Implementations MUST make the insert atomic across all server instances.
    /// Implementations SHOULD remove expired rows through backend maintenance so
    /// request latency is independent of nonce-table cleanup.
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` for unexpected backend failures.
    async fn claim_signed_request_nonce(
        &self,
        pubkey: &Ed25519PublicKey,
        nonce: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, CatalogError>;

    /// Return the current health status of the backend.
    ///
    /// A healthy backend returns `HealthStatus { healthy: true, detail: "ok" }`.
    /// A degraded backend returns `healthy: false` with a description of the
    /// failure in `detail`. This method SHOULD NOT itself return `Err`; prefer
    /// returning `Ok(HealthStatus { healthy: false, ... })` for degraded states.
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` -- the backend is so degraded it cannot
    ///   even construct a health response.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn health(&self) -> Result<HealthStatus, CatalogError>;

    /// Set the `extends` field on the pack head record.
    ///
    /// Records the base persona pack name from the manifest `extends` field.
    /// Pass `None` to clear the value (root pack with no base). This is a
    /// best-effort update called after `register_pack_version`; the caller
    /// MUST ensure the pack row already exists (i.e. `register_pack_version`
    /// succeeded) before calling this method.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack"`) -- the pack does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn set_pack_extends(
        &self,
        pack_name: &str,
        extends: Option<&str>,
    ) -> Result<(), CatalogError>;

    /// Set the `description` and `tags` fields on the pack head record.
    ///
    /// Records the marketplace-facing description and discovery tags from the
    /// manifest so that `search_packs` (which ranks on `description`) can find
    /// published packs. This is a best-effort update called after
    /// `register_pack_version`; the caller MUST ensure the pack row already
    /// exists (i.e. `register_pack_version` succeeded) before calling this
    /// method.
    ///
    /// # Errors
    ///
    /// - `CatalogError::NotFound` (kind `"pack"`) -- the pack does not exist.
    /// - `CatalogError::BackendError` -- unexpected backend failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn set_pack_metadata(
        &self,
        name: &str,
        description: &str,
        tags: &[String],
    ) -> Result<(), CatalogError>;
}
