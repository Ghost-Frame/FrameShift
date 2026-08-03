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
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use frameshift_catalog::backend::CatalogBackend;
use frameshift_catalog::error::{CatalogError, HealthStatus};
use frameshift_catalog::filters::{PackSearchFilters, PackSearchResult};
use frameshift_catalog::identity::Ed25519PublicKey;
use frameshift_catalog::records::{
    AccountAuthAuditEventRecord, AccountInviteIssueRequest, AccountInviteRecord,
    AccountInviteRequestRecord, AccountInviteReviewRequest, AccountInviteStatus,
    AccountMfaActivationRequest, AccountMfaAuthenticatorRecord, AccountMfaAuthenticatorState,
    AccountMfaChallengeCompletionRequest, AccountMfaChallengeCompletionResult,
    AccountMfaChallengeCreationRequest, AccountMfaChallengeProof, AccountMfaDisableRequest,
    AccountMfaEnrollmentRequest, AccountMfaLoginChallengeRecord, AccountPasswordCredentialRecord,
    AccountPasswordRehashRequest, AccountRecord, AccountSessionCreationRequest,
    AccountSessionIssuance, AccountSessionRecord, AccountSessionRefreshRequest,
    AccountSessionRefreshResult, AccountStatus, AccountStatusChangeRequest, AuthorRecord,
    EncryptedPasswordRecoveryDelivery, LocalAccountRegistrationRequest,
    LocalAccountRegistrationResult, MembershipState, NativeAuthorizationCodeCreationRequest,
    NativeAuthorizationCodeExchangeRequest, NativeAuthorizationCodeExchangeResult,
    NativeAuthorizationCodeRecord, PackRecord, PackVersionRecord,
    PasswordRecoveryCompletionRequest, PasswordRecoveryDeliveryClaimRequest,
    PasswordRecoveryDeliveryKind, PasswordRecoveryDeliveryRecord, PasswordRecoveryEnqueueRequest,
    PlatformRole, PlatformRoleAssignmentRequest, PlatformRoleRecord, PlatformRoleRevocationRequest,
    PlatformRoleState, PublicationAppealCaseRecord, PublicationAppealCursor,
    PublicationAppealDisposition, PublicationAppealRecord, PublicationAppealRequest,
    PublicationAppealResolutionRecord, PublicationAppealResolutionRequest, PublicationIntentRecord,
    PublicationLifecycleAction, PublicationLifecycleCursor, PublicationLifecycleDecisionRecord,
    PublicationModerationAction, PublicationModerationDecisionRecord,
    PublicationModerationDecisionRequest, PublicationModerationSnapshot,
    PublicationPromotionRecord, PublicationPromotionRequest, PublicationSubmissionRecord,
    PublicationSubmissionRequest, PublicationSubmissionState, PublicationTombstoneRequest,
    PublicationWithdrawalRequest, PublisherAuditEventRecord, PublisherKeyRecord, PublisherKeyState,
    PublisherMembershipRecord, PublisherModerationStatus, PublisherProfileRecord, PublisherRole,
    PublisherSuspensionRequest,
};
use frameshift_catalog::status::{PackStatus, TombstoneRecord};
use frameshift_catalog::AccountSessionClientKind;
// Reuse the exact same version-precedence comparator the Postgres adapter
// uses for `register_pack_version`'s `latest_version` selection, so the
// mock's tombstone head-recompute can never drift from the real ordering.
use frameshift_catalog::PublishQuota;
use frameshift_catalog_postgres::backend::semver_gt;
use frameshift_pack::ObjectHash;

/// Digest-only reset-token lifecycle retained by the in-memory catalog double.
#[derive(Clone)]
pub struct MockPasswordRecoveryToken {
    /// Stable token-row identifier.
    pub id: uuid::Uuid,
    /// Account authorized by this reset token.
    pub account_id: uuid::Uuid,
    /// SHA-256 digest of the caller-held bearer.
    pub token_digest: Vec<u8>,
    /// Exclusive token consumption deadline.
    pub expires_at: DateTime<Utc>,
    /// Successful one-time consumption timestamp.
    pub consumed_at: Option<DateTime<Utc>>,
    /// Explicit supersession timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Request admission timestamp.
    pub created_at: DateTime<Utc>,
}

/// Digest-only refresh generation retained by the in-memory catalog double.
#[derive(Clone)]
pub struct MockRefreshToken {
    /// Stable refresh-generation identifier.
    pub id: uuid::Uuid,
    /// Session family owning this generation.
    pub session_id: uuid::Uuid,
    /// SHA-256 digest of the caller-held refresh token.
    pub token_digest: Vec<u8>,
    /// Exclusive token consumption deadline.
    pub expires_at: DateTime<Utc>,
    /// Successful consumption timestamp used to detect replay.
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Digest-only recovery code retained by the in-memory catalog double.
#[derive(Clone)]
pub struct MockMfaRecoveryCode {
    /// Authenticator whose activation created the code.
    pub authenticator_id: uuid::Uuid,
    /// Account that owns the code.
    pub account_id: uuid::Uuid,
    /// Whether a successful challenge already consumed the code.
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Shared mutable state for [`MockCatalog`].
///
/// Wrapped in `Arc<RwLock<MockState>>` so that the catalog can be cloned
/// cheaply and mutated from test setup code.
#[derive(Default)]
pub struct MockState {
    /// Invite applications keyed by normalized email for duplicate suppression.
    pub account_invite_requests: HashMap<String, AccountInviteRequestRecord>,

    /// Issued account invitations keyed by stable identifier.
    pub account_invites: HashMap<uuid::Uuid, AccountInviteRecord>,

    /// First-party password credentials keyed by normalized email.
    pub account_password_credentials: HashMap<String, AccountPasswordCredentialRecord>,

    /// Revocable first-party sessions keyed by stable identifier.
    pub account_sessions: HashMap<uuid::Uuid, AccountSessionRecord>,

    /// Digest-only refresh generations keyed by their token digest.
    pub account_refresh_tokens: HashMap<Vec<u8>, MockRefreshToken>,

    /// Encrypted MFA authenticators keyed by stable identifier.
    pub account_mfa_authenticators: HashMap<uuid::Uuid, AccountMfaAuthenticatorRecord>,

    /// Digest-only recovery codes keyed by their token digest.
    pub account_mfa_recovery_codes: HashMap<Vec<u8>, MockMfaRecoveryCode>,

    /// Digest-only MFA login challenges keyed by their token digest.
    pub account_mfa_challenges: HashMap<Vec<u8>, AccountMfaLoginChallengeRecord>,

    /// Digest-only native authorization codes keyed by their token digest.
    pub native_authorization_codes: HashMap<Vec<u8>, NativeAuthorizationCodeRecord>,

    /// Immutable sanitized first-party authentication audit events.
    pub account_auth_audit_events: Vec<AccountAuthAuditEventRecord>,

    /// Digest-only password reset tokens keyed by stable identifier.
    pub password_recovery_tokens: HashMap<uuid::Uuid, MockPasswordRecoveryToken>,

    /// Encrypted recovery outbox rows keyed by provider idempotency identifier.
    pub password_recovery_deliveries: HashMap<uuid::Uuid, PasswordRecoveryDeliveryRecord>,

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

    /// Optional aggregate moderation snapshot returned to operations tests.
    pub publication_moderation_snapshot: Option<PublicationModerationSnapshot>,

    /// Global platform-role assignments retained for authorization tests.
    pub platform_roles: Vec<PlatformRoleRecord>,

    /// Immutable publication moderation decisions keyed by stable identifier.
    pub publication_moderation_decisions: HashMap<uuid::Uuid, PublicationModerationDecisionRecord>,

    /// Immutable publication appeal filings keyed by stable identifier.
    pub publication_appeals: HashMap<uuid::Uuid, PublicationAppealRecord>,

    /// Immutable publication appeal resolutions keyed by stable identifier.
    pub publication_appeal_resolutions: HashMap<uuid::Uuid, PublicationAppealResolutionRecord>,

    /// Immutable successful promotions keyed by stable identifier.
    pub publication_promotions: HashMap<uuid::Uuid, PublicationPromotionRecord>,

    /// Immutable publication lifecycle decisions keyed by stable identifier.
    pub publication_lifecycle_decisions: HashMap<uuid::Uuid, PublicationLifecycleDecisionRecord>,

    /// Optional persistent backend failure injected into submission creation.
    pub publication_submission_error: Option<String>,

    /// Optional persistent backend failure injected into publication promotion.
    pub publication_promotion_error: Option<String>,

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
    /// Per-email enqueue latency used to prove response timing independence.
    password_recovery_enqueue_delays: Arc<RwLock<HashMap<String, StdDuration>>>,
}

/// Constructors for the in-memory catalog test double.
impl MockCatalog {
    /// Create an empty [`MockCatalog`] with no pre-populated records.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(MockState::default())),
            password_recovery_enqueue_delays: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Delay one normalized recovery-email enqueue without blocking mock state access.
    #[allow(dead_code)]
    pub fn delay_password_recovery_enqueue(&self, normalized_email: &str, delay: StdDuration) {
        self.password_recovery_enqueue_delays
            .write()
            .unwrap()
            .insert(normalized_email.to_string(), delay);
    }
}

/// Default construction of an empty mock catalog.
impl Default for MockCatalog {
    /// Returns an empty [`MockCatalog`].
    fn default() -> Self {
        Self::new()
    }
}

/// Persist one mock access session and its initial digest-only refresh generation.
fn insert_mock_session_issuance(
    state: &mut MockState,
    issuance: AccountSessionIssuance,
) -> Result<AccountSessionRecord, CatalogError> {
    let session = issuance.session;
    if state.account_sessions.contains_key(&session.id)
        || state
            .account_refresh_tokens
            .values()
            .any(|token| token.id == issuance.refresh_token_id)
        || state
            .account_refresh_tokens
            .contains_key(&issuance.refresh_token_digest)
    {
        return Err(CatalogError::Conflict {
            kind: "account_session",
            key: session.id.to_string(),
        });
    }
    let refresh = MockRefreshToken {
        id: issuance.refresh_token_id,
        session_id: session.id,
        token_digest: issuance.refresh_token_digest,
        expires_at: issuance.refresh_expires_at,
        consumed_at: None,
    };
    state
        .account_refresh_tokens
        .insert(refresh.token_digest.clone(), refresh);
    state.account_sessions.insert(session.id, session.clone());
    Ok(session)
}

/// Return whether the mock account exists and remains active.
fn mock_account_is_active(state: &MockState, account_id: uuid::Uuid) -> bool {
    state
        .accounts
        .get(&account_id)
        .is_some_and(|account| account.status == AccountStatus::Active)
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

/// Expand a caller-encrypted envelope into one pending mock outbox record.
fn mock_recovery_delivery(
    account_id: uuid::Uuid,
    recipient: String,
    kind: PasswordRecoveryDeliveryKind,
    delivery: EncryptedPasswordRecoveryDelivery,
    created_at: DateTime<Utc>,
) -> PasswordRecoveryDeliveryRecord {
    PasswordRecoveryDeliveryRecord {
        id: delivery.id,
        account_id,
        kind,
        recipient,
        ciphertext: delivery.ciphertext,
        nonce: delivery.nonce,
        key_version: delivery.key_version,
        attempt_count: 0,
        last_attempt_at: None,
        claim_id: None,
        claimed_at: None,
        next_attempt_at: created_at,
        expires_at: delivery.expires_at,
        sent_at: None,
        provider_message_id: None,
        failed_at: None,
        last_error_code: None,
        created_at,
    }
}

#[async_trait]
/// In-memory implementation of every catalog operation used by server tests.
impl CatalogBackend for MockCatalog {
    /// Store the first invite application for a normalized email.
    async fn create_account_invite_request(
        &self,
        record: AccountInviteRequestRecord,
    ) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        state
            .account_invite_requests
            .entry(record.normalized_email.clone())
            .or_insert(record);
        Ok(())
    }

    /// List invite applications after checking the mock administrator role.
    async fn list_account_invite_requests(
        &self,
        actor_account_id: uuid::Uuid,
        status: Option<AccountInviteStatus>,
        limit: u32,
    ) -> Result<Vec<AccountInviteRequestRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        require_mock_administrator(&state, actor_account_id, "account_invite_request")?;
        let mut records: Vec<_> = state
            .account_invite_requests
            .values()
            .filter(|record| status.is_none_or(|status| record.status == status))
            .cloned()
            .collect();
        records.sort_by_key(|record| (record.created_at, record.id));
        records.truncate(limit as usize);
        Ok(records)
    }

    /// Transition one mock invite application under administrator authority.
    async fn review_account_invite_request(
        &self,
        request: AccountInviteReviewRequest,
    ) -> Result<AccountInviteRequestRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        require_mock_administrator(&state, request.actor_account_id, "account_invite_request")?;
        let record = state
            .account_invite_requests
            .values_mut()
            .find(|record| record.id == request.request_id)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account_invite_request",
                key: request.request_id.to_string(),
            })?;
        if record.status == AccountInviteStatus::Invited
            || request.status == AccountInviteStatus::Invited
        {
            return Err(CatalogError::Conflict {
                kind: "account_invite_request",
                key: request.request_id.to_string(),
            });
        }
        record.status = request.status;
        record.updated_at = Utc::now();
        Ok(record.clone())
    }

    /// Issue one mock invitation and mark the application invited atomically.
    async fn issue_account_invite(
        &self,
        request: AccountInviteIssueRequest,
    ) -> Result<AccountInviteRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        require_mock_administrator(&state, request.actor_account_id, "account_invite")?;
        let application = state
            .account_invite_requests
            .values_mut()
            .find(|record| record.id == request.request_id)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account_invite_request",
                key: request.request_id.to_string(),
            })?;
        if !matches!(
            application.status,
            AccountInviteStatus::Pending | AccountInviteStatus::Reviewing
        ) {
            return Err(CatalogError::Conflict {
                kind: "account_invite_request",
                key: request.request_id.to_string(),
            });
        }
        application.status = AccountInviteStatus::Invited;
        application.updated_at = request.created_at;
        let invite = AccountInviteRecord {
            id: request.id,
            request_id: Some(request.request_id),
            normalized_email: application.normalized_email.clone(),
            token_digest: request.token_digest,
            issued_by_account_id: Some(request.actor_account_id),
            is_bootstrap: false,
            expires_at: request.expires_at,
            consumed_at: None,
            revoked_at: None,
            created_at: request.created_at,
        };
        state.account_invites.insert(invite.id, invite.clone());
        Ok(invite)
    }

    /// Redeem one mock invitation into an account, credential, and session.
    async fn register_local_account(
        &self,
        request: LocalAccountRegistrationRequest,
    ) -> Result<LocalAccountRegistrationResult, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let invitation_id = state
            .account_invites
            .values()
            .find(|invite| invite.token_digest == request.invite_token_digest)
            .filter(|invite| {
                invite.consumed_at.is_none()
                    && invite.revoked_at.is_none()
                    && invite.expires_at > request.account.created_at
            })
            .ok_or_else(|| CatalogError::Unauthorized {
                kind: "account_invite",
                key: "invalid-or-expired".to_string(),
            })?
            .id;
        let invitation = state.account_invites.get(&invitation_id).unwrap();
        if invitation.normalized_email != request.credential.normalized_email {
            return Err(CatalogError::Unauthorized {
                kind: "account_invite",
                key: "email-mismatch".to_string(),
            });
        }
        let identity = (
            request.account.issuer.clone(),
            request.account.subject.clone(),
        );
        if state.accounts.contains_key(&request.account.id)
            || state
                .account_password_credentials
                .contains_key(&request.credential.normalized_email)
        {
            return Err(CatalogError::Conflict {
                kind: "account",
                key: request.account.id.to_string(),
            });
        }
        state
            .account_invites
            .get_mut(&invitation_id)
            .unwrap()
            .consumed_at = Some(request.account.created_at);
        state.account_subjects.insert(identity, request.account.id);
        state
            .accounts
            .insert(request.account.id, request.account.clone());
        state.account_password_credentials.insert(
            request.credential.normalized_email.clone(),
            request.credential,
        );
        let session = insert_mock_session_issuance(&mut state, request.session)?;
        state.account_auth_audit_events.push(request.audit_event);
        Ok(LocalAccountRegistrationResult {
            account: request.account,
            session,
        })
    }

    /// Retrieve one mock first-party password credential.
    async fn get_account_password_credential(
        &self,
        normalized_email: &str,
    ) -> Result<AccountPasswordCredentialRecord, CatalogError> {
        self.state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?
            .account_password_credentials
            .get(normalized_email)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account_password_credential",
                key: normalized_email.to_string(),
            })
    }

    /// Conditionally replace one unchanged mock credential hash.
    async fn rehash_account_password_credential(
        &self,
        request: AccountPasswordRehashRequest,
    ) -> Result<bool, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let Some(credential) = state
            .account_password_credentials
            .get_mut(&request.normalized_email)
        else {
            return Ok(false);
        };
        if credential.account_id != request.account_id
            || credential.password_hash != request.expected_password_hash
            || credential.password_version != request.expected_password_version
            || credential.pepper_version != request.expected_pepper_version
            || credential.updated_at != request.expected_updated_at
        {
            return Ok(false);
        }
        credential.password_hash = request.new_password_hash;
        credential.password_version = request.new_password_version;
        credential.pepper_version = request.new_pepper_version;
        credential.updated_at = request.updated_at;
        Ok(true)
    }

    /// Atomically create one eligible mock reset token and encrypted delivery.
    async fn enqueue_account_password_recovery(
        &self,
        request: PasswordRecoveryEnqueueRequest,
    ) -> Result<bool, CatalogError> {
        let delay = self
            .password_recovery_enqueue_delays
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?
            .get(&request.normalized_email)
            .copied();
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let Some(credential) = state
            .account_password_credentials
            .get(&request.normalized_email)
            .cloned()
        else {
            return Ok(false);
        };
        let eligible = credential.email_verified_at.is_some()
            && state
                .accounts
                .get(&credential.account_id)
                .is_some_and(|account| account.status == AccountStatus::Active);
        if !eligible
            || state.password_recovery_tokens.values().any(|token| {
                token.account_id == credential.account_id
                    && token.created_at > request.cooldown_cutoff
            })
        {
            return Ok(false);
        }
        if state
            .password_recovery_tokens
            .contains_key(&request.token_id)
            || state
                .password_recovery_deliveries
                .contains_key(&request.delivery.id)
        {
            return Err(CatalogError::Conflict {
                kind: "password_recovery",
                key: request.token_id.to_string(),
            });
        }

        for token in state.password_recovery_tokens.values_mut() {
            if token.account_id == credential.account_id
                && token.consumed_at.is_none()
                && token.revoked_at.is_none()
            {
                token.revoked_at = Some(request.requested_at);
            }
        }
        let token = MockPasswordRecoveryToken {
            id: request.token_id,
            account_id: credential.account_id,
            token_digest: request.token_digest,
            expires_at: request.token_expires_at,
            consumed_at: None,
            revoked_at: None,
            created_at: request.requested_at,
        };
        let delivery = mock_recovery_delivery(
            credential.account_id,
            credential.normalized_email,
            PasswordRecoveryDeliveryKind::Reset,
            request.delivery,
            request.requested_at,
        );
        state.password_recovery_tokens.insert(token.id, token);
        state
            .password_recovery_deliveries
            .insert(delivery.id, delivery);
        Ok(true)
    }

    /// Atomically consume one mock token, replace its password, revoke sessions, and enqueue notice.
    async fn complete_account_password_recovery(
        &self,
        request: PasswordRecoveryCompletionRequest,
    ) -> Result<bool, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let Some(token) = state
            .password_recovery_tokens
            .values()
            .find(|token| token.token_digest == request.token_digest)
            .cloned()
        else {
            return Ok(false);
        };
        if token.consumed_at.is_some()
            || token.revoked_at.is_some()
            || token.expires_at <= request.completed_at
            || !state
                .accounts
                .get(&token.account_id)
                .is_some_and(|account| account.status == AccountStatus::Active)
        {
            return Ok(false);
        }
        let Some(normalized_email) = state
            .account_password_credentials
            .iter()
            .find(|(_, credential)| {
                credential.account_id == token.account_id && credential.email_verified_at.is_some()
            })
            .map(|(email, _)| email.clone())
        else {
            return Ok(false);
        };
        if state
            .password_recovery_deliveries
            .contains_key(&request.delivery.id)
        {
            return Err(CatalogError::Conflict {
                kind: "password_recovery_delivery",
                key: request.delivery.id.to_string(),
            });
        }

        for candidate in state.password_recovery_tokens.values_mut() {
            if candidate.account_id != token.account_id {
                continue;
            }
            if candidate.id == token.id {
                candidate.consumed_at = Some(request.completed_at);
            } else if candidate.consumed_at.is_none() && candidate.revoked_at.is_none() {
                candidate.revoked_at = Some(request.completed_at);
            }
        }
        let credential = state
            .account_password_credentials
            .get_mut(&normalized_email)
            .expect("credential identity was resolved while holding the write lock");
        credential.password_hash = request.new_password_hash;
        credential.password_version = request.new_password_version;
        credential.pepper_version = request.new_pepper_version;
        credential.password_changed_at = request.completed_at;
        credential.updated_at = request.completed_at;
        for session in state.account_sessions.values_mut() {
            if session.account_id == token.account_id && session.revoked_at.is_none() {
                session.revoked_at = Some(request.completed_at);
            }
        }
        let delivery = mock_recovery_delivery(
            token.account_id,
            normalized_email,
            PasswordRecoveryDeliveryKind::PasswordChanged,
            request.delivery,
            request.completed_at,
        );
        state
            .password_recovery_deliveries
            .insert(delivery.id, delivery);
        Ok(true)
    }

    /// Lease a bounded deterministic batch of ready mock recovery deliveries.
    async fn claim_password_recovery_deliveries(
        &self,
        request: PasswordRecoveryDeliveryClaimRequest,
    ) -> Result<Vec<PasswordRecoveryDeliveryRecord>, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let mut ids: Vec<_> = state
            .password_recovery_deliveries
            .values()
            .filter(|delivery| {
                delivery.sent_at.is_none()
                    && delivery.failed_at.is_none()
                    && delivery.expires_at > request.claimed_at
                    && delivery.next_attempt_at <= request.claimed_at
                    && (delivery.claim_id.is_none()
                        || delivery
                            .claimed_at
                            .is_some_and(|claimed_at| claimed_at <= request.stale_before))
            })
            .map(|delivery| delivery.id)
            .collect();
        ids.sort_by_key(|id| {
            let delivery = &state.password_recovery_deliveries[id];
            (delivery.next_attempt_at, delivery.created_at, delivery.id)
        });
        ids.truncate(request.limit as usize);

        let mut claimed = Vec::with_capacity(ids.len());
        for id in ids {
            let delivery = state.password_recovery_deliveries.get_mut(&id).unwrap();
            delivery.claim_id = Some(request.claim_id);
            delivery.claimed_at = Some(request.claimed_at);
            delivery.last_attempt_at = Some(request.claimed_at);
            delivery.attempt_count = delivery.attempt_count.saturating_add(1);
            claimed.push(delivery.clone());
        }
        Ok(claimed)
    }

    /// Acknowledge one successful mock delivery under its exact claim fence.
    async fn mark_password_recovery_delivery_sent(
        &self,
        delivery_id: uuid::Uuid,
        claim_id: uuid::Uuid,
        sent_at: DateTime<Utc>,
        provider_message_id: String,
    ) -> Result<bool, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let Some(delivery) = state.password_recovery_deliveries.get_mut(&delivery_id) else {
            return Ok(false);
        };
        if delivery.claim_id != Some(claim_id)
            || delivery.sent_at.is_some()
            || delivery.failed_at.is_some()
        {
            return Ok(false);
        }
        delivery.claim_id = None;
        delivery.claimed_at = None;
        delivery.sent_at = Some(sent_at);
        delivery.provider_message_id = Some(provider_message_id);
        delivery.last_error_code = None;
        Ok(true)
    }

    /// Release one mock delivery claim for a scheduled retry.
    async fn retry_password_recovery_delivery(
        &self,
        delivery_id: uuid::Uuid,
        claim_id: uuid::Uuid,
        next_attempt_at: DateTime<Utc>,
        last_error_code: String,
    ) -> Result<bool, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let Some(delivery) = state.password_recovery_deliveries.get_mut(&delivery_id) else {
            return Ok(false);
        };
        if delivery.claim_id != Some(claim_id)
            || delivery.sent_at.is_some()
            || delivery.failed_at.is_some()
        {
            return Ok(false);
        }
        delivery.claim_id = None;
        delivery.claimed_at = None;
        delivery.next_attempt_at = next_attempt_at;
        delivery.last_error_code = Some(last_error_code);
        Ok(true)
    }

    /// Mark one mock delivery terminal under its exact claim fence.
    async fn fail_password_recovery_delivery(
        &self,
        delivery_id: uuid::Uuid,
        claim_id: uuid::Uuid,
        failed_at: DateTime<Utc>,
        last_error_code: String,
    ) -> Result<bool, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let Some(delivery) = state.password_recovery_deliveries.get_mut(&delivery_id) else {
            return Ok(false);
        };
        if delivery.claim_id != Some(claim_id)
            || delivery.sent_at.is_some()
            || delivery.failed_at.is_some()
        {
            return Ok(false);
        }
        delivery.claim_id = None;
        delivery.claimed_at = None;
        delivery.failed_at = Some(failed_at);
        delivery.last_error_code = Some(last_error_code);
        Ok(true)
    }

    /// Create one mock first-party session.
    async fn create_account_session(
        &self,
        request: AccountSessionCreationRequest,
    ) -> Result<AccountSessionRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let session = insert_mock_session_issuance(&mut state, request.issuance)?;
        state.account_auth_audit_events.push(request.audit_event);
        Ok(session)
    }

    /// Resolve one active mock first-party session.
    async fn get_active_account_session(
        &self,
        token_digest: &[u8],
        now: DateTime<Utc>,
    ) -> Result<AccountSessionRecord, CatalogError> {
        self.state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?
            .account_sessions
            .values()
            .find(|session| {
                session.token_digest == token_digest
                    && session.revoked_at.is_none()
                    && session.access_expires_at > now
                    && session.idle_expires_at > now
                    && session.absolute_expires_at > now
            })
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account_session",
                key: "opaque-token".to_string(),
            })
    }

    /// Advance one active mock session.
    async fn touch_account_session(
        &self,
        session_id: uuid::Uuid,
        last_seen_at: DateTime<Utc>,
        idle_expires_at: DateTime<Utc>,
    ) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let session =
            state
                .account_sessions
                .get_mut(&session_id)
                .ok_or_else(|| CatalogError::NotFound {
                    kind: "account_session",
                    key: session_id.to_string(),
                })?;
        session.last_seen_at = last_seen_at;
        session.idle_expires_at = idle_expires_at;
        Ok(())
    }

    /// Revoke one mock session belonging to the authenticated account.
    async fn revoke_account_session(
        &self,
        session_id: uuid::Uuid,
        account_id: uuid::Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let session = state
            .account_sessions
            .get_mut(&session_id)
            .filter(|session| session.account_id == account_id)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account_session",
                key: session_id.to_string(),
            })?;
        session.revoked_at = Some(revoked_at);
        Ok(())
    }

    /// Rotate one mock refresh generation or revoke its family after replay.
    async fn refresh_account_session(
        &self,
        request: AccountSessionRefreshRequest,
    ) -> Result<AccountSessionRefreshResult, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let Some(refresh) = state
            .account_refresh_tokens
            .get(&request.presented_refresh_token_digest)
            .cloned()
        else {
            return Ok(AccountSessionRefreshResult::Rejected);
        };
        let Some(session) = state.account_sessions.get(&refresh.session_id).cloned() else {
            return Ok(AccountSessionRefreshResult::Rejected);
        };

        if refresh.consumed_at.is_some() {
            if let Some(stored_session) = state.account_sessions.get_mut(&session.id) {
                stored_session.revoked_at.get_or_insert(request.rotated_at);
            }
            state
                .account_auth_audit_events
                .push(request.replay_audit_event);
            return Ok(AccountSessionRefreshResult::ReplayRevoked);
        }
        if refresh.expires_at <= request.rotated_at
            || !mock_account_is_active(&state, session.account_id)
            || session.revoked_at.is_some()
            || session.idle_expires_at <= request.rotated_at
            || session.absolute_expires_at <= request.rotated_at
            || request.replacement_access_expires_at > session.absolute_expires_at
            || request.replacement_idle_expires_at > session.absolute_expires_at
            || request.replacement_refresh_expires_at > session.absolute_expires_at
        {
            return Ok(AccountSessionRefreshResult::Rejected);
        }
        if state
            .account_refresh_tokens
            .contains_key(&request.replacement_refresh_token_digest)
            || state
                .account_refresh_tokens
                .values()
                .any(|token| token.id == request.replacement_refresh_token_id)
        {
            return Err(CatalogError::Conflict {
                kind: "account_session_refresh",
                key: request.replacement_refresh_token_id.to_string(),
            });
        }

        state
            .account_refresh_tokens
            .get_mut(&request.presented_refresh_token_digest)
            .expect("refresh generation was resolved while holding the write lock")
            .consumed_at = Some(request.rotated_at);
        let replacement = MockRefreshToken {
            id: request.replacement_refresh_token_id,
            session_id: session.id,
            token_digest: request.replacement_refresh_token_digest,
            expires_at: request.replacement_refresh_expires_at,
            consumed_at: None,
        };
        state
            .account_refresh_tokens
            .insert(replacement.token_digest.clone(), replacement);
        let stored_session = state
            .account_sessions
            .get_mut(&session.id)
            .expect("session was resolved while holding the write lock");
        stored_session.token_digest = request.replacement_access_token_digest;
        stored_session.last_seen_at = request.rotated_at;
        stored_session.access_expires_at = request.replacement_access_expires_at;
        stored_session.idle_expires_at = request.replacement_idle_expires_at;
        let rotated = stored_session.clone();
        state
            .account_auth_audit_events
            .push(request.success_audit_event);
        Ok(AccountSessionRefreshResult::Rotated(rotated))
    }

    /// Retrieve the active mock authenticator for one account.
    async fn get_active_account_mfa_authenticator(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<AccountMfaAuthenticatorRecord, CatalogError> {
        self.state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?
            .account_mfa_authenticators
            .values()
            .find(|authenticator| {
                authenticator.account_id == account_id
                    && authenticator.state == AccountMfaAuthenticatorState::Active
            })
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account_mfa_authenticator",
                key: account_id.to_string(),
            })
    }

    /// Retrieve one exact unexpired pending mock authenticator.
    async fn get_pending_account_mfa_authenticator(
        &self,
        account_id: uuid::Uuid,
        authenticator_id: uuid::Uuid,
        now: DateTime<Utc>,
    ) -> Result<AccountMfaAuthenticatorRecord, CatalogError> {
        self.state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?
            .account_mfa_authenticators
            .get(&authenticator_id)
            .filter(|authenticator| {
                authenticator.account_id == account_id
                    && authenticator.state == AccountMfaAuthenticatorState::Pending
                    && authenticator
                        .pending_expires_at
                        .is_some_and(|expires_at| expires_at > now)
            })
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "account_mfa_authenticator",
                key: authenticator_id.to_string(),
            })
    }

    /// Replace pending mock enrollment state and retain its success audit.
    async fn begin_account_mfa_enrollment(
        &self,
        request: AccountMfaEnrollmentRequest,
    ) -> Result<AccountMfaAuthenticatorRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if !mock_account_is_active(&state, request.authenticator.account_id) {
            return Err(CatalogError::Unauthorized {
                kind: "account_mfa_authenticator",
                key: request.authenticator.account_id.to_string(),
            });
        }
        for authenticator in state.account_mfa_authenticators.values_mut() {
            if authenticator.account_id == request.authenticator.account_id
                && authenticator.state == AccountMfaAuthenticatorState::Pending
            {
                authenticator.state = AccountMfaAuthenticatorState::Disabled;
                authenticator.pending_expires_at = None;
                authenticator.disabled_at = Some(request.authenticator.created_at);
            }
        }
        let authenticator = request.authenticator;
        state
            .account_mfa_authenticators
            .insert(authenticator.id, authenticator.clone());
        state.account_auth_audit_events.push(request.audit_event);
        Ok(authenticator)
    }

    /// Activate one pending mock authenticator and replace its recovery codes.
    async fn activate_account_mfa(
        &self,
        request: AccountMfaActivationRequest,
    ) -> Result<AccountMfaAuthenticatorRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let pending_is_valid = state
            .account_mfa_authenticators
            .get(&request.authenticator_id)
            .is_some_and(|authenticator| {
                authenticator.account_id == request.account_id
                    && authenticator.state == AccountMfaAuthenticatorState::Pending
                    && authenticator
                        .pending_expires_at
                        .is_some_and(|expires_at| expires_at > request.activated_at)
                    && authenticator
                        .last_used_timestep
                        .is_none_or(|timestep| request.verified_timestep > timestep)
            });
        if !pending_is_valid || !mock_account_is_active(&state, request.account_id) {
            return Err(CatalogError::Unauthorized {
                kind: "account_mfa_authenticator",
                key: request.authenticator_id.to_string(),
            });
        }
        for authenticator in state.account_mfa_authenticators.values_mut() {
            if authenticator.account_id == request.account_id
                && authenticator.state == AccountMfaAuthenticatorState::Active
            {
                authenticator.state = AccountMfaAuthenticatorState::Disabled;
                authenticator.disabled_at = Some(request.activated_at);
            }
        }
        let authenticator = state
            .account_mfa_authenticators
            .get_mut(&request.authenticator_id)
            .expect("pending authenticator was resolved while holding the write lock");
        authenticator.state = AccountMfaAuthenticatorState::Active;
        authenticator.pending_expires_at = None;
        authenticator.last_used_timestep = Some(request.verified_timestep);
        authenticator.activated_at = Some(request.activated_at);
        let activated = authenticator.clone();
        state
            .account_mfa_recovery_codes
            .retain(|_, code| code.account_id != request.account_id);
        for seed in request.recovery_codes {
            state.account_mfa_recovery_codes.insert(
                seed.code_digest,
                MockMfaRecoveryCode {
                    authenticator_id: request.authenticator_id,
                    account_id: request.account_id,
                    consumed_at: None,
                },
            );
        }
        state.account_auth_audit_events.push(request.audit_event);
        Ok(activated)
    }

    /// Disable active mock MFA unless a platform role requires it.
    async fn disable_account_mfa(
        &self,
        request: AccountMfaDisableRequest,
    ) -> Result<bool, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if state.platform_roles.iter().any(|role| {
            role.account_id == request.account_id && role.state == PlatformRoleState::Active
        }) {
            return Err(CatalogError::Validation(
                "active privileged roles require MFA".to_string(),
            ));
        }
        let mut disabled = false;
        for authenticator in state.account_mfa_authenticators.values_mut() {
            if authenticator.account_id == request.account_id
                && authenticator.state == AccountMfaAuthenticatorState::Active
            {
                authenticator.state = AccountMfaAuthenticatorState::Disabled;
                authenticator.disabled_at = Some(request.disabled_at);
                disabled = true;
            }
        }
        if disabled {
            state.account_auth_audit_events.push(request.audit_event);
        }
        Ok(disabled)
    }

    /// Create one digest-only mock MFA login challenge.
    async fn create_account_mfa_challenge(
        &self,
        request: AccountMfaChallengeCreationRequest,
    ) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let active_authenticator_count = state
            .account_mfa_authenticators
            .values()
            .filter(|authenticator| {
                authenticator.account_id == request.challenge.account_id
                    && authenticator.state == AccountMfaAuthenticatorState::Active
            })
            .count();
        if !mock_account_is_active(&state, request.challenge.account_id)
            || active_authenticator_count != 1
        {
            return Err(CatalogError::Unauthorized {
                kind: "account_mfa_authenticator",
                key: request.challenge.account_id.to_string(),
            });
        }
        if state
            .account_mfa_challenges
            .contains_key(&request.challenge.token_digest)
        {
            return Err(CatalogError::Conflict {
                kind: "account_mfa_challenge",
                key: request.challenge.id.to_string(),
            });
        }
        state
            .account_mfa_challenges
            .insert(request.challenge.token_digest.clone(), request.challenge);
        state.account_auth_audit_events.push(request.audit_event);
        Ok(())
    }

    /// Consume one mock MFA challenge and issue a verified session family.
    async fn complete_account_mfa_challenge(
        &self,
        request: AccountMfaChallengeCompletionRequest,
    ) -> Result<AccountMfaChallengeCompletionResult, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let Some(challenge) = state
            .account_mfa_challenges
            .get(&request.challenge_token_digest)
            .cloned()
        else {
            return Ok(AccountMfaChallengeCompletionResult::Rejected);
        };
        let Some(authenticator) = state
            .account_mfa_authenticators
            .get(&request.authenticator_id)
            .cloned()
        else {
            return Ok(AccountMfaChallengeCompletionResult::Rejected);
        };
        if challenge.consumed_at.is_some()
            || challenge.expires_at <= request.completed_at
            || challenge.account_id != request.issuance.session.account_id
            || challenge.client_kind != request.issuance.session.client_kind
            || !mock_account_is_active(&state, challenge.account_id)
            || authenticator.account_id != challenge.account_id
            || authenticator.state != AccountMfaAuthenticatorState::Active
            || request.issuance.session.mfa_verified_at != Some(request.completed_at)
        {
            return Ok(AccountMfaChallengeCompletionResult::Rejected);
        }

        match &request.proof {
            AccountMfaChallengeProof::TotpTimestep(timestep) => {
                if *timestep < 0
                    || authenticator
                        .last_used_timestep
                        .is_some_and(|last_used| *timestep <= last_used)
                {
                    return Ok(AccountMfaChallengeCompletionResult::Rejected);
                }
            }
            AccountMfaChallengeProof::RecoveryCodeDigest(digest) => {
                let usable = state
                    .account_mfa_recovery_codes
                    .get(digest)
                    .is_some_and(|code| {
                        code.authenticator_id == authenticator.id
                            && code.account_id == challenge.account_id
                            && code.consumed_at.is_none()
                    });
                if !usable {
                    return Ok(AccountMfaChallengeCompletionResult::Rejected);
                }
            }
        }
        if state
            .account_sessions
            .contains_key(&request.issuance.session.id)
            || state
                .account_refresh_tokens
                .contains_key(&request.issuance.refresh_token_digest)
        {
            return Err(CatalogError::Conflict {
                kind: "account_session",
                key: request.issuance.session.id.to_string(),
            });
        }

        match &request.proof {
            AccountMfaChallengeProof::TotpTimestep(timestep) => {
                state
                    .account_mfa_authenticators
                    .get_mut(&authenticator.id)
                    .expect("active authenticator was resolved while holding the write lock")
                    .last_used_timestep = Some(*timestep);
            }
            AccountMfaChallengeProof::RecoveryCodeDigest(digest) => {
                state
                    .account_mfa_recovery_codes
                    .get_mut(digest)
                    .expect("recovery code was resolved while holding the write lock")
                    .consumed_at = Some(request.completed_at);
            }
        }
        state
            .account_mfa_challenges
            .get_mut(&request.challenge_token_digest)
            .expect("MFA challenge was resolved while holding the write lock")
            .consumed_at = Some(request.completed_at);
        let session = insert_mock_session_issuance(&mut state, request.issuance)?;
        state.account_auth_audit_events.push(request.audit_event);
        Ok(AccountMfaChallengeCompletionResult::Completed(session))
    }

    /// Create one exactly bound digest-only mock native authorization code.
    async fn create_native_authorization_code(
        &self,
        request: NativeAuthorizationCodeCreationRequest,
    ) -> Result<(), CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if !mock_account_is_active(&state, request.code.account_id) {
            return Err(CatalogError::Unauthorized {
                kind: "native_authorization_code",
                key: request.code.account_id.to_string(),
            });
        }
        if state
            .native_authorization_codes
            .contains_key(&request.code.token_digest)
        {
            return Err(CatalogError::Conflict {
                kind: "native_authorization_code",
                key: request.code.id.to_string(),
            });
        }
        state
            .native_authorization_codes
            .insert(request.code.token_digest.clone(), request.code);
        state.account_auth_audit_events.push(request.audit_event);
        Ok(())
    }

    /// Exchange one exactly bound mock native code for a session family.
    async fn exchange_native_authorization_code(
        &self,
        request: NativeAuthorizationCodeExchangeRequest,
    ) -> Result<NativeAuthorizationCodeExchangeResult, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let Some(code) = state
            .native_authorization_codes
            .get(&request.code_token_digest)
            .cloned()
        else {
            return Ok(NativeAuthorizationCodeExchangeResult::Rejected);
        };
        if code.consumed_at.is_some()
            || code.expires_at <= request.exchanged_at
            || code.client_kind == AccountSessionClientKind::Browser
            || code.client_kind != request.client_kind
            || code.redirect_uri != request.redirect_uri
            || code.pkce_challenge != request.pkce_challenge
            || code.account_id != request.issuance.session.account_id
            || code.mfa_verified_at != request.issuance.session.mfa_verified_at
            || !mock_account_is_active(&state, code.account_id)
        {
            return Ok(NativeAuthorizationCodeExchangeResult::Rejected);
        }
        state
            .native_authorization_codes
            .get_mut(&request.code_token_digest)
            .expect("native code was resolved while holding the write lock")
            .consumed_at = Some(request.exchanged_at);
        let session = insert_mock_session_issuance(&mut state, request.issuance)?;
        state.account_auth_audit_events.push(request.audit_event);
        Ok(NativeAuthorizationCodeExchangeResult::Exchanged(session))
    }

    /// Append one sanitized mock authentication audit event.
    async fn append_account_auth_audit_event(
        &self,
        event: AccountAuthAuditEventRecord,
    ) -> Result<(), CatalogError> {
        self.state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?
            .account_auth_audit_events
            .push(event);
        Ok(())
    }

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

    /// List all versions for a pack in stable publication order.
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
        let mut versions: Vec<_> = state
            .versions
            .values()
            .filter(|v| v.pack_name == name)
            .cloned()
            .collect();
        versions.sort_by(|left, right| {
            left.published_at
                .cmp(&right.published_at)
                .then_with(|| left.version.cmp(&right.version))
        });
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

    /// Return the configured bounded moderation snapshot for operations tests.
    async fn publication_moderation_snapshot(
        &self,
    ) -> Result<Option<PublicationModerationSnapshot>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        Ok(state.publication_moderation_snapshot.clone())
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

    /// Grant or reactivate one platform role under administrator authority.
    async fn assign_account_platform_role(
        &self,
        request: PlatformRoleAssignmentRequest,
    ) -> Result<PlatformRoleRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        require_mock_administrator(&state, request.actor_account_id, "platform_role")?;
        if !state.accounts.contains_key(&request.account_id) {
            return Err(CatalogError::NotFound {
                kind: "account",
                key: request.account_id.to_string(),
            });
        }
        let now = Utc::now();
        if let Some(existing) = state
            .platform_roles
            .iter_mut()
            .find(|record| record.account_id == request.account_id && record.role == request.role)
        {
            if existing.state == PlatformRoleState::Active {
                return Ok(existing.clone());
            }
            existing.state = PlatformRoleState::Active;
            existing.assigned_by_account_id = request.actor_account_id;
            existing.updated_at = now;
            return Ok(existing.clone());
        }
        let record = PlatformRoleRecord {
            account_id: request.account_id,
            role: request.role,
            state: PlatformRoleState::Active,
            assigned_by_account_id: request.actor_account_id,
            created_at: now,
            updated_at: now,
        };
        state.platform_roles.push(record.clone());
        Ok(record)
    }

    /// Revoke one platform role, preserving the assignment for audit.
    async fn revoke_account_platform_role(
        &self,
        request: PlatformRoleRevocationRequest,
    ) -> Result<PlatformRoleRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        require_mock_administrator(&state, request.actor_account_id, "platform_role")?;
        let coverage = mock_administrator_coverage(&state);
        let existing_state = state
            .platform_roles
            .iter()
            .find(|record| record.account_id == request.account_id && record.role == request.role)
            .map(|record| record.state)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "platform_role",
                key: request.account_id.to_string(),
            })?;
        if existing_state == PlatformRoleState::Revoked {
            return Ok(state
                .platform_roles
                .iter()
                .find(|record| {
                    record.account_id == request.account_id && record.role == request.role
                })
                .cloned()
                .expect("revoked role was located above"));
        }
        if request.role == PlatformRole::Administrator && coverage <= 1 {
            return Err(CatalogError::Validation(
                "cannot revoke the last active administrator".to_string(),
            ));
        }
        let record = state
            .platform_roles
            .iter_mut()
            .find(|record| record.account_id == request.account_id && record.role == request.role)
            .expect("active role was located above");
        record.state = PlatformRoleState::Revoked;
        record.updated_at = Utc::now();
        Ok(record.clone())
    }

    /// Transition one account's status under administrator authority.
    async fn set_account_status(
        &self,
        request: AccountStatusChangeRequest,
    ) -> Result<AccountRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        require_mock_administrator(&state, request.actor_account_id, "account_status")?;
        let coverage = mock_administrator_coverage(&state);
        let holds_administrator = state.platform_roles.iter().any(|record| {
            record.account_id == request.account_id
                && record.role == PlatformRole::Administrator
                && record.state == PlatformRoleState::Active
        });
        let account =
            state
                .accounts
                .get_mut(&request.account_id)
                .ok_or_else(|| CatalogError::NotFound {
                    kind: "account",
                    key: request.account_id.to_string(),
                })?;
        if account.status == request.status {
            return Ok(account.clone());
        }
        if request.status != AccountStatus::Active && holds_administrator && coverage <= 1 {
            return Err(CatalogError::Validation(
                "cannot suspend or disable the last active administrator".to_string(),
            ));
        }
        account.status = request.status;
        account.updated_at = Utc::now();
        Ok(account.clone())
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

    /// File one owner-authenticated appeal against an adverse moderation decision.
    async fn file_publication_appeal(
        &self,
        request: PublicationAppealRequest,
    ) -> Result<PublicationAppealRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let exact_retry = |record: &PublicationAppealRecord| {
            record.id == request.id
                && record.decision_id == request.decision_id
                && record.publisher_id == request.publisher_id
                && record.actor_account_id == request.actor_account_id
                && record.statement == request.statement
                && record.request_id == request.request_id
        };
        if let Some(existing) = state.publication_appeals.values().find(|record| {
            record.id == request.id
                || record.decision_id == request.decision_id
                || record.request_id == request.request_id
        }) {
            return if exact_retry(existing) {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_appeal",
                    key: request.id.to_string(),
                })
            };
        }
        if request.statement.trim().is_empty() || request.statement.chars().count() > 4_000 {
            return Err(CatalogError::InvalidArgument(
                "publication appeal statement must be non-blank and at most 4000 characters"
                    .to_string(),
            ));
        }
        let active_owner = mock_active_account(&state, request.actor_account_id)
            && state.publisher_memberships.values().any(|membership| {
                membership.account_id == request.actor_account_id
                    && membership.publisher_id == request.publisher_id
                    && membership.role == PublisherRole::Owner
                    && membership.state == MembershipState::Active
            });
        if !active_owner {
            return Err(CatalogError::Unauthorized {
                kind: "publication_appeal",
                key: request.id.to_string(),
            });
        }
        let decision = state
            .publication_moderation_decisions
            .get(&request.decision_id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publication_moderation_decision",
                key: request.decision_id.to_string(),
            })?;
        if !matches!(
            decision.action,
            PublicationModerationAction::RequestChanges | PublicationModerationAction::Reject
        ) {
            return Err(CatalogError::Conflict {
                kind: "publication_moderation_decision",
                key: request.decision_id.to_string(),
            });
        }
        let submission = state
            .publication_submissions
            .get(&decision.submission_id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publication_submission",
                key: decision.submission_id.to_string(),
            })?;
        if submission.publisher_id != request.publisher_id {
            return Err(CatalogError::Unauthorized {
                kind: "publication_appeal",
                key: request.id.to_string(),
            });
        }
        if submission.state != decision.to_state {
            return Err(CatalogError::Conflict {
                kind: "publication_submission",
                key: submission.id.to_string(),
            });
        }
        let created_at = Utc::now();
        let age = created_at.signed_duration_since(decision.created_at);
        if age < Duration::zero() || age > Duration::days(30) {
            return Err(CatalogError::Conflict {
                kind: "publication_appeal_deadline",
                key: request.decision_id.to_string(),
            });
        }
        let appeal = PublicationAppealRecord {
            id: request.id,
            decision_id: request.decision_id,
            submission_id: submission.id,
            publisher_id: submission.publisher_id,
            actor_account_id: request.actor_account_id,
            statement: request.statement,
            request_id: request.request_id,
            created_at,
        };
        state.publication_appeals.insert(appeal.id, appeal.clone());
        Ok(appeal)
    }

    /// Resolve one appeal under administrator and reviewer-separation policy.
    async fn resolve_publication_appeal(
        &self,
        request: PublicationAppealResolutionRequest,
    ) -> Result<PublicationAppealResolutionRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let exact_retry = |record: &PublicationAppealResolutionRecord| {
            record.id == request.id
                && record.appeal_id == request.appeal_id
                && record.actor_account_id == request.actor_account_id
                && record.disposition == request.disposition
                && record.rationale == request.rationale
                && record.separation_exception_reason == request.separation_exception_reason
                && record.request_id == request.request_id
        };
        if let Some(existing) = state
            .publication_appeal_resolutions
            .values()
            .find(|record| {
                record.id == request.id
                    || record.appeal_id == request.appeal_id
                    || record.request_id == request.request_id
            })
        {
            return if exact_retry(existing) {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_appeal_resolution",
                    key: request.id.to_string(),
                })
            };
        }
        if request.rationale.trim().is_empty() || request.rationale.chars().count() > 4_000 {
            return Err(CatalogError::InvalidArgument(
                "publication appeal rationale must be non-blank and at most 4000 characters"
                    .to_string(),
            ));
        }
        if request
            .separation_exception_reason
            .as_ref()
            .is_some_and(|reason| reason.trim().is_empty() || reason.chars().count() > 1_000)
        {
            return Err(CatalogError::InvalidArgument(
                "publication appeal separation_exception_reason must be non-blank and at most 1000 characters"
                    .to_string(),
            ));
        }
        if !mock_active_administrator(&state, request.actor_account_id) {
            return Err(CatalogError::Unauthorized {
                kind: "publication_appeal_resolution",
                key: request.id.to_string(),
            });
        }
        let appeal = state
            .publication_appeals
            .get(&request.appeal_id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publication_appeal",
                key: request.appeal_id.to_string(),
            })?;
        let decision = state
            .publication_moderation_decisions
            .get(&appeal.decision_id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publication_moderation_decision",
                key: appeal.decision_id.to_string(),
            })?;
        let self_resolution = request.actor_account_id == decision.actor_account_id;
        let another_administrator = state.platform_roles.iter().any(|role| {
            role.account_id != request.actor_account_id
                && role.role == PlatformRole::Administrator
                && role.state == PlatformRoleState::Active
                && mock_active_account(&state, role.account_id)
        });
        if self_resolution
            && (another_administrator || request.separation_exception_reason.is_none())
        {
            return Err(CatalogError::Unauthorized {
                kind: "publication_appeal_separation",
                key: request.appeal_id.to_string(),
            });
        }
        if !self_resolution && request.separation_exception_reason.is_some() {
            return Err(CatalogError::InvalidArgument(
                "separation_exception_reason is allowed only for unavoidable self-resolution"
                    .to_string(),
            ));
        }
        let submission = state
            .publication_submissions
            .get_mut(&appeal.submission_id)
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publication_submission",
                key: appeal.submission_id.to_string(),
            })?;
        if submission.state != decision.to_state {
            return Err(CatalogError::Conflict {
                kind: "publication_submission",
                key: submission.id.to_string(),
            });
        }
        let created_at = Utc::now();
        if request.disposition == PublicationAppealDisposition::Overturn {
            submission.state = PublicationSubmissionState::Approved;
            submission.updated_at = created_at;
        }
        let resolution = PublicationAppealResolutionRecord {
            id: request.id,
            appeal_id: request.appeal_id,
            actor_account_id: request.actor_account_id,
            disposition: request.disposition,
            rationale: request.rationale,
            separation_exception_reason: request.separation_exception_reason,
            request_id: request.request_id,
            created_at,
        };
        state
            .publication_appeal_resolutions
            .insert(resolution.id, resolution.clone());
        Ok(resolution)
    }

    /// List one publisher's private appeal cases for an owner or administrator.
    async fn list_publisher_publication_appeals(
        &self,
        actor_account_id: uuid::Uuid,
        publisher_id: uuid::Uuid,
        before: Option<PublicationAppealCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationAppealCaseRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let active_owner = mock_active_account(&state, actor_account_id)
            && state.publisher_memberships.values().any(|membership| {
                membership.account_id == actor_account_id
                    && membership.publisher_id == publisher_id
                    && membership.role == PublisherRole::Owner
                    && membership.state == MembershipState::Active
            });
        if !active_owner && !mock_active_administrator(&state, actor_account_id) {
            return Err(CatalogError::Unauthorized {
                kind: "publication_appeal",
                key: format!("{actor_account_id}:{publisher_id}"),
            });
        }
        Ok(mock_appeal_page(&state, Some(publisher_id), before, limit))
    }

    /// List global private appeal cases for an active administrator.
    async fn list_administrator_publication_appeals(
        &self,
        actor_account_id: uuid::Uuid,
        before: Option<PublicationAppealCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationAppealCaseRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if !mock_active_administrator(&state, actor_account_id) {
            return Err(CatalogError::Unauthorized {
                kind: "publication_appeal",
                key: actor_account_id.to_string(),
            });
        }
        Ok(mock_appeal_page(&state, None, before, limit))
    }

    /// Authorize and atomically activate one approved publication submission.
    async fn promote_publication_submission(
        &self,
        request: PublicationPromotionRequest,
        _quota: PublishQuota,
    ) -> Result<PublicationPromotionRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let exact_retry = |record: &PublicationPromotionRecord| {
            record.id == request.id
                && record.submission_id == request.submission_id
                && record.actor_account_id == request.actor_account_id
                && record.pack_name == request.version.pack_name
                && record.version == request.version.version
                && record.content_hash == request.version.content_hash
                && record.request_id == request.request_id
        };
        if let Some(existing) = state.publication_promotions.values().find(|record| {
            record.id == request.id
                || record.submission_id == request.submission_id
                || record.request_id == request.request_id
        }) {
            return if exact_retry(existing) {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_promotion",
                    key: request.id.to_string(),
                })
            };
        }
        if let Some(message) = &state.publication_promotion_error {
            return Err(CatalogError::BackendError(
                std::io::Error::other(message.clone()).into(),
            ));
        }

        let submission = state
            .publication_submissions
            .get(&request.submission_id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publication_submission",
                key: request.submission_id.to_string(),
            })?;
        let actor_is_active = state
            .accounts
            .get(&request.actor_account_id)
            .is_some_and(|account| account.status == AccountStatus::Active);
        let role_is_active = state.platform_roles.iter().any(|role| {
            role.account_id == request.actor_account_id
                && role.state == PlatformRoleState::Active
                && matches!(
                    role.role,
                    PlatformRole::Moderator | PlatformRole::Administrator
                )
        });
        let actor_is_owner = state.publisher_memberships.values().any(|membership| {
            membership.account_id == request.actor_account_id
                && membership.publisher_id == submission.publisher_id
                && membership.role == PublisherRole::Owner
                && membership.state == MembershipState::Active
        });
        let publisher_is_approved =
            state
                .publishers
                .get(&submission.publisher_id)
                .is_some_and(|publisher| {
                    publisher.moderation_status == PublisherModerationStatus::Approved
                });
        let key_is_active = state
            .publisher_keys
            .get(&submission.publisher_key_id)
            .is_some_and(|key| {
                key.publisher_id == submission.publisher_id
                    && key.state == PublisherKeyState::Active
                    && key.public_key == request.version.author_pubkey
            });
        if submission.state != PublicationSubmissionState::Approved
            || request.version.content_hash != submission.archive_hash
            || request.version.publisher_key_id != Some(submission.publisher_key_id)
        {
            return Err(CatalogError::Conflict {
                kind: "publication_submission",
                key: request.submission_id.to_string(),
            });
        }
        if !actor_is_active
            || !role_is_active
            || actor_is_owner
            || !publisher_is_approved
            || !key_is_active
        {
            return Err(CatalogError::Unauthorized {
                kind: "publication_promotion",
                key: request.id.to_string(),
            });
        }
        let version_key = (
            request.version.pack_name.clone(),
            request.version.version.clone(),
        );
        if state.versions.contains_key(&version_key) {
            return Err(CatalogError::Conflict {
                kind: "pack_version",
                key: format!("{}@{}", version_key.0, version_key.1),
            });
        }

        let now = Utc::now();
        let pack = state
            .packs
            .entry(request.version.pack_name.clone())
            .or_insert_with(|| PackRecord {
                name: request.version.pack_name.clone(),
                current_author: request.version.author_pubkey,
                publisher_id: Some(submission.publisher_id),
                tags: Vec::new(),
                description: String::new(),
                created_at: now,
                latest_version: None,
                total_downloads: 0,
                extends: None,
            });
        if pack.publisher_id != Some(submission.publisher_id) {
            return Err(CatalogError::Unauthorized {
                kind: "pack",
                key: request.version.pack_name,
            });
        }
        pack.latest_version = Some(request.version.version.clone());
        pack.description = request.description;
        pack.tags = request.tags;
        pack.extends = request.extends;
        state.versions.insert(version_key, request.version.clone());
        let promotion = PublicationPromotionRecord {
            id: request.id,
            submission_id: request.submission_id,
            actor_account_id: request.actor_account_id,
            pack_name: request.version.pack_name,
            version: request.version.version,
            content_hash: request.version.content_hash,
            request_id: request.request_id,
            created_at: now,
        };
        let stored_submission = state
            .publication_submissions
            .get_mut(&request.submission_id)
            .expect("validated publication submission must remain present");
        stored_submission.state = PublicationSubmissionState::Promoted;
        stored_submission.updated_at = now;
        state
            .publication_promotions
            .insert(promotion.id, promotion.clone());
        Ok(promotion)
    }

    /// Withdraw one non-public submission under active owner authority.
    async fn withdraw_publication_submission(
        &self,
        request: PublicationWithdrawalRequest,
    ) -> Result<PublicationLifecycleDecisionRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if let Some(existing) = state
            .publication_lifecycle_decisions
            .values()
            .find(|record| {
                record.id == request.id
                    || record.submission_id == Some(request.submission_id)
                    || record.request_id == request.request_id
            })
        {
            let exact = existing.id == request.id
                && existing.action == PublicationLifecycleAction::WithdrawSubmission
                && existing.actor_account_id == request.actor_account_id
                && existing.submission_id == Some(request.submission_id)
                && existing.reason_code == request.reason_code
                && existing.request_id == request.request_id;
            return if exact {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_lifecycle_decision",
                    key: request.id.to_string(),
                })
            };
        }
        let submission = state
            .publication_submissions
            .get(&request.submission_id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publication_submission",
                key: request.submission_id.to_string(),
            })?;
        let actor_active = state
            .accounts
            .get(&request.actor_account_id)
            .is_some_and(|account| account.status == AccountStatus::Active);
        let owner_active = state.publisher_memberships.values().any(|membership| {
            membership.account_id == request.actor_account_id
                && membership.publisher_id == submission.publisher_id
                && membership.role == PublisherRole::Owner
                && membership.state == MembershipState::Active
        });
        if !actor_active || !owner_active {
            return Err(CatalogError::Unauthorized {
                kind: "publication_withdrawal",
                key: request.id.to_string(),
            });
        }
        if !matches!(
            submission.state,
            PublicationSubmissionState::Quarantined
                | PublicationSubmissionState::NeedsReview
                | PublicationSubmissionState::Approved
        ) {
            return Err(CatalogError::Conflict {
                kind: "publication_submission",
                key: request.submission_id.to_string(),
            });
        }
        let now = Utc::now();
        let decision = PublicationLifecycleDecisionRecord {
            id: request.id,
            action: PublicationLifecycleAction::WithdrawSubmission,
            actor_account_id: request.actor_account_id,
            publisher_id: Some(submission.publisher_id),
            submission_id: Some(request.submission_id),
            pack_name: None,
            version: None,
            from_state: lifecycle_submission_state(submission.state),
            to_state: "withdrawn".to_string(),
            reason_code: request.reason_code,
            request_id: request.request_id,
            created_at: now,
        };
        let stored = state
            .publication_submissions
            .get_mut(&request.submission_id)
            .expect("validated withdrawal submission must remain present");
        stored.state = PublicationSubmissionState::Withdrawn;
        stored.updated_at = now;
        state
            .publication_lifecycle_decisions
            .insert(decision.id, decision.clone());
        Ok(decision)
    }

    /// Suspend one publisher under active administrator authority.
    async fn suspend_publisher(
        &self,
        request: PublisherSuspensionRequest,
    ) -> Result<PublicationLifecycleDecisionRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if let Some(existing) = state
            .publication_lifecycle_decisions
            .values()
            .find(|record| {
                record.id == request.id
                    || (record.action == PublicationLifecycleAction::SuspendPublisher
                        && record.publisher_id == Some(request.publisher_id))
                    || record.request_id == request.request_id
            })
        {
            let exact = existing.id == request.id
                && existing.action == PublicationLifecycleAction::SuspendPublisher
                && existing.actor_account_id == request.actor_account_id
                && existing.publisher_id == Some(request.publisher_id)
                && existing.reason_code == request.reason_code
                && existing.request_id == request.request_id;
            return if exact {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_lifecycle_decision",
                    key: request.id.to_string(),
                })
            };
        }
        if !mock_active_administrator(&state, request.actor_account_id) {
            return Err(CatalogError::Unauthorized {
                kind: "publisher_suspension",
                key: request.id.to_string(),
            });
        }
        let publisher = state
            .publishers
            .get(&request.publisher_id)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "publisher",
                key: request.publisher_id.to_string(),
            })?;
        if !matches!(
            publisher.moderation_status,
            PublisherModerationStatus::Pending | PublisherModerationStatus::Approved
        ) {
            return Err(CatalogError::Conflict {
                kind: "publisher",
                key: request.publisher_id.to_string(),
            });
        }
        let now = Utc::now();
        let decision = PublicationLifecycleDecisionRecord {
            id: request.id,
            action: PublicationLifecycleAction::SuspendPublisher,
            actor_account_id: request.actor_account_id,
            publisher_id: Some(request.publisher_id),
            submission_id: None,
            pack_name: None,
            version: None,
            from_state: lifecycle_publisher_state(publisher.moderation_status),
            to_state: "suspended".to_string(),
            reason_code: request.reason_code,
            request_id: request.request_id,
            created_at: now,
        };
        let stored = state
            .publishers
            .get_mut(&request.publisher_id)
            .expect("validated suspension publisher must remain present");
        stored.moderation_status = PublisherModerationStatus::Suspended;
        stored.updated_at = now;
        state
            .publication_lifecycle_decisions
            .insert(decision.id, decision.clone());
        Ok(decision)
    }

    /// Tombstone one active release under active administrator authority.
    async fn tombstone_publication_release(
        &self,
        request: PublicationTombstoneRequest,
    ) -> Result<PublicationLifecycleDecisionRecord, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if let Some(existing) = state
            .publication_lifecycle_decisions
            .values()
            .find(|record| {
                record.id == request.id
                    || (record.action == PublicationLifecycleAction::TombstoneRelease
                        && record.pack_name.as_deref() == Some(&request.pack_name)
                        && record.version.as_deref() == Some(&request.version))
                    || record.request_id == request.request_id
            })
        {
            let reason_code = lifecycle_tombstone_reason(&request.reason);
            let exact = existing.id == request.id
                && existing.action == PublicationLifecycleAction::TombstoneRelease
                && existing.actor_account_id == request.actor_account_id
                && existing.pack_name.as_deref() == Some(&request.pack_name)
                && existing.version.as_deref() == Some(&request.version)
                && existing.reason_code == reason_code
                && existing.request_id == request.request_id;
            return if exact {
                Ok(existing.clone())
            } else {
                Err(CatalogError::Conflict {
                    kind: "publication_lifecycle_decision",
                    key: request.id.to_string(),
                })
            };
        }
        if !mock_active_administrator(&state, request.actor_account_id) {
            return Err(CatalogError::Unauthorized {
                kind: "publication_tombstone",
                key: request.id.to_string(),
            });
        }
        let key = (request.pack_name.clone(), request.version.clone());
        let version = state
            .versions
            .get(&key)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "pack_version",
                key: format!("{}@{}", request.pack_name, request.version),
            })?;
        if !matches!(version.status, PackStatus::Active) {
            return Err(CatalogError::Conflict {
                kind: "pack_version",
                key: format!("{}@{}", request.pack_name, request.version),
            });
        }
        let now = Utc::now();
        let reason_code = lifecycle_tombstone_reason(&request.reason);
        let decision = PublicationLifecycleDecisionRecord {
            id: request.id,
            action: PublicationLifecycleAction::TombstoneRelease,
            actor_account_id: request.actor_account_id,
            publisher_id: state
                .packs
                .get(&request.pack_name)
                .and_then(|pack| pack.publisher_id),
            submission_id: None,
            pack_name: Some(request.pack_name.clone()),
            version: Some(request.version.clone()),
            from_state: "active".to_string(),
            to_state: "tombstone".to_string(),
            reason_code,
            request_id: request.request_id,
            created_at: now,
        };
        state
            .versions
            .get_mut(&key)
            .expect("validated tombstone version must remain present")
            .status = PackStatus::Tombstone {
            reason: request.reason,
            recorded_at: now,
        };
        let newest_active = state
            .versions
            .iter()
            .filter(|((pack_name, _), version)| {
                pack_name == &request.pack_name && matches!(version.status, PackStatus::Active)
            })
            .map(|((_, version), _)| version.clone())
            .fold(None::<String>, |best, candidate| match best {
                None => Some(candidate),
                Some(current) if semver_gt(&candidate, &current) => Some(candidate),
                Some(current) => Some(current),
            });
        if let Some(pack) = state.packs.get_mut(&request.pack_name) {
            pack.latest_version = newest_active;
        }
        state
            .publication_lifecycle_decisions
            .insert(decision.id, decision.clone());
        Ok(decision)
    }

    /// List publisher lifecycle evidence for an active owner or administrator.
    async fn list_publisher_lifecycle_decisions(
        &self,
        actor_account_id: uuid::Uuid,
        publisher_id: uuid::Uuid,
        before: Option<PublicationLifecycleCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationLifecycleDecisionRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        let owner = state.publisher_memberships.values().any(|membership| {
            membership.account_id == actor_account_id
                && membership.publisher_id == publisher_id
                && membership.role == PublisherRole::Owner
                && membership.state == MembershipState::Active
        });
        if !mock_active_account(&state, actor_account_id)
            || (!owner && !mock_active_administrator(&state, actor_account_id))
        {
            return Err(CatalogError::Unauthorized {
                kind: "publication_lifecycle_audit",
                key: format!("{actor_account_id}:{publisher_id}"),
            });
        }
        Ok(mock_lifecycle_page(
            state
                .publication_lifecycle_decisions
                .values()
                .filter(|record| record.publisher_id == Some(publisher_id))
                .cloned()
                .collect(),
            before,
            limit,
        ))
    }

    /// List global lifecycle evidence for an active administrator.
    async fn list_administrator_lifecycle_decisions(
        &self,
        actor_account_id: uuid::Uuid,
        before: Option<PublicationLifecycleCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationLifecycleDecisionRecord>, CatalogError> {
        let state = self
            .state
            .read()
            .map_err(|error| CatalogError::BackendError(error.to_string().into()))?;
        if !mock_active_administrator(&state, actor_account_id) {
            return Err(CatalogError::Unauthorized {
                kind: "publication_lifecycle_audit",
                key: actor_account_id.to_string(),
            });
        }
        Ok(mock_lifecycle_page(
            state
                .publication_lifecycle_decisions
                .values()
                .cloned()
                .collect(),
            before,
            limit,
        ))
    }
}

/// Return whether one mock account is active.
fn mock_active_account(state: &MockState, account_id: uuid::Uuid) -> bool {
    state
        .accounts
        .get(&account_id)
        .is_some_and(|account| account.status == AccountStatus::Active)
}

/// Return whether one mock account holds an active administrator role.
fn mock_active_administrator(state: &MockState, account_id: uuid::Uuid) -> bool {
    mock_active_account(state, account_id)
        && state.platform_roles.iter().any(|role| {
            role.account_id == account_id
                && role.role == PlatformRole::Administrator
                && role.state == PlatformRoleState::Active
        })
}

/// Encode one submission state as its stable database-style value.
fn lifecycle_submission_state(state: PublicationSubmissionState) -> String {
    match state {
        PublicationSubmissionState::Quarantined => "quarantined",
        PublicationSubmissionState::NeedsReview => "needs_review",
        PublicationSubmissionState::Approved => "approved",
        PublicationSubmissionState::Rejected => "rejected",
        PublicationSubmissionState::Promoted => "promoted",
        PublicationSubmissionState::Withdrawn => "withdrawn",
        _ => "unknown",
    }
    .to_string()
}

/// Encode one publisher moderation state as its stable database-style value.
fn lifecycle_publisher_state(state: PublisherModerationStatus) -> String {
    match state {
        PublisherModerationStatus::Pending => "pending",
        PublisherModerationStatus::Approved => "approved",
        PublisherModerationStatus::Suspended => "suspended",
        PublisherModerationStatus::Rejected => "rejected",
    }
    .to_string()
}

/// Encode one tombstone reason as its stable public value.
fn lifecycle_tombstone_reason(reason: &frameshift_catalog::TombstoneReason) -> String {
    match reason {
        frameshift_catalog::TombstoneReason::AuthorRequest => "author-request",
        frameshift_catalog::TombstoneReason::TosViolation => "tos-violation",
        frameshift_catalog::TombstoneReason::Dmca => "dmca",
    }
    .to_string()
}

/// Sort, keyset-filter, and bound one mock lifecycle audit page.
fn mock_lifecycle_page(
    mut records: Vec<PublicationLifecycleDecisionRecord>,
    before: Option<PublicationLifecycleCursor>,
    limit: u32,
) -> Vec<PublicationLifecycleDecisionRecord> {
    records.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    records
        .into_iter()
        .filter(|record| {
            before.is_none_or(|cursor| {
                record.created_at < cursor.created_at
                    || (record.created_at == cursor.created_at && record.id < cursor.id)
            })
        })
        .take(limit.min(100) as usize)
        .collect()
}

/// Require an active mock account holding an active administrator role.
fn require_mock_administrator(
    state: &MockState,
    actor_account_id: uuid::Uuid,
    kind: &'static str,
) -> Result<(), CatalogError> {
    let actor_is_active = state
        .accounts
        .get(&actor_account_id)
        .is_some_and(|account| account.status == AccountStatus::Active);
    let holds_administrator = state.platform_roles.iter().any(|record| {
        record.account_id == actor_account_id
            && record.role == PlatformRole::Administrator
            && record.state == PlatformRoleState::Active
    });
    if actor_is_active && holds_administrator {
        return Ok(());
    }
    Err(CatalogError::Unauthorized {
        kind,
        key: actor_account_id.to_string(),
    })
}

/// Count mock accounts that currently provide administrator authority.
fn mock_administrator_coverage(state: &MockState) -> usize {
    state
        .platform_roles
        .iter()
        .filter(|record| {
            record.role == PlatformRole::Administrator
                && record.state == PlatformRoleState::Active
                && state
                    .accounts
                    .get(&record.account_id)
                    .is_some_and(|account| account.status == AccountStatus::Active)
        })
        .count()
}

/// Sort, keyset-filter, bound, and resolve one mock appeal page.
fn mock_appeal_page(
    state: &MockState,
    publisher_id: Option<uuid::Uuid>,
    before: Option<PublicationAppealCursor>,
    limit: u32,
) -> Vec<PublicationAppealCaseRecord> {
    let mut appeals = state
        .publication_appeals
        .values()
        .filter(|appeal| publisher_id.is_none_or(|id| appeal.publisher_id == id))
        .cloned()
        .collect::<Vec<_>>();
    appeals.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    appeals
        .into_iter()
        .filter(|appeal| {
            before.is_none_or(|cursor| {
                appeal.created_at < cursor.created_at
                    || (appeal.created_at == cursor.created_at && appeal.id < cursor.id)
            })
        })
        .take(limit.min(100) as usize)
        .map(|appeal| {
            let resolution = state
                .publication_appeal_resolutions
                .values()
                .find(|resolution| resolution.appeal_id == appeal.id)
                .cloned();
            PublicationAppealCaseRecord { appeal, resolution }
        })
        .collect()
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
