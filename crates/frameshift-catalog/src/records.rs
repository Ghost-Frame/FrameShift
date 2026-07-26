//! Catalog record types.
//!
//! These structs represent the canonical data shapes stored and returned by
//! [`crate::backend::CatalogBackend`] implementations. They are plain Rust
//! types with serde derives -- no database-specific code or annotations.

use chrono::{DateTime, Utc};

use crate::identity::Ed25519PublicKey;
use crate::status::{PackStatus, TombstoneReason};
use frameshift_pack::ObjectHash;
use uuid::Uuid;

/// Lifecycle state for an OIDC-backed FrameShift account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// The account may authenticate and perform authorized operations.
    Active,
    /// The account is temporarily denied access by an operator action.
    Suspended,
    /// The account is permanently disabled while its audit history is retained.
    Disabled,
}

/// A user account identified by an exact OIDC issuer and subject pair.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountRecord {
    /// Internal stable account identifier.
    pub id: Uuid,
    /// Canonical OIDC issuer URL from the validated token.
    pub issuer: String,
    /// Issuer-scoped OIDC subject identifier from the validated token.
    pub subject: String,
    /// Optional email claim retained only as mutable profile metadata.
    pub email: Option<String>,
    /// Optional user-selected display name.
    pub display_name: Option<String>,
    /// Current account lifecycle state.
    pub status: AccountStatus,
    /// UTC timestamp when the account was created.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of the most recent account update.
    pub updated_at: DateTime<Utc>,
}

/// Moderation state for a public publisher profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherModerationStatus {
    /// The profile exists but public publication still requires review.
    Pending,
    /// The profile is approved for the configured publication policy.
    Approved,
    /// The profile is temporarily prevented from publishing.
    Suspended,
    /// The profile was rejected but remains available to the audit trail.
    Rejected,
}

/// Public identity and moderation state for an artifact publisher.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublisherProfileRecord {
    /// Internal stable publisher identifier.
    pub id: Uuid,
    /// Unique lowercase public handle.
    pub handle: String,
    /// Public publisher display name.
    pub display_name: String,
    /// Optional bounded public biography.
    pub biography: Option<String>,
    /// Current moderation state.
    pub moderation_status: PublisherModerationStatus,
    /// UTC timestamp when the profile was created.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of the most recent profile update.
    pub updated_at: DateTime<Utc>,
}

/// Authorization role assigned through a publisher membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherRole {
    /// Full publisher ownership authority.
    Owner,
}

/// Lifecycle state for a publisher membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    /// The account currently holds the membership role.
    Active,
    /// The membership has been revoked but remains auditable.
    Revoked,
}

/// An account's role within one publisher profile.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublisherMembershipRecord {
    /// Account holding the membership.
    pub account_id: Uuid,
    /// Publisher to which the membership grants access.
    pub publisher_id: Uuid,
    /// Authorization role held by the account.
    pub role: PublisherRole,
    /// Current membership lifecycle state.
    pub state: MembershipState,
    /// UTC timestamp when the membership was created.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of the most recent membership update.
    pub updated_at: DateTime<Utc>,
}

/// Global authority assigned independently of publisher ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformRole {
    /// Authority to review publication submissions.
    Moderator,
    /// Authority to administer moderation and also review submissions.
    Administrator,
}

/// Lifecycle state for a global platform-role assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformRoleState {
    /// The role currently grants its authority.
    Active,
    /// The role no longer grants authority but remains auditable.
    Revoked,
}

/// Durable global role assignment for one account.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlatformRoleRecord {
    /// Account receiving the global authority.
    pub account_id: Uuid,
    /// Authority assigned to the account.
    pub role: PlatformRole,
    /// Current assignment lifecycle state.
    pub state: PlatformRoleState,
    /// Account that assigned the role.
    pub assigned_by_account_id: Uuid,
    /// Database timestamp when the assignment was created.
    pub created_at: DateTime<Utc>,
    /// Database timestamp of the most recent assignment update.
    pub updated_at: DateTime<Utc>,
}

/// Exact input for one administrator-authorized platform role grant.
///
/// Granting a role that is already active is idempotent, and granting a
/// previously revoked role reactivates that same assignment row rather than
/// creating a second one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformRoleAssignmentRequest {
    /// Account receiving the authority.
    pub account_id: Uuid,
    /// Authority being granted.
    pub role: PlatformRole,
    /// Account performing the grant, which must hold an active administrator role.
    pub actor_account_id: Uuid,
}

/// Exact input for one administrator-authorized platform role revocation.
///
/// Revocation marks the assignment revoked and never deletes it, so the
/// original grant, its assigning account, and its creation time remain
/// auditable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformRoleRevocationRequest {
    /// Account losing the authority.
    pub account_id: Uuid,
    /// Authority being revoked.
    pub role: PlatformRole,
    /// Account performing the revocation, which must hold an active administrator role.
    pub actor_account_id: Uuid,
}

/// Exact input for one administrator-authorized account status transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStatusChangeRequest {
    /// Account whose status is changing.
    pub account_id: Uuid,
    /// Status the account must hold after the transition.
    pub status: AccountStatus,
    /// Account performing the transition, which must hold an active administrator role.
    pub actor_account_id: Uuid,
}

/// Lifecycle state for an enrolled publisher signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherKeyState {
    /// The key may authorize new publisher writes.
    Active,
    /// The key may verify historical evidence but cannot authorize new writes.
    Revoked,
}

/// A public Ed25519 key enrolled to a publisher profile.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublisherKeyRecord {
    /// Internal stable key identifier.
    pub id: Uuid,
    /// Publisher that owns the key.
    pub publisher_id: Uuid,
    /// Raw public key used to verify proof-of-possession and signed requests.
    pub public_key: Ed25519PublicKey,
    /// User-visible device or purpose label.
    pub label: String,
    /// Current key lifecycle state.
    pub state: PublisherKeyState,
    /// UTC timestamp when the key was enrolled.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp when the key was revoked, when applicable.
    pub revoked_at: Option<DateTime<Utc>>,
    /// UTC timestamp of the most recent successful use, when known.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Immutable audit event for security-sensitive publisher operations.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PublisherAuditEventRecord {
    /// Internal stable audit event identifier.
    pub id: Uuid,
    /// Account responsible for the action, when an account initiated it.
    pub actor_account_id: Option<Uuid>,
    /// Publisher affected by the action.
    pub publisher_id: Uuid,
    /// Stable action name suitable for filtering.
    pub action: String,
    /// Optional publisher key affected by the action.
    pub target_key_id: Option<Uuid>,
    /// Optional pack version affected by the action.
    pub target_version: Option<String>,
    /// Request correlation identifier from the HTTP boundary.
    pub request_id: Option<Uuid>,
    /// UTC timestamp when the event was recorded.
    pub created_at: DateTime<Utc>,
    /// Sanitized structured metadata that must not contain credentials.
    pub metadata: serde_json::Value,
}

/// Durable authorization envelope for one exact publication artifact.
///
/// The three hashes bind the intent to the uploaded archive, its manifest, and
/// the normalized file inventory produced by the declared scanner schema.
/// Consumption is a one-way transition represented by `consumed_at`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationIntentRecord {
    /// Stable caller-generated identifier used as the idempotency key.
    pub id: Uuid,
    /// Account that requested the publication intent.
    pub account_id: Uuid,
    /// Publisher under which the artifact may be submitted.
    pub publisher_id: Uuid,
    /// Active publisher key that must sign the eventual submission.
    pub publisher_key_id: Uuid,
    /// SHA-256 digest of the exact archive bytes.
    pub archive_hash: ObjectHash,
    /// SHA-256 digest of the canonical manifest bytes.
    pub manifest_hash: ObjectHash,
    /// SHA-256 digest of the normalized file inventory.
    pub file_inventory_hash: ObjectHash,
    /// Positive version of the scanner contract used for the inventory.
    pub scan_schema_version: u32,
    /// UTC timestamp when the intent was created.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp after which the intent cannot be consumed.
    pub expires_at: DateTime<Utc>,
    /// UTC timestamp of the successful one-time consumption, when present.
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Exact identity and artifact binding required to consume an intent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationIntentClaim {
    /// Identifier of the intent being consumed.
    pub id: Uuid,
    /// Account presenting the intent.
    pub account_id: Uuid,
    /// Publisher receiving the submission.
    pub publisher_id: Uuid,
    /// Publisher key authorizing the submission.
    pub publisher_key_id: Uuid,
    /// SHA-256 digest of the submitted archive bytes.
    pub archive_hash: ObjectHash,
    /// SHA-256 digest of the submitted canonical manifest.
    pub manifest_hash: ObjectHash,
    /// SHA-256 digest of the submitted normalized file inventory.
    pub file_inventory_hash: ObjectHash,
    /// Scanner contract version used for the submitted inventory.
    pub scan_schema_version: u32,
}

/// Non-public review lifecycle for a durable publication submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PublicationSubmissionState {
    /// The artifact remains isolated from every public catalog read.
    Quarantined,
    /// A moderator requested clarification or a replacement submission.
    NeedsReview,
    /// A moderator approved the artifact, but it is not yet publicly active.
    Approved,
    /// A moderator rejected the artifact while retaining its audit history.
    Rejected,
    /// The approved artifact is bound to one active public catalog version.
    Promoted,
    /// The publisher owner ended the non-public workflow without deleting evidence.
    Withdrawn,
}

/// Review action applied to a quarantined publication submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationModerationAction {
    /// Approve the reviewed artifact without making it public.
    Approve,
    /// Keep the artifact non-public while requesting follow-up.
    RequestChanges,
    /// Reject the reviewed artifact.
    Reject,
}

/// Exact input for one idempotent moderation decision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationModerationDecisionRequest {
    /// Stable decision identifier and primary idempotency key.
    pub id: Uuid,
    /// Submission receiving the decision.
    pub submission_id: Uuid,
    /// Authenticated account attempting the moderation action.
    pub actor_account_id: Uuid,
    /// Review action to apply.
    pub action: PublicationModerationAction,
    /// Stable bounded private reason code.
    pub reason_code: String,
    /// Optional bounded private explanation for the publisher.
    pub private_explanation: Option<String>,
    /// Stable request identifier used to reject replay under a different decision ID.
    pub request_id: Uuid,
}

/// Immutable moderation evidence for one accepted review decision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationModerationDecisionRecord {
    /// Stable decision identifier.
    pub id: Uuid,
    /// Submission receiving the decision.
    pub submission_id: Uuid,
    /// Account that exercised moderation authority.
    pub actor_account_id: Uuid,
    /// Review action that was applied.
    pub action: PublicationModerationAction,
    /// Submission state observed before the action.
    pub from_state: PublicationSubmissionState,
    /// Submission state committed by the action.
    pub to_state: PublicationSubmissionState,
    /// Stable bounded private reason code.
    pub reason_code: String,
    /// Optional bounded private explanation for the publisher.
    pub private_explanation: Option<String>,
    /// Stable request identifier retained for replay detection.
    pub request_id: Uuid,
    /// Database timestamp when the decision was committed.
    pub created_at: DateTime<Utc>,
}

/// Final administrator disposition for one publication appeal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationAppealDisposition {
    /// Preserve the original adverse moderation decision and submission state.
    Uphold,
    /// Reverse the adverse decision and approve the unchanged submission.
    Overturn,
}

/// Exact input for one idempotent publisher-owner appeal filing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationAppealRequest {
    /// Stable appeal identifier and primary idempotency key.
    pub id: Uuid,
    /// Immutable adverse moderation decision being appealed.
    pub decision_id: Uuid,
    /// Path-bound publisher expected to own the appealed submission.
    pub publisher_id: Uuid,
    /// Authenticated publisher owner filing the appeal.
    pub actor_account_id: Uuid,
    /// Bounded private statement explaining the appeal.
    pub statement: String,
    /// Stable request identifier used to reject replay substitution.
    pub request_id: Uuid,
}

/// Immutable evidence for one accepted publication appeal filing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationAppealRecord {
    /// Stable appeal identifier.
    pub id: Uuid,
    /// Immutable adverse moderation decision being appealed.
    pub decision_id: Uuid,
    /// Submission bound to the original decision.
    pub submission_id: Uuid,
    /// Publisher that owns the appealed submission.
    pub publisher_id: Uuid,
    /// Authenticated owner that filed the appeal.
    pub actor_account_id: Uuid,
    /// Bounded private appeal statement.
    pub statement: String,
    /// Stable request identifier retained for replay detection.
    pub request_id: Uuid,
    /// Database timestamp when the appeal was filed.
    pub created_at: DateTime<Utc>,
}

/// Exact input for one idempotent administrator appeal resolution.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationAppealResolutionRequest {
    /// Stable resolution identifier and primary idempotency key.
    pub id: Uuid,
    /// Appeal being resolved.
    pub appeal_id: Uuid,
    /// Authenticated administrator resolving the appeal.
    pub actor_account_id: Uuid,
    /// Final appeal disposition.
    pub disposition: PublicationAppealDisposition,
    /// Bounded private rationale for the disposition.
    pub rationale: String,
    /// Required audited reason only for unavoidable self-resolution.
    pub separation_exception_reason: Option<String>,
    /// Stable request identifier used to reject replay substitution.
    pub request_id: Uuid,
}

/// Immutable evidence for one completed publication appeal resolution.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationAppealResolutionRecord {
    /// Stable resolution identifier.
    pub id: Uuid,
    /// Appeal resolved by this record.
    pub appeal_id: Uuid,
    /// Authenticated administrator that resolved the appeal.
    pub actor_account_id: Uuid,
    /// Final appeal disposition.
    pub disposition: PublicationAppealDisposition,
    /// Bounded private rationale for the disposition.
    pub rationale: String,
    /// Audited reason for an unavoidable sole-administrator self-resolution.
    pub separation_exception_reason: Option<String>,
    /// Stable request identifier retained for replay detection.
    pub request_id: Uuid,
    /// Database timestamp when the resolution committed.
    pub created_at: DateTime<Utc>,
}

/// One appeal filing paired with its optional immutable resolution.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationAppealCaseRecord {
    /// Immutable appeal filing evidence.
    pub appeal: PublicationAppealRecord,
    /// Immutable resolution evidence once the appeal has been decided.
    pub resolution: Option<PublicationAppealResolutionRecord>,
}

/// Stable keyset cursor for newest-first publication appeal reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationAppealCursor {
    /// Timestamp of the last appeal returned by the preceding page.
    pub created_at: DateTime<Utc>,
    /// Identifier used to order appeals that share the same timestamp.
    pub id: Uuid,
}

/// Exact input required to atomically claim an intent and create a submission.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationSubmissionRequest {
    /// Stable caller-generated submission identifier and idempotency key.
    pub id: Uuid,
    /// Exact identity and artifact binding copied from the publication intent.
    pub intent: PublicationIntentClaim,
    /// Deterministic server-side validation result for the quarantined artifact.
    pub scan_report: frameshift_publication::PublicationReport,
}

/// Durable record for an artifact admitted only to the quarantine boundary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationSubmissionRecord {
    /// Stable submission identifier.
    pub id: Uuid,
    /// One-time publication intent consumed by this submission.
    pub intent_id: Uuid,
    /// Account that presented the submission.
    pub account_id: Uuid,
    /// Publisher under which the artifact may eventually be reviewed.
    pub publisher_id: Uuid,
    /// Publisher key that authorized the exact artifact.
    pub publisher_key_id: Uuid,
    /// SHA-256 digest of the exact quarantined archive bytes.
    pub archive_hash: ObjectHash,
    /// SHA-256 digest of the canonical manifest bytes.
    pub manifest_hash: ObjectHash,
    /// SHA-256 digest of the normalized file inventory.
    pub file_inventory_hash: ObjectHash,
    /// Positive scanner contract version used by the server report.
    pub scan_schema_version: u32,
    /// Deterministic server-side validation result retained for review.
    pub scan_report: frameshift_publication::PublicationReport,
    /// Current non-public lifecycle state.
    pub state: PublicationSubmissionState,
    /// Database timestamp when the intent was consumed and submission created.
    pub created_at: DateTime<Utc>,
    /// Database timestamp of the most recent lifecycle update.
    pub updated_at: DateTime<Utc>,
}

/// Bounded operational snapshot of unresolved publication review work.
///
/// Counts and timestamps describe aggregate queue state only. No account,
/// publisher, key, submission, or artifact identifiers cross this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationModerationSnapshot {
    /// Submissions still in the initial quarantine state.
    pub quarantined_submissions: u64,
    /// Creation time of the oldest initially quarantined submission.
    pub oldest_quarantined_at: Option<DateTime<Utc>>,
    /// All unresolved submissions awaiting review or requested changes.
    pub queued_submissions: u64,
    /// Creation time of the oldest unresolved submission.
    pub oldest_queued_at: Option<DateTime<Utc>>,
    /// Distinct accounts holding at least one active moderation role.
    pub active_reviewers: u64,
}

/// Exact input for one idempotent approved-submission promotion.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicationPromotionRequest {
    /// Stable caller-generated promotion identifier and primary idempotency key.
    pub id: Uuid,
    /// Approved submission whose exact archive is being promoted.
    pub submission_id: Uuid,
    /// Authenticated account exercising promotion authority.
    pub actor_account_id: Uuid,
    /// Stable request correlation identifier used to reject replay substitution.
    pub request_id: Uuid,
    /// Active catalog version derived exclusively from the verified archive.
    pub version: PackVersionRecord,
    /// Public one-line description derived from the verified manifest.
    pub description: String,
    /// Public topical tags derived from the verified manifest.
    pub tags: Vec<String>,
    /// Optional base pack name derived from the verified manifest.
    pub extends: Option<String>,
}

/// Immutable evidence that one approved submission became publicly active.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationPromotionRecord {
    /// Stable promotion identifier.
    pub id: Uuid,
    /// Submission promoted by this event.
    pub submission_id: Uuid,
    /// Account that exercised promotion authority.
    pub actor_account_id: Uuid,
    /// Public pack name created or extended by the promotion.
    pub pack_name: String,
    /// Public semantic version activated by the promotion.
    pub version: String,
    /// Exact public object hash bound to the approved submission.
    pub content_hash: ObjectHash,
    /// Stable request correlation identifier retained for replay detection.
    pub request_id: Uuid,
    /// Database timestamp when the promotion transaction committed.
    pub created_at: DateTime<Utc>,
}

/// Audited control applied to a publication submission, publisher, or release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationLifecycleAction {
    /// An active publisher owner withdrew a non-public submission.
    WithdrawSubmission,
    /// An active administrator suspended a publisher profile.
    SuspendPublisher,
    /// An active administrator removed a release from public availability.
    TombstoneRelease,
}

/// Exact input for one idempotent publisher-owner submission withdrawal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationWithdrawalRequest {
    /// Stable lifecycle-decision identifier and primary idempotency key.
    pub id: Uuid,
    /// Non-public submission being withdrawn.
    pub submission_id: Uuid,
    /// Authenticated account attempting the withdrawal.
    pub actor_account_id: Uuid,
    /// Stable bounded private reason code.
    pub reason_code: String,
    /// Stable request identifier used to reject replay substitution.
    pub request_id: Uuid,
}

/// Exact input for one idempotent administrator publisher suspension.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublisherSuspensionRequest {
    /// Stable lifecycle-decision identifier and primary idempotency key.
    pub id: Uuid,
    /// Publisher profile being suspended.
    pub publisher_id: Uuid,
    /// Authenticated account attempting the suspension.
    pub actor_account_id: Uuid,
    /// Stable bounded private reason code.
    pub reason_code: String,
    /// Stable request identifier used to reject replay substitution.
    pub request_id: Uuid,
}

/// Exact input for one idempotent administrator release tombstone.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationTombstoneRequest {
    /// Stable lifecycle-decision identifier and primary idempotency key.
    pub id: Uuid,
    /// Public pack containing the release.
    pub pack_name: String,
    /// Public semantic version being tombstoned.
    pub version: String,
    /// Authenticated account attempting the tombstone.
    pub actor_account_id: Uuid,
    /// Bounded public tombstone reason category.
    pub reason: TombstoneReason,
    /// Stable request identifier used to reject replay substitution.
    pub request_id: Uuid,
}

/// Immutable evidence for one accepted publication lifecycle control.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationLifecycleDecisionRecord {
    /// Stable lifecycle-decision identifier.
    pub id: Uuid,
    /// Control action that was committed.
    pub action: PublicationLifecycleAction,
    /// Account that exercised owner or administrator authority.
    pub actor_account_id: Uuid,
    /// Affected publisher when the target has current publisher ownership.
    pub publisher_id: Option<Uuid>,
    /// Affected submission for a withdrawal.
    pub submission_id: Option<Uuid>,
    /// Affected public pack for a release tombstone.
    pub pack_name: Option<String>,
    /// Affected public semantic version for a release tombstone.
    pub version: Option<String>,
    /// Stable state observed before the control.
    pub from_state: String,
    /// Stable state committed by the control.
    pub to_state: String,
    /// Stable bounded reason code or public tombstone category.
    pub reason_code: String,
    /// Stable request identifier retained for replay detection.
    pub request_id: Uuid,
    /// Database timestamp when the control committed.
    pub created_at: DateTime<Utc>,
}

/// Stable keyset cursor for newest-first publication lifecycle audit reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicationLifecycleCursor {
    /// Timestamp of the last decision returned by the preceding page.
    pub created_at: DateTime<Utc>,
    /// Identifier used to order decisions that share the same timestamp.
    pub id: Uuid,
}

/// A registered marketplace author.
///
/// Authors are identified by their Ed25519 public key (`pubkey`). The `handle`
/// is a human-readable unique alias that maps to the pubkey. Handles can be
/// updated via [`crate::backend::CatalogBackend::set_handle_pubkey`], but each
/// handle may only point to one key at a time.
///
/// # Invariants
///
/// - `handle` is unique across all `AuthorRecord`s in the catalog.
/// - `display_name` is `None` if the author did not supply one; an empty string
///   MUST NOT be stored (backends reject it with `CatalogError::Validation`).
/// - `oauth_links` may be empty; this is valid and serializes as `[]`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuthorRecord {
    /// The author's Ed25519 public key, used as the primary identifier.
    pub pubkey: Ed25519PublicKey,

    /// The author's unique human-readable handle (e.g. `"alice"`).
    ///
    /// Must be unique within the catalog. Maximum length and allowed characters
    /// are enforced at the HTTP layer, not by this type.
    pub handle: String,

    /// Optional display name chosen by the author.
    ///
    /// `None` means the author did not supply a display name. Empty strings
    /// are rejected at registration time -- callers must pass `None`.
    pub display_name: Option<String>,

    /// UTC timestamp when this author record was first created.
    pub created_at: DateTime<Utc>,

    /// OAuth provider links associated with this author.
    ///
    /// May be empty. Each entry identifies a linked OAuth identity (e.g.
    /// GitHub, Google).
    pub oauth_links: Vec<OauthLink>,
}

/// A linked OAuth identity for an author.
///
/// Records that the author authenticated with `provider` (e.g. `"github"`)
/// using the OAuth subject identifier `subject` (e.g. a numeric user ID).
///
/// # Usage
///
/// `OauthLink` records are informational -- the catalog does not use them for
/// access control. The HTTP layer is responsible for verifying OAuth tokens
/// before creating these records.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OauthLink {
    /// The OAuth provider name (e.g. `"github"`, `"google"`).
    pub provider: String,

    /// The provider-assigned subject identifier for this author.
    ///
    /// Typically a numeric or UUID string that uniquely identifies the user
    /// within the provider's system.
    pub subject: String,

    /// UTC timestamp when the OAuth link was established.
    pub linked_at: DateTime<Utc>,
}

/// Top-level pack record representing a named persona pack in the catalog.
///
/// A `PackRecord` is the mutable "head" entry for a pack -- it tracks the
/// latest published version and the total download count. Immutable version
/// history is stored in [`PackVersionRecord`].
///
/// # Invariants
///
/// - `name` is unique within the catalog.
/// - `latest_version` is `None` until at least one version has been published,
///   is updated atomically when a new version is registered, and is
///   recomputed (possibly back to `None`) whenever a version is tombstoned --
///   see [`crate::backend::CatalogBackend::tombstone_pack`]'s recompute
///   contract.
/// - `total_downloads` is a monotonically increasing counter; it is never
///   decremented even if a version is tombstoned.
/// - `tags` may be empty; duplicates within the vec are discouraged but not
///   enforced at this layer.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PackRecord {
    /// The unique name of this pack (e.g. `"my-persona"`).
    ///
    /// Names are enforced as globally unique by the catalog backend.
    pub name: String,

    /// The public key of the current pack author/owner.
    ///
    /// May differ from the original creator if ownership was transferred.
    pub current_author: Ed25519PublicKey,

    /// Optional publisher profile that owns the pack after identity backfill.
    ///
    /// `None` preserves the legacy author-key ownership path during migration.
    pub publisher_id: Option<Uuid>,

    /// Tags associated with this pack for search and discovery.
    ///
    /// Example: `["roleplay", "assistant", "creative"]`.
    pub tags: Vec<String>,

    /// Short human-readable description of the pack's purpose.
    pub description: String,

    /// UTC timestamp when this pack was first created in the catalog.
    pub created_at: DateTime<Utc>,

    /// The semver string of the newest `PackStatus::Active` version.
    ///
    /// `None` until the first version is registered, and also `None` again if
    /// every version is later tombstoned. Updated atomically by
    /// `register_pack_version` on publish and recomputed by `tombstone_pack`
    /// on takedown (see that method's doc for the recompute contract). This
    /// field, not any per-version status, is what `search_packs` uses to
    /// decide whether a pack is currently installable.
    pub latest_version: Option<String>,

    /// Cumulative download count across all versions of this pack.
    ///
    /// Incremented by [`crate::backend::CatalogBackend::increment_download_counter`].
    /// Never decremented.
    pub total_downloads: u64,

    /// Base persona pack name from the manifest `extends` field.
    ///
    /// `None` for root packs that do not extend another pack.
    /// Format is the raw value from the pack manifest (e.g. `"base@^1.0"`).
    pub extends: Option<String>,
}

/// An immutable record of a specific published version of a pack.
///
/// Each `PackVersionRecord` is an append-only entry. Once registered, a version
/// record is never mutated except to update its `status` field (which can only
/// transition from `Active` to `Tombstone`).
///
/// # Invariants
///
/// - `(pack_name, version)` is unique within the catalog.
/// - `signature` MUST be exactly 64 bytes (Ed25519 signature length). Backends
///   MUST reject registration of records with other lengths with
///   `CatalogError::InvalidArgument`.
/// - `parent_hash` references the `content_hash` of the previous version in
///   the pack's history chain, or `None` for the first version. The catalog
///   does NOT validate that the referenced hash exists -- transparency log
///   infrastructure handles lineage validation.
/// - `schema_version` identifies the pack schema used at publication time,
///   allowing future readers to apply the correct parsing logic.
/// - `status` starts as `PackStatus::Active` and can only be set to
///   `PackStatus::Tombstone` via `tombstone_pack`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PackVersionRecord {
    /// The name of the parent pack this version belongs to.
    pub pack_name: String,

    /// The semver version string for this release (e.g. `"1.2.0"`).
    pub version: String,

    /// The content-addressed hash of the pack's canonical byte content.
    ///
    /// Computed by the pack tooling (SHA-256 of the canonical pack serialization).
    /// Used for content-addressed retrieval from the object store.
    pub content_hash: ObjectHash,

    /// The Ed25519 signature over the canonical pack content.
    ///
    /// Must be exactly 64 bytes. Verified against `author_pubkey` by callers;
    /// the catalog stores it verbatim without re-verifying.
    #[serde(with = "crate::serde_helpers::bytes_as_b64")]
    pub signature: Vec<u8>,

    /// The Ed25519 public key of the author who published this version.
    pub author_pubkey: Ed25519PublicKey,

    /// Optional enrolled publisher key associated with this version.
    ///
    /// Historical `author_pubkey` bytes remain immutable even when this link is set.
    pub publisher_key_id: Option<Uuid>,

    /// The content hash of the previous version in this pack's history chain.
    ///
    /// `None` for the first version of a pack. Subsequent versions SHOULD set
    /// this to the `content_hash` of the previous version to form a verifiable
    /// hash chain. The catalog does NOT enforce that the referenced hash exists.
    pub parent_hash: Option<ObjectHash>,

    /// The capability manifest as a JSON string.
    ///
    /// Describes what capabilities this pack requests (e.g. network access,
    /// file system access). The schema is defined by the pack runtime; the
    /// catalog stores it opaquely.
    pub capability_manifest_json: String,

    /// The schema version of the pack format used at publication time.
    ///
    /// Monotonically increasing integer. Readers use this to select the correct
    /// deserialization path.
    pub schema_version: u32,

    /// The SPDX license identifier for this pack (e.g. `"MIT"`, `"Apache-2.0"`).
    pub license: String,

    /// UTC timestamp when this version was published.
    pub published_at: DateTime<Utc>,

    /// The publication status of this version.
    ///
    /// Starts as `PackStatus::Active`. Can only transition to
    /// `PackStatus::Tombstone` via `tombstone_pack`.
    pub status: PackStatus,

    /// The size of the pack content in bytes.
    ///
    /// Reflects the size of the packed artifact as stored in the object store.
    pub size_bytes: u64,
}

#[cfg(test)]
/// Unit tests for catalog record serde roundtrips.
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    /// OauthLink serde JSON roundtrip preserves all fields.
    fn oauth_link_serde_roundtrip() {
        let link = OauthLink {
            provider: "github".to_string(),
            subject: "12345".to_string(),
            linked_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
        };
        let json = serde_json::to_string(&link).expect("serialize");
        let back: OauthLink = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(link, back);
    }

    #[test]
    /// AuthorRecord with empty oauth_links serializes as `[]` and roundtrips correctly.
    fn author_record_empty_oauth_links_roundtrip() {
        let record = AuthorRecord {
            pubkey: Ed25519PublicKey([0u8; 32]),
            handle: "bob".to_string(),
            display_name: None,
            created_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            oauth_links: vec![],
        };
        let json = serde_json::to_string(&record).expect("serialize");
        assert!(json.contains(r#""oauth_links":[]"#));
        let back: AuthorRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }
}
