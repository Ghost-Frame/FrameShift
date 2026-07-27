//! Diesel `Queryable`/`Insertable` row structs for the frameshift catalog schema.
//!
//! These structs map directly to database rows. They use primitive Rust types
//! (`Vec<u8>`, `serde_json::Value`) because Diesel's PostgreSQL driver works at
//! that level. Conversion to/from the domain types defined in `frameshift-catalog`
//! happens at the boundary in `backend.rs`.
//!
//! # BYTEA conversion convention
//!
//! `Ed25519PublicKey` and `ObjectHash` are stored as `Vec<u8>` (BYTEA) in the
//! DB layer. The conversion helpers at the bottom of this module convert between
//! `Vec<u8>` and the typed newtypes, returning `CatalogError::BackendError` when
//! the byte length is wrong (which indicates data corruption).

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde_json::Value as JsonValue;

use frameshift_catalog::{
    AccountInviteIntent, AccountInviteRecord, AccountInviteRequestRecord, AccountInviteStatus,
    AccountPasswordCredentialRecord, AccountRecord, AccountSessionClientKind, AccountSessionRecord,
    AccountStatus, AuthorRecord, CatalogError, Ed25519PublicKey, MembershipState, OauthLink,
    ObjectHash, PackRecord, PackStatus, PackVersionRecord, PlatformRole, PlatformRoleRecord,
    PlatformRoleState, PublicationAppealDisposition, PublicationAppealRecord,
    PublicationAppealResolutionRecord, PublicationIntentRecord, PublicationLifecycleAction,
    PublicationLifecycleDecisionRecord, PublicationModerationAction,
    PublicationModerationDecisionRecord, PublicationPromotionRecord, PublicationSubmissionRecord,
    PublicationSubmissionState, PublisherKeyRecord, PublisherKeyState, PublisherMembershipRecord,
    PublisherModerationStatus, PublisherProfileRecord, PublisherRole,
};
use uuid::Uuid;

use crate::schema::{
    account_invite_requests, account_invites, account_password_credentials, account_platform_roles,
    account_sessions, accounts, authors, handles, pack_downloads, pack_versions, packs,
    publication_appeal_resolutions, publication_appeals, publication_intents,
    publication_lifecycle_decisions, publication_moderation_decisions, publication_promotions,
    publication_submissions, publisher_audit_events, publisher_keys, publisher_memberships,
    publisher_profiles,
};

/// Queryable account row mapped from the `accounts` table.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct AccountRow {
    /// Internal account identifier.
    pub id: Uuid,
    /// Canonical OIDC issuer.
    pub issuer: String,
    /// Issuer-scoped OIDC subject.
    pub subject: String,
    /// Optional profile email.
    pub email: Option<String>,
    /// Optional account display name.
    pub display_name: Option<String>,
    /// Account lifecycle state string.
    pub status: String,
    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent account update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Queryable global platform-role assignment row.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = account_platform_roles)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PlatformRoleRow {
    /// Account receiving the authority.
    pub account_id: Uuid,
    /// Global role string.
    pub role: String,
    /// Assignment lifecycle state string.
    pub state: String,
    /// Account that assigned the role.
    pub assigned_by_account_id: Uuid,
    /// Assignment creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent assignment update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Insertable account row used by account creation.
#[derive(Debug, Insertable)]
#[diesel(table_name = accounts)]
pub(crate) struct NewAccountRow {
    /// Internal account identifier.
    pub id: Uuid,
    /// Canonical OIDC issuer.
    pub issuer: String,
    /// Issuer-scoped OIDC subject.
    pub subject: String,
    /// Optional profile email.
    pub email: Option<String>,
    /// Optional account display name.
    pub display_name: Option<String>,
    /// Account lifecycle state string.
    pub status: String,
    /// Account creation timestamp supplied by the caller.
    pub created_at: DateTime<Utc>,
    /// Initial account update timestamp supplied by the caller.
    pub updated_at: DateTime<Utc>,
}

/// Insertable invite application used by the public account intake route.
#[derive(Debug, Insertable)]
#[diesel(table_name = account_invite_requests)]
pub(crate) struct NewAccountInviteRequestRow {
    /// Stable internal application identifier.
    pub id: Uuid,
    /// Lowercase, trimmed applicant email.
    pub normalized_email: String,
    /// Optional applicant name retained for review.
    pub display_name: Option<String>,
    /// Applicant-selected intent encoded as stable snake case.
    pub intent: String,
    /// Bounded private application statement.
    pub statement: String,
    /// Review lifecycle state encoded as stable snake case.
    pub status: String,
    /// Applicant contact-consent timestamp.
    pub consented_at: DateTime<Utc>,
    /// Initial application timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent application update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Queryable invite application used by the administrator review queue.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = account_invite_requests)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct AccountInviteRequestRow {
    /// Stable internal application identifier.
    pub id: Uuid,
    /// Lowercase, trimmed applicant email.
    pub normalized_email: String,
    /// Optional applicant name retained for review.
    pub display_name: Option<String>,
    /// Applicant-selected intent encoded as stable snake case.
    pub intent: String,
    /// Bounded private application statement.
    pub statement: String,
    /// Review lifecycle state encoded as stable snake case.
    pub status: String,
    /// Applicant contact-consent timestamp.
    pub consented_at: DateTime<Utc>,
    /// Initial application timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent application update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Queryable one-time account invitation row.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = account_invites)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct AccountInviteRow {
    /// Stable internal invitation identifier.
    pub id: Uuid,
    /// Application approved by the invitation.
    pub request_id: Option<Uuid>,
    /// Lowercase, trimmed authorized email.
    pub normalized_email: String,
    /// SHA-256 digest of the opaque invitation token.
    pub token_digest: Vec<u8>,
    /// Administrator that issued the invitation.
    pub issued_by_account_id: Option<Uuid>,
    /// Whether the invitation was inserted out of band for initial bootstrap.
    pub is_bootstrap: bool,
    /// Exclusive invitation expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Successful one-time redemption timestamp.
    pub consumed_at: Option<DateTime<Utc>>,
    /// Explicit revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Invitation creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Insertable one-time account invitation row.
#[derive(Debug, Insertable)]
#[diesel(table_name = account_invites)]
pub(crate) struct NewAccountInviteRow {
    /// Stable internal invitation identifier.
    pub id: Uuid,
    /// Application approved by the invitation.
    pub request_id: Option<Uuid>,
    /// Lowercase, trimmed authorized email.
    pub normalized_email: String,
    /// SHA-256 digest of the opaque invitation token.
    pub token_digest: Vec<u8>,
    /// Administrator that issued the invitation.
    pub issued_by_account_id: Option<Uuid>,
    /// Whether the invitation was inserted out of band for initial bootstrap.
    pub is_bootstrap: bool,
    /// Exclusive invitation expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Successful one-time redemption timestamp.
    pub consumed_at: Option<DateTime<Utc>>,
    /// Explicit revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Invitation creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Queryable first-party password credential row.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = account_password_credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct AccountPasswordCredentialRow {
    /// Account authenticated by this credential.
    pub account_id: Uuid,
    /// Lowercase, trimmed unique sign-in email.
    pub normalized_email: String,
    /// Argon2id PHC password hash.
    pub password_hash: String,
    /// Application credential-record schema version.
    pub password_version: i16,
    /// External deployment-pepper version.
    pub pepper_version: i16,
    /// Successful email-verification timestamp.
    pub email_verified_at: Option<DateTime<Utc>>,
    /// Credential creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent password-change timestamp.
    pub password_changed_at: DateTime<Utc>,
    /// Most recent credential-record update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Insertable first-party password credential row.
#[derive(Debug, Insertable)]
#[diesel(table_name = account_password_credentials)]
pub(crate) struct NewAccountPasswordCredentialRow {
    /// Account authenticated by this credential.
    pub account_id: Uuid,
    /// Lowercase, trimmed unique sign-in email.
    pub normalized_email: String,
    /// Argon2id PHC password hash.
    pub password_hash: String,
    /// Application credential-record schema version.
    pub password_version: i16,
    /// External deployment-pepper version.
    pub pepper_version: i16,
    /// Successful email-verification timestamp.
    pub email_verified_at: Option<DateTime<Utc>>,
    /// Credential creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent password-change timestamp.
    pub password_changed_at: DateTime<Utc>,
    /// Most recent credential-record update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Queryable revocable account session row.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = account_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct AccountSessionRow {
    /// Stable internal session identifier.
    pub id: Uuid,
    /// Account authenticated by the session.
    pub account_id: Uuid,
    /// SHA-256 digest of the opaque session token.
    pub token_digest: Vec<u8>,
    /// Browser, desktop, or CLI client kind.
    pub client_kind: String,
    /// Session creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent authenticated-use timestamp.
    pub last_seen_at: DateTime<Utc>,
    /// Sliding inactivity expiry timestamp.
    pub idle_expires_at: DateTime<Utc>,
    /// Non-extendable absolute expiry timestamp.
    pub absolute_expires_at: DateTime<Utc>,
    /// Explicit revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Insertable revocable account session row.
#[derive(Debug, Insertable)]
#[diesel(table_name = account_sessions)]
pub(crate) struct NewAccountSessionRow {
    /// Stable internal session identifier.
    pub id: Uuid,
    /// Account authenticated by the session.
    pub account_id: Uuid,
    /// SHA-256 digest of the opaque session token.
    pub token_digest: Vec<u8>,
    /// Browser, desktop, or CLI client kind.
    pub client_kind: String,
    /// Session creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent authenticated-use timestamp.
    pub last_seen_at: DateTime<Utc>,
    /// Sliding inactivity expiry timestamp.
    pub idle_expires_at: DateTime<Utc>,
    /// Non-extendable absolute expiry timestamp.
    pub absolute_expires_at: DateTime<Utc>,
    /// Explicit revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Queryable public publisher profile row.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = publisher_profiles)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublisherProfileRow {
    /// Internal publisher identifier.
    pub id: Uuid,
    /// Normalized publisher handle.
    pub handle: String,
    /// Public display name.
    pub display_name: String,
    /// Optional public biography.
    pub biography: Option<String>,
    /// Moderation state string.
    pub moderation_status: String,
    /// Profile creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent profile update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Insertable public publisher profile row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publisher_profiles)]
pub(crate) struct NewPublisherProfileRow {
    /// Internal publisher identifier.
    pub id: Uuid,
    /// Normalized publisher handle.
    pub handle: String,
    /// Public display name.
    pub display_name: String,
    /// Optional public biography.
    pub biography: Option<String>,
    /// Moderation state string.
    pub moderation_status: String,
    /// Profile creation timestamp supplied by the caller.
    pub created_at: DateTime<Utc>,
    /// Initial profile update timestamp supplied by the caller.
    pub updated_at: DateTime<Utc>,
}

/// Queryable account-to-publisher membership row.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = publisher_memberships)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublisherMembershipRow {
    /// Account holding the membership.
    pub account_id: Uuid,
    /// Publisher receiving the membership.
    pub publisher_id: Uuid,
    /// Role string.
    pub role: String,
    /// Membership state string.
    pub state: String,
    /// Membership creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most recent membership update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Insertable account-to-publisher membership row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publisher_memberships)]
pub(crate) struct NewPublisherMembershipRow {
    /// Account holding the membership.
    pub account_id: Uuid,
    /// Publisher receiving the membership.
    pub publisher_id: Uuid,
    /// Role string.
    pub role: String,
    /// Membership state string.
    pub state: String,
    /// Membership creation timestamp supplied by the caller.
    pub created_at: DateTime<Utc>,
    /// Initial membership update timestamp supplied by the caller.
    pub updated_at: DateTime<Utc>,
}

/// Queryable enrolled publisher key row.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = publisher_keys)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublisherKeyRow {
    /// Internal key identifier.
    pub id: Uuid,
    /// Publisher owning the key.
    pub publisher_id: Uuid,
    /// Raw Ed25519 public key bytes.
    pub public_key: Vec<u8>,
    /// User-visible key label.
    pub label: String,
    /// Key lifecycle state string.
    pub state: String,
    /// Key enrollment timestamp.
    pub created_at: DateTime<Utc>,
    /// Optional key revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Optional most recent successful use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Insertable enrolled publisher key row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publisher_keys)]
pub(crate) struct NewPublisherKeyRow {
    /// Internal key identifier.
    pub id: Uuid,
    /// Publisher owning the key.
    pub publisher_id: Uuid,
    /// Raw Ed25519 public key bytes.
    pub public_key: Vec<u8>,
    /// User-visible key label.
    pub label: String,
    /// Key lifecycle state string.
    pub state: String,
    /// Key enrollment timestamp supplied by the caller.
    pub created_at: DateTime<Utc>,
    /// Optional key revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Optional most recent successful use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Insertable immutable publisher audit event row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publisher_audit_events)]
pub(crate) struct NewPublisherAuditEventRow {
    /// Internal event identifier.
    pub id: Uuid,
    /// Optional account responsible for the event.
    pub actor_account_id: Option<Uuid>,
    /// Publisher affected by the event.
    pub publisher_id: Uuid,
    /// Stable action name.
    pub action: String,
    /// Optional affected publisher key.
    pub target_key_id: Option<Uuid>,
    /// Optional affected pack version.
    pub target_version: Option<String>,
    /// Optional request correlation identifier.
    pub request_id: Option<Uuid>,
    /// Event timestamp supplied by the caller.
    pub created_at: DateTime<Utc>,
    /// Sanitized structured metadata.
    pub metadata: JsonValue,
}

/// Queryable durable publication intent row.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = publication_intents)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublicationIntentRow {
    /// Stable intent identifier.
    pub id: Uuid,
    /// Account that created the intent.
    pub account_id: Uuid,
    /// Publisher receiving the future submission.
    pub publisher_id: Uuid,
    /// Publisher key authorizing the future submission.
    pub publisher_key_id: Uuid,
    /// Raw archive SHA-256 digest.
    pub archive_hash: Vec<u8>,
    /// Raw canonical manifest SHA-256 digest.
    pub manifest_hash: Vec<u8>,
    /// Raw normalized inventory SHA-256 digest.
    pub file_inventory_hash: Vec<u8>,
    /// Scanner contract version.
    pub scan_schema_version: i32,
    /// Intent creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Exclusive intent expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Successful one-time consumption timestamp.
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Insertable durable publication intent row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publication_intents)]
pub(crate) struct NewPublicationIntentRow {
    /// Stable intent identifier.
    pub id: Uuid,
    /// Account that created the intent.
    pub account_id: Uuid,
    /// Publisher receiving the future submission.
    pub publisher_id: Uuid,
    /// Publisher key authorizing the future submission.
    pub publisher_key_id: Uuid,
    /// Raw archive SHA-256 digest.
    pub archive_hash: Vec<u8>,
    /// Raw canonical manifest SHA-256 digest.
    pub manifest_hash: Vec<u8>,
    /// Raw normalized inventory SHA-256 digest.
    pub file_inventory_hash: Vec<u8>,
    /// Scanner contract version.
    pub scan_schema_version: i32,
    /// Intent creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Exclusive intent expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Successful one-time consumption timestamp.
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Queryable publication submission row retained behind the quarantine boundary.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = publication_submissions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublicationSubmissionRow {
    /// Stable submission identifier.
    pub id: Uuid,
    /// One-time intent consumed by the submission.
    pub intent_id: Uuid,
    /// Account that presented the artifact.
    pub account_id: Uuid,
    /// Publisher receiving the future reviewed artifact.
    pub publisher_id: Uuid,
    /// Publisher key that authorized the artifact.
    pub publisher_key_id: Uuid,
    /// Raw archive SHA-256 digest.
    pub archive_hash: Vec<u8>,
    /// Raw canonical manifest SHA-256 digest.
    pub manifest_hash: Vec<u8>,
    /// Raw normalized inventory SHA-256 digest.
    pub file_inventory_hash: Vec<u8>,
    /// Server scanner contract version.
    pub scan_schema_version: i32,
    /// Typed server validation report serialized as JSON.
    pub scan_report: JsonValue,
    /// Non-public lifecycle state string.
    pub state: String,
    /// Database submission creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Database lifecycle update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Insertable publication submission row created with a consumed intent.
#[derive(Debug, Insertable)]
#[diesel(table_name = publication_submissions)]
pub(crate) struct NewPublicationSubmissionRow {
    /// Stable submission identifier.
    pub id: Uuid,
    /// One-time intent consumed by the submission.
    pub intent_id: Uuid,
    /// Account that presented the artifact.
    pub account_id: Uuid,
    /// Publisher receiving the future reviewed artifact.
    pub publisher_id: Uuid,
    /// Publisher key that authorized the artifact.
    pub publisher_key_id: Uuid,
    /// Raw archive SHA-256 digest.
    pub archive_hash: Vec<u8>,
    /// Raw canonical manifest SHA-256 digest.
    pub manifest_hash: Vec<u8>,
    /// Raw normalized inventory SHA-256 digest.
    pub file_inventory_hash: Vec<u8>,
    /// Server scanner contract version.
    pub scan_schema_version: i32,
    /// Typed server validation report serialized as JSON.
    pub scan_report: JsonValue,
    /// Initial non-public lifecycle state string.
    pub state: String,
    /// Database submission creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Database lifecycle update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Queryable immutable publication moderation decision row.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = publication_moderation_decisions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublicationModerationDecisionRow {
    /// Stable decision identifier.
    pub id: Uuid,
    /// Submission receiving the decision.
    pub submission_id: Uuid,
    /// Account that exercised moderation authority.
    pub actor_account_id: Uuid,
    /// Review action string.
    pub action: String,
    /// Submission state observed before the action.
    pub from_state: String,
    /// Submission state committed by the action.
    pub to_state: String,
    /// Stable private reason code.
    pub reason_code: String,
    /// Optional private explanation for the publisher.
    pub private_explanation: Option<String>,
    /// Stable request identifier used for replay detection.
    pub request_id: Uuid,
    /// Decision commit timestamp.
    pub created_at: DateTime<Utc>,
}

/// Insertable immutable publication moderation decision row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publication_moderation_decisions)]
pub(crate) struct NewPublicationModerationDecisionRow {
    /// Stable decision identifier.
    pub id: Uuid,
    /// Submission receiving the decision.
    pub submission_id: Uuid,
    /// Account that exercised moderation authority.
    pub actor_account_id: Uuid,
    /// Review action string.
    pub action: String,
    /// Submission state observed before the action.
    pub from_state: String,
    /// Submission state committed by the action.
    pub to_state: String,
    /// Stable private reason code.
    pub reason_code: String,
    /// Optional private explanation for the publisher.
    pub private_explanation: Option<String>,
    /// Stable request identifier used for replay detection.
    pub request_id: Uuid,
    /// Decision commit timestamp.
    pub created_at: DateTime<Utc>,
}

/// Queryable immutable publication appeal filing row.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = publication_appeals)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublicationAppealRow {
    /// Stable appeal identifier.
    pub id: Uuid,
    /// Immutable moderation decision being appealed.
    pub decision_id: Uuid,
    /// Submission bound to the original decision.
    pub submission_id: Uuid,
    /// Publisher that owns the submission.
    pub publisher_id: Uuid,
    /// Authenticated owner that filed the appeal.
    pub actor_account_id: Uuid,
    /// Bounded private appeal statement.
    pub statement: String,
    /// Stable request identifier used for replay detection.
    pub request_id: Uuid,
    /// Appeal filing timestamp.
    pub created_at: DateTime<Utc>,
}

/// Insertable immutable publication appeal filing row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publication_appeals)]
pub(crate) struct NewPublicationAppealRow {
    /// Stable appeal identifier.
    pub id: Uuid,
    /// Immutable moderation decision being appealed.
    pub decision_id: Uuid,
    /// Submission bound to the original decision.
    pub submission_id: Uuid,
    /// Publisher that owns the submission.
    pub publisher_id: Uuid,
    /// Authenticated owner that filed the appeal.
    pub actor_account_id: Uuid,
    /// Bounded private appeal statement.
    pub statement: String,
    /// Stable request identifier used for replay detection.
    pub request_id: Uuid,
    /// Appeal filing timestamp.
    pub created_at: DateTime<Utc>,
}

/// Queryable immutable publication appeal resolution row.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = publication_appeal_resolutions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublicationAppealResolutionRow {
    /// Stable resolution identifier.
    pub id: Uuid,
    /// Appeal resolved by this record.
    pub appeal_id: Uuid,
    /// Authenticated administrator that resolved the appeal.
    pub actor_account_id: Uuid,
    /// Final disposition string.
    pub disposition: String,
    /// Bounded private resolution rationale.
    pub rationale: String,
    /// Audited reason for unavoidable sole-administrator self-resolution.
    pub separation_exception_reason: Option<String>,
    /// Stable request identifier used for replay detection.
    pub request_id: Uuid,
    /// Resolution commit timestamp.
    pub created_at: DateTime<Utc>,
}

/// Insertable immutable publication appeal resolution row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publication_appeal_resolutions)]
pub(crate) struct NewPublicationAppealResolutionRow {
    /// Stable resolution identifier.
    pub id: Uuid,
    /// Appeal resolved by this record.
    pub appeal_id: Uuid,
    /// Authenticated administrator that resolved the appeal.
    pub actor_account_id: Uuid,
    /// Final disposition string.
    pub disposition: String,
    /// Bounded private resolution rationale.
    pub rationale: String,
    /// Audited reason for unavoidable sole-administrator self-resolution.
    pub separation_exception_reason: Option<String>,
    /// Stable request identifier used for replay detection.
    pub request_id: Uuid,
    /// Resolution commit timestamp.
    pub created_at: DateTime<Utc>,
}

/// Queryable immutable publication promotion row.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = publication_promotions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublicationPromotionRow {
    /// Stable promotion identifier.
    pub id: Uuid,
    /// Submission activated by this promotion.
    pub submission_id: Uuid,
    /// Account that exercised promotion authority.
    pub actor_account_id: Uuid,
    /// Public pack name.
    pub pack_name: String,
    /// Public semantic version.
    pub version: String,
    /// Raw 32-byte public object hash.
    pub content_hash: Vec<u8>,
    /// Stable request correlation identifier.
    pub request_id: Uuid,
    /// Promotion commit timestamp.
    pub created_at: DateTime<Utc>,
}

/// Insertable immutable publication promotion row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publication_promotions)]
pub(crate) struct NewPublicationPromotionRow {
    /// Stable promotion identifier.
    pub id: Uuid,
    /// Submission activated by this promotion.
    pub submission_id: Uuid,
    /// Account that exercised promotion authority.
    pub actor_account_id: Uuid,
    /// Public pack name.
    pub pack_name: String,
    /// Public semantic version.
    pub version: String,
    /// Raw 32-byte public object hash.
    pub content_hash: Vec<u8>,
    /// Stable request correlation identifier.
    pub request_id: Uuid,
    /// Promotion commit timestamp.
    pub created_at: DateTime<Utc>,
}

/// Queryable immutable publication lifecycle decision row.
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = publication_lifecycle_decisions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PublicationLifecycleDecisionRow {
    /// Stable lifecycle-decision identifier.
    pub id: Uuid,
    /// Stable control action string.
    pub action: String,
    /// Account that exercised owner or administrator authority.
    pub actor_account_id: Uuid,
    /// Affected publisher when linked to current ownership.
    pub publisher_id: Option<Uuid>,
    /// Affected non-public submission for withdrawals.
    pub submission_id: Option<Uuid>,
    /// Affected public pack for tombstones.
    pub pack_name: Option<String>,
    /// Affected public semantic version for tombstones.
    pub version: Option<String>,
    /// Stable state observed before the control.
    pub from_state: String,
    /// Stable state committed by the control.
    pub to_state: String,
    /// Bounded reason code or public tombstone category.
    pub reason_code: String,
    /// Stable request identifier used for replay detection.
    pub request_id: Uuid,
    /// Decision commit timestamp.
    pub created_at: DateTime<Utc>,
}

/// Insertable immutable publication lifecycle decision row.
#[derive(Debug, Insertable)]
#[diesel(table_name = publication_lifecycle_decisions)]
pub(crate) struct NewPublicationLifecycleDecisionRow {
    /// Stable lifecycle-decision identifier.
    pub id: Uuid,
    /// Stable control action string.
    pub action: String,
    /// Account that exercised owner or administrator authority.
    pub actor_account_id: Uuid,
    /// Affected publisher when linked to current ownership.
    pub publisher_id: Option<Uuid>,
    /// Affected non-public submission for withdrawals.
    pub submission_id: Option<Uuid>,
    /// Affected public pack for tombstones.
    pub pack_name: Option<String>,
    /// Affected public semantic version for tombstones.
    pub version: Option<String>,
    /// Stable state observed before the control.
    pub from_state: String,
    /// Stable state committed by the control.
    pub to_state: String,
    /// Bounded reason code or public tombstone category.
    pub reason_code: String,
    /// Stable request identifier used for replay detection.
    pub request_id: Uuid,
    /// Decision commit timestamp.
    pub created_at: DateTime<Utc>,
}

/// Row struct for the `authors` table.
///
/// All BYTEA columns are `Vec<u8>`; JSON columns are `serde_json::Value`.
/// Converted to [`AuthorRecord`] via [`AuthorRow::into_record`].
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = authors)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct AuthorRow {
    /// Raw 32-byte Ed25519 public key.
    pub pubkey: Vec<u8>,
    /// Unique handle string.
    pub handle: String,
    /// Optional display name; None when not supplied.
    pub display_name: Option<String>,
    /// UTC registration timestamp.
    pub created_at: DateTime<Utc>,
    /// JSON array of OAuth links.
    pub oauth_links: JsonValue,
}

/// Insertable struct for the `authors` table.
///
/// Used by [`crate::backend::PostgresCatalog::register_author`] to insert a
/// new row. All fields are owned to satisfy Diesel's Insertable bounds.
#[derive(Debug, Insertable)]
#[diesel(table_name = authors)]
pub(crate) struct NewAuthorRow {
    /// Raw 32-byte Ed25519 public key.
    pub pubkey: Vec<u8>,
    /// Unique handle string.
    pub handle: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// JSON array of OAuth links.
    pub oauth_links: JsonValue,
}

/// Row struct for the `packs` table.
///
/// Converted to [`PackRecord`] via [`PackRow::into_record`].
///
/// `QueryableByName` is derived in addition to `Queryable` and `Selectable` so
/// that `PackRow` can be returned by `diesel::sql_query(...)` calls in
/// `search_raw`, where the column set is determined at runtime.
#[derive(Debug, Queryable, QueryableByName, Selectable)]
#[diesel(table_name = packs)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PackRow {
    /// Pack name string.
    pub name: String,
    /// Raw 32-byte Ed25519 pubkey of the current owner.
    pub current_author: Vec<u8>,
    /// Nullable publisher owner during the compatibility migration.
    pub publisher_id: Option<Uuid>,
    /// Tag array.
    pub tags: Vec<String>,
    /// Short description.
    pub description: String,
    /// UTC creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Latest version string; None until first publish.
    pub latest_version: Option<String>,
    /// Cumulative download counter; stored as i64, converted to u64 on read.
    pub total_downloads: i64,
    /// Base persona pack name from the manifest `extends` field; None for root packs.
    pub extends: Option<String>,
}

/// Insertable struct for the `packs` table.
///
/// Used by [`crate::backend::PostgresCatalog::register_pack_version`] when
/// creating the parent pack row for the first time.
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = packs)]
pub(crate) struct NewPackRow {
    /// Pack name string.
    pub name: String,
    /// Raw 32-byte Ed25519 pubkey of the initial owner.
    pub current_author: Vec<u8>,
    /// Nullable publisher owner during the compatibility migration.
    pub publisher_id: Option<Uuid>,
    /// Initial tag list (empty at creation time; set by caller).
    pub tags: Vec<String>,
    /// Initial description.
    pub description: String,
    /// Initial latest_version (set to the first version being registered).
    pub latest_version: Option<String>,
    /// Base persona pack name from the manifest `extends` field; None for root packs.
    pub extends: Option<String>,
}

/// Row struct for the `pack_versions` table.
///
/// Converted to [`PackVersionRecord`] via [`PackVersionRow::into_record`].
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = pack_versions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct PackVersionRow {
    /// Parent pack name.
    pub pack_name: String,
    /// Version string.
    pub version: String,
    /// Raw 32-byte SHA-256 content hash.
    pub content_hash: Vec<u8>,
    /// Raw 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
    /// Raw 32-byte Ed25519 author pubkey.
    pub author_pubkey: Vec<u8>,
    /// Nullable enrolled publisher key during the compatibility migration.
    pub publisher_key_id: Option<Uuid>,
    /// Optional raw 32-byte parent content hash.
    pub parent_hash: Option<Vec<u8>>,
    /// JSON capability manifest.
    pub capability_manifest_json: JsonValue,
    /// Pack schema version integer; stored as i32, converted to u32 on read.
    pub schema_version: i32,
    /// SPDX license string.
    pub license: String,
    /// UTC publication timestamp.
    pub published_at: DateTime<Utc>,
    /// JSON status object.
    pub status: JsonValue,
    /// Size in bytes; stored as i64, converted to u64 on read.
    pub size_bytes: i64,
}

/// Insertable struct for the `pack_versions` table.
///
/// Used by [`crate::backend::PostgresCatalog::register_pack_version`].
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = pack_versions)]
pub(crate) struct NewPackVersionRow {
    /// Parent pack name.
    pub pack_name: String,
    /// Version string.
    pub version: String,
    /// Raw 32-byte SHA-256 content hash.
    pub content_hash: Vec<u8>,
    /// Raw 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
    /// Raw 32-byte Ed25519 author pubkey.
    pub author_pubkey: Vec<u8>,
    /// Nullable enrolled publisher key during the compatibility migration.
    pub publisher_key_id: Option<Uuid>,
    /// Optional raw 32-byte parent content hash.
    pub parent_hash: Option<Vec<u8>>,
    /// JSON capability manifest.
    pub capability_manifest_json: JsonValue,
    /// Pack schema version integer; passed as i32 (u32 converted before insert).
    pub schema_version: i32,
    /// SPDX license string.
    pub license: String,
    /// JSON status object.
    pub status: JsonValue,
    /// Size in bytes; passed as i64 (u64 converted before insert).
    pub size_bytes: i64,
}

/// Row struct for the `handles` table.
///
/// Used by `get_handle_pubkey` and `set_handle_pubkey`.
/// The `handle` and `updated_at` fields are present to match the table schema
/// for `Queryable`/`Selectable` derivation; only `pubkey` is used by the current
/// trait surface. They are retained for forward compatibility.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = handles)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[allow(dead_code)]
pub(crate) struct HandleRow {
    /// Handle string.
    pub handle: String,
    /// Raw 32-byte Ed25519 pubkey of the current owner.
    pub pubkey: Vec<u8>,
    /// UTC timestamp of last ownership update.
    pub updated_at: DateTime<Utc>,
}

/// Insertable struct for the `handles` table.
#[derive(Debug, Insertable)]
#[diesel(table_name = handles)]
pub(crate) struct NewHandleRow {
    /// Handle string.
    pub handle: String,
    /// Raw 32-byte Ed25519 pubkey.
    pub pubkey: Vec<u8>,
}

/// Insertable struct for the `pack_downloads` audit table.
///
/// `downloaded_at` is omitted; the DB column defaults to `NOW()`.
/// Used by [`crate::backend::PostgresCatalog::record_download`].
#[derive(Debug, Insertable)]
#[diesel(table_name = pack_downloads)]
pub(crate) struct NewPackDownloadRow {
    /// Name of the pack that was downloaded.
    pub pack_name: String,
    /// Semver version string that was downloaded.
    pub version: String,
}

// ── Conversion helpers ──────────────────────────────────────────────────────

/// Convert a raw BYTEA `Vec<u8>` to an [`Ed25519PublicKey`].
///
/// Returns `CatalogError::BackendError` if the byte length is not 32, which
/// would indicate data corruption (the DB CHECK constraint should prevent this,
/// but we defend in depth).
pub(crate) fn vec_to_pubkey(bytes: Vec<u8>) -> Result<Ed25519PublicKey, CatalogError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        CatalogError::BackendError(Box::new(std::io::Error::other(format!(
            "author pubkey in DB has wrong length: {} bytes",
            v.len()
        ))))
    })?;
    Ok(Ed25519PublicKey(arr))
}

/// Convert a raw BYTEA `Vec<u8>` to an [`ObjectHash`].
///
/// Returns `CatalogError::BackendError` if the byte length is not 32.
pub(crate) fn vec_to_hash(bytes: Vec<u8>) -> Result<ObjectHash, CatalogError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        CatalogError::BackendError(Box::new(std::io::Error::other(format!(
            "content_hash in DB has wrong length: {} bytes",
            v.len()
        ))))
    })?;
    Ok(ObjectHash::from_bytes(arr))
}

/// Decode a serde string enum stored in a PostgreSQL TEXT column.
fn parse_text_enum<T>(value: String, kind: &str) -> Result<T, CatalogError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(JsonValue::String(value.clone())).map_err(|error| {
        CatalogError::BackendError(Box::new(std::io::Error::other(format!(
            "invalid {kind} value in DB: {value}: {error}"
        ))))
    })
}

/// Encode a serde string enum for a PostgreSQL TEXT column.
pub(crate) fn encode_text_enum<T>(value: T) -> Result<String, CatalogError>
where
    T: serde::Serialize,
{
    match serde_json::to_value(value)
        .map_err(|error| CatalogError::BackendError(Box::new(error)))?
    {
        JsonValue::String(value) => Ok(value),
        other => Err(CatalogError::BackendError(Box::new(std::io::Error::other(
            format!("expected string enum serialization, got {other}"),
        )))),
    }
}

/// Conversion helpers for account rows.
impl AccountRow {
    /// Convert this database row into an [`AccountRecord`].
    pub(crate) fn into_record(self) -> Result<AccountRecord, CatalogError> {
        Ok(AccountRecord {
            id: self.id,
            issuer: self.issuer,
            subject: self.subject,
            email: self.email,
            display_name: self.display_name,
            status: parse_text_enum::<AccountStatus>(self.status, "account status")?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Conversion helpers for invite application rows.
impl AccountInviteRequestRow {
    /// Convert this database row into a typed invite application.
    pub(crate) fn into_record(self) -> Result<AccountInviteRequestRecord, CatalogError> {
        Ok(AccountInviteRequestRecord {
            id: self.id,
            normalized_email: self.normalized_email,
            display_name: self.display_name,
            intent: parse_text_enum::<AccountInviteIntent>(self.intent, "account invite intent")?,
            statement: self.statement,
            status: parse_text_enum::<AccountInviteStatus>(self.status, "account invite status")?,
            consented_at: self.consented_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Conversion helpers for one-time invitation rows.
impl AccountInviteRow {
    /// Convert this database row into a typed one-time invitation.
    pub(crate) fn into_record(self) -> AccountInviteRecord {
        AccountInviteRecord {
            id: self.id,
            request_id: self.request_id,
            normalized_email: self.normalized_email,
            token_digest: self.token_digest,
            issued_by_account_id: self.issued_by_account_id,
            is_bootstrap: self.is_bootstrap,
            expires_at: self.expires_at,
            consumed_at: self.consumed_at,
            revoked_at: self.revoked_at,
            created_at: self.created_at,
        }
    }
}

/// Conversion helpers for first-party password credential rows.
impl AccountPasswordCredentialRow {
    /// Convert this database row into a typed password credential.
    pub(crate) fn into_record(self) -> AccountPasswordCredentialRecord {
        AccountPasswordCredentialRecord {
            account_id: self.account_id,
            normalized_email: self.normalized_email,
            password_hash: self.password_hash,
            password_version: self.password_version,
            pepper_version: self.pepper_version,
            email_verified_at: self.email_verified_at,
            created_at: self.created_at,
            password_changed_at: self.password_changed_at,
            updated_at: self.updated_at,
        }
    }
}

/// Conversion helpers for first-party session rows.
impl AccountSessionRow {
    /// Convert this database row into a typed account session.
    pub(crate) fn into_record(self) -> Result<AccountSessionRecord, CatalogError> {
        Ok(AccountSessionRecord {
            id: self.id,
            account_id: self.account_id,
            token_digest: self.token_digest,
            client_kind: parse_text_enum::<AccountSessionClientKind>(
                self.client_kind,
                "account session client kind",
            )?,
            created_at: self.created_at,
            last_seen_at: self.last_seen_at,
            idle_expires_at: self.idle_expires_at,
            absolute_expires_at: self.absolute_expires_at,
            revoked_at: self.revoked_at,
        })
    }
}

/// Conversion helpers for global platform-role rows.
impl PlatformRoleRow {
    /// Convert this database row into a typed platform-role record.
    pub(crate) fn into_record(self) -> Result<PlatformRoleRecord, CatalogError> {
        Ok(PlatformRoleRecord {
            account_id: self.account_id,
            role: parse_text_enum::<PlatformRole>(self.role, "platform role")?,
            state: parse_text_enum::<PlatformRoleState>(self.state, "platform role state")?,
            assigned_by_account_id: self.assigned_by_account_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Conversion helpers for publisher profile rows.
impl PublisherProfileRow {
    /// Convert this database row into a [`PublisherProfileRecord`].
    pub(crate) fn into_record(self) -> Result<PublisherProfileRecord, CatalogError> {
        Ok(PublisherProfileRecord {
            id: self.id,
            handle: self.handle,
            display_name: self.display_name,
            biography: self.biography,
            moderation_status: parse_text_enum::<PublisherModerationStatus>(
                self.moderation_status,
                "publisher moderation status",
            )?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Conversion helpers for publisher membership rows.
impl PublisherMembershipRow {
    /// Convert this database row into a [`PublisherMembershipRecord`].
    pub(crate) fn into_record(self) -> Result<PublisherMembershipRecord, CatalogError> {
        Ok(PublisherMembershipRecord {
            account_id: self.account_id,
            publisher_id: self.publisher_id,
            role: parse_text_enum::<PublisherRole>(self.role, "publisher role")?,
            state: parse_text_enum::<MembershipState>(self.state, "membership state")?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Conversion helpers for publisher key rows.
impl PublisherKeyRow {
    /// Convert this database row into a [`PublisherKeyRecord`].
    pub(crate) fn into_record(self) -> Result<PublisherKeyRecord, CatalogError> {
        Ok(PublisherKeyRecord {
            id: self.id,
            publisher_id: self.publisher_id,
            public_key: vec_to_pubkey(self.public_key)?,
            label: self.label,
            state: parse_text_enum::<PublisherKeyState>(self.state, "publisher key state")?,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
            last_used_at: self.last_used_at,
        })
    }
}

/// Conversion helpers for publication intent rows.
impl PublicationIntentRow {
    /// Convert this database row into a typed [`PublicationIntentRecord`].
    pub(crate) fn into_record(self) -> Result<PublicationIntentRecord, CatalogError> {
        let scan_schema_version = u32::try_from(self.scan_schema_version).map_err(|_| {
            CatalogError::BackendError(Box::new(std::io::Error::other(
                "publication intent scan_schema_version in DB is negative",
            )))
        })?;
        Ok(PublicationIntentRecord {
            id: self.id,
            account_id: self.account_id,
            publisher_id: self.publisher_id,
            publisher_key_id: self.publisher_key_id,
            archive_hash: vec_to_hash(self.archive_hash)?,
            manifest_hash: vec_to_hash(self.manifest_hash)?,
            file_inventory_hash: vec_to_hash(self.file_inventory_hash)?,
            scan_schema_version,
            created_at: self.created_at,
            expires_at: self.expires_at,
            consumed_at: self.consumed_at,
        })
    }
}

/// Conversion helpers for durable publication submission rows.
impl PublicationSubmissionRow {
    /// Convert this database row into a typed quarantine submission record.
    pub(crate) fn into_record(self) -> Result<PublicationSubmissionRecord, CatalogError> {
        let scan_schema_version = u32::try_from(self.scan_schema_version).map_err(|_| {
            CatalogError::BackendError(Box::new(std::io::Error::other(format!(
                "invalid publication submission scan schema version for {}",
                self.id
            ))))
        })?;
        let state = match self.state.as_str() {
            "quarantined" => PublicationSubmissionState::Quarantined,
            "needs_review" => PublicationSubmissionState::NeedsReview,
            "approved" => PublicationSubmissionState::Approved,
            "rejected" => PublicationSubmissionState::Rejected,
            "promoted" => PublicationSubmissionState::Promoted,
            "withdrawn" => PublicationSubmissionState::Withdrawn,
            value => {
                return Err(CatalogError::BackendError(Box::new(std::io::Error::other(
                    format!(
                        "invalid publication submission state {value:?} for {}",
                        self.id
                    ),
                ))));
            }
        };
        let scan_report = serde_json::from_value(self.scan_report).map_err(|error| {
            CatalogError::BackendError(Box::new(std::io::Error::other(format!(
                "invalid publication submission scan report for {}: {error}",
                self.id
            ))))
        })?;
        Ok(PublicationSubmissionRecord {
            id: self.id,
            intent_id: self.intent_id,
            account_id: self.account_id,
            publisher_id: self.publisher_id,
            publisher_key_id: self.publisher_key_id,
            archive_hash: vec_to_hash(self.archive_hash)?,
            manifest_hash: vec_to_hash(self.manifest_hash)?,
            file_inventory_hash: vec_to_hash(self.file_inventory_hash)?,
            scan_schema_version,
            scan_report,
            state,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Conversion helpers for immutable publication promotion rows.
impl PublicationPromotionRow {
    /// Convert this database row into typed promotion evidence.
    pub(crate) fn into_record(self) -> Result<PublicationPromotionRecord, CatalogError> {
        Ok(PublicationPromotionRecord {
            id: self.id,
            submission_id: self.submission_id,
            actor_account_id: self.actor_account_id,
            pack_name: self.pack_name,
            version: self.version,
            content_hash: vec_to_hash(self.content_hash)?,
            request_id: self.request_id,
            created_at: self.created_at,
        })
    }
}

/// Conversion helpers for immutable publication lifecycle rows.
impl PublicationLifecycleDecisionRow {
    /// Convert this database row into typed lifecycle evidence.
    pub(crate) fn into_record(self) -> Result<PublicationLifecycleDecisionRecord, CatalogError> {
        Ok(PublicationLifecycleDecisionRecord {
            id: self.id,
            action: parse_text_enum::<PublicationLifecycleAction>(
                self.action,
                "publication lifecycle action",
            )?,
            actor_account_id: self.actor_account_id,
            publisher_id: self.publisher_id,
            submission_id: self.submission_id,
            pack_name: self.pack_name,
            version: self.version,
            from_state: self.from_state,
            to_state: self.to_state,
            reason_code: self.reason_code,
            request_id: self.request_id,
            created_at: self.created_at,
        })
    }
}

/// Conversion helpers for immutable moderation decision rows.
impl PublicationModerationDecisionRow {
    /// Convert this database row into a typed moderation decision record.
    pub(crate) fn into_record(self) -> Result<PublicationModerationDecisionRecord, CatalogError> {
        Ok(PublicationModerationDecisionRecord {
            id: self.id,
            submission_id: self.submission_id,
            actor_account_id: self.actor_account_id,
            action: parse_text_enum::<PublicationModerationAction>(
                self.action,
                "publication moderation action",
            )?,
            from_state: parse_text_enum::<PublicationSubmissionState>(
                self.from_state,
                "publication moderation from state",
            )?,
            to_state: parse_text_enum::<PublicationSubmissionState>(
                self.to_state,
                "publication moderation to state",
            )?,
            reason_code: self.reason_code,
            private_explanation: self.private_explanation,
            request_id: self.request_id,
            created_at: self.created_at,
        })
    }
}

/// Conversion helpers for immutable publication appeal filing rows.
impl PublicationAppealRow {
    /// Convert this database row into typed appeal filing evidence.
    pub(crate) fn into_record(self) -> PublicationAppealRecord {
        PublicationAppealRecord {
            id: self.id,
            decision_id: self.decision_id,
            submission_id: self.submission_id,
            publisher_id: self.publisher_id,
            actor_account_id: self.actor_account_id,
            statement: self.statement,
            request_id: self.request_id,
            created_at: self.created_at,
        }
    }
}

/// Conversion helpers for immutable publication appeal resolution rows.
impl PublicationAppealResolutionRow {
    /// Convert this database row into typed appeal resolution evidence.
    pub(crate) fn into_record(self) -> Result<PublicationAppealResolutionRecord, CatalogError> {
        Ok(PublicationAppealResolutionRecord {
            id: self.id,
            appeal_id: self.appeal_id,
            actor_account_id: self.actor_account_id,
            disposition: parse_text_enum::<PublicationAppealDisposition>(
                self.disposition,
                "publication appeal disposition",
            )?,
            rationale: self.rationale,
            separation_exception_reason: self.separation_exception_reason,
            request_id: self.request_id,
            created_at: self.created_at,
        })
    }
}

/// Converts persisted author rows into catalog domain records.
impl AuthorRow {
    /// Convert this database row into an [`AuthorRecord`].
    ///
    /// Fails with `CatalogError::BackendError` if the stored `pubkey` byte
    /// slice is not exactly 32 bytes (data corruption) or if `oauth_links`
    /// cannot be deserialised from JSON.
    pub(crate) fn into_record(self) -> Result<AuthorRecord, CatalogError> {
        let pubkey = vec_to_pubkey(self.pubkey)?;
        let oauth_links: Vec<OauthLink> = serde_json::from_value(self.oauth_links)
            .map_err(|e| CatalogError::BackendError(Box::new(e)))?;
        Ok(AuthorRecord {
            pubkey,
            handle: self.handle,
            display_name: self.display_name,
            created_at: self.created_at,
            oauth_links,
        })
    }
}

/// Converts persisted pack rows into catalog domain records.
impl PackRow {
    /// Convert this database row into a [`PackRecord`].
    ///
    /// `total_downloads` is stored as `i64` (Postgres BIGINT) and cast to `u64`.
    /// Negative values are clamped to 0 (should never occur in practice).
    pub(crate) fn into_record(self) -> Result<PackRecord, CatalogError> {
        let current_author = vec_to_pubkey(self.current_author)?;
        Ok(PackRecord {
            name: self.name,
            current_author,
            publisher_id: self.publisher_id,
            tags: self.tags,
            description: self.description,
            created_at: self.created_at,
            latest_version: self.latest_version,
            total_downloads: self.total_downloads.max(0) as u64,
            extends: self.extends,
        })
    }
}

/// Converts persisted pack-version rows into catalog domain records.
impl PackVersionRow {
    /// Convert this database row into a [`PackVersionRecord`].
    ///
    /// `schema_version` is `i32` in the DB and `u32` in the domain; negative
    /// values (impossible via the application layer) would produce a
    /// `BackendError`.
    ///
    /// `status` is deserialised from the stored JSONB object.
    pub(crate) fn into_record(self) -> Result<PackVersionRecord, CatalogError> {
        let content_hash = vec_to_hash(self.content_hash)?;
        let author_pubkey = vec_to_pubkey(self.author_pubkey)?;
        let parent_hash = self.parent_hash.map(vec_to_hash).transpose()?;
        let schema_version = u32::try_from(self.schema_version).map_err(|_| {
            CatalogError::BackendError(Box::new(std::io::Error::other(
                "schema_version in DB is negative",
            )))
        })?;
        let size_bytes = u64::try_from(self.size_bytes).map_err(|_| {
            CatalogError::BackendError(Box::new(std::io::Error::other(format!(
                "size_bytes from DB is negative: {}",
                self.size_bytes
            ))))
        })?;
        let status: PackStatus = serde_json::from_value(self.status)
            .map_err(|e| CatalogError::BackendError(Box::new(e)))?;
        let capability_manifest_json = serde_json::to_string(&self.capability_manifest_json)
            .map_err(|e| CatalogError::BackendError(Box::new(e)))?;
        Ok(PackVersionRecord {
            pack_name: self.pack_name,
            version: self.version,
            content_hash,
            signature: self.signature,
            author_pubkey,
            publisher_key_id: self.publisher_key_id,
            parent_hash,
            capability_manifest_json,
            schema_version,
            license: self.license,
            published_at: self.published_at,
            status,
            size_bytes,
        })
    }
}
