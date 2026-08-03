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

/// Stated reason an applicant wants access to invite-only account features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountInviteIntent {
    /// The applicant wants to publish personas in the marketplace.
    PublishPersonas,
    /// The applicant wants access to premium account features.
    PremiumFeatures,
    /// The applicant is evaluating FrameShift for a team.
    TeamEvaluation,
    /// The applicant wants to contribute to the FrameShift ecosystem.
    Contribute,
    /// The applicant has another bounded reason described in their statement.
    Other,
}

/// Review state for an invite-only account application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountInviteStatus {
    /// The application is waiting for an initial review.
    Pending,
    /// An operator is actively reviewing the application.
    Reviewing,
    /// An operator issued an invite for the application.
    Invited,
    /// An operator declined the application without deleting its audit record.
    Declined,
}

/// Durable application for access to invite-only account registration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountInviteRequestRecord {
    /// Stable internal application identifier.
    pub id: Uuid,
    /// Lowercase, trimmed applicant email used for duplicate suppression.
    pub normalized_email: String,
    /// Optional applicant name retained only for review.
    pub display_name: Option<String>,
    /// Applicant-selected reason for requesting an invite.
    pub intent: AccountInviteIntent,
    /// Applicant's bounded private explanation for review.
    pub statement: String,
    /// Current review lifecycle state.
    pub status: AccountInviteStatus,
    /// UTC timestamp when the applicant accepted the stated contact terms.
    pub consented_at: DateTime<Utc>,
    /// UTC timestamp when the application was first stored.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of the most recent application update.
    pub updated_at: DateTime<Utc>,
}

/// Durable one-time invitation authorizing first-party account registration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountInviteRecord {
    /// Stable internal invitation identifier.
    pub id: Uuid,
    /// Application that produced this invitation, absent only for bootstrap invites.
    pub request_id: Option<Uuid>,
    /// Lowercase, trimmed email to which redemption is bound.
    pub normalized_email: String,
    /// SHA-256 digest of the random invitation token.
    #[serde(with = "crate::serde_helpers::bytes_as_b64")]
    pub token_digest: Vec<u8>,
    /// Administrator that issued the invitation, absent only for bootstrap invites.
    pub issued_by_account_id: Option<Uuid>,
    /// Whether this invitation was created out of band for initial authority bootstrap.
    pub is_bootstrap: bool,
    /// Exclusive UTC redemption deadline.
    pub expires_at: DateTime<Utc>,
    /// Successful one-time redemption timestamp.
    pub consumed_at: Option<DateTime<Utc>>,
    /// Explicit revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// UTC timestamp when the invitation was issued.
    pub created_at: DateTime<Utc>,
}

/// Administrator-authorized transition for one invite application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInviteReviewRequest {
    /// Application whose review state is changing.
    pub request_id: Uuid,
    /// New non-invited review state.
    pub status: AccountInviteStatus,
    /// Account performing the transition, which must be an active administrator.
    pub actor_account_id: Uuid,
}

/// Administrator-authorized input for issuing one application invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInviteIssueRequest {
    /// Stable invitation identifier generated by the application.
    pub id: Uuid,
    /// Application being approved.
    pub request_id: Uuid,
    /// SHA-256 digest of the random token returned once by the HTTP boundary.
    pub token_digest: Vec<u8>,
    /// Account issuing the invitation, which must be an active administrator.
    pub actor_account_id: Uuid,
    /// Exclusive UTC redemption deadline.
    pub expires_at: DateTime<Utc>,
    /// UTC issuance timestamp.
    pub created_at: DateTime<Utc>,
}

/// First-party password credential linked to a stable account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPasswordCredentialRecord {
    /// Account authenticated by this credential.
    pub account_id: Uuid,
    /// Lowercase, trimmed unique email used for sign-in.
    pub normalized_email: String,
    /// Argon2id PHC string containing salt and cost parameters.
    pub password_hash: String,
    /// Application credential-record schema version.
    pub password_version: i16,
    /// External deployment-pepper version.
    pub pepper_version: i16,
    /// Successful verification time for the invite-bound email.
    pub email_verified_at: Option<DateTime<Utc>>,
    /// UTC credential creation timestamp.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of the most recent password change.
    pub password_changed_at: DateTime<Utc>,
    /// UTC timestamp of the most recent credential update.
    pub updated_at: DateTime<Utc>,
}

/// Conditional replacement of a verified first-party password hash.
///
/// The expected fields bind the mutation to the exact credential observed by
/// the verifier so a pepper upgrade cannot overwrite a concurrent password
/// change. A pepper-only upgrade preserves `password_changed_at`; only the
/// hash metadata and `updated_at` change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPasswordRehashRequest {
    /// Account whose credential was successfully verified.
    pub account_id: Uuid,
    /// Normalized sign-in email used to locate the credential.
    pub normalized_email: String,
    /// Password hash that was successfully verified.
    pub expected_password_hash: String,
    /// Application credential version observed during verification.
    pub expected_password_version: i16,
    /// Deployment pepper version observed during verification.
    pub expected_pepper_version: i16,
    /// Credential update timestamp observed during verification.
    pub expected_updated_at: DateTime<Utc>,
    /// Fresh Argon2id PHC string produced with the current pepper.
    pub new_password_hash: String,
    /// Application credential version for the fresh hash.
    pub new_password_version: i16,
    /// Current deployment pepper version for the fresh hash.
    pub new_pepper_version: i16,
    /// UTC timestamp of the conditional credential update.
    pub updated_at: DateTime<Utc>,
}

/// Stable purpose attached to one encrypted password-recovery delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordRecoveryDeliveryKind {
    /// A message carrying the single-use password-reset link.
    Reset,
    /// A notification confirming that the account password changed.
    PasswordChanged,
}

/// Caller-encrypted payload and immutable metadata for one recovery delivery.
///
/// The catalog never receives the plaintext payload or encryption key. The
/// caller binds `id`, the operation-specific delivery kind, and `key_version`
/// into its authenticated encryption associated data before constructing this
/// envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedPasswordRecoveryDelivery {
    /// Stable outbox identifier and provider idempotency key.
    pub id: Uuid,
    /// Opaque authenticated ciphertext containing the delivery payload.
    pub ciphertext: Vec<u8>,
    /// Random 192-bit XChaCha20-Poly1305 nonce.
    pub nonce: [u8; 24],
    /// Deployment-managed encryption-key version used for this ciphertext.
    pub key_version: i16,
    /// Exclusive deadline after which a worker must not send this payload.
    pub expires_at: DateTime<Utc>,
}

/// Atomic input for creating a password-reset token and encrypted delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordRecoveryEnqueueRequest {
    /// Stable internal identifier for the digest-only reset-token row.
    pub token_id: Uuid,
    /// Lowercase, trimmed email used for an indistinguishable account lookup.
    pub normalized_email: String,
    /// SHA-256 digest of the raw reset token retained only by the requester.
    pub token_digest: Vec<u8>,
    /// UTC timestamp at which the request was admitted.
    pub requested_at: DateTime<Utc>,
    /// Exclusive deadline for consuming the reset token.
    pub token_expires_at: DateTime<Utc>,
    /// Requests newer than this timestamp suppress this enqueue operation.
    pub cooldown_cutoff: DateTime<Utc>,
    /// Encrypted reset-link delivery stored in the same transaction.
    pub delivery: EncryptedPasswordRecoveryDelivery,
}

/// Atomic input for consuming a reset token and replacing its credential.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordRecoveryCompletionRequest {
    /// SHA-256 digest of the reset token presented by the caller.
    pub token_digest: Vec<u8>,
    /// Fresh Argon2id PHC string produced under the current password policy.
    pub new_password_hash: String,
    /// Application credential-record version for the fresh hash.
    pub new_password_version: i16,
    /// Deployment-pepper version used to produce the fresh hash.
    pub new_pepper_version: i16,
    /// UTC timestamp committed as the password-change and revocation time.
    pub completed_at: DateTime<Utc>,
    /// Encrypted password-changed notice stored in the same transaction.
    pub delivery: EncryptedPasswordRecoveryDelivery,
}

/// One encrypted password-recovery delivery and its durable worker lifecycle.
///
/// This record deliberately contains no plaintext message body, reset URL, or
/// bearer token. `claim_id` fences worker acknowledgements and is present only
/// while the row has an active lease.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordRecoveryDeliveryRecord {
    /// Stable outbox identifier and provider idempotency key.
    pub id: Uuid,
    /// Account receiving the recovery-related message.
    pub account_id: Uuid,
    /// Stable message purpose used in authenticated encryption metadata.
    pub kind: PasswordRecoveryDeliveryKind,
    /// Lowercase, trimmed destination email derived from the credential row.
    pub recipient: String,
    /// Opaque authenticated ciphertext containing the message payload.
    pub ciphertext: Vec<u8>,
    /// Random 192-bit XChaCha20-Poly1305 nonce.
    pub nonce: [u8; 24],
    /// Deployment-managed encryption-key version required to decrypt the payload.
    pub key_version: i16,
    /// Number of leases issued for this row, including stale reclaims.
    pub attempt_count: u32,
    /// Most recent time a worker acquired this row, retained after lease release.
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// UUID fencing the currently active worker lease.
    pub claim_id: Option<Uuid>,
    /// Time at which the currently active worker lease began.
    pub claimed_at: Option<DateTime<Utc>>,
    /// Earliest time at which an unclaimed worker may acquire this row.
    pub next_attempt_at: DateTime<Utc>,
    /// Exclusive deadline after which no worker may acquire this row.
    pub expires_at: DateTime<Utc>,
    /// Time at which a fenced worker acknowledged successful delivery.
    pub sent_at: Option<DateTime<Utc>>,
    /// Provider-assigned message identifier retained after successful delivery.
    pub provider_message_id: Option<String>,
    /// Time at which a fenced worker marked the delivery permanently failed.
    pub failed_at: Option<DateTime<Utc>>,
    /// Bounded static diagnostic code from the most recent failed attempt.
    pub last_error_code: Option<String>,
    /// UTC timestamp at which the transaction created this row.
    pub created_at: DateTime<Utc>,
}

/// Bounded request for leasing pending recovery deliveries to one worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRecoveryDeliveryClaimRequest {
    /// UUID shared by every delivery leased in this batch.
    pub claim_id: Uuid,
    /// UTC timestamp recorded for this lease attempt.
    pub claimed_at: DateTime<Utc>,
    /// Existing claims at or before this timestamp may be reclaimed as stale.
    pub stale_before: DateTime<Utc>,
    /// Maximum number of rows to lease in this batch.
    pub limit: u32,
}

/// Client class receiving a first-party account session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountSessionClientKind {
    /// Browser session presented through a secure HTTP-only cookie.
    Browser,
    /// Desktop application session presented as an explicit bearer token.
    Desktop,
    /// Command-line session presented as an explicit bearer token.
    Cli,
}

/// Stable kind for one sanitized first-party authentication audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountAuthAuditEventKind {
    /// A password, registration, MFA, or authorization-code flow issued a session.
    SessionCreated,
    /// A valid refresh credential rotated an existing session family.
    SessionRefreshed,
    /// A consumed refresh credential was replayed and revoked its family.
    SessionReplayRevoked,
    /// An encrypted TOTP authenticator entered pending enrollment.
    MfaEnrollmentStarted,
    /// A verified pending authenticator replaced the prior active authenticator.
    MfaEnrollmentActivated,
    /// An unprivileged account disabled its active authenticator.
    MfaDisabled,
    /// Password verification created an expiring second-factor challenge.
    MfaChallengeCreated,
    /// A TOTP timestep or recovery code completed a second-factor challenge.
    MfaChallengeCompleted,
    /// An authenticated browser issued a one-time native authorization code.
    NativeAuthorizationCodeCreated,
    /// A native client exchanged a bound authorization code using S256 PKCE.
    NativeAuthorizationCodeConsumed,
    /// An authentication attempt was rejected without exposing sensitive input.
    AuthenticationRejected,
}

/// Stable outcome for a sanitized authentication audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountAuthAuditOutcome {
    /// The audited state transition committed successfully.
    Success,
    /// The audited authentication attempt was rejected.
    Rejected,
}

/// Append-only authentication audit event containing only sanitized fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountAuthAuditEventRecord {
    /// Stable event identifier used to make atomic writes externally traceable.
    pub id: Uuid,
    /// Stable event class that never contains caller-controlled text.
    pub event_kind: AccountAuthAuditEventKind,
    /// Stable success or rejection outcome.
    pub outcome: AccountAuthAuditOutcome,
    /// Affected account when it is safe and known.
    pub account_id: Option<Uuid>,
    /// Affected session family when one exists.
    pub session_id: Option<Uuid>,
    /// Client class involved in the authentication flow.
    pub client_kind: Option<AccountSessionClientKind>,
    /// Optional deployment-keyed digest of a canonical identifier.
    pub identifier_tag: Option<Vec<u8>>,
    /// Optional deployment-keyed digest of a canonical network prefix.
    pub network_tag: Option<Vec<u8>>,
    /// Optional bounded static reason code containing no user input.
    pub reason_code: Option<String>,
    /// UTC timestamp at which the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Revocable first-party session storing only a short-lived access-token digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSessionRecord {
    /// Stable internal session identifier.
    pub id: Uuid,
    /// Account authenticated by the session.
    pub account_id: Uuid,
    /// SHA-256 digest of the current random access token returned once to the client.
    pub token_digest: Vec<u8>,
    /// Client class controlling token presentation.
    pub client_kind: AccountSessionClientKind,
    /// UTC session creation timestamp.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of the most recent authenticated use.
    pub last_seen_at: DateTime<Utc>,
    /// Exclusive expiry of the current short-lived access token.
    pub access_expires_at: DateTime<Utc>,
    /// Sliding inactivity expiry.
    pub idle_expires_at: DateTime<Utc>,
    /// Non-extendable absolute expiry.
    pub absolute_expires_at: DateTime<Utc>,
    /// Most recent second-factor verification inherited by this session.
    pub mfa_verified_at: Option<DateTime<Utc>>,
    /// Explicit revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Digest-only initial credentials for creating one session family atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSessionIssuance {
    /// Persisted session family carrying the current access-token digest.
    pub session: AccountSessionRecord,
    /// Stable identifier for refresh generation zero.
    pub refresh_token_id: Uuid,
    /// SHA-256 digest of the initial random refresh token.
    pub refresh_token_digest: Vec<u8>,
    /// Exclusive expiry of the initial refresh token.
    pub refresh_expires_at: DateTime<Utc>,
}

/// Atomic session-family creation request with its sanitized success audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSessionCreationRequest {
    /// Access and initial refresh credentials to persist together.
    pub issuance: AccountSessionIssuance,
    /// Session-created success event committed in the same transaction.
    pub audit_event: AccountAuthAuditEventRecord,
}

/// Atomic request to rotate one presented refresh token and its access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSessionRefreshRequest {
    /// SHA-256 digest of the refresh token presented by the client.
    pub presented_refresh_token_digest: Vec<u8>,
    /// SHA-256 digest of the replacement access token.
    pub replacement_access_token_digest: Vec<u8>,
    /// Exclusive expiry of the replacement access token.
    pub replacement_access_expires_at: DateTime<Utc>,
    /// Replacement sliding inactivity expiry for the refreshed family.
    pub replacement_idle_expires_at: DateTime<Utc>,
    /// Stable identifier for the replacement refresh generation.
    pub replacement_refresh_token_id: Uuid,
    /// SHA-256 digest of the replacement refresh token.
    pub replacement_refresh_token_digest: Vec<u8>,
    /// Exclusive expiry of the replacement refresh token.
    pub replacement_refresh_expires_at: DateTime<Utc>,
    /// UTC timestamp committed for consumption, rotation, or replay revocation.
    pub rotated_at: DateTime<Utc>,
    /// Success event committed only when rotation succeeds.
    pub success_audit_event: AccountAuthAuditEventRecord,
    /// Replay event committed only when a consumed generation is presented.
    pub replay_audit_event: AccountAuthAuditEventRecord,
}

/// Security-preserving result of one refresh-token transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountSessionRefreshResult {
    /// The access token and refresh generation rotated successfully.
    Rotated(AccountSessionRecord),
    /// A consumed generation was replayed and the complete family was revoked.
    ReplayRevoked,
    /// The digest was unknown, expired, or belonged to an unusable family.
    Rejected,
}

/// Lifecycle state for encrypted TOTP authenticator metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountMfaAuthenticatorState {
    /// The authenticator awaits a proof-of-possession confirmation.
    Pending,
    /// The authenticator may satisfy second-factor challenges.
    Active,
    /// The authenticator is retained only as security history.
    Disabled,
}

/// Caller-encrypted TOTP secret metadata containing no plaintext secret.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedTotpSecret {
    /// Opaque authenticated ciphertext containing the TOTP seed.
    pub ciphertext: Vec<u8>,
    /// Random 192-bit XChaCha20-Poly1305 nonce.
    pub nonce: [u8; 24],
    /// Deployment-managed encryption-key version required for decryption.
    pub key_version: i16,
}

/// Durable encrypted TOTP authenticator state for one account.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountMfaAuthenticatorRecord {
    /// Stable authenticator identifier.
    pub id: Uuid,
    /// Account that owns the authenticator.
    pub account_id: Uuid,
    /// Pending, active, or disabled lifecycle state.
    pub state: AccountMfaAuthenticatorState,
    /// Encrypted TOTP seed and deployment key metadata.
    pub secret: EncryptedTotpSecret,
    /// Exclusive deadline for confirming a pending enrollment.
    pub pending_expires_at: Option<DateTime<Utc>>,
    /// Greatest successfully consumed TOTP timestep.
    pub last_used_timestep: Option<i64>,
    /// UTC timestamp when the encrypted metadata was created.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp when enrollment was confirmed.
    pub activated_at: Option<DateTime<Utc>>,
    /// UTC timestamp when the authenticator stopped being active.
    pub disabled_at: Option<DateTime<Utc>>,
}

/// Digest-only seed for one high-entropy MFA recovery code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMfaRecoveryCodeSeed {
    /// Stable recovery-code row identifier.
    pub id: Uuid,
    /// SHA-256 digest of the random recovery code shown once to the account.
    pub code_digest: Vec<u8>,
}

/// Atomic request to begin or replace a pending TOTP enrollment.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountMfaEnrollmentRequest {
    /// Pending encrypted authenticator record to persist.
    pub authenticator: AccountMfaAuthenticatorRecord,
    /// Enrollment-started success event committed with the pending state.
    pub audit_event: AccountAuthAuditEventRecord,
}

/// Atomic request to activate a verified pending TOTP authenticator.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountMfaActivationRequest {
    /// Account whose pending authenticator is being activated.
    pub account_id: Uuid,
    /// Exact pending authenticator that passed proof of possession.
    pub authenticator_id: Uuid,
    /// TOTP timestep consumed by enrollment confirmation.
    pub verified_timestep: i64,
    /// Digest-only high-entropy recovery codes created with activation.
    pub recovery_codes: Vec<AccountMfaRecoveryCodeSeed>,
    /// UTC timestamp committed as the activation and old-authenticator disable time.
    pub activated_at: DateTime<Utc>,
    /// Enrollment-activated success event committed with the swap.
    pub audit_event: AccountAuthAuditEventRecord,
}

/// Atomic request to disable active MFA for an unprivileged account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMfaDisableRequest {
    /// Account whose active authenticator is being disabled.
    pub account_id: Uuid,
    /// UTC timestamp committed as the disable time.
    pub disabled_at: DateTime<Utc>,
    /// MFA-disabled success event committed with the state change.
    pub audit_event: AccountAuthAuditEventRecord,
}

/// Digest-only expiring challenge issued after password verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMfaLoginChallengeRecord {
    /// Stable challenge identifier.
    pub id: Uuid,
    /// Account that passed the first authentication factor.
    pub account_id: Uuid,
    /// SHA-256 digest of the random challenge token.
    pub token_digest: Vec<u8>,
    /// Client class to which challenge completion is bound.
    pub client_kind: AccountSessionClientKind,
    /// UTC challenge creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Exclusive challenge-completion deadline.
    pub expires_at: DateTime<Utc>,
    /// Successful one-time completion timestamp.
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Atomic request to create a password-bound MFA login challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMfaChallengeCreationRequest {
    /// Digest-only challenge record to persist.
    pub challenge: AccountMfaLoginChallengeRecord,
    /// Challenge-created success event committed in the same transaction.
    pub audit_event: AccountAuthAuditEventRecord,
}

/// Database-fenced proof already verified against an encrypted authenticator.
#[derive(Clone, PartialEq, Eq)]
pub enum AccountMfaChallengeProof {
    /// TOTP timestep whose code was verified by the caller.
    TotpTimestep(i64),
    /// SHA-256 digest of a presented high-entropy recovery code.
    RecoveryCodeDigest(Vec<u8>),
}

/// Atomic request to consume an MFA challenge and issue a verified session.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountMfaChallengeCompletionRequest {
    /// SHA-256 digest of the random challenge token.
    pub challenge_token_digest: Vec<u8>,
    /// Exact active authenticator whose secret or recovery code verified the proof.
    pub authenticator_id: Uuid,
    /// TOTP timestep or recovery-code digest to consume once.
    pub proof: AccountMfaChallengeProof,
    /// Access and initial refresh credentials to persist on success.
    pub issuance: AccountSessionIssuance,
    /// UTC timestamp used for expiry, consumption, and MFA assurance.
    pub completed_at: DateTime<Utc>,
    /// Challenge-completed success event committed with the session.
    pub audit_event: AccountAuthAuditEventRecord,
}

/// Result of atomically completing one MFA login challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountMfaChallengeCompletionResult {
    /// The proof and challenge were consumed and a session family was issued.
    Completed(AccountSessionRecord),
    /// The challenge or proof was unusable without exposing which condition failed.
    Rejected,
}

/// Digest-only native authorization code bound to an exact S256 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAuthorizationCodeRecord {
    /// Stable authorization-code identifier.
    pub id: Uuid,
    /// Browser-authenticated account authorizing the native client.
    pub account_id: Uuid,
    /// SHA-256 digest of the random one-time authorization code.
    pub token_digest: Vec<u8>,
    /// Desktop or CLI client receiving the code.
    pub client_kind: AccountSessionClientKind,
    /// Exact IP-literal loopback redirect URI string.
    pub redirect_uri: String,
    /// Decoded 32-byte S256 PKCE challenge.
    pub pkce_challenge: Vec<u8>,
    /// MFA assurance inherited from the authorizing browser session.
    pub mfa_verified_at: Option<DateTime<Utc>>,
    /// UTC code creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Exclusive code-exchange deadline.
    pub expires_at: DateTime<Utc>,
    /// Successful one-time exchange timestamp.
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Atomic request to issue one native authorization code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAuthorizationCodeCreationRequest {
    /// Exact digest-only authorization record to persist.
    pub code: NativeAuthorizationCodeRecord,
    /// Code-created success event committed in the same transaction.
    pub audit_event: AccountAuthAuditEventRecord,
}

/// Atomic S256 exchange request for one native authorization code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAuthorizationCodeExchangeRequest {
    /// SHA-256 digest of the random authorization code.
    pub code_token_digest: Vec<u8>,
    /// Desktop or CLI client class expected by the code.
    pub client_kind: AccountSessionClientKind,
    /// Exact redirect URI string expected by the code.
    pub redirect_uri: String,
    /// SHA-256 digest of the presented PKCE verifier.
    pub pkce_challenge: Vec<u8>,
    /// Access and initial refresh credentials to persist on success.
    pub issuance: AccountSessionIssuance,
    /// UTC timestamp used for expiry and one-time consumption.
    pub exchanged_at: DateTime<Utc>,
    /// Code-consumed success event committed with the session.
    pub audit_event: AccountAuthAuditEventRecord,
}

/// Result of atomically exchanging one native authorization code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeAuthorizationCodeExchangeResult {
    /// The exact code, client, redirect, and S256 challenge issued a session.
    Exchanged(AccountSessionRecord),
    /// The exchange failed without revealing which binding was unusable.
    Rejected,
}

/// Atomic first-party registration input consumed with one invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAccountRegistrationRequest {
    /// SHA-256 digest identifying the invitation without exposing its raw token.
    pub invite_token_digest: Vec<u8>,
    /// Stable local account row to create.
    pub account: AccountRecord,
    /// Argon2id password credential to create.
    pub credential: AccountPasswordCredentialRecord,
    /// Initial authenticated access and refresh credentials to create.
    pub session: AccountSessionIssuance,
    /// Session-created success event committed with registration.
    pub audit_event: AccountAuthAuditEventRecord,
}

/// Result of an atomic first-party invitation redemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAccountRegistrationResult {
    /// Newly created active account.
    pub account: AccountRecord,
    /// Newly created authenticated session.
    pub session: AccountSessionRecord,
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
