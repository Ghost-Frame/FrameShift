//! [`CatalogBackend`] implementation for PostgreSQL.
//!
//! [`PostgresCatalog`] holds a `bb8` pool and implements every method of the
//! trait by translating the typed catalog API into Diesel DSL queries executed
//! on `AsyncPgConnection` connections checked out from the pool.
//!
//! # Migrations
//!
//! Migrations are run automatically inside [`PostgresCatalog::new`] using
//! [`diesel_migrations::MigrationHarness::run_pending_migrations`]. Diesel
//! tracks applied migrations in the `__diesel_schema_migrations` table; calling
//! `new()` a second time is a safe no-op (only unapplied migrations are run).
//!
//! # Error mapping
//!
//! All Diesel errors are translated by [`crate::errors::map_diesel_error`].
//! Pool checkout failures are mapped by [`crate::errors::map_pool_error`].

use async_trait::async_trait;
use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness as _};
use tracing::{debug, error, instrument};

use frameshift_catalog::{
    AccountInviteIssueRequest, AccountInviteRecord, AccountInviteRequestRecord,
    AccountInviteReviewRequest, AccountInviteStatus, AccountPasswordCredentialRecord,
    AccountPasswordRehashRequest, AccountRecord, AccountSessionRecord, AccountStatusChangeRequest,
    AuthorRecord, CatalogBackend, CatalogError, Ed25519PublicKey, HealthStatus,
    LocalAccountRegistrationRequest, LocalAccountRegistrationResult, MembershipState, PackRecord,
    PackSearchFilters, PackSearchResult, PackStatus, PackVersionRecord, PlatformRole,
    PlatformRoleAssignmentRequest, PlatformRoleRecord, PlatformRoleRevocationRequest,
    PublicationAppealCaseRecord, PublicationAppealCursor, PublicationAppealDisposition,
    PublicationAppealRecord, PublicationAppealRequest, PublicationAppealResolutionRecord,
    PublicationAppealResolutionRequest, PublicationIntentClaim, PublicationIntentRecord,
    PublicationLifecycleAction, PublicationLifecycleCursor, PublicationLifecycleDecisionRecord,
    PublicationModerationAction, PublicationModerationDecisionRecord,
    PublicationModerationDecisionRequest, PublicationModerationSnapshot,
    PublicationPromotionRecord, PublicationPromotionRequest, PublicationSubmissionRecord,
    PublicationSubmissionRequest, PublicationSubmissionState, PublicationTombstoneRequest,
    PublicationWithdrawalRequest, PublishQuota, PublisherAuditEventRecord, PublisherKeyRecord,
    PublisherMembershipRecord, PublisherProfileRecord, PublisherSuspensionRequest, SortMode,
    TombstoneRecord,
};
use frameshift_publication::{inventory_hash, FindingSeverity, REPORT_SCHEMA_VERSION};

use crate::config::PostgresCatalogConfig;
use crate::errors::{map_diesel_error, map_migration_error, map_pool_error};
use crate::models::{
    encode_text_enum, vec_to_pubkey, AccountInviteRequestRow, AccountInviteRow,
    AccountPasswordCredentialRow, AccountRow, AccountSessionRow, AuthorRow, HandleRow,
    NewAccountInviteRequestRow, NewAccountInviteRow, NewAccountPasswordCredentialRow,
    NewAccountRow, NewAccountSessionRow, NewAuthorRow, NewHandleRow, NewPackDownloadRow,
    NewPackRow, NewPackVersionRow, NewPublicationAppealResolutionRow, NewPublicationAppealRow,
    NewPublicationIntentRow, NewPublicationLifecycleDecisionRow,
    NewPublicationModerationDecisionRow, NewPublicationPromotionRow, NewPublicationSubmissionRow,
    NewPublisherAuditEventRow, NewPublisherKeyRow, NewPublisherMembershipRow,
    NewPublisherProfileRow, PackRow, PackVersionRow, PlatformRoleRow,
    PublicationAppealResolutionRow, PublicationAppealRow, PublicationIntentRow,
    PublicationLifecycleDecisionRow, PublicationModerationDecisionRow, PublicationPromotionRow,
    PublicationSubmissionRow, PublisherKeyRow, PublisherMembershipRow, PublisherProfileRow,
};
use crate::pool::{build_pool, PgPool};
use crate::schema::{
    account_invite_requests, account_invites, account_password_credentials, account_platform_roles,
    account_sessions, accounts, authors, handles, pack_downloads, pack_versions, packs,
    publication_appeal_resolutions, publication_appeals, publication_intents,
    publication_lifecycle_decisions, publication_moderation_decisions, publication_promotions,
    publication_submissions, publisher_audit_events, publisher_keys, publisher_memberships,
    publisher_profiles, signed_request_nonces,
};

/// Embedded migration files compiled into the binary at build time.
///
/// The path is relative to the crate root (where `Cargo.toml` lives), NOT the
/// source file. `cargo build` resolves it correctly as long as the `migrations/`
/// directory exists at `crates/frameshift-catalog-postgres/migrations/`.
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

/// Postgres-backed implementation of [`CatalogBackend`].
///
/// Holds a `bb8` connection pool. All trait methods are `async` and check out
/// a connection from the pool for the duration of each operation. Long-running
/// queries are subject to the `statement_timeout` configured via
/// [`PostgresCatalogConfig`].
///
/// # Thread safety
///
/// `PostgresCatalog` is `Send + Sync`. The pool is `Arc`-backed internally by
/// `bb8` and safe to share across threads and async tasks.
#[derive(Debug, Clone)]
pub struct PostgresCatalog {
    /// The bb8 connection pool.
    pool: PgPool,
}

/// Bounded result row for registry-wide storage accounting.
#[derive(QueryableByName)]
struct TotalBytesRow {
    /// Total bytes represented by all published pack versions.
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    total: i64,
}

/// Bounded result row for the unresolved moderation queue aggregates.
#[derive(QueryableByName)]
struct ModerationQueueRow {
    /// Submissions still in the initial quarantine state.
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    quarantined: i64,
    /// Creation time of the oldest initially quarantined submission.
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    oldest_quarantined_at: Option<DateTime<Utc>>,
    /// All unresolved submissions awaiting review or requested changes.
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    queued: i64,
    /// Creation time of the oldest unresolved submission.
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    oldest_queued_at: Option<DateTime<Utc>>,
}

/// Transaction error preserving catalog policy failures across Diesel rollbacks.
enum CatalogTransactionError {
    /// A domain-level catalog failure that must be returned unchanged.
    Catalog(CatalogError),
    /// A raw Diesel failure that must be mapped after the transaction ends.
    Diesel(diesel::result::Error),
}

/// Convert raw Diesel failures into the shared transaction error wrapper.
impl From<diesel::result::Error> for CatalogTransactionError {
    /// Preserve the Diesel error until the caller can attach resource context.
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

/// Validate and convert a catalog audit record into its insertable row.
fn new_publisher_audit_row(
    event: PublisherAuditEventRecord,
) -> Result<NewPublisherAuditEventRow, CatalogError> {
    if event.action.trim().is_empty() || !event.metadata.is_object() {
        return Err(CatalogError::Validation(
            "audit action must be non-blank and metadata must be an object".to_string(),
        ));
    }
    Ok(NewPublisherAuditEventRow {
        id: event.id,
        actor_account_id: event.actor_account_id,
        publisher_id: event.publisher_id,
        action: event.action,
        target_key_id: event.target_key_id,
        target_version: event.target_version,
        request_id: event.request_id,
        created_at: event.created_at,
        metadata: event.metadata,
    })
}

/// Require an optional audit event to describe the publisher being mutated.
fn validate_audit_publisher(
    event: Option<&PublisherAuditEventRecord>,
    publisher_id: uuid::Uuid,
) -> Result<(), CatalogError> {
    if event.is_some_and(|event| event.publisher_id != publisher_id) {
        return Err(CatalogError::InvalidArgument(
            "audit publisher_id must match the mutated publisher".to_string(),
        ));
    }
    Ok(())
}

/// Convert a positive domain scan schema version into its PostgreSQL representation.
fn publication_intent_scan_schema(scan_schema_version: u32) -> Result<i32, CatalogError> {
    if scan_schema_version == 0 {
        return Err(CatalogError::InvalidArgument(
            "publication intent scan_schema_version must be positive".to_string(),
        ));
    }
    i32::try_from(scan_schema_version).map_err(|_| {
        CatalogError::InvalidArgument(
            "publication intent scan_schema_version exceeds PostgreSQL INTEGER".to_string(),
        )
    })
}

/// Compare an idempotent create retry at PostgreSQL's microsecond precision.
fn publication_intent_matches(
    existing: &PublicationIntentRecord,
    requested: &PublicationIntentRecord,
) -> bool {
    existing.id == requested.id
        && existing.account_id == requested.account_id
        && existing.publisher_id == requested.publisher_id
        && existing.publisher_key_id == requested.publisher_key_id
        && existing.archive_hash == requested.archive_hash
        && existing.manifest_hash == requested.manifest_hash
        && existing.file_inventory_hash == requested.file_inventory_hash
        && existing.scan_schema_version == requested.scan_schema_version
        && existing.created_at.timestamp_micros() == requested.created_at.timestamp_micros()
        && existing.expires_at.timestamp_micros() == requested.expires_at.timestamp_micros()
}

/// Construct a uniform authorization failure for publication intent creation.
fn publication_intent_unauthorized(id: uuid::Uuid) -> CatalogTransactionError {
    CatalogTransactionError::Catalog(CatalogError::Unauthorized {
        kind: "publication_intent",
        key: id.to_string(),
    })
}

/// Validate a typed server report against the exact intent claim.
fn validate_publication_submission(
    request: &PublicationSubmissionRequest,
) -> Result<(i32, serde_json::Value), CatalogError> {
    let scan_schema_version = publication_intent_scan_schema(request.intent.scan_schema_version)?;
    if request.scan_report.schema_version != request.intent.scan_schema_version {
        return Err(CatalogError::InvalidArgument(
            "publication submission report schema must match its intent".to_string(),
        ));
    }
    if request.scan_report.schema_version != REPORT_SCHEMA_VERSION {
        return Err(CatalogError::InvalidArgument(
            "publication submission report schema is not supported".to_string(),
        ));
    }
    if !request.scan_report.valid
        || request
            .scan_report
            .findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Error)
    {
        return Err(CatalogError::Validation(
            "publication submission requires a valid server scan report".to_string(),
        ));
    }
    let declared_inventory_hash = frameshift_catalog::ObjectHash::from_hex(
        &request.scan_report.inventory_hash,
    )
    .map_err(|_| {
        CatalogError::InvalidArgument(
            "publication submission report has an invalid inventory hash".to_string(),
        )
    })?;
    if declared_inventory_hash != request.intent.file_inventory_hash {
        return Err(CatalogError::Unauthorized {
            kind: "publication_submission",
            key: request.id.to_string(),
        });
    }
    if frameshift_catalog::ObjectHash::from_hex(&inventory_hash(&request.scan_report.inventory))
        .map_err(|_| {
            CatalogError::BackendError(Box::new(std::io::Error::other(
                "shared publication inventory hash was not valid hexadecimal",
            )))
        })?
        != declared_inventory_hash
    {
        return Err(CatalogError::Validation(
            "publication submission report inventory hash is inconsistent".to_string(),
        ));
    }
    if !request
        .scan_report
        .inventory
        .windows(2)
        .all(|pair| pair[0].path.as_bytes() < pair[1].path.as_bytes())
        || !request
            .scan_report
            .findings
            .windows(2)
            .all(|pair| pair[0] <= pair[1])
    {
        return Err(CatalogError::InvalidArgument(
            "publication submission report must be deterministically sorted".to_string(),
        ));
    }
    let scan_report = serde_json::to_value(&request.scan_report)
        .map_err(|error| CatalogError::BackendError(Box::new(error)))?;
    Ok((scan_schema_version, scan_report))
}

/// Compare an exact submission retry without caller-controlled timestamps.
fn publication_submission_matches(
    existing: &PublicationSubmissionRecord,
    requested: &PublicationSubmissionRequest,
) -> bool {
    existing.id == requested.id
        && existing.intent_id == requested.intent.id
        && existing.account_id == requested.intent.account_id
        && existing.publisher_id == requested.intent.publisher_id
        && existing.publisher_key_id == requested.intent.publisher_key_id
        && existing.archive_hash == requested.intent.archive_hash
        && existing.manifest_hash == requested.intent.manifest_hash
        && existing.file_inventory_hash == requested.intent.file_inventory_hash
        && existing.scan_schema_version == requested.intent.scan_schema_version
        && existing.scan_report == requested.scan_report
        && existing.state == PublicationSubmissionState::Quarantined
}

/// Construct an exact idempotency conflict for a publication submission.
fn publication_submission_conflict(id: uuid::Uuid) -> CatalogTransactionError {
    CatalogTransactionError::Catalog(CatalogError::Conflict {
        kind: "publication_submission",
        key: id.to_string(),
    })
}

/// Convert an existing row into an exact retry or an idempotency conflict.
fn resolve_publication_submission_retry(
    row: PublicationSubmissionRow,
    request: &PublicationSubmissionRequest,
) -> Result<PublicationSubmissionRow, CatalogTransactionError> {
    let record = row
        .clone()
        .into_record()
        .map_err(CatalogTransactionError::Catalog)?;
    if publication_submission_matches(&record, request) {
        Ok(row)
    } else {
        Err(publication_submission_conflict(request.id))
    }
}

/// Compare immutable promotion evidence with one exact retry request.
fn publication_promotion_matches(
    existing: &PublicationPromotionRecord,
    request: &PublicationPromotionRequest,
) -> bool {
    existing.id == request.id
        && existing.submission_id == request.submission_id
        && existing.actor_account_id == request.actor_account_id
        && existing.pack_name == request.version.pack_name
        && existing.version == request.version.version
        && existing.content_hash == request.version.content_hash
        && existing.request_id == request.request_id
}

/// Resolve one completed promotion retry or reject identifier substitution.
fn resolve_publication_promotion_retry(
    row: PublicationPromotionRow,
    request: &PublicationPromotionRequest,
) -> Result<PublicationPromotionRow, CatalogTransactionError> {
    let record = row
        .clone()
        .into_record()
        .map_err(CatalogTransactionError::Catalog)?;
    if publication_promotion_matches(&record, request) {
        Ok(row)
    } else {
        Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
            kind: "publication_promotion",
            key: request.id.to_string(),
        }))
    }
}

/// Validate bounded moderation fields before starting a database transaction.
fn validate_publication_moderation_request(
    request: &PublicationModerationDecisionRequest,
) -> Result<(), CatalogError> {
    let reason = request.reason_code.as_bytes();
    let reason_valid = !reason.is_empty()
        && reason.len() <= 64
        && reason
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    let reason_tail_valid = reason.iter().skip(1).all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
    });
    if !reason_valid || !reason_tail_valid {
        return Err(CatalogError::InvalidArgument(
            "publication moderation reason_code must use 1-64 lowercase ASCII letters, digits, '.', '_', or '-'"
                .to_string(),
        ));
    }
    if request
        .private_explanation
        .as_ref()
        .is_some_and(|value| value.trim().is_empty() || value.chars().count() > 2_000)
    {
        return Err(CatalogError::InvalidArgument(
            "publication moderation private_explanation must be non-blank and at most 2000 characters"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validate a stable bounded lifecycle reason code.
fn validate_publication_lifecycle_reason(reason_code: &str) -> Result<(), CatalogError> {
    let reason = reason_code.as_bytes();
    let valid_head = !reason.is_empty()
        && reason.len() <= 64
        && reason
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    let valid_tail = reason.iter().skip(1).all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
    });
    if !valid_head || !valid_tail {
        return Err(CatalogError::InvalidArgument(
            "publication lifecycle reason_code must use 1-64 lowercase ASCII letters, digits, '.', '_', or '-'"
                .to_string(),
        ));
    }
    Ok(())
}

/// Return an idempotency conflict for a lifecycle request.
fn publication_lifecycle_conflict(id: uuid::Uuid) -> CatalogTransactionError {
    CatalogTransactionError::Catalog(CatalogError::Conflict {
        kind: "publication_lifecycle_decision",
        key: id.to_string(),
    })
}

/// Exact immutable fields supplied by one lifecycle request.
struct ExpectedPublicationLifecycleDecision<'a> {
    /// Stable decision identifier.
    id: uuid::Uuid,
    /// Lifecycle action being retried.
    action: PublicationLifecycleAction,
    /// Account that originally exercised authority.
    actor_account_id: uuid::Uuid,
    /// Optional affected publisher.
    publisher_id: Option<uuid::Uuid>,
    /// Optional affected submission.
    submission_id: Option<uuid::Uuid>,
    /// Optional affected pack.
    pack_name: Option<&'a str>,
    /// Optional affected pack version.
    version: Option<&'a str>,
    /// Stable reason code.
    reason_code: &'a str,
    /// Stable request correlation identifier.
    request_id: uuid::Uuid,
}

/// Resolve one completed lifecycle retry or reject identifier substitution.
fn resolve_publication_lifecycle_retry(
    row: PublicationLifecycleDecisionRow,
    expected: ExpectedPublicationLifecycleDecision<'_>,
) -> Result<PublicationLifecycleDecisionRow, CatalogTransactionError> {
    let record = row
        .clone()
        .into_record()
        .map_err(CatalogTransactionError::Catalog)?;
    let matches = record.id == expected.id
        && record.action == expected.action
        && record.actor_account_id == expected.actor_account_id
        && record.publisher_id == expected.publisher_id
        && record.submission_id == expected.submission_id
        && record.pack_name.as_deref() == expected.pack_name
        && record.version.as_deref() == expected.version
        && record.reason_code == expected.reason_code
        && record.request_id == expected.request_id;
    if matches {
        Ok(row)
    } else {
        Err(publication_lifecycle_conflict(expected.id))
    }
}

/// Validate a bounded lifecycle audit page size.
fn publication_lifecycle_limit(limit: u32) -> Result<i64, CatalogError> {
    if !(1..=100).contains(&limit) {
        return Err(CatalogError::InvalidArgument(
            "publication lifecycle audit limit must be between 1 and 100".to_string(),
        ));
    }
    Ok(i64::from(limit))
}

/// Return the non-public submission state produced by one moderation action.
fn publication_moderation_target(
    action: PublicationModerationAction,
) -> PublicationSubmissionState {
    match action {
        PublicationModerationAction::Approve => PublicationSubmissionState::Approved,
        PublicationModerationAction::RequestChanges => PublicationSubmissionState::NeedsReview,
        PublicationModerationAction::Reject => PublicationSubmissionState::Rejected,
    }
}

/// Compare an immutable moderation decision with an exact retry request.
fn publication_moderation_decision_matches(
    existing: &PublicationModerationDecisionRecord,
    request: &PublicationModerationDecisionRequest,
) -> bool {
    existing.id == request.id
        && existing.submission_id == request.submission_id
        && existing.actor_account_id == request.actor_account_id
        && existing.action == request.action
        && existing.to_state == publication_moderation_target(request.action)
        && existing.reason_code == request.reason_code
        && existing.private_explanation == request.private_explanation
        && existing.request_id == request.request_id
}

/// Construct a uniform moderation idempotency conflict.
fn publication_moderation_conflict(id: uuid::Uuid) -> CatalogTransactionError {
    CatalogTransactionError::Catalog(CatalogError::Conflict {
        kind: "publication_moderation_decision",
        key: id.to_string(),
    })
}

/// Convert an existing decision into an exact retry or idempotency conflict.
fn resolve_publication_moderation_retry(
    row: PublicationModerationDecisionRow,
    request: &PublicationModerationDecisionRequest,
) -> Result<PublicationModerationDecisionRow, CatalogTransactionError> {
    let record = row
        .clone()
        .into_record()
        .map_err(CatalogTransactionError::Catalog)?;
    if publication_moderation_decision_matches(&record, request) {
        Ok(row)
    } else {
        Err(publication_moderation_conflict(request.id))
    }
}

/// Validate one required bounded private appeal text field.
fn validate_publication_appeal_text(
    value: &str,
    field: &str,
    maximum: usize,
) -> Result<(), CatalogError> {
    if value.trim().is_empty() || value.chars().count() > maximum {
        return Err(CatalogError::InvalidArgument(format!(
            "publication appeal {field} must be non-blank and at most {maximum} characters"
        )));
    }
    Ok(())
}

/// Validate all caller-controlled fields for one appeal filing.
fn validate_publication_appeal_request(
    request: &PublicationAppealRequest,
) -> Result<(), CatalogError> {
    validate_publication_appeal_text(&request.statement, "statement", 4_000)
}

/// Validate all caller-controlled fields for one appeal resolution.
fn validate_publication_appeal_resolution_request(
    request: &PublicationAppealResolutionRequest,
) -> Result<(), CatalogError> {
    validate_publication_appeal_text(&request.rationale, "rationale", 4_000)?;
    if let Some(reason) = &request.separation_exception_reason {
        validate_publication_appeal_text(reason, "separation_exception_reason", 1_000)?;
    }
    Ok(())
}

/// Return whether one moderation action may be appealed under the launch policy.
fn publication_moderation_action_is_appealable(action: PublicationModerationAction) -> bool {
    matches!(
        action,
        PublicationModerationAction::RequestChanges | PublicationModerationAction::Reject
    )
}

/// Return an idempotency conflict for an appeal filing.
fn publication_appeal_conflict(id: uuid::Uuid) -> CatalogTransactionError {
    CatalogTransactionError::Catalog(CatalogError::Conflict {
        kind: "publication_appeal",
        key: id.to_string(),
    })
}

/// Resolve one completed appeal filing retry or reject identifier substitution.
fn resolve_publication_appeal_retry(
    row: PublicationAppealRow,
    request: &PublicationAppealRequest,
) -> Result<PublicationAppealRow, CatalogTransactionError> {
    let record = row.clone().into_record();
    if record.id == request.id
        && record.decision_id == request.decision_id
        && record.publisher_id == request.publisher_id
        && record.actor_account_id == request.actor_account_id
        && record.statement == request.statement
        && record.request_id == request.request_id
    {
        Ok(row)
    } else {
        Err(publication_appeal_conflict(request.id))
    }
}

/// Return an idempotency conflict for an appeal resolution.
fn publication_appeal_resolution_conflict(id: uuid::Uuid) -> CatalogTransactionError {
    CatalogTransactionError::Catalog(CatalogError::Conflict {
        kind: "publication_appeal_resolution",
        key: id.to_string(),
    })
}

/// Resolve one completed appeal resolution retry or reject substitution.
fn resolve_publication_appeal_resolution_retry(
    row: PublicationAppealResolutionRow,
    request: &PublicationAppealResolutionRequest,
) -> Result<PublicationAppealResolutionRow, CatalogTransactionError> {
    let record = row
        .clone()
        .into_record()
        .map_err(CatalogTransactionError::Catalog)?;
    if record.id == request.id
        && record.appeal_id == request.appeal_id
        && record.actor_account_id == request.actor_account_id
        && record.disposition == request.disposition
        && record.rationale == request.rationale
        && record.separation_exception_reason == request.separation_exception_reason
        && record.request_id == request.request_id
    {
        Ok(row)
    } else {
        Err(publication_appeal_resolution_conflict(request.id))
    }
}

/// Validate a bounded publication appeal page size.
fn publication_appeal_limit(limit: u32) -> Result<i64, CatalogError> {
    if !(1..=100).contains(&limit) {
        return Err(CatalogError::InvalidArgument(
            "publication appeal limit must be between 1 and 100".to_string(),
        ));
    }
    Ok(i64::from(limit))
}

/// Pair appeal filing rows with optional immutable resolution rows.
fn publication_appeal_cases(
    appeals: Vec<PublicationAppealRow>,
    resolutions: Vec<PublicationAppealResolutionRow>,
) -> Result<Vec<PublicationAppealCaseRecord>, CatalogError> {
    let mut resolutions_by_appeal = resolutions
        .into_iter()
        .map(|row| row.into_record().map(|record| (record.appeal_id, record)))
        .collect::<Result<HashMap<_, _>, _>>()?;
    Ok(appeals
        .into_iter()
        .map(|appeal| {
            let appeal = appeal.into_record();
            let resolution = resolutions_by_appeal.remove(&appeal.id);
            PublicationAppealCaseRecord { appeal, resolution }
        })
        .collect())
}

/// Inherent methods on [`PostgresCatalog`]: constructor, pool accessor.
impl PostgresCatalog {
    /// Create a new [`PostgresCatalog`], open the connection pool, and run
    /// all pending embedded migrations.
    ///
    /// # Migration behaviour
    ///
    /// Migrations are embedded via `embed_migrations!` and run using Diesel's
    /// `MigrationHarness`. The `__diesel_schema_migrations` table tracks which
    /// migrations have already been applied, so calling `new()` on a database
    /// that already has all migrations applied is a safe no-op. This makes
    /// `new()` safe to call on every application startup.
    ///
    /// # Errors
    ///
    /// - `CatalogError::BackendError` -- pool construction failed (bad URL,
    ///   unreachable host) or a migration failed to apply.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn new(config: PostgresCatalogConfig) -> Result<Self, CatalogError> {
        let pool = build_pool(&config)
            .await
            .map_err(CatalogError::BackendError)?;

        // Run migrations using a synchronous connection (diesel_migrations
        // requires a sync connection for the migration harness).
        {
            use secrecy::ExposeSecret as _;
            let url = config.url.expose_secret().to_string();
            let migration_result = tokio::task::spawn_blocking(move || {
                let mut conn = diesel::PgConnection::establish(&url)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                conn.run_pending_migrations(MIGRATIONS)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?;
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            })
            .await
            .map_err(|e| {
                CatalogError::BackendError(Box::new(std::io::Error::other(e.to_string())))
            })?;

            migration_result.map_err(map_migration_error)?;
        }

        debug!(
            "PostgresCatalog initialised with pool_size={}",
            config.pool_size
        );
        Ok(Self { pool })
    }

    /// Return a reference to the underlying bb8 pool.
    ///
    /// Exposed for observability integrations that want to inspect pool state
    /// (e.g. idle connection count) without going through the trait.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Delete at most `batch_size` expired signed-request nonce rows.
    ///
    /// Row selection uses `FOR UPDATE SKIP LOCKED` so maintenance workers on
    /// multiple server instances can clean separate batches without waiting on
    /// each other. The nonce table's expiration index keeps selection bounded.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidArgument`] when `batch_size` is not
    /// positive, or a backend error when the connection or deletion fails.
    pub async fn cleanup_expired_signed_request_nonces(
        &self,
        batch_size: i64,
    ) -> Result<usize, CatalogError> {
        if batch_size <= 0 {
            return Err(CatalogError::InvalidArgument(
                "signed-request nonce cleanup batch size must be positive".to_string(),
            ));
        }

        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        diesel::sql_query(
            "DELETE FROM signed_request_nonces AS target \
             USING ( \
                 SELECT pubkey, nonce \
                 FROM signed_request_nonces \
                 WHERE expires_at < NOW() \
                 ORDER BY expires_at \
                 LIMIT $1 \
                 FOR UPDATE SKIP LOCKED \
             ) AS expired \
             WHERE target.pubkey = expired.pubkey \
               AND target.nonce = expired.nonce",
        )
        .bind::<diesel::sql_types::BigInt, _>(batch_size)
        .execute(&mut *conn)
        .await
        .map_err(|error| {
            map_diesel_error(error, "signed_request_nonce", "expired cleanup".to_string())
        })
    }
}

/// Serialize platform-role mutations so coverage checks cannot race.
///
/// Every administrator-coverage decision reads the whole role table and then
/// writes, so the read must not be able to go stale before the write commits.
/// The actor row locks taken by [`require_active_administrator`] already
/// serialize or deadlock the concurrent pairs reachable through these routes
/// today, so this lock is defense in depth rather than the sole guarantee: it
/// keeps the count-then-write atomic for any future caller that does not
/// happen to lock an overlapping row, including bulk or operator paths.
async fn lock_platform_roles(
    conn: &mut diesel_async::AsyncPgConnection,
) -> Result<(), CatalogTransactionError> {
    diesel::sql_query("LOCK TABLE account_platform_roles IN SHARE ROW EXCLUSIVE MODE")
        .execute(conn)
        .await?;
    Ok(())
}

/// Require that the actor is an active account holding an active administrator role.
///
/// Both the account row and the role row are locked so the authority cannot be
/// revoked between this check and the write it authorizes.
async fn require_active_administrator(
    conn: &mut diesel_async::AsyncPgConnection,
    actor_account_id: uuid::Uuid,
    kind: &'static str,
) -> Result<(), CatalogTransactionError> {
    let actor_status = accounts::table
        .find(actor_account_id)
        .for_update()
        .select(accounts::status)
        .first::<String>(conn)
        .await
        .optional()?;
    let active_admin = account_platform_roles::table
        .filter(account_platform_roles::account_id.eq(actor_account_id))
        .filter(account_platform_roles::role.eq("administrator"))
        .filter(account_platform_roles::state.eq("active"))
        .for_update()
        .select(PlatformRoleRow::as_select())
        .first(conn)
        .await
        .optional()?;
    if actor_status.as_deref() != Some("active") || active_admin.is_none() {
        return Err(CatalogTransactionError::Catalog(
            CatalogError::Unauthorized {
                kind,
                key: actor_account_id.to_string(),
            },
        ));
    }
    Ok(())
}

/// Reject a role grant for an account that does not exist.
///
/// The foreign key would also reject it, but an explicit check keeps the error
/// specific instead of surfacing a constraint violation.
async fn require_existing_account(
    conn: &mut diesel_async::AsyncPgConnection,
    account_id: uuid::Uuid,
) -> Result<(), CatalogTransactionError> {
    let exists = accounts::table
        .find(account_id)
        .select(accounts::id)
        .first::<uuid::Uuid>(conn)
        .await
        .optional()?;
    if exists.is_none() {
        return Err(CatalogTransactionError::Catalog(CatalogError::NotFound {
            kind: "account",
            key: account_id.to_string(),
        }));
    }
    Ok(())
}

/// Load one role assignment in any state, locked for update.
async fn active_or_revoked_role(
    conn: &mut diesel_async::AsyncPgConnection,
    account_id: uuid::Uuid,
    role_text: &str,
) -> Result<Option<PlatformRoleRow>, CatalogTransactionError> {
    account_platform_roles::table
        .filter(account_platform_roles::account_id.eq(account_id))
        .filter(account_platform_roles::role.eq(role_text))
        .for_update()
        .select(PlatformRoleRow::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(CatalogTransactionError::from)
}

/// Count accounts that currently provide administrator authority.
///
/// Authority requires both an active administrator role and an active account,
/// so a suspended administrator does not count toward coverage.
async fn administrator_coverage(
    conn: &mut diesel_async::AsyncPgConnection,
) -> Result<i64, CatalogTransactionError> {
    accounts::table
        .inner_join(
            account_platform_roles::table.on(account_platform_roles::account_id.eq(accounts::id)),
        )
        .filter(accounts::status.eq("active"))
        .filter(account_platform_roles::role.eq("administrator"))
        .filter(account_platform_roles::state.eq("active"))
        .select(diesel::dsl::count_star())
        .first::<i64>(conn)
        .await
        .map_err(CatalogTransactionError::from)
}

/// Report whether one account currently holds an active administrator role.
async fn account_holds_active_administrator(
    conn: &mut diesel_async::AsyncPgConnection,
    account_id: uuid::Uuid,
) -> Result<bool, CatalogTransactionError> {
    let held = account_platform_roles::table
        .filter(account_platform_roles::account_id.eq(account_id))
        .filter(account_platform_roles::role.eq("administrator"))
        .filter(account_platform_roles::state.eq("active"))
        .select(account_platform_roles::account_id)
        .first::<uuid::Uuid>(conn)
        .await
        .optional()?;
    Ok(held.is_some())
}

/// Owned inputs required by one version-registration transaction.
struct PackRegistrationTransaction {
    /// Database row inserted after ownership and quota checks pass.
    new_version: NewPackVersionRow,
    /// Stable pack name used for locks and conflict mapping.
    pack_name: String,
    /// Stable semantic version used for duplicate detection.
    version: String,
    /// Exact author key bytes used for ownership validation.
    incoming_author: Vec<u8>,
    /// Optional enrolled publisher key selected for the write.
    incoming_publisher_key_id: Option<uuid::Uuid>,
    /// Uncompressed catalog size charged against publication quotas.
    incoming_size: u64,
    /// Publication quota limits enforced inside the transaction.
    quota: PublishQuota,
}

/// Register one pack version using an existing PostgreSQL transaction.
async fn register_pack_version_on_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    registration: PackRegistrationTransaction,
) -> Result<(), CatalogTransactionError> {
    // diesel-async 0.9 takes an `AsyncFnOnce`, so the old
    // `|conn| Box::pin(async move { .. })` wrapper is gone -- the body
    // is now the async closure directly. `new_pack` and `new_version`
    // are captured by move under their own names; comparison values
    // are rebound (by move, no clone) to the short names used below.
    let PackRegistrationTransaction {
        new_version,
        pack_name,
        version,
        incoming_author,
        incoming_publisher_key_id,
        incoming_size,
        quota,
    } = registration;
    // Cross the ownership migration boundary before resolving
    // either namespace. ROW EXCLUSIVE conflicts with backfill's
    // SHARE ROW EXCLUSIVE lock while remaining compatible with
    // concurrent publishers. Aggregate quota accounting retains
    // the stronger self-conflicting lock it already required.
    if quota.max_total_bytes.is_some() {
        diesel::sql_query("LOCK TABLE pack_versions IN SHARE ROW EXCLUSIVE MODE")
            .execute(conn)
            .await?;
    } else {
        diesel::sql_query("LOCK TABLE pack_versions IN ROW EXCLUSIVE MODE")
            .execute(conn)
            .await?;
    }
    // Lock and validate the authoritative write identity before any
    // quota reads. Publisher profiles serialize quota accounting,
    // and their key rows serialize publication with revocation;
    // legacy authors retain their existing key lock.
    let incoming_publisher_id = if let Some(key_id) = incoming_publisher_key_id {
        let publisher_id = publisher_keys::table
            .find(key_id)
            .select(publisher_keys::publisher_id)
            .first::<uuid::Uuid>(conn)
            .await
            .optional()
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(
                    e,
                    "publisher_key",
                    key_id.to_string(),
                ))
            })?
            .ok_or_else(|| {
                CatalogTransactionError::Catalog(CatalogError::Unauthorized {
                    kind: "publisher_key",
                    key: key_id.to_string(),
                })
            })?;
        publisher_profiles::table
            .find(publisher_id)
            .for_update()
            .select(publisher_profiles::id)
            .first::<uuid::Uuid>(conn)
            .await
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(
                    e,
                    "publisher",
                    publisher_id.to_string(),
                ))
            })?;
        let key = publisher_keys::table
            .find(key_id)
            .for_update()
            .select(PublisherKeyRow::as_select())
            .first(conn)
            .await
            .optional()
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(
                    e,
                    "publisher_key",
                    key_id.to_string(),
                ))
            })?;
        match key {
            Some(key)
                if key.publisher_id == publisher_id
                    && key.state == "active"
                    && key.public_key == incoming_author =>
            {
                Some(publisher_id)
            }
            _ => {
                return Err(CatalogTransactionError::Catalog(
                    CatalogError::Unauthorized {
                        kind: "publisher_key",
                        key: key_id.to_string(),
                    },
                ));
            }
        }
    } else {
        let legacy_handle = authors::table
            .filter(authors::pubkey.eq(&incoming_author))
            .for_update()
            .select(authors::handle)
            .first::<String>(conn)
            .await
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(
                    e,
                    "author",
                    hex::encode(&incoming_author),
                ))
            })?;
        let publisher_exists = publisher_profiles::table
            .filter(publisher_profiles::handle.eq(&legacy_handle))
            .select(publisher_profiles::id)
            .first::<uuid::Uuid>(conn)
            .await
            .optional()
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(
                    e,
                    "publisher",
                    legacy_handle.clone(),
                ))
            })?
            .is_some();
        if publisher_exists {
            return Err(CatalogTransactionError::Catalog(
                CatalogError::Unauthorized {
                    kind: "publisher",
                    key: legacy_handle,
                },
            ));
        }
        None
    };
    let publisher_key_ids: Vec<Option<uuid::Uuid>> =
        if let Some(publisher_id) = incoming_publisher_id {
            publisher_keys::table
                .filter(publisher_keys::publisher_id.eq(publisher_id))
                .select(publisher_keys::id)
                .load::<uuid::Uuid>(conn)
                .await
                .map_err(|e| {
                    CatalogTransactionError::Catalog(map_diesel_error(
                        e,
                        "publisher_key",
                        publisher_id.to_string(),
                    ))
                })?
                .into_iter()
                .map(Some)
                .collect()
        } else {
            Vec::new()
        };
    let (version_count, stored_sizes): (i64, Vec<i64>) = if incoming_publisher_id.is_some() {
        let count = pack_versions::table
            .filter(pack_versions::publisher_key_id.eq_any(&publisher_key_ids))
            .count()
            .get_result(conn)
            .await
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(
                    e,
                    "pack_version",
                    pack_name.clone(),
                ))
            })?;
        let sizes = pack_versions::table
            .filter(pack_versions::publisher_key_id.eq_any(&publisher_key_ids))
            .select(pack_versions::size_bytes)
            .load(conn)
            .await
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(
                    e,
                    "pack_version",
                    pack_name.clone(),
                ))
            })?;
        (count, sizes)
    } else {
        let count = pack_versions::table
            .filter(pack_versions::author_pubkey.eq(&incoming_author))
            .count()
            .get_result(conn)
            .await
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(
                    e,
                    "pack_version",
                    pack_name.clone(),
                ))
            })?;
        let sizes = pack_versions::table
            .filter(pack_versions::author_pubkey.eq(&incoming_author))
            .select(pack_versions::size_bytes)
            .load(conn)
            .await
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(
                    e,
                    "pack_version",
                    pack_name.clone(),
                ))
            })?;
        (count, sizes)
    };
    let next_versions = u64::try_from(version_count)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let stored_bytes = stored_sizes.into_iter().fold(0u64, |total, size| {
        total.saturating_add(u64::try_from(size).unwrap_or(u64::MAX))
    });
    let next_bytes = stored_bytes.saturating_add(incoming_size);
    if quota
        .max_versions
        .is_some_and(|limit| next_versions > limit)
    {
        return Err(CatalogTransactionError::Catalog(CatalogError::Validation(
            "publisher version quota exceeded".to_string(),
        )));
    }
    if quota.max_bytes.is_some_and(|limit| next_bytes > limit) {
        return Err(CatalogTransactionError::Catalog(CatalogError::Validation(
            "publisher storage quota exceeded".to_string(),
        )));
    }
    if let Some(limit) = quota.max_total_bytes {
        let total_row: TotalBytesRow = diesel::sql_query(
            "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT AS total FROM pack_versions",
        )
        .get_result(conn)
        .await
        .map_err(|e| {
            CatalogTransactionError::Catalog(map_diesel_error(e, "pack_version", pack_name.clone()))
        })?;
        let stored_total = u64::try_from(total_row.total).unwrap_or(u64::MAX);
        let next_total_bytes = stored_total.saturating_add(incoming_size);
        if next_total_bytes > limit {
            return Err(CatalogTransactionError::Catalog(CatalogError::Validation(
                "registry storage quota exceeded".to_string(),
            )));
        }
    }
    // Upsert the parent pack row; do nothing if it already exists.
    let new_pack = NewPackRow {
        name: pack_name.clone(),
        current_author: incoming_author.clone(),
        publisher_id: incoming_publisher_id,
        tags: vec![],
        description: String::new(),
        latest_version: Some(version.clone()),
        extends: None,
    };
    diesel::insert_into(packs::table)
        .values(&new_pack)
        .on_conflict(packs::name)
        .do_nothing()
        .execute(conn)
        .await
        .map_err(|e| {
            CatalogTransactionError::Catalog(map_diesel_error(e, "pack", pack_name.clone()))
        })?;

    // The conflict-resolving insert above may have waited for a
    // concurrent first publisher. Authorize against the actual
    // winning row while holding its lock before inserting a version.
    let stored_pack: PackRow = packs::table
        .filter(packs::name.eq(&pack_name))
        .for_update()
        .select(PackRow::as_select())
        .first(conn)
        .await
        .map_err(|e| {
            CatalogTransactionError::Catalog(map_diesel_error(e, "pack", pack_name.clone()))
        })?;
    let ownership_matches = match (stored_pack.publisher_id, incoming_publisher_id) {
        (Some(existing), Some(incoming)) => existing == incoming,
        (None, None) => stored_pack.current_author == incoming_author,
        _ => false,
    };
    if !ownership_matches {
        return Err(CatalogTransactionError::Catalog(
            CatalogError::Unauthorized {
                kind: "pack",
                key: pack_name.clone(),
            },
        ));
    }

    // Insert the version row.
    diesel::insert_into(pack_versions::table)
        .values(&new_version)
        .execute(conn)
        .await
        .map_err(|e| {
            CatalogTransactionError::Catalog(map_diesel_error(
                e,
                "pack_version",
                format!("{pack_name}@{version}"),
            ))
        })?;

    // Only a committed version counts as key use. Keeping this
    // update after the insert also leaves conflicts and rollbacks
    // with their previous last_used_at value.
    if let Some(key_id) = incoming_publisher_key_id {
        diesel::update(publisher_keys::table.find(key_id))
            .set(publisher_keys::last_used_at.eq(Some(Utc::now())))
            .execute(conn)
            .await
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(
                    e,
                    "publisher_key",
                    key_id.to_string(),
                ))
            })?;
    }

    // Update latest_version using true semver precedence. Read the
    // current stored value (may have changed from the
    // row we fetched above if this is a first insert), then
    // compare using semver_gt before issuing the UPDATE.
    let current_latest: Option<String> = packs::table
        .filter(packs::name.eq(&pack_name))
        .select(packs::latest_version)
        .first(conn)
        .await
        .map_err(|e| {
            CatalogTransactionError::Catalog(map_diesel_error(e, "pack", pack_name.clone()))
        })?;

    // Only update when the new version has strictly higher
    // semver precedence than the stored latest.
    let should_update = match &current_latest {
        None => true,
        Some(stored) => semver_gt(&version, stored),
    };

    if should_update {
        diesel::update(packs::table.filter(packs::name.eq(&pack_name)))
            .set(packs::latest_version.eq(Some(&version)))
            .execute(conn)
            .await
            .map_err(|e| {
                CatalogTransactionError::Catalog(map_diesel_error(e, "pack", pack_name.clone()))
            })?;
    }

    Ok(())
}

/// PostgreSQL implementation of the [`CatalogBackend`] trait.
///
/// Each method checks out a connection from the pool, executes the relevant
/// Diesel DSL or raw SQL query, and maps driver errors to [`CatalogError`].
#[async_trait]
impl CatalogBackend for PostgresCatalog {
    /// Store one invite application while suppressing repeated normalized emails.
    async fn create_account_invite_request(
        &self,
        record: AccountInviteRequestRecord,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let key = record.normalized_email.clone();
        let row = NewAccountInviteRequestRow {
            id: record.id,
            normalized_email: record.normalized_email,
            display_name: record.display_name,
            intent: encode_text_enum(record.intent)?,
            statement: record.statement,
            status: encode_text_enum(record.status)?,
            consented_at: record.consented_at,
            created_at: record.created_at,
            updated_at: record.updated_at,
        };
        diesel::insert_into(account_invite_requests::table)
            .values(row)
            .on_conflict(account_invite_requests::normalized_email)
            .do_nothing()
            .execute(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "account invite request", key))?;
        Ok(())
    }

    /// List invite applications in stable queue order under administrator authority.
    async fn list_account_invite_requests(
        &self,
        actor_account_id: uuid::Uuid,
        status: Option<AccountInviteStatus>,
        limit: u32,
    ) -> Result<Vec<AccountInviteRequestRecord>, CatalogError> {
        if limit == 0 || limit > 200 {
            return Err(CatalogError::Validation(
                "invite request list limit must be between 1 and 200".to_string(),
            ));
        }
        let status = status.map(encode_text_enum).transpose()?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<Vec<AccountInviteRequestRow>, CatalogTransactionError, _>(
                async move |conn| {
                    require_active_administrator(conn, actor_account_id, "account_invite_request")
                        .await?;
                    let mut query = account_invite_requests::table.into_boxed();
                    if let Some(status) = status {
                        query = query.filter(account_invite_requests::status.eq(status));
                    }
                    query
                        .order((
                            account_invite_requests::created_at.asc(),
                            account_invite_requests::id.asc(),
                        ))
                        .limit(i64::from(limit))
                        .select(AccountInviteRequestRow::as_select())
                        .load(conn)
                        .await
                        .map_err(CatalogTransactionError::from)
                },
            )
            .await;
        match result {
            Ok(rows) => rows
                .into_iter()
                .map(AccountInviteRequestRow::into_record)
                .collect(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "account_invite_request",
                "list".to_string(),
            )),
        }
    }

    /// Transition one invite application under administrator authority.
    async fn review_account_invite_request(
        &self,
        request: AccountInviteReviewRequest,
    ) -> Result<AccountInviteRequestRecord, CatalogError> {
        if request.status == AccountInviteStatus::Invited {
            return Err(CatalogError::Validation(
                "invited status may only be reached by issuing an invitation".to_string(),
            ));
        }
        let status = encode_text_enum(request.status)?;
        let request_id = request.request_id;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<AccountInviteRequestRow, CatalogTransactionError, _>(async move |conn| {
                require_active_administrator(
                    conn,
                    request.actor_account_id,
                    "account_invite_request",
                )
                .await?;
                let existing = account_invite_requests::table
                    .find(request.request_id)
                    .for_update()
                    .select(AccountInviteRequestRow::as_select())
                    .first(conn)
                    .await
                    .optional()?
                    .ok_or_else(|| {
                        CatalogTransactionError::Catalog(CatalogError::NotFound {
                            kind: "account_invite_request",
                            key: request.request_id.to_string(),
                        })
                    })?;
                if existing.status == "invited" {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "account_invite_request",
                        key: request.request_id.to_string(),
                    }));
                }
                diesel::update(account_invite_requests::table.find(request.request_id))
                    .set((
                        account_invite_requests::status.eq(status),
                        account_invite_requests::updated_at.eq(Utc::now()),
                    ))
                    .returning(AccountInviteRequestRow::as_returning())
                    .get_result(conn)
                    .await
                    .map_err(CatalogTransactionError::from)
            })
            .await;
        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "account_invite_request",
                request_id.to_string(),
            )),
        }
    }

    /// Issue one invitation and mark its application invited in the same transaction.
    async fn issue_account_invite(
        &self,
        request: AccountInviteIssueRequest,
    ) -> Result<AccountInviteRecord, CatalogError> {
        if request.token_digest.len() != 32 || request.expires_at <= request.created_at {
            return Err(CatalogError::Validation(
                "invite token digest must be 32 bytes and expiry must follow creation".to_string(),
            ));
        }
        let request_id = request.request_id;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<AccountInviteRow, CatalogTransactionError, _>(async move |conn| {
                require_active_administrator(conn, request.actor_account_id, "account_invite")
                    .await?;
                let application = account_invite_requests::table
                    .find(request.request_id)
                    .for_update()
                    .select(AccountInviteRequestRow::as_select())
                    .first(conn)
                    .await
                    .optional()?
                    .ok_or_else(|| {
                        CatalogTransactionError::Catalog(CatalogError::NotFound {
                            kind: "account_invite_request",
                            key: request.request_id.to_string(),
                        })
                    })?;
                if !matches!(application.status.as_str(), "pending" | "reviewing") {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "account_invite_request",
                        key: request.request_id.to_string(),
                    }));
                }
                let row = NewAccountInviteRow {
                    id: request.id,
                    request_id: Some(request.request_id),
                    normalized_email: application.normalized_email,
                    token_digest: request.token_digest,
                    issued_by_account_id: Some(request.actor_account_id),
                    is_bootstrap: false,
                    expires_at: request.expires_at,
                    consumed_at: None,
                    revoked_at: None,
                    created_at: request.created_at,
                };
                let invitation = diesel::insert_into(account_invites::table)
                    .values(row)
                    .returning(AccountInviteRow::as_returning())
                    .get_result(conn)
                    .await?;
                diesel::update(account_invite_requests::table.find(request.request_id))
                    .set((
                        account_invite_requests::status.eq("invited"),
                        account_invite_requests::updated_at.eq(request.created_at),
                    ))
                    .execute(conn)
                    .await?;
                Ok(invitation)
            })
            .await;
        match result {
            Ok(row) => Ok(row.into_record()),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "account_invite",
                request_id.to_string(),
            )),
        }
    }

    /// Redeem one invitation into an account, password credential, and session atomically.
    async fn register_local_account(
        &self,
        request: LocalAccountRegistrationRequest,
    ) -> Result<LocalAccountRegistrationResult, CatalogError> {
        if request.invite_token_digest.len() != 32
            || request.session.token_digest.len() != 32
            || request.credential.account_id != request.account.id
            || request.session.account_id != request.account.id
            || request.account.email.as_deref()
                != Some(request.credential.normalized_email.as_str())
            || request.credential.email_verified_at.is_none()
        {
            return Err(CatalogError::Validation(
                "local registration records are inconsistent".to_string(),
            ));
        }
        let account_result = request.account.clone();
        let session_result = request.session.clone();
        let account_key = request.account.id;
        let now = request.account.created_at;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<(), CatalogTransactionError, _>(async move |conn| {
                let invitation = account_invites::table
                    .filter(account_invites::token_digest.eq(&request.invite_token_digest))
                    .filter(account_invites::consumed_at.is_null())
                    .filter(account_invites::revoked_at.is_null())
                    .filter(account_invites::created_at.le(now))
                    .filter(account_invites::expires_at.gt(now))
                    .for_update()
                    .select(AccountInviteRow::as_select())
                    .first(conn)
                    .await
                    .optional()?
                    .ok_or_else(|| {
                        CatalogTransactionError::Catalog(CatalogError::Unauthorized {
                            kind: "account_invite",
                            key: "invalid-or-expired".to_string(),
                        })
                    })?;
                if invitation.normalized_email != request.credential.normalized_email {
                    return Err(CatalogTransactionError::Catalog(
                        CatalogError::Unauthorized {
                            kind: "account_invite",
                            key: "email-mismatch".to_string(),
                        },
                    ));
                }
                diesel::update(
                    account_invites::table
                        .find(invitation.id)
                        .filter(account_invites::consumed_at.is_null())
                        .filter(account_invites::revoked_at.is_null()),
                )
                .set(account_invites::consumed_at.eq(now))
                .execute(conn)
                .await?;
                diesel::insert_into(accounts::table)
                    .values(NewAccountRow {
                        id: request.account.id,
                        issuer: request.account.issuer,
                        subject: request.account.subject,
                        email: request.account.email,
                        display_name: request.account.display_name,
                        status: encode_text_enum(request.account.status)
                            .map_err(CatalogTransactionError::Catalog)?,
                        created_at: request.account.created_at,
                        updated_at: request.account.updated_at,
                    })
                    .execute(conn)
                    .await?;
                diesel::insert_into(account_password_credentials::table)
                    .values(NewAccountPasswordCredentialRow {
                        account_id: request.credential.account_id,
                        normalized_email: request.credential.normalized_email,
                        password_hash: request.credential.password_hash,
                        password_version: request.credential.password_version,
                        pepper_version: request.credential.pepper_version,
                        email_verified_at: request.credential.email_verified_at,
                        created_at: request.credential.created_at,
                        password_changed_at: request.credential.password_changed_at,
                        updated_at: request.credential.updated_at,
                    })
                    .execute(conn)
                    .await?;
                diesel::insert_into(account_sessions::table)
                    .values(NewAccountSessionRow {
                        id: request.session.id,
                        account_id: request.session.account_id,
                        token_digest: request.session.token_digest,
                        client_kind: encode_text_enum(request.session.client_kind)
                            .map_err(CatalogTransactionError::Catalog)?,
                        created_at: request.session.created_at,
                        last_seen_at: request.session.last_seen_at,
                        idle_expires_at: request.session.idle_expires_at,
                        absolute_expires_at: request.session.absolute_expires_at,
                        revoked_at: request.session.revoked_at,
                    })
                    .execute(conn)
                    .await?;
                Ok(())
            })
            .await;
        match result {
            Ok(()) => Ok(LocalAccountRegistrationResult {
                account: account_result,
                session: session_result,
            }),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "local_account_registration",
                account_key.to_string(),
            )),
        }
    }

    /// Retrieve one first-party password credential by normalized email.
    async fn get_account_password_credential(
        &self,
        normalized_email: &str,
    ) -> Result<AccountPasswordCredentialRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        account_password_credentials::table
            .filter(account_password_credentials::normalized_email.eq(normalized_email))
            .select(AccountPasswordCredentialRow::as_select())
            .first(&mut conn)
            .await
            .map(AccountPasswordCredentialRow::into_record)
            .map_err(|error| {
                map_diesel_error(
                    error,
                    "account_password_credential",
                    normalized_email.to_string(),
                )
            })
    }

    /// Conditionally replace an unchanged credential with a freshly peppered hash.
    async fn rehash_account_password_credential(
        &self,
        request: AccountPasswordRehashRequest,
    ) -> Result<bool, CatalogError> {
        if request.normalized_email.is_empty()
            || request.expected_password_hash.is_empty()
            || request.new_password_hash.is_empty()
            || request.expected_password_version <= 0
            || request.expected_pepper_version <= 0
            || request.new_password_version <= 0
            || request.new_pepper_version <= 0
            || request.updated_at < request.expected_updated_at
        {
            return Err(CatalogError::Validation(
                "password rehash request is invalid".to_string(),
            ));
        }
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let account_id = request.account_id;
        let rows_affected = diesel::update(
            account_password_credentials::table
                .filter(account_password_credentials::account_id.eq(account_id))
                .filter(account_password_credentials::normalized_email.eq(request.normalized_email))
                .filter(
                    account_password_credentials::password_hash.eq(request.expected_password_hash),
                )
                .filter(
                    account_password_credentials::password_version
                        .eq(request.expected_password_version),
                )
                .filter(
                    account_password_credentials::pepper_version
                        .eq(request.expected_pepper_version),
                )
                .filter(account_password_credentials::updated_at.eq(request.expected_updated_at)),
        )
        .set((
            account_password_credentials::password_hash.eq(request.new_password_hash),
            account_password_credentials::password_version.eq(request.new_password_version),
            account_password_credentials::pepper_version.eq(request.new_pepper_version),
            account_password_credentials::updated_at.eq(request.updated_at),
        ))
        .execute(&mut conn)
        .await
        .map_err(|error| {
            map_diesel_error(error, "account_password_credential", account_id.to_string())
        })?;
        Ok(rows_affected == 1)
    }

    /// Create one revocable first-party session after successful authentication.
    async fn create_account_session(
        &self,
        record: AccountSessionRecord,
    ) -> Result<(), CatalogError> {
        if record.token_digest.len() != 32 {
            return Err(CatalogError::Validation(
                "session token digest must be 32 bytes".to_string(),
            ));
        }
        let key = record.id.to_string();
        let client_kind = encode_text_enum(record.client_kind)?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        diesel::insert_into(account_sessions::table)
            .values(NewAccountSessionRow {
                id: record.id,
                account_id: record.account_id,
                token_digest: record.token_digest,
                client_kind,
                created_at: record.created_at,
                last_seen_at: record.last_seen_at,
                idle_expires_at: record.idle_expires_at,
                absolute_expires_at: record.absolute_expires_at,
                revoked_at: record.revoked_at,
            })
            .execute(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "account_session", key))?;
        Ok(())
    }

    /// Resolve one active first-party session by its opaque token digest.
    async fn get_active_account_session(
        &self,
        token_digest: &[u8],
        now: DateTime<Utc>,
    ) -> Result<AccountSessionRecord, CatalogError> {
        if token_digest.len() != 32 {
            return Err(CatalogError::NotFound {
                kind: "account_session",
                key: "opaque-token".to_string(),
            });
        }
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        account_sessions::table
            .filter(account_sessions::token_digest.eq(token_digest))
            .filter(account_sessions::revoked_at.is_null())
            .filter(account_sessions::idle_expires_at.gt(now))
            .filter(account_sessions::absolute_expires_at.gt(now))
            .select(AccountSessionRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|error| {
                map_diesel_error(error, "account_session", "opaque-token".to_string())
            })?
            .into_record()
    }

    /// Advance one active session's last-seen and sliding-expiry timestamps.
    async fn touch_account_session(
        &self,
        session_id: uuid::Uuid,
        last_seen_at: DateTime<Utc>,
        idle_expires_at: DateTime<Utc>,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let rows = diesel::update(
            account_sessions::table
                .find(session_id)
                .filter(account_sessions::revoked_at.is_null())
                .filter(account_sessions::absolute_expires_at.gt(last_seen_at))
                .filter(account_sessions::idle_expires_at.gt(last_seen_at)),
        )
        .set((
            account_sessions::last_seen_at.eq(last_seen_at),
            account_sessions::idle_expires_at.eq(idle_expires_at),
        ))
        .execute(&mut conn)
        .await
        .map_err(|error| map_diesel_error(error, "account_session", session_id.to_string()))?;
        if rows == 0 {
            return Err(CatalogError::NotFound {
                kind: "account_session",
                key: session_id.to_string(),
            });
        }
        Ok(())
    }

    /// Revoke one session only when it belongs to the authenticated account.
    async fn revoke_account_session(
        &self,
        session_id: uuid::Uuid,
        account_id: uuid::Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let rows = diesel::update(
            account_sessions::table
                .find(session_id)
                .filter(account_sessions::account_id.eq(account_id))
                .filter(account_sessions::revoked_at.is_null()),
        )
        .set(account_sessions::revoked_at.eq(revoked_at))
        .execute(&mut conn)
        .await
        .map_err(|error| map_diesel_error(error, "account_session", session_id.to_string()))?;
        if rows == 0 {
            return Err(CatalogError::NotFound {
                kind: "account_session",
                key: session_id.to_string(),
            });
        }
        Ok(())
    }

    /// Create an OIDC-backed account with a unique identity pair.
    #[instrument(skip(self, record), fields(account_id = %record.id, issuer = %record.issuer))]
    async fn create_account(&self, record: AccountRecord) -> Result<(), CatalogError> {
        if record.issuer.trim().is_empty() || record.subject.trim().is_empty() {
            return Err(CatalogError::Validation(
                "account issuer and subject must not be blank".to_string(),
            ));
        }
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row = NewAccountRow {
            id: record.id,
            issuer: record.issuer.clone(),
            subject: record.subject,
            email: record.email,
            display_name: record.display_name,
            status: encode_text_enum(record.status)?,
            created_at: record.created_at,
            updated_at: record.updated_at,
        };
        diesel::insert_into(accounts::table)
            .values(row)
            .execute(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "account", record.issuer))?;
        Ok(())
    }

    /// Retrieve an account by its internal identifier.
    async fn get_account(&self, id: uuid::Uuid) -> Result<AccountRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        accounts::table
            .find(id)
            .select(AccountRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "account", id.to_string()))?
            .into_record()
    }

    /// Retrieve an account by its exact OIDC issuer and subject pair.
    async fn get_account_by_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<AccountRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        accounts::table
            .filter(accounts::issuer.eq(issuer))
            .filter(accounts::subject.eq(subject))
            .select(AccountRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "account", format!("{issuer}#{subject}")))?
            .into_record()
    }

    /// Update mutable account profile fields without changing OIDC identity.
    async fn update_account_profile(
        &self,
        id: uuid::Uuid,
        email: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<AccountRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        diesel::update(accounts::table.find(id))
            .set((
                accounts::email.eq(email),
                accounts::display_name.eq(display_name),
                accounts::updated_at.eq(Utc::now()),
            ))
            .returning(AccountRow::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "account", id.to_string()))?
            .into_record()
    }

    /// Atomically create a publisher profile and its first owner membership.
    async fn create_publisher(
        &self,
        profile: PublisherProfileRecord,
        owner: PublisherMembershipRecord,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<(), CatalogError> {
        validate_audit_publisher(audit.as_ref(), profile.id)?;
        if profile.id != owner.publisher_id {
            return Err(CatalogError::InvalidArgument(
                "owner membership publisher_id must match profile id".to_string(),
            ));
        }
        if owner.state != MembershipState::Active {
            return Err(CatalogError::InvalidArgument(
                "initial owner membership must be active".to_string(),
            ));
        }
        let profile_handle = profile.handle.clone();
        let new_profile = NewPublisherProfileRow {
            id: profile.id,
            handle: profile.handle.clone(),
            display_name: profile.display_name,
            biography: profile.biography,
            moderation_status: encode_text_enum(profile.moderation_status)?,
            created_at: profile.created_at,
            updated_at: profile.updated_at,
        };
        let new_owner = NewPublisherMembershipRow {
            account_id: owner.account_id,
            publisher_id: owner.publisher_id,
            role: encode_text_enum(owner.role)?,
            state: encode_text_enum(owner.state)?,
            created_at: owner.created_at,
            updated_at: owner.updated_at,
        };
        let audit = audit.map(new_publisher_audit_row).transpose()?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let tx_result = conn
            .transaction::<(), CatalogTransactionError, _>(async move |conn| {
                // All namespace writers take this lock in the same order so a
                // legacy author and publisher cannot concurrently claim one handle.
                diesel::sql_query(
                    "LOCK TABLE authors, handles, publisher_profiles \
                     IN SHARE ROW EXCLUSIVE MODE",
                )
                .execute(conn)
                .await?;
                let legacy_author_exists = authors::table
                    .filter(authors::handle.eq(&profile_handle))
                    .select(authors::pubkey)
                    .first::<Vec<u8>>(conn)
                    .await
                    .optional()?;
                let legacy_handle_exists = handles::table
                    .filter(handles::handle.eq(&profile_handle))
                    .select(handles::pubkey)
                    .first::<Vec<u8>>(conn)
                    .await
                    .optional()?;
                if legacy_author_exists.is_some() || legacy_handle_exists.is_some() {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "publisher",
                        key: profile_handle.clone(),
                    }));
                }
                diesel::insert_into(publisher_profiles::table)
                    .values(new_profile)
                    .execute(conn)
                    .await?;
                diesel::insert_into(publisher_memberships::table)
                    .values(new_owner)
                    .execute(conn)
                    .await?;
                if let Some(audit) = audit {
                    diesel::insert_into(publisher_audit_events::table)
                        .values(audit)
                        .execute(conn)
                        .await?;
                }
                Ok(())
            })
            .await;
        match tx_result {
            Ok(()) => Ok(()),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => {
                Err(map_diesel_error(error, "publisher", profile.handle))
            }
        }
    }

    /// Retrieve a public publisher profile by normalized handle.
    async fn get_publisher_by_handle(
        &self,
        handle: &str,
    ) -> Result<PublisherProfileRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        publisher_profiles::table
            .filter(publisher_profiles::handle.eq(handle))
            .select(PublisherProfileRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "publisher", handle.to_string()))?
            .into_record()
    }

    /// Retrieve a public publisher profile by its stable internal identifier.
    async fn get_publisher(&self, id: uuid::Uuid) -> Result<PublisherProfileRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        publisher_profiles::table
            .find(id)
            .select(PublisherProfileRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "publisher", id.to_string()))?
            .into_record()
    }

    /// Update mutable public publisher profile fields.
    async fn update_publisher_profile(
        &self,
        id: uuid::Uuid,
        display_name: &str,
        biography: Option<&str>,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<PublisherProfileRecord, CatalogError> {
        validate_audit_publisher(audit.as_ref(), id)?;
        let audit = audit.map(new_publisher_audit_row).transpose()?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let row = conn
            .transaction::<PublisherProfileRow, diesel::result::Error, _>(async move |conn| {
                let row = diesel::update(publisher_profiles::table.find(id))
                    .set((
                        publisher_profiles::display_name.eq(display_name),
                        publisher_profiles::biography.eq(biography),
                        publisher_profiles::updated_at.eq(Utc::now()),
                    ))
                    .returning(PublisherProfileRow::as_returning())
                    .get_result(conn)
                    .await?;
                if let Some(audit) = audit {
                    diesel::insert_into(publisher_audit_events::table)
                        .values(audit)
                        .execute(conn)
                        .await?;
                }
                Ok(row)
            })
            .await
            .map_err(|error| map_diesel_error(error, "publisher", id.to_string()))?;
        row.into_record()
    }

    /// List all memberships held by one account.
    async fn list_account_memberships(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<Vec<PublisherMembershipRecord>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let rows = publisher_memberships::table
            .filter(publisher_memberships::account_id.eq(account_id))
            .order(publisher_memberships::created_at.asc())
            .select(PublisherMembershipRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|error| {
                map_diesel_error(error, "publisher_membership", account_id.to_string())
            })?;
        rows.into_iter()
            .map(PublisherMembershipRow::into_record)
            .collect()
    }

    /// Retrieve one account-to-publisher membership.
    async fn get_publisher_membership(
        &self,
        account_id: uuid::Uuid,
        publisher_id: uuid::Uuid,
    ) -> Result<PublisherMembershipRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        publisher_memberships::table
            .find((account_id, publisher_id))
            .select(PublisherMembershipRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|error| {
                map_diesel_error(
                    error,
                    "publisher_membership",
                    format!("{account_id}:{publisher_id}"),
                )
            })?
            .into_record()
    }

    /// Enroll a public signing key to a publisher profile idempotently.
    async fn create_publisher_key(
        &self,
        record: PublisherKeyRecord,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<PublisherKeyRecord, CatalogError> {
        validate_audit_publisher(audit.as_ref(), record.publisher_id)?;
        if record.label.trim().is_empty() {
            return Err(CatalogError::Validation(
                "publisher key label must not be blank".to_string(),
            ));
        }
        let id = record.id;
        let publisher_id = record.publisher_id;
        let public_key = record.public_key.0.to_vec();
        let public_key_display = record.public_key.to_string();
        let row = NewPublisherKeyRow {
            id,
            publisher_id,
            public_key: public_key.clone(),
            label: record.label,
            state: encode_text_enum(record.state)?,
            created_at: record.created_at,
            revoked_at: record.revoked_at,
            last_used_at: record.last_used_at,
        };
        let audit = audit.map(new_publisher_audit_row).transpose()?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let tx_result = conn
            .transaction::<PublisherKeyRow, CatalogTransactionError, _>(async move |conn| {
                let inserted = diesel::insert_into(publisher_keys::table)
                    .values(row)
                    .on_conflict(publisher_keys::public_key)
                    .do_nothing()
                    .returning(PublisherKeyRow::as_returning())
                    .get_result(conn)
                    .await
                    .optional()?;
                if let Some(inserted) = inserted {
                    if let Some(audit) = audit {
                        diesel::insert_into(publisher_audit_events::table)
                            .values(audit)
                            .execute(conn)
                            .await?;
                    }
                    return Ok(inserted);
                }

                let existing = publisher_keys::table
                    .filter(publisher_keys::public_key.eq(public_key))
                    .for_update()
                    .select(PublisherKeyRow::as_select())
                    .first(conn)
                    .await?;
                if existing.publisher_id != publisher_id || existing.state != "active" {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "publisher_key",
                        key: public_key_display,
                    }));
                }
                Ok(existing)
            })
            .await;
        match tx_result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => {
                Err(map_diesel_error(error, "publisher_key", id.to_string()))
            }
        }
    }

    /// List a publisher's enrolled public keys.
    async fn list_publisher_keys(
        &self,
        publisher_id: uuid::Uuid,
    ) -> Result<Vec<PublisherKeyRecord>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let rows = publisher_keys::table
            .filter(publisher_keys::publisher_id.eq(publisher_id))
            .order(publisher_keys::created_at.asc())
            .select(PublisherKeyRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "publisher_key", publisher_id.to_string()))?;
        rows.into_iter().map(PublisherKeyRow::into_record).collect()
    }

    /// Retrieve one enrolled publisher key by stable identifier.
    async fn get_publisher_key(&self, id: uuid::Uuid) -> Result<PublisherKeyRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        publisher_keys::table
            .find(id)
            .select(PublisherKeyRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "publisher_key", id.to_string()))?
            .into_record()
    }

    /// Revoke a publisher key while retaining its historical evidence.
    async fn revoke_publisher_key(
        &self,
        publisher_id: uuid::Uuid,
        key_id: uuid::Uuid,
        revoked_at: chrono::DateTime<Utc>,
        audit: Option<PublisherAuditEventRecord>,
    ) -> Result<PublisherKeyRecord, CatalogError> {
        validate_audit_publisher(audit.as_ref(), publisher_id)?;
        let audit = audit.map(new_publisher_audit_row).transpose()?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let row = conn
            .transaction::<PublisherKeyRow, diesel::result::Error, _>(async move |conn| {
                publisher_profiles::table
                    .find(publisher_id)
                    .select(publisher_profiles::id)
                    .for_update()
                    .first::<uuid::Uuid>(conn)
                    .await?;
                let current = publisher_keys::table
                    .find(key_id)
                    .filter(publisher_keys::publisher_id.eq(publisher_id))
                    .for_update()
                    .select(PublisherKeyRow::as_select())
                    .first(conn)
                    .await?;
                if current.state == "revoked" {
                    return Ok(current);
                }
                let active_count = publisher_keys::table
                    .filter(publisher_keys::publisher_id.eq(publisher_id))
                    .filter(publisher_keys::state.eq("active"))
                    .count()
                    .get_result::<i64>(conn)
                    .await?;
                if active_count <= 1 {
                    return Err(diesel::result::Error::RollbackTransaction);
                }
                let updated = diesel::update(publisher_keys::table.find(key_id))
                    .set((
                        publisher_keys::state.eq("revoked"),
                        publisher_keys::revoked_at.eq(Some(revoked_at)),
                    ))
                    .returning(PublisherKeyRow::as_returning())
                    .get_result(conn)
                    .await?;
                if let Some(audit) = audit {
                    diesel::insert_into(publisher_audit_events::table)
                        .values(audit)
                        .execute(conn)
                        .await?;
                }
                Ok(updated)
            })
            .await
            .map_err(|error| match error {
                diesel::result::Error::RollbackTransaction => CatalogError::Validation(
                    "cannot revoke the last active publisher key".to_string(),
                ),
                other => map_diesel_error(other, "publisher_key", key_id.to_string()),
            })?;
        row.into_record()
    }

    /// Append an immutable, sanitized publisher audit event.
    async fn append_publisher_audit_event(
        &self,
        event: PublisherAuditEventRecord,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let id = event.id;
        let row = new_publisher_audit_row(event)?;
        diesel::insert_into(publisher_audit_events::table)
            .values(row)
            .execute(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "publisher_audit_event", id.to_string()))?;
        Ok(())
    }

    /// Create an exact publication intent after locking and validating its identity chain.
    async fn create_publication_intent(
        &self,
        record: PublicationIntentRecord,
    ) -> Result<PublicationIntentRecord, CatalogError> {
        let scan_schema_version = publication_intent_scan_schema(record.scan_schema_version)?;
        if record.expires_at <= record.created_at {
            return Err(CatalogError::InvalidArgument(
                "publication intent expires_at must be after created_at".to_string(),
            ));
        }
        if record.consumed_at.is_some() {
            return Err(CatalogError::InvalidArgument(
                "new publication intent must not already be consumed".to_string(),
            ));
        }

        let requested = record.clone();
        let row = NewPublicationIntentRow {
            id: record.id,
            account_id: record.account_id,
            publisher_id: record.publisher_id,
            publisher_key_id: record.publisher_key_id,
            archive_hash: record.archive_hash.as_bytes().to_vec(),
            manifest_hash: record.manifest_hash.as_bytes().to_vec(),
            file_inventory_hash: record.file_inventory_hash.as_bytes().to_vec(),
            scan_schema_version,
            created_at: record.created_at,
            expires_at: record.expires_at,
            consumed_at: None,
        };
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PublicationIntentRow, CatalogTransactionError, _>(async move |conn| {
                let publisher_status = publisher_profiles::table
                    .find(requested.publisher_id)
                    .for_update()
                    .select(publisher_profiles::moderation_status)
                    .first::<String>(conn)
                    .await
                    .optional()?;
                if publisher_status.as_deref() != Some("approved") {
                    return Err(publication_intent_unauthorized(requested.id));
                }

                let account_status = accounts::table
                    .find(requested.account_id)
                    .for_update()
                    .select(accounts::status)
                    .first::<String>(conn)
                    .await
                    .optional()?;
                if account_status.as_deref() != Some("active") {
                    return Err(publication_intent_unauthorized(requested.id));
                }

                let membership = publisher_memberships::table
                    .find((requested.account_id, requested.publisher_id))
                    .for_update()
                    .select((publisher_memberships::role, publisher_memberships::state))
                    .first::<(String, String)>(conn)
                    .await
                    .optional()?;
                if !matches!(
                    membership.as_ref(),
                    Some((role, state)) if role == "owner" && state == "active"
                ) {
                    return Err(publication_intent_unauthorized(requested.id));
                }

                let publisher_key = publisher_keys::table
                    .find(requested.publisher_key_id)
                    .for_update()
                    .select((publisher_keys::publisher_id, publisher_keys::state))
                    .first::<(uuid::Uuid, String)>(conn)
                    .await
                    .optional()?;
                if !matches!(
                    publisher_key.as_ref(),
                    Some((publisher_id, state))
                        if *publisher_id == requested.publisher_id && state == "active"
                ) {
                    return Err(publication_intent_unauthorized(requested.id));
                }

                let inserted = diesel::insert_into(publication_intents::table)
                    .values(row)
                    .on_conflict(publication_intents::id)
                    .do_nothing()
                    .returning(PublicationIntentRow::as_returning())
                    .get_result(conn)
                    .await
                    .optional()?;
                if let Some(inserted) = inserted {
                    return Ok(inserted);
                }

                let existing = publication_intents::table
                    .find(requested.id)
                    .for_update()
                    .select(PublicationIntentRow::as_select())
                    .first(conn)
                    .await?;
                let existing_record = existing
                    .clone()
                    .into_record()
                    .map_err(CatalogTransactionError::Catalog)?;
                if !publication_intent_matches(&existing_record, &requested) {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "publication_intent",
                        key: requested.id.to_string(),
                    }));
                }
                Ok(existing)
            })
            .await;

        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_intent",
                record.id.to_string(),
            )),
        }
    }

    /// Retrieve one durable publication intent.
    async fn get_publication_intent(
        &self,
        id: uuid::Uuid,
    ) -> Result<PublicationIntentRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        publication_intents::table
            .find(id)
            .select(PublicationIntentRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "publication_intent", id.to_string()))?
            .into_record()
    }

    /// Atomically consume one exact, unexpired intent while all identities remain active.
    async fn consume_publication_intent(
        &self,
        claim: PublicationIntentClaim,
    ) -> Result<bool, CatalogError> {
        let scan_schema_version = publication_intent_scan_schema(claim.scan_schema_version)?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let database_now = diesel::dsl::now;
        let active_account = diesel::dsl::exists(
            accounts::table
                .filter(accounts::id.eq(claim.account_id))
                .filter(accounts::status.eq("active")),
        );
        let approved_publisher = diesel::dsl::exists(
            publisher_profiles::table
                .filter(publisher_profiles::id.eq(claim.publisher_id))
                .filter(publisher_profiles::moderation_status.eq("approved")),
        );
        let active_membership = diesel::dsl::exists(
            publisher_memberships::table
                .filter(publisher_memberships::account_id.eq(claim.account_id))
                .filter(publisher_memberships::publisher_id.eq(claim.publisher_id))
                .filter(publisher_memberships::role.eq("owner"))
                .filter(publisher_memberships::state.eq("active")),
        );
        let active_key = diesel::dsl::exists(
            publisher_keys::table
                .filter(publisher_keys::id.eq(claim.publisher_key_id))
                .filter(publisher_keys::publisher_id.eq(claim.publisher_id))
                .filter(publisher_keys::state.eq("active")),
        );
        let changed = diesel::update(
            publication_intents::table
                .find(claim.id)
                .filter(publication_intents::account_id.eq(claim.account_id))
                .filter(publication_intents::publisher_id.eq(claim.publisher_id))
                .filter(publication_intents::publisher_key_id.eq(claim.publisher_key_id))
                .filter(publication_intents::archive_hash.eq(claim.archive_hash.as_bytes()))
                .filter(publication_intents::manifest_hash.eq(claim.manifest_hash.as_bytes()))
                .filter(
                    publication_intents::file_inventory_hash
                        .eq(claim.file_inventory_hash.as_bytes()),
                )
                .filter(publication_intents::scan_schema_version.eq(scan_schema_version))
                .filter(publication_intents::consumed_at.is_null())
                .filter(publication_intents::created_at.le(database_now))
                .filter(publication_intents::expires_at.gt(database_now))
                .filter(active_account)
                .filter(approved_publisher)
                .filter(active_membership)
                .filter(active_key),
        )
        .set(publication_intents::consumed_at.eq(database_now))
        .execute(&mut conn)
        .await
        .map_err(|error| map_diesel_error(error, "publication_intent", claim.id.to_string()))?;
        Ok(changed == 1)
    }

    /// Atomically consume one exact intent and persist its quarantined submission.
    async fn create_publication_submission(
        &self,
        request: PublicationSubmissionRequest,
    ) -> Result<PublicationSubmissionRecord, CatalogError> {
        let (scan_schema_version, scan_report) = validate_publication_submission(&request)?;
        let request_id = request.id;
        let intent_id = request.intent.id;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PublicationSubmissionRow, CatalogTransactionError, _>(
                async move |conn| {
                    let existing_by_id = publication_submissions::table
                        .find(request.id)
                        .select(PublicationSubmissionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if let Some(existing) = existing_by_id {
                        return resolve_publication_submission_retry(existing, &request);
                    }

                    let existing_for_intent = publication_submissions::table
                        .filter(publication_submissions::intent_id.eq(request.intent.id))
                        .select(PublicationSubmissionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if let Some(existing) = existing_for_intent {
                        return resolve_publication_submission_retry(existing, &request);
                    }

                    let database_now = diesel::dsl::now;
                    let active_account = diesel::dsl::exists(
                        accounts::table
                            .filter(accounts::id.eq(request.intent.account_id))
                            .filter(accounts::status.eq("active")),
                    );
                    let approved_publisher = diesel::dsl::exists(
                        publisher_profiles::table
                            .filter(publisher_profiles::id.eq(request.intent.publisher_id))
                            .filter(publisher_profiles::moderation_status.eq("approved")),
                    );
                    let active_membership = diesel::dsl::exists(
                        publisher_memberships::table
                            .filter(publisher_memberships::account_id.eq(request.intent.account_id))
                            .filter(
                                publisher_memberships::publisher_id.eq(request.intent.publisher_id),
                            )
                            .filter(publisher_memberships::role.eq("owner"))
                            .filter(publisher_memberships::state.eq("active")),
                    );
                    let active_key = diesel::dsl::exists(
                        publisher_keys::table
                            .filter(publisher_keys::id.eq(request.intent.publisher_key_id))
                            .filter(publisher_keys::publisher_id.eq(request.intent.publisher_id))
                            .filter(publisher_keys::state.eq("active")),
                    );
                    let consumed_at = diesel::update(
                        publication_intents::table
                            .find(request.intent.id)
                            .filter(publication_intents::account_id.eq(request.intent.account_id))
                            .filter(
                                publication_intents::publisher_id.eq(request.intent.publisher_id),
                            )
                            .filter(
                                publication_intents::publisher_key_id
                                    .eq(request.intent.publisher_key_id),
                            )
                            .filter(
                                publication_intents::archive_hash
                                    .eq(request.intent.archive_hash.as_bytes()),
                            )
                            .filter(
                                publication_intents::manifest_hash
                                    .eq(request.intent.manifest_hash.as_bytes()),
                            )
                            .filter(
                                publication_intents::file_inventory_hash
                                    .eq(request.intent.file_inventory_hash.as_bytes()),
                            )
                            .filter(
                                publication_intents::scan_schema_version.eq(scan_schema_version),
                            )
                            .filter(publication_intents::consumed_at.is_null())
                            .filter(publication_intents::created_at.le(database_now))
                            .filter(publication_intents::expires_at.gt(database_now))
                            .filter(active_account)
                            .filter(approved_publisher)
                            .filter(active_membership)
                            .filter(active_key),
                    )
                    .set(publication_intents::consumed_at.eq(database_now))
                    .returning(publication_intents::consumed_at)
                    .get_result::<Option<chrono::DateTime<Utc>>>(conn)
                    .await
                    .optional()?
                    .flatten();

                    let Some(created_at) = consumed_at else {
                        let retry = publication_submissions::table
                            .filter(publication_submissions::intent_id.eq(request.intent.id))
                            .select(PublicationSubmissionRow::as_select())
                            .first(conn)
                            .await
                            .optional()?;
                        return match retry {
                            Some(existing) => {
                                resolve_publication_submission_retry(existing, &request)
                            }
                            None => Err(CatalogTransactionError::Catalog(
                                CatalogError::Unauthorized {
                                    kind: "publication_submission",
                                    key: request.id.to_string(),
                                },
                            )),
                        };
                    };

                    let row = NewPublicationSubmissionRow {
                        id: request.id,
                        intent_id: request.intent.id,
                        account_id: request.intent.account_id,
                        publisher_id: request.intent.publisher_id,
                        publisher_key_id: request.intent.publisher_key_id,
                        archive_hash: request.intent.archive_hash.as_bytes().to_vec(),
                        manifest_hash: request.intent.manifest_hash.as_bytes().to_vec(),
                        file_inventory_hash: request.intent.file_inventory_hash.as_bytes().to_vec(),
                        scan_schema_version,
                        scan_report,
                        state: "quarantined".to_string(),
                        created_at,
                        updated_at: created_at,
                    };
                    diesel::insert_into(publication_submissions::table)
                        .values(row)
                        .returning(PublicationSubmissionRow::as_returning())
                        .get_result(conn)
                        .await
                        .map_err(CatalogTransactionError::Diesel)
                },
            )
            .await;

        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_submission",
                format!("{request_id}:{intent_id}"),
            )),
        }
    }

    /// Retrieve one durable publication submission without changing its state.
    async fn get_publication_submission(
        &self,
        id: uuid::Uuid,
    ) -> Result<PublicationSubmissionRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        publication_submissions::table
            .find(id)
            .select(PublicationSubmissionRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "publication_submission", id.to_string()))?
            .into_record()
    }

    /// Aggregate unresolved review work and distinct active reviewer accounts.
    ///
    /// One statement produces every submission aggregate so the quarantine and
    /// queue gauges always describe the same MVCC snapshot, and the reviewer
    /// count stays inside SQL so no account identifiers cross into this path.
    async fn publication_moderation_snapshot(
        &self,
    ) -> Result<Option<PublicationModerationSnapshot>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let queue_row: ModerationQueueRow = diesel::sql_query(
            "SELECT COUNT(*) FILTER (WHERE state = 'quarantined') AS quarantined, \
             MIN(created_at) FILTER (WHERE state = 'quarantined') AS oldest_quarantined_at, \
             COUNT(*) AS queued, \
             MIN(created_at) AS oldest_queued_at \
             FROM publication_submissions \
             WHERE state IN ('quarantined', 'needs_review')",
        )
        .get_result(&mut conn)
        .await
        .map_err(|error| {
            map_diesel_error(
                error,
                "publication_moderation_snapshot",
                "queue".to_string(),
            )
        })?;
        let active_reviewers = account_platform_roles::table
            .filter(account_platform_roles::state.eq("active"))
            .filter(account_platform_roles::role.eq_any(["moderator", "administrator"]))
            .select({
                use diesel::expression_methods::AggregateExpressionMethods as _;
                diesel::dsl::count(account_platform_roles::account_id).aggregate_distinct()
            })
            .first::<i64>(&mut conn)
            .await
            .map_err(|error| {
                map_diesel_error(
                    error,
                    "publication_moderation_snapshot",
                    "reviewers".to_string(),
                )
            })?;

        // COUNT aggregates cannot be negative; zero is also the fail-closed
        // alerting direction for the reviewer availability gauge.
        Ok(Some(PublicationModerationSnapshot {
            quarantined_submissions: u64::try_from(queue_row.quarantined).unwrap_or_default(),
            oldest_quarantined_at: queue_row.oldest_quarantined_at,
            queued_submissions: u64::try_from(queue_row.queued).unwrap_or_default(),
            oldest_queued_at: queue_row.oldest_queued_at,
            active_reviewers: u64::try_from(active_reviewers).unwrap_or_default(),
        }))
    }

    /// List an account's global platform roles in stable role order.
    async fn list_account_platform_roles(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<Vec<PlatformRoleRecord>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        account_platform_roles::table
            .filter(account_platform_roles::account_id.eq(account_id))
            .order(account_platform_roles::role.asc())
            .select(PlatformRoleRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|error| map_diesel_error(error, "platform_role", account_id.to_string()))?
            .into_iter()
            .map(PlatformRoleRow::into_record)
            .collect()
    }

    /// Atomically grant or reactivate one platform role under administrator authority.
    async fn assign_account_platform_role(
        &self,
        request: PlatformRoleAssignmentRequest,
    ) -> Result<PlatformRoleRecord, CatalogError> {
        let role_text = encode_text_enum(request.role)?;
        let target_account_id = request.account_id;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PlatformRoleRow, CatalogTransactionError, _>(async move |conn| {
                lock_platform_roles(conn).await?;
                require_active_administrator(conn, request.actor_account_id, "platform_role")
                    .await?;
                require_existing_account(conn, request.account_id).await?;
                let existing = active_or_revoked_role(conn, request.account_id, &role_text).await?;
                let now = Utc::now();
                if let Some(existing) = existing {
                    // An already active assignment is returned untouched so a
                    // repeated grant cannot rewrite its assigning account or
                    // its original grant time.
                    if existing.state == "active" {
                        return Ok(existing);
                    }
                    // Reactivation reuses the retained row, so `created_at` and
                    // the revoked assignment's history are preserved.
                    return diesel::update(
                        account_platform_roles::table
                            .filter(account_platform_roles::account_id.eq(request.account_id))
                            .filter(account_platform_roles::role.eq(&role_text)),
                    )
                    .set((
                        account_platform_roles::state.eq("active"),
                        account_platform_roles::assigned_by_account_id.eq(request.actor_account_id),
                        account_platform_roles::updated_at.eq(now),
                    ))
                    .returning(PlatformRoleRow::as_returning())
                    .get_result(conn)
                    .await
                    .map_err(CatalogTransactionError::from);
                }
                diesel::insert_into(account_platform_roles::table)
                    .values((
                        account_platform_roles::account_id.eq(request.account_id),
                        account_platform_roles::role.eq(&role_text),
                        account_platform_roles::state.eq("active"),
                        account_platform_roles::assigned_by_account_id.eq(request.actor_account_id),
                        account_platform_roles::created_at.eq(now),
                        account_platform_roles::updated_at.eq(now),
                    ))
                    .returning(PlatformRoleRow::as_returning())
                    .get_result(conn)
                    .await
                    .map_err(CatalogTransactionError::from)
            })
            .await;
        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "platform_role",
                target_account_id.to_string(),
            )),
        }
    }

    /// Atomically revoke one platform role while preserving its assignment history.
    async fn revoke_account_platform_role(
        &self,
        request: PlatformRoleRevocationRequest,
    ) -> Result<PlatformRoleRecord, CatalogError> {
        let role_text = encode_text_enum(request.role)?;
        let target_account_id = request.account_id;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PlatformRoleRow, CatalogTransactionError, _>(async move |conn| {
                lock_platform_roles(conn).await?;
                require_active_administrator(conn, request.actor_account_id, "platform_role")
                    .await?;
                let existing = active_or_revoked_role(conn, request.account_id, &role_text)
                    .await?
                    .ok_or_else(|| {
                        CatalogTransactionError::Catalog(CatalogError::NotFound {
                            kind: "platform_role",
                            key: request.account_id.to_string(),
                        })
                    })?;
                // An already revoked assignment is returned untouched.
                if existing.state == "revoked" {
                    return Ok(existing);
                }
                // Losing every administrator would permanently remove the
                // ability to moderate, promote, or restore authority, and no
                // in-application path could recover it.
                if request.role == PlatformRole::Administrator
                    && administrator_coverage(conn).await? <= 1
                {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Validation(
                        "cannot revoke the last active administrator".to_string(),
                    )));
                }
                diesel::update(
                    account_platform_roles::table
                        .filter(account_platform_roles::account_id.eq(request.account_id))
                        .filter(account_platform_roles::role.eq(&role_text)),
                )
                .set((
                    account_platform_roles::state.eq("revoked"),
                    account_platform_roles::updated_at.eq(Utc::now()),
                ))
                .returning(PlatformRoleRow::as_returning())
                .get_result(conn)
                .await
                .map_err(CatalogTransactionError::from)
            })
            .await;
        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "platform_role",
                target_account_id.to_string(),
            )),
        }
    }

    /// Atomically transition one account's status under administrator authority.
    async fn set_account_status(
        &self,
        request: AccountStatusChangeRequest,
    ) -> Result<AccountRecord, CatalogError> {
        let status_text = encode_text_enum(request.status)?;
        let target_account_id = request.account_id;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<AccountRow, CatalogTransactionError, _>(async move |conn| {
                // Administrator coverage is computed from role rows, so this
                // transaction takes the same lock as role mutation to keep the
                // two paths from racing each other to zero administrators.
                lock_platform_roles(conn).await?;
                require_active_administrator(conn, request.actor_account_id, "account_status")
                    .await?;
                let target = accounts::table
                    .find(request.account_id)
                    .for_update()
                    .select(AccountRow::as_select())
                    .first(conn)
                    .await
                    .optional()?
                    .ok_or_else(|| {
                        CatalogTransactionError::Catalog(CatalogError::NotFound {
                            kind: "account",
                            key: request.account_id.to_string(),
                        })
                    })?;
                // Setting the status an account already holds is a no-op.
                if target.status == status_text {
                    return Ok(target);
                }
                // A non-active account grants no authority, so suspending the
                // sole administrator would strand the platform exactly as
                // revoking their role would.
                if status_text != "active"
                    && administrator_coverage(conn).await? <= 1
                    && account_holds_active_administrator(conn, request.account_id).await?
                {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Validation(
                        "cannot suspend or disable the last active administrator".to_string(),
                    )));
                }
                diesel::update(accounts::table.find(request.account_id))
                    .set((
                        accounts::status.eq(&status_text),
                        accounts::updated_at.eq(Utc::now()),
                    ))
                    .returning(AccountRow::as_returning())
                    .get_result(conn)
                    .await
                    .map_err(CatalogTransactionError::from)
            })
            .await;
        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "account_status",
                target_account_id.to_string(),
            )),
        }
    }

    /// Atomically authorize, record, and apply one non-public moderation decision.
    async fn moderate_publication_submission(
        &self,
        request: PublicationModerationDecisionRequest,
    ) -> Result<PublicationModerationDecisionRecord, CatalogError> {
        validate_publication_moderation_request(&request)?;
        let action = encode_text_enum(request.action)?;
        let target_state = publication_moderation_target(request.action);
        let target_state_text = encode_text_enum(target_state)?;
        let decision_id = request.id;
        let submission_id = request.submission_id;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PublicationModerationDecisionRow, CatalogTransactionError, _>(
                async move |conn| {
                    let actor_status = accounts::table
                        .find(request.actor_account_id)
                        .for_update()
                        .select(accounts::status)
                        .first::<String>(conn)
                        .await
                        .optional()?;
                    let active_role = account_platform_roles::table
                        .filter(account_platform_roles::account_id.eq(request.actor_account_id))
                        .filter(account_platform_roles::state.eq("active"))
                        .filter(account_platform_roles::role.eq_any(["moderator", "administrator"]))
                        .order(account_platform_roles::role.asc())
                        .for_update()
                        .select(PlatformRoleRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if actor_status.as_deref() != Some("active") || active_role.is_none() {
                        return Err(CatalogTransactionError::Catalog(
                            CatalogError::Unauthorized {
                                kind: "publication_moderation",
                                key: request.id.to_string(),
                            },
                        ));
                    }

                    let submission = publication_submissions::table
                        .find(request.submission_id)
                        .for_update()
                        .select(PublicationSubmissionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?
                        .ok_or_else(|| {
                            CatalogTransactionError::Catalog(CatalogError::NotFound {
                                kind: "publication_submission",
                                key: request.submission_id.to_string(),
                            })
                        })?;
                    let submission_record = submission
                        .clone()
                        .into_record()
                        .map_err(CatalogTransactionError::Catalog)?;
                    let active_ownership = publisher_memberships::table
                        .filter(publisher_memberships::account_id.eq(request.actor_account_id))
                        .filter(
                            publisher_memberships::publisher_id.eq(submission_record.publisher_id),
                        )
                        .filter(publisher_memberships::role.eq("owner"))
                        .filter(publisher_memberships::state.eq("active"))
                        .for_update()
                        .select(PublisherMembershipRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if active_ownership.is_some() {
                        return Err(CatalogTransactionError::Catalog(
                            CatalogError::Unauthorized {
                                kind: "publication_moderation",
                                key: request.id.to_string(),
                            },
                        ));
                    }

                    let existing_by_id = publication_moderation_decisions::table
                        .find(request.id)
                        .select(PublicationModerationDecisionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if let Some(existing) = existing_by_id {
                        return resolve_publication_moderation_retry(existing, &request);
                    }
                    let existing_by_request = publication_moderation_decisions::table
                        .filter(publication_moderation_decisions::request_id.eq(request.request_id))
                        .select(PublicationModerationDecisionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if let Some(existing) = existing_by_request {
                        return resolve_publication_moderation_retry(existing, &request);
                    }

                    if !matches!(
                        submission_record.state,
                        PublicationSubmissionState::Quarantined
                            | PublicationSubmissionState::NeedsReview
                    ) {
                        return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                            kind: "publication_submission",
                            key: request.submission_id.to_string(),
                        }));
                    }
                    let from_state_text = encode_text_enum(submission_record.state)
                        .map_err(CatalogTransactionError::Catalog)?;
                    let created_at = diesel::select(diesel::dsl::sql::<
                        diesel::sql_types::Timestamptz,
                    >("CURRENT_TIMESTAMP"))
                    .get_result::<chrono::DateTime<Utc>>(conn)
                    .await?;
                    let decision = diesel::insert_into(publication_moderation_decisions::table)
                        .values(NewPublicationModerationDecisionRow {
                            id: request.id,
                            submission_id: request.submission_id,
                            actor_account_id: request.actor_account_id,
                            action,
                            from_state: from_state_text.clone(),
                            to_state: target_state_text.clone(),
                            reason_code: request.reason_code,
                            private_explanation: request.private_explanation,
                            request_id: request.request_id,
                            created_at,
                        })
                        .returning(PublicationModerationDecisionRow::as_returning())
                        .get_result(conn)
                        .await?;
                    let changed = diesel::update(
                        publication_submissions::table
                            .find(request.submission_id)
                            .filter(publication_submissions::state.eq(from_state_text)),
                    )
                    .set((
                        publication_submissions::state.eq(target_state_text),
                        publication_submissions::updated_at.eq(created_at),
                    ))
                    .execute(conn)
                    .await?;
                    if changed != 1 {
                        return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                            kind: "publication_submission",
                            key: request.submission_id.to_string(),
                        }));
                    }
                    Ok(decision)
                },
            )
            .await;

        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_moderation_decision",
                format!("{decision_id}:{submission_id}"),
            )),
        }
    }

    /// Atomically file one owner-authenticated appeal against an adverse decision.
    async fn file_publication_appeal(
        &self,
        request: PublicationAppealRequest,
    ) -> Result<PublicationAppealRecord, CatalogError> {
        validate_publication_appeal_request(&request)?;
        let appeal_id = request.id;
        let decision_id = request.decision_id;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PublicationAppealRow, CatalogTransactionError, _>(async move |conn| {
                let existing = publication_appeals::table
                    .filter(
                        publication_appeals::id
                            .eq(request.id)
                            .or(publication_appeals::decision_id.eq(request.decision_id))
                            .or(publication_appeals::request_id.eq(request.request_id)),
                    )
                    .select(PublicationAppealRow::as_select())
                    .first(conn)
                    .await
                    .optional()?;
                if let Some(existing) = existing {
                    return resolve_publication_appeal_retry(existing, &request);
                }

                let actor_status = accounts::table
                    .find(request.actor_account_id)
                    .for_update()
                    .select(accounts::status)
                    .first::<String>(conn)
                    .await
                    .optional()?;
                let active_owner = publisher_memberships::table
                    .filter(publisher_memberships::account_id.eq(request.actor_account_id))
                    .filter(publisher_memberships::publisher_id.eq(request.publisher_id))
                    .filter(publisher_memberships::role.eq("owner"))
                    .filter(publisher_memberships::state.eq("active"))
                    .for_update()
                    .select(PublisherMembershipRow::as_select())
                    .first(conn)
                    .await
                    .optional()?;
                if actor_status.as_deref() != Some("active") || active_owner.is_none() {
                    return Err(CatalogTransactionError::Catalog(
                        CatalogError::Unauthorized {
                            kind: "publication_appeal",
                            key: request.id.to_string(),
                        },
                    ));
                }

                let decision = publication_moderation_decisions::table
                    .find(request.decision_id)
                    .for_update()
                    .select(PublicationModerationDecisionRow::as_select())
                    .first(conn)
                    .await
                    .optional()?
                    .ok_or_else(|| {
                        CatalogTransactionError::Catalog(CatalogError::NotFound {
                            kind: "publication_moderation_decision",
                            key: request.decision_id.to_string(),
                        })
                    })?;
                let decision_record = decision
                    .into_record()
                    .map_err(CatalogTransactionError::Catalog)?;
                if !publication_moderation_action_is_appealable(decision_record.action) {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "publication_moderation_decision",
                        key: request.decision_id.to_string(),
                    }));
                }

                let existing = publication_appeals::table
                    .filter(
                        publication_appeals::id
                            .eq(request.id)
                            .or(publication_appeals::decision_id.eq(request.decision_id))
                            .or(publication_appeals::request_id.eq(request.request_id)),
                    )
                    .select(PublicationAppealRow::as_select())
                    .first(conn)
                    .await
                    .optional()?;
                if let Some(existing) = existing {
                    return resolve_publication_appeal_retry(existing, &request);
                }

                let submission = publication_submissions::table
                    .find(decision_record.submission_id)
                    .for_update()
                    .select(PublicationSubmissionRow::as_select())
                    .first(conn)
                    .await?;
                let submission_record = submission
                    .into_record()
                    .map_err(CatalogTransactionError::Catalog)?;
                if submission_record.publisher_id != request.publisher_id {
                    return Err(CatalogTransactionError::Catalog(
                        CatalogError::Unauthorized {
                            kind: "publication_appeal",
                            key: request.id.to_string(),
                        },
                    ));
                }
                if submission_record.state != decision_record.to_state {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "publication_submission",
                        key: decision_record.submission_id.to_string(),
                    }));
                }

                let created_at = diesel::select(
                    diesel::dsl::sql::<diesel::sql_types::Timestamptz>("CURRENT_TIMESTAMP"),
                )
                .get_result::<DateTime<Utc>>(conn)
                .await?;
                let age = created_at.signed_duration_since(decision_record.created_at);
                if age < Duration::zero() || age > Duration::days(30) {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "publication_appeal_deadline",
                        key: request.decision_id.to_string(),
                    }));
                }

                diesel::insert_into(publication_appeals::table)
                    .values(NewPublicationAppealRow {
                        id: request.id,
                        decision_id: request.decision_id,
                        submission_id: decision_record.submission_id,
                        publisher_id: submission_record.publisher_id,
                        actor_account_id: request.actor_account_id,
                        statement: request.statement,
                        request_id: request.request_id,
                        created_at,
                    })
                    .returning(PublicationAppealRow::as_returning())
                    .get_result(conn)
                    .await
                    .map_err(Into::into)
            })
            .await;

        match result {
            Ok(row) => Ok(row.into_record()),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_appeal",
                format!("{appeal_id}:{decision_id}"),
            )),
        }
    }

    /// Atomically resolve one appeal under current administrator authority.
    async fn resolve_publication_appeal(
        &self,
        request: PublicationAppealResolutionRequest,
    ) -> Result<PublicationAppealResolutionRecord, CatalogError> {
        validate_publication_appeal_resolution_request(&request)?;
        let resolution_id = request.id;
        let appeal_id = request.appeal_id;
        let disposition_text = encode_text_enum(request.disposition)?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PublicationAppealResolutionRow, CatalogTransactionError, _>(
                async move |conn| {
                    let existing = publication_appeal_resolutions::table
                        .filter(
                            publication_appeal_resolutions::id
                                .eq(request.id)
                                .or(publication_appeal_resolutions::appeal_id.eq(request.appeal_id))
                                .or(publication_appeal_resolutions::request_id.eq(request.request_id)),
                        )
                        .select(PublicationAppealResolutionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if let Some(existing) = existing {
                        return resolve_publication_appeal_resolution_retry(existing, &request);
                    }

                    diesel::sql_query("LOCK TABLE account_platform_roles IN SHARE MODE")
                        .execute(conn)
                        .await?;
                    let active_administrators = accounts::table
                        .inner_join(
                            account_platform_roles::table.on(account_platform_roles::account_id
                                .eq(accounts::id)),
                        )
                        .filter(accounts::status.eq("active"))
                        .filter(account_platform_roles::role.eq("administrator"))
                        .filter(account_platform_roles::state.eq("active"))
                        .for_update()
                        .select(accounts::id)
                        .load::<uuid::Uuid>(conn)
                        .await?;
                    if !active_administrators.contains(&request.actor_account_id) {
                        return Err(CatalogTransactionError::Catalog(
                            CatalogError::Unauthorized {
                                kind: "publication_appeal_resolution",
                                key: request.id.to_string(),
                            },
                        ));
                    }

                    let appeal = publication_appeals::table
                        .find(request.appeal_id)
                        .for_update()
                        .select(PublicationAppealRow::as_select())
                        .first(conn)
                        .await
                        .optional()?
                        .ok_or_else(|| {
                            CatalogTransactionError::Catalog(CatalogError::NotFound {
                                kind: "publication_appeal",
                                key: request.appeal_id.to_string(),
                            })
                        })?;

                    let existing = publication_appeal_resolutions::table
                        .filter(
                            publication_appeal_resolutions::id
                                .eq(request.id)
                                .or(publication_appeal_resolutions::appeal_id.eq(request.appeal_id))
                                .or(publication_appeal_resolutions::request_id.eq(request.request_id)),
                        )
                        .select(PublicationAppealResolutionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if let Some(existing) = existing {
                        return resolve_publication_appeal_resolution_retry(existing, &request);
                    }

                    let decision = publication_moderation_decisions::table
                        .find(appeal.decision_id)
                        .select(PublicationModerationDecisionRow::as_select())
                        .first(conn)
                        .await?;
                    let decision_record = decision
                        .into_record()
                        .map_err(CatalogTransactionError::Catalog)?;
                    let is_self_resolution =
                        request.actor_account_id == decision_record.actor_account_id;
                    if is_self_resolution {
                        let another_administrator = active_administrators
                            .iter()
                            .any(|account_id| *account_id != request.actor_account_id);
                        if another_administrator
                            || request.separation_exception_reason.is_none()
                        {
                            return Err(CatalogTransactionError::Catalog(
                                CatalogError::Unauthorized {
                                    kind: "publication_appeal_separation",
                                    key: request.appeal_id.to_string(),
                                },
                            ));
                        }
                    } else if request.separation_exception_reason.is_some() {
                        return Err(CatalogTransactionError::Catalog(
                            CatalogError::InvalidArgument(
                                "separation_exception_reason is allowed only for unavoidable self-resolution"
                                    .to_string(),
                            ),
                        ));
                    }

                    let submission = publication_submissions::table
                        .find(appeal.submission_id)
                        .for_update()
                        .select(PublicationSubmissionRow::as_select())
                        .first(conn)
                        .await?;
                    let submission_record = submission
                        .into_record()
                        .map_err(CatalogTransactionError::Catalog)?;
                    if submission_record.state != decision_record.to_state {
                        return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                            kind: "publication_submission",
                            key: appeal.submission_id.to_string(),
                        }));
                    }

                    let created_at = diesel::select(diesel::dsl::sql::<
                        diesel::sql_types::Timestamptz,
                    >("CURRENT_TIMESTAMP"))
                    .get_result::<DateTime<Utc>>(conn)
                    .await?;
                    if request.disposition == PublicationAppealDisposition::Overturn {
                        let from_state = encode_text_enum(submission_record.state)
                            .map_err(CatalogTransactionError::Catalog)?;
                        let changed = diesel::update(
                            publication_submissions::table
                                .find(appeal.submission_id)
                                .filter(publication_submissions::state.eq(from_state)),
                        )
                        .set((
                            publication_submissions::state.eq("approved"),
                            publication_submissions::updated_at.eq(created_at),
                        ))
                        .execute(conn)
                        .await?;
                        if changed != 1 {
                            return Err(CatalogTransactionError::Catalog(
                                CatalogError::Conflict {
                                    kind: "publication_submission",
                                    key: appeal.submission_id.to_string(),
                                },
                            ));
                        }
                    }

                    diesel::insert_into(publication_appeal_resolutions::table)
                        .values(NewPublicationAppealResolutionRow {
                            id: request.id,
                            appeal_id: request.appeal_id,
                            actor_account_id: request.actor_account_id,
                            disposition: disposition_text,
                            rationale: request.rationale,
                            separation_exception_reason: request.separation_exception_reason,
                            request_id: request.request_id,
                            created_at,
                        })
                        .returning(PublicationAppealResolutionRow::as_returning())
                        .get_result(conn)
                        .await
                        .map_err(Into::into)
                },
            )
            .await;

        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_appeal_resolution",
                format!("{resolution_id}:{appeal_id}"),
            )),
        }
    }

    /// List one publisher's private appeal cases for an owner or administrator.
    async fn list_publisher_publication_appeals(
        &self,
        actor_account_id: uuid::Uuid,
        publisher_id: uuid::Uuid,
        before: Option<PublicationAppealCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationAppealCaseRecord>, CatalogError> {
        let limit = publication_appeal_limit(limit)?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<(
                Vec<PublicationAppealRow>,
                Vec<PublicationAppealResolutionRow>,
            ), CatalogTransactionError, _>(async move |conn| {
                let actor_status = accounts::table
                    .find(actor_account_id)
                    .select(accounts::status)
                    .first::<String>(conn)
                    .await
                    .optional()?;
                let active_admin = account_platform_roles::table
                    .filter(account_platform_roles::account_id.eq(actor_account_id))
                    .filter(account_platform_roles::role.eq("administrator"))
                    .filter(account_platform_roles::state.eq("active"))
                    .select(account_platform_roles::account_id)
                    .first::<uuid::Uuid>(conn)
                    .await
                    .optional()?;
                let active_owner = publisher_memberships::table
                    .filter(publisher_memberships::account_id.eq(actor_account_id))
                    .filter(publisher_memberships::publisher_id.eq(publisher_id))
                    .filter(publisher_memberships::role.eq("owner"))
                    .filter(publisher_memberships::state.eq("active"))
                    .select(publisher_memberships::account_id)
                    .first::<uuid::Uuid>(conn)
                    .await
                    .optional()?;
                if actor_status.as_deref() != Some("active")
                    || (active_admin.is_none() && active_owner.is_none())
                {
                    return Err(CatalogTransactionError::Catalog(
                        CatalogError::Unauthorized {
                            kind: "publication_appeal",
                            key: format!("{actor_account_id}:{publisher_id}"),
                        },
                    ));
                }

                let mut query = publication_appeals::table
                    .filter(publication_appeals::publisher_id.eq(publisher_id))
                    .into_boxed();
                if let Some(cursor) = before {
                    query = query.filter(
                        publication_appeals::created_at.lt(cursor.created_at).or(
                            publication_appeals::created_at
                                .eq(cursor.created_at)
                                .and(publication_appeals::id.lt(cursor.id)),
                        ),
                    );
                }
                let appeals = query
                    .order((
                        publication_appeals::created_at.desc(),
                        publication_appeals::id.desc(),
                    ))
                    .limit(limit)
                    .select(PublicationAppealRow::as_select())
                    .load(conn)
                    .await?;
                let appeal_ids = appeals.iter().map(|appeal| appeal.id).collect::<Vec<_>>();
                let resolutions = if appeal_ids.is_empty() {
                    Vec::new()
                } else {
                    publication_appeal_resolutions::table
                        .filter(publication_appeal_resolutions::appeal_id.eq_any(appeal_ids))
                        .select(PublicationAppealResolutionRow::as_select())
                        .load(conn)
                        .await?
                };
                Ok((appeals, resolutions))
            })
            .await;
        match result {
            Ok((appeals, resolutions)) => publication_appeal_cases(appeals, resolutions),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_appeal",
                format!("{actor_account_id}:{publisher_id}"),
            )),
        }
    }

    /// List global private appeal cases for an active administrator.
    async fn list_administrator_publication_appeals(
        &self,
        actor_account_id: uuid::Uuid,
        before: Option<PublicationAppealCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationAppealCaseRecord>, CatalogError> {
        let limit = publication_appeal_limit(limit)?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<(
                Vec<PublicationAppealRow>,
                Vec<PublicationAppealResolutionRow>,
            ), CatalogTransactionError, _>(async move |conn| {
                let actor_status = accounts::table
                    .find(actor_account_id)
                    .select(accounts::status)
                    .first::<String>(conn)
                    .await
                    .optional()?;
                let active_admin = account_platform_roles::table
                    .filter(account_platform_roles::account_id.eq(actor_account_id))
                    .filter(account_platform_roles::role.eq("administrator"))
                    .filter(account_platform_roles::state.eq("active"))
                    .select(account_platform_roles::account_id)
                    .first::<uuid::Uuid>(conn)
                    .await
                    .optional()?;
                if actor_status.as_deref() != Some("active") || active_admin.is_none() {
                    return Err(CatalogTransactionError::Catalog(
                        CatalogError::Unauthorized {
                            kind: "publication_appeal",
                            key: actor_account_id.to_string(),
                        },
                    ));
                }

                let mut query = publication_appeals::table.into_boxed();
                if let Some(cursor) = before {
                    query = query.filter(
                        publication_appeals::created_at.lt(cursor.created_at).or(
                            publication_appeals::created_at
                                .eq(cursor.created_at)
                                .and(publication_appeals::id.lt(cursor.id)),
                        ),
                    );
                }
                let appeals = query
                    .order((
                        publication_appeals::created_at.desc(),
                        publication_appeals::id.desc(),
                    ))
                    .limit(limit)
                    .select(PublicationAppealRow::as_select())
                    .load(conn)
                    .await?;
                let appeal_ids = appeals.iter().map(|appeal| appeal.id).collect::<Vec<_>>();
                let resolutions = if appeal_ids.is_empty() {
                    Vec::new()
                } else {
                    publication_appeal_resolutions::table
                        .filter(publication_appeal_resolutions::appeal_id.eq_any(appeal_ids))
                        .select(PublicationAppealResolutionRow::as_select())
                        .load(conn)
                        .await?
                };
                Ok((appeals, resolutions))
            })
            .await;
        match result {
            Ok((appeals, resolutions)) => publication_appeal_cases(appeals, resolutions),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_appeal",
                actor_account_id.to_string(),
            )),
        }
    }

    /// Atomically activate one approved quarantine submission in the public catalog.
    async fn promote_publication_submission(
        &self,
        request: PublicationPromotionRequest,
        quota: PublishQuota,
    ) -> Result<PublicationPromotionRecord, CatalogError> {
        if request.version.signature.len() != 64 {
            return Err(CatalogError::InvalidArgument(format!(
                "signature must be exactly 64 bytes, got {}",
                request.version.signature.len()
            )));
        }
        if !matches!(request.version.status, PackStatus::Active) {
            return Err(CatalogError::InvalidArgument(
                "promoted pack version must be active".to_string(),
            ));
        }

        let capability_json: serde_json::Value =
            serde_json::from_str(&request.version.capability_manifest_json).map_err(|error| {
                CatalogError::InvalidArgument(format!("capability_manifest_json: {error}"))
            })?;
        let status_json = serde_json::to_value(&request.version.status)
            .map_err(|error| CatalogError::BackendError(Box::new(error)))?;
        let schema_version = i32::try_from(request.version.schema_version).map_err(|_| {
            CatalogError::InvalidArgument(format!(
                "schema_version {} exceeds i32::MAX",
                request.version.schema_version
            ))
        })?;
        let size_bytes = i64::try_from(request.version.size_bytes).map_err(|_| {
            CatalogError::InvalidArgument(format!(
                "size_bytes {} exceeds i64::MAX",
                request.version.size_bytes
            ))
        })?;
        let new_version = NewPackVersionRow {
            pack_name: request.version.pack_name.clone(),
            version: request.version.version.clone(),
            content_hash: request.version.content_hash.as_bytes().to_vec(),
            signature: request.version.signature.clone(),
            author_pubkey: request.version.author_pubkey.0.to_vec(),
            publisher_key_id: request.version.publisher_key_id,
            parent_hash: request
                .version
                .parent_hash
                .map(|hash| hash.as_bytes().to_vec()),
            capability_manifest_json: capability_json,
            schema_version,
            license: request.version.license.clone(),
            status: status_json,
            size_bytes,
        };

        let promotion_id = request.id;
        let submission_id = request.submission_id;
        let pack_name = request.version.pack_name.clone();
        let version = request.version.version.clone();
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PublicationPromotionRow, CatalogTransactionError, _>(async move |conn| {
                let submission = publication_submissions::table
                    .find(request.submission_id)
                    .for_update()
                    .select(PublicationSubmissionRow::as_select())
                    .first(conn)
                    .await
                    .optional()?
                    .ok_or_else(|| {
                        CatalogTransactionError::Catalog(CatalogError::NotFound {
                            kind: "publication_submission",
                            key: request.submission_id.to_string(),
                        })
                    })?;
                let submission_record = submission
                    .clone()
                    .into_record()
                    .map_err(CatalogTransactionError::Catalog)?;

                let existing_by_submission = publication_promotions::table
                    .filter(publication_promotions::submission_id.eq(request.submission_id))
                    .select(PublicationPromotionRow::as_select())
                    .first(conn)
                    .await
                    .optional()?;
                if let Some(existing) = existing_by_submission {
                    return resolve_publication_promotion_retry(existing, &request);
                }
                let existing_by_id = publication_promotions::table
                    .find(request.id)
                    .select(PublicationPromotionRow::as_select())
                    .first(conn)
                    .await
                    .optional()?;
                if let Some(existing) = existing_by_id {
                    return resolve_publication_promotion_retry(existing, &request);
                }
                let existing_by_request = publication_promotions::table
                    .filter(publication_promotions::request_id.eq(request.request_id))
                    .select(PublicationPromotionRow::as_select())
                    .first(conn)
                    .await
                    .optional()?;
                if let Some(existing) = existing_by_request {
                    return resolve_publication_promotion_retry(existing, &request);
                }

                if submission_record.state != PublicationSubmissionState::Approved {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "publication_submission",
                        key: request.submission_id.to_string(),
                    }));
                }
                if request.version.content_hash != submission_record.archive_hash
                    || request.version.publisher_key_id != Some(submission_record.publisher_key_id)
                {
                    return Err(CatalogTransactionError::Catalog(
                        CatalogError::Unauthorized {
                            kind: "publication_promotion",
                            key: request.id.to_string(),
                        },
                    ));
                }

                let actor_status = accounts::table
                    .find(request.actor_account_id)
                    .for_update()
                    .select(accounts::status)
                    .first::<String>(conn)
                    .await
                    .optional()?;
                let active_role = account_platform_roles::table
                    .filter(account_platform_roles::account_id.eq(request.actor_account_id))
                    .filter(account_platform_roles::state.eq("active"))
                    .filter(account_platform_roles::role.eq_any(["moderator", "administrator"]))
                    .order(account_platform_roles::role.asc())
                    .for_update()
                    .select(PlatformRoleRow::as_select())
                    .first(conn)
                    .await
                    .optional()?;
                let active_ownership = publisher_memberships::table
                    .filter(publisher_memberships::account_id.eq(request.actor_account_id))
                    .filter(publisher_memberships::publisher_id.eq(submission_record.publisher_id))
                    .filter(publisher_memberships::role.eq("owner"))
                    .filter(publisher_memberships::state.eq("active"))
                    .for_update()
                    .select(PublisherMembershipRow::as_select())
                    .first(conn)
                    .await
                    .optional()?;
                let publisher_status = publisher_profiles::table
                    .find(submission_record.publisher_id)
                    .for_update()
                    .select(publisher_profiles::moderation_status)
                    .first::<String>(conn)
                    .await
                    .optional()?;
                if actor_status.as_deref() != Some("active")
                    || active_role.is_none()
                    || active_ownership.is_some()
                    || publisher_status.as_deref() != Some("approved")
                {
                    return Err(CatalogTransactionError::Catalog(
                        CatalogError::Unauthorized {
                            kind: "publication_promotion",
                            key: request.id.to_string(),
                        },
                    ));
                }

                register_pack_version_on_connection(
                    conn,
                    PackRegistrationTransaction {
                        new_version,
                        pack_name: request.version.pack_name.clone(),
                        version: request.version.version.clone(),
                        incoming_author: request.version.author_pubkey.0.to_vec(),
                        incoming_publisher_key_id: request.version.publisher_key_id,
                        incoming_size: request.version.size_bytes,
                        quota,
                    },
                )
                .await?;

                diesel::update(packs::table.find(&request.version.pack_name))
                    .set((
                        packs::description.eq(request.description),
                        packs::tags.eq(request.tags),
                        packs::extends.eq(request.extends),
                    ))
                    .execute(conn)
                    .await?;

                let created_at = diesel::select(
                    diesel::dsl::sql::<diesel::sql_types::Timestamptz>("CURRENT_TIMESTAMP"),
                )
                .get_result::<chrono::DateTime<Utc>>(conn)
                .await?;
                let promotion = diesel::insert_into(publication_promotions::table)
                    .values(NewPublicationPromotionRow {
                        id: request.id,
                        submission_id: request.submission_id,
                        actor_account_id: request.actor_account_id,
                        pack_name: request.version.pack_name,
                        version: request.version.version,
                        content_hash: request.version.content_hash.as_bytes().to_vec(),
                        request_id: request.request_id,
                        created_at,
                    })
                    .returning(PublicationPromotionRow::as_returning())
                    .get_result(conn)
                    .await?;
                let changed = diesel::update(
                    publication_submissions::table
                        .find(request.submission_id)
                        .filter(publication_submissions::state.eq("approved")),
                )
                .set((
                    publication_submissions::state.eq("promoted"),
                    publication_submissions::updated_at.eq(created_at),
                ))
                .execute(conn)
                .await?;
                if changed != 1 {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "publication_submission",
                        key: request.submission_id.to_string(),
                    }));
                }
                Ok(promotion)
            })
            .await;

        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_promotion",
                format!("{promotion_id}:{submission_id}:{pack_name}@{version}"),
            )),
        }
    }

    /// Atomically withdraw one eligible non-public publication submission.
    async fn withdraw_publication_submission(
        &self,
        request: PublicationWithdrawalRequest,
    ) -> Result<PublicationLifecycleDecisionRecord, CatalogError> {
        validate_publication_lifecycle_reason(&request.reason_code)?;
        let decision_id = request.id;
        let submission_id = request.submission_id;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PublicationLifecycleDecisionRow, CatalogTransactionError, _>(
                async move |conn| {
                    let submission = publication_submissions::table
                        .find(request.submission_id)
                        .for_update()
                        .select(PublicationSubmissionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?
                        .ok_or_else(|| {
                            CatalogTransactionError::Catalog(CatalogError::NotFound {
                                kind: "publication_submission",
                                key: request.submission_id.to_string(),
                            })
                        })?;
                    let submission_record = submission
                        .clone()
                        .into_record()
                        .map_err(CatalogTransactionError::Catalog)?;
                    let existing = publication_lifecycle_decisions::table
                        .filter(publication_lifecycle_decisions::action.eq("withdraw_submission"))
                        .filter(
                            publication_lifecycle_decisions::submission_id
                                .eq(request.submission_id),
                        )
                        .or_filter(publication_lifecycle_decisions::id.eq(request.id))
                        .or_filter(
                            publication_lifecycle_decisions::request_id.eq(request.request_id),
                        )
                        .select(PublicationLifecycleDecisionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if let Some(existing) = existing {
                        return resolve_publication_lifecycle_retry(
                            existing,
                            ExpectedPublicationLifecycleDecision {
                                id: request.id,
                                action: PublicationLifecycleAction::WithdrawSubmission,
                                actor_account_id: request.actor_account_id,
                                publisher_id: Some(submission_record.publisher_id),
                                submission_id: Some(request.submission_id),
                                pack_name: None,
                                version: None,
                                reason_code: &request.reason_code,
                                request_id: request.request_id,
                            },
                        );
                    }

                    let actor_status = accounts::table
                        .find(request.actor_account_id)
                        .for_update()
                        .select(accounts::status)
                        .first::<String>(conn)
                        .await
                        .optional()?;
                    let active_owner = publisher_memberships::table
                        .filter(publisher_memberships::account_id.eq(request.actor_account_id))
                        .filter(
                            publisher_memberships::publisher_id.eq(submission_record.publisher_id),
                        )
                        .filter(publisher_memberships::role.eq("owner"))
                        .filter(publisher_memberships::state.eq("active"))
                        .for_update()
                        .select(PublisherMembershipRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if actor_status.as_deref() != Some("active") || active_owner.is_none() {
                        return Err(CatalogTransactionError::Catalog(
                            CatalogError::Unauthorized {
                                kind: "publication_withdrawal",
                                key: request.id.to_string(),
                            },
                        ));
                    }
                    if !matches!(
                        submission_record.state,
                        PublicationSubmissionState::Quarantined
                            | PublicationSubmissionState::NeedsReview
                            | PublicationSubmissionState::Approved
                    ) {
                        return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                            kind: "publication_submission",
                            key: request.submission_id.to_string(),
                        }));
                    }

                    let from_state = encode_text_enum(submission_record.state)
                        .map_err(CatalogTransactionError::Catalog)?;
                    let created_at = diesel::select(diesel::dsl::sql::<
                        diesel::sql_types::Timestamptz,
                    >("CURRENT_TIMESTAMP"))
                    .get_result::<DateTime<Utc>>(conn)
                    .await?;
                    let decision = diesel::insert_into(publication_lifecycle_decisions::table)
                        .values(NewPublicationLifecycleDecisionRow {
                            id: request.id,
                            action: "withdraw_submission".to_string(),
                            actor_account_id: request.actor_account_id,
                            publisher_id: Some(submission_record.publisher_id),
                            submission_id: Some(request.submission_id),
                            pack_name: None,
                            version: None,
                            from_state,
                            to_state: "withdrawn".to_string(),
                            reason_code: request.reason_code,
                            request_id: request.request_id,
                            created_at,
                        })
                        .returning(PublicationLifecycleDecisionRow::as_returning())
                        .get_result(conn)
                        .await?;
                    let changed = diesel::update(
                        publication_submissions::table
                            .find(request.submission_id)
                            .filter(publication_submissions::state.ne_all([
                                "rejected",
                                "promoted",
                                "withdrawn",
                            ])),
                    )
                    .set((
                        publication_submissions::state.eq("withdrawn"),
                        publication_submissions::updated_at.eq(created_at),
                    ))
                    .execute(conn)
                    .await?;
                    if changed != 1 {
                        return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                            kind: "publication_submission",
                            key: request.submission_id.to_string(),
                        }));
                    }
                    Ok(decision)
                },
            )
            .await;
        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_withdrawal",
                format!("{decision_id}:{submission_id}"),
            )),
        }
    }

    /// Atomically suspend one publisher under active administrator authority.
    async fn suspend_publisher(
        &self,
        request: PublisherSuspensionRequest,
    ) -> Result<PublicationLifecycleDecisionRecord, CatalogError> {
        validate_publication_lifecycle_reason(&request.reason_code)?;
        let decision_id = request.id;
        let publisher_id = request.publisher_id;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PublicationLifecycleDecisionRow, CatalogTransactionError, _>(
                async move |conn| {
                    let from_state = publisher_profiles::table
                        .find(request.publisher_id)
                        .for_update()
                        .select(publisher_profiles::moderation_status)
                        .first::<String>(conn)
                        .await
                        .optional()?
                        .ok_or_else(|| {
                            CatalogTransactionError::Catalog(CatalogError::NotFound {
                                kind: "publisher",
                                key: request.publisher_id.to_string(),
                            })
                        })?;
                    let existing = publication_lifecycle_decisions::table
                        .filter(publication_lifecycle_decisions::action.eq("suspend_publisher"))
                        .filter(
                            publication_lifecycle_decisions::publisher_id.eq(request.publisher_id),
                        )
                        .or_filter(publication_lifecycle_decisions::id.eq(request.id))
                        .or_filter(
                            publication_lifecycle_decisions::request_id.eq(request.request_id),
                        )
                        .select(PublicationLifecycleDecisionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if let Some(existing) = existing {
                        return resolve_publication_lifecycle_retry(
                            existing,
                            ExpectedPublicationLifecycleDecision {
                                id: request.id,
                                action: PublicationLifecycleAction::SuspendPublisher,
                                actor_account_id: request.actor_account_id,
                                publisher_id: Some(request.publisher_id),
                                submission_id: None,
                                pack_name: None,
                                version: None,
                                reason_code: &request.reason_code,
                                request_id: request.request_id,
                            },
                        );
                    }

                    let actor_status = accounts::table
                        .find(request.actor_account_id)
                        .for_update()
                        .select(accounts::status)
                        .first::<String>(conn)
                        .await
                        .optional()?;
                    let active_admin = account_platform_roles::table
                        .filter(account_platform_roles::account_id.eq(request.actor_account_id))
                        .filter(account_platform_roles::role.eq("administrator"))
                        .filter(account_platform_roles::state.eq("active"))
                        .for_update()
                        .select(PlatformRoleRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if actor_status.as_deref() != Some("active") || active_admin.is_none() {
                        return Err(CatalogTransactionError::Catalog(
                            CatalogError::Unauthorized {
                                kind: "publisher_suspension",
                                key: request.id.to_string(),
                            },
                        ));
                    }
                    if !matches!(from_state.as_str(), "pending" | "approved") {
                        return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                            kind: "publisher",
                            key: request.publisher_id.to_string(),
                        }));
                    }
                    let created_at = diesel::select(diesel::dsl::sql::<
                        diesel::sql_types::Timestamptz,
                    >("CURRENT_TIMESTAMP"))
                    .get_result::<DateTime<Utc>>(conn)
                    .await?;
                    let decision = diesel::insert_into(publication_lifecycle_decisions::table)
                        .values(NewPublicationLifecycleDecisionRow {
                            id: request.id,
                            action: "suspend_publisher".to_string(),
                            actor_account_id: request.actor_account_id,
                            publisher_id: Some(request.publisher_id),
                            submission_id: None,
                            pack_name: None,
                            version: None,
                            from_state,
                            to_state: "suspended".to_string(),
                            reason_code: request.reason_code,
                            request_id: request.request_id,
                            created_at,
                        })
                        .returning(PublicationLifecycleDecisionRow::as_returning())
                        .get_result(conn)
                        .await?;
                    let changed = diesel::update(
                        publisher_profiles::table
                            .find(request.publisher_id)
                            .filter(publisher_profiles::moderation_status.ne("suspended")),
                    )
                    .set((
                        publisher_profiles::moderation_status.eq("suspended"),
                        publisher_profiles::updated_at.eq(created_at),
                    ))
                    .execute(conn)
                    .await?;
                    if changed != 1 {
                        return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                            kind: "publisher",
                            key: request.publisher_id.to_string(),
                        }));
                    }
                    Ok(decision)
                },
            )
            .await;
        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publisher_suspension",
                format!("{decision_id}:{publisher_id}"),
            )),
        }
    }

    /// Atomically tombstone one active release under administrator authority.
    async fn tombstone_publication_release(
        &self,
        request: PublicationTombstoneRequest,
    ) -> Result<PublicationLifecycleDecisionRecord, CatalogError> {
        let reason_code = encode_text_enum(request.reason.clone())?;
        validate_publication_lifecycle_reason(&reason_code)?;
        let decision_id = request.id;
        let release_key = format!("{}@{}", request.pack_name, request.version);
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<PublicationLifecycleDecisionRow, CatalogTransactionError, _>(
                async move |conn| {
                    let status_json = pack_versions::table
                        .find((&request.pack_name, &request.version))
                        .for_update()
                        .select(pack_versions::status)
                        .first::<serde_json::Value>(conn)
                        .await
                        .optional()?
                        .ok_or_else(|| {
                            CatalogTransactionError::Catalog(CatalogError::NotFound {
                                kind: "pack_version",
                                key: format!("{}@{}", request.pack_name, request.version),
                            })
                        })?;
                    let publisher_id = packs::table
                        .find(&request.pack_name)
                        .for_update()
                        .select(packs::publisher_id)
                        .first::<Option<uuid::Uuid>>(conn)
                        .await
                        .optional()?
                        .flatten();
                    let existing = publication_lifecycle_decisions::table
                        .filter(publication_lifecycle_decisions::action.eq("tombstone_release"))
                        .filter(publication_lifecycle_decisions::pack_name.eq(&request.pack_name))
                        .filter(publication_lifecycle_decisions::version.eq(&request.version))
                        .or_filter(publication_lifecycle_decisions::id.eq(request.id))
                        .or_filter(
                            publication_lifecycle_decisions::request_id.eq(request.request_id),
                        )
                        .select(PublicationLifecycleDecisionRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if let Some(existing) = existing {
                        return resolve_publication_lifecycle_retry(
                            existing,
                            ExpectedPublicationLifecycleDecision {
                                id: request.id,
                                action: PublicationLifecycleAction::TombstoneRelease,
                                actor_account_id: request.actor_account_id,
                                publisher_id,
                                submission_id: None,
                                pack_name: Some(&request.pack_name),
                                version: Some(&request.version),
                                reason_code: &reason_code,
                                request_id: request.request_id,
                            },
                        );
                    }

                    let actor_status = accounts::table
                        .find(request.actor_account_id)
                        .for_update()
                        .select(accounts::status)
                        .first::<String>(conn)
                        .await
                        .optional()?;
                    let active_admin = account_platform_roles::table
                        .filter(account_platform_roles::account_id.eq(request.actor_account_id))
                        .filter(account_platform_roles::role.eq("administrator"))
                        .filter(account_platform_roles::state.eq("active"))
                        .for_update()
                        .select(PlatformRoleRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if actor_status.as_deref() != Some("active") || active_admin.is_none() {
                        return Err(CatalogTransactionError::Catalog(
                            CatalogError::Unauthorized {
                                kind: "publication_tombstone",
                                key: request.id.to_string(),
                            },
                        ));
                    }
                    let status: PackStatus =
                        serde_json::from_value(status_json).map_err(|error| {
                            CatalogTransactionError::Catalog(CatalogError::BackendError(Box::new(
                                error,
                            )))
                        })?;
                    if !matches!(status, PackStatus::Active) {
                        return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                            kind: "pack_version",
                            key: format!("{}@{}", request.pack_name, request.version),
                        }));
                    }

                    let created_at = diesel::select(diesel::dsl::sql::<
                        diesel::sql_types::Timestamptz,
                    >("CURRENT_TIMESTAMP"))
                    .get_result::<DateTime<Utc>>(conn)
                    .await?;
                    let tombstone_status = serde_json::to_value(PackStatus::Tombstone {
                        reason: request.reason,
                        recorded_at: created_at,
                    })
                    .map_err(|error| {
                        CatalogTransactionError::Catalog(CatalogError::BackendError(Box::new(
                            error,
                        )))
                    })?;
                    let decision = diesel::insert_into(publication_lifecycle_decisions::table)
                        .values(NewPublicationLifecycleDecisionRow {
                            id: request.id,
                            action: "tombstone_release".to_string(),
                            actor_account_id: request.actor_account_id,
                            publisher_id,
                            submission_id: None,
                            pack_name: Some(request.pack_name.clone()),
                            version: Some(request.version.clone()),
                            from_state: "active".to_string(),
                            to_state: "tombstone".to_string(),
                            reason_code,
                            request_id: request.request_id,
                            created_at,
                        })
                        .returning(PublicationLifecycleDecisionRow::as_returning())
                        .get_result(conn)
                        .await?;
                    let changed = diesel::update(
                        pack_versions::table.find((&request.pack_name, &request.version)),
                    )
                    .set(pack_versions::status.eq(tombstone_status))
                    .execute(conn)
                    .await?;
                    if changed != 1 {
                        return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                            kind: "pack_version",
                            key: format!("{}@{}", request.pack_name, request.version),
                        }));
                    }
                    let versions = pack_versions::table
                        .filter(pack_versions::pack_name.eq(&request.pack_name))
                        .select((pack_versions::version, pack_versions::status))
                        .load::<(String, serde_json::Value)>(conn)
                        .await?;
                    let newest_active = versions
                        .into_iter()
                        .filter_map(|(version, status_json)| {
                            let status = serde_json::from_value::<PackStatus>(status_json).ok()?;
                            matches!(status, PackStatus::Active).then_some(version)
                        })
                        .fold(None::<String>, |best, candidate| match best {
                            None => Some(candidate),
                            Some(current) if semver_gt(&candidate, &current) => Some(candidate),
                            Some(current) => Some(current),
                        });
                    diesel::update(packs::table.find(&request.pack_name))
                        .set(packs::latest_version.eq(newest_active))
                        .execute(conn)
                        .await?;
                    Ok(decision)
                },
            )
            .await;
        match result {
            Ok(row) => row.into_record(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_tombstone",
                format!("{decision_id}:{release_key}"),
            )),
        }
    }

    /// List one publisher's lifecycle evidence for an owner or administrator.
    async fn list_publisher_lifecycle_decisions(
        &self,
        actor_account_id: uuid::Uuid,
        publisher_id: uuid::Uuid,
        before: Option<PublicationLifecycleCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationLifecycleDecisionRecord>, CatalogError> {
        let limit = publication_lifecycle_limit(limit)?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<Vec<PublicationLifecycleDecisionRow>, CatalogTransactionError, _>(
                async move |conn| {
                    let actor_status = accounts::table
                        .find(actor_account_id)
                        .for_update()
                        .select(accounts::status)
                        .first::<String>(conn)
                        .await
                        .optional()?;
                    let active_admin = account_platform_roles::table
                        .filter(account_platform_roles::account_id.eq(actor_account_id))
                        .filter(account_platform_roles::role.eq("administrator"))
                        .filter(account_platform_roles::state.eq("active"))
                        .for_update()
                        .select(PlatformRoleRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    let active_owner = publisher_memberships::table
                        .filter(publisher_memberships::account_id.eq(actor_account_id))
                        .filter(publisher_memberships::publisher_id.eq(publisher_id))
                        .filter(publisher_memberships::role.eq("owner"))
                        .filter(publisher_memberships::state.eq("active"))
                        .for_update()
                        .select(PublisherMembershipRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if actor_status.as_deref() != Some("active")
                        || (active_admin.is_none() && active_owner.is_none())
                    {
                        return Err(CatalogTransactionError::Catalog(
                            CatalogError::Unauthorized {
                                kind: "publication_lifecycle_audit",
                                key: format!("{actor_account_id}:{publisher_id}"),
                            },
                        ));
                    }
                    let mut query = publication_lifecycle_decisions::table
                        .filter(publication_lifecycle_decisions::publisher_id.eq(publisher_id))
                        .into_boxed();
                    if let Some(cursor) = before {
                        query = query.filter(
                            publication_lifecycle_decisions::created_at
                                .lt(cursor.created_at)
                                .or(publication_lifecycle_decisions::created_at
                                    .eq(cursor.created_at)
                                    .and(publication_lifecycle_decisions::id.lt(cursor.id))),
                        );
                    }
                    query
                        .order((
                            publication_lifecycle_decisions::created_at.desc(),
                            publication_lifecycle_decisions::id.desc(),
                        ))
                        .limit(limit)
                        .select(PublicationLifecycleDecisionRow::as_select())
                        .load(conn)
                        .await
                        .map_err(CatalogTransactionError::Diesel)
                },
            )
            .await;
        match result {
            Ok(rows) => rows.into_iter().map(|row| row.into_record()).collect(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_lifecycle_audit",
                publisher_id.to_string(),
            )),
        }
    }

    /// List global lifecycle evidence for an active administrator.
    async fn list_administrator_lifecycle_decisions(
        &self,
        actor_account_id: uuid::Uuid,
        before: Option<PublicationLifecycleCursor>,
        limit: u32,
    ) -> Result<Vec<PublicationLifecycleDecisionRecord>, CatalogError> {
        let limit = publication_lifecycle_limit(limit)?;
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        use diesel_async::AsyncConnection as _;
        let result = conn
            .transaction::<Vec<PublicationLifecycleDecisionRow>, CatalogTransactionError, _>(
                async move |conn| {
                    let actor_status = accounts::table
                        .find(actor_account_id)
                        .for_update()
                        .select(accounts::status)
                        .first::<String>(conn)
                        .await
                        .optional()?;
                    let active_admin = account_platform_roles::table
                        .filter(account_platform_roles::account_id.eq(actor_account_id))
                        .filter(account_platform_roles::role.eq("administrator"))
                        .filter(account_platform_roles::state.eq("active"))
                        .for_update()
                        .select(PlatformRoleRow::as_select())
                        .first(conn)
                        .await
                        .optional()?;
                    if actor_status.as_deref() != Some("active") || active_admin.is_none() {
                        return Err(CatalogTransactionError::Catalog(
                            CatalogError::Unauthorized {
                                kind: "publication_lifecycle_audit",
                                key: actor_account_id.to_string(),
                            },
                        ));
                    }
                    let mut query = publication_lifecycle_decisions::table.into_boxed();
                    if let Some(cursor) = before {
                        query = query.filter(
                            publication_lifecycle_decisions::created_at
                                .lt(cursor.created_at)
                                .or(publication_lifecycle_decisions::created_at
                                    .eq(cursor.created_at)
                                    .and(publication_lifecycle_decisions::id.lt(cursor.id))),
                        );
                    }
                    query
                        .order((
                            publication_lifecycle_decisions::created_at.desc(),
                            publication_lifecycle_decisions::id.desc(),
                        ))
                        .limit(limit)
                        .select(PublicationLifecycleDecisionRow::as_select())
                        .load(conn)
                        .await
                        .map_err(CatalogTransactionError::Diesel)
                },
            )
            .await;
        match result {
            Ok(rows) => rows.into_iter().map(|row| row.into_record()).collect(),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => Err(map_diesel_error(
                error,
                "publication_lifecycle_audit",
                actor_account_id.to_string(),
            )),
        }
    }

    /// Register a new author or confirm an identical author already exists.
    ///
    /// SQL shape:
    /// ```sql
    /// INSERT INTO authors (pubkey, handle, display_name, oauth_links)
    ///   VALUES ($1, $2, $3, $4)
    ///   ON CONFLICT DO NOTHING
    /// ```
    /// After the insert attempt, a `SELECT ... FROM authors WHERE handle = $handle`
    /// is used to determine whether a handle collision occurred. If the stored
    /// pubkey does not match the supplied pubkey, `CatalogError::HandleTaken` is
    /// returned with the current owner's key. If the stored pubkey matches, the
    /// registration is treated as a no-op and `Ok(())` is returned.
    ///
    /// A `UniqueViolation` on the `pubkey` column (same pubkey, different handle)
    /// surfaces as `CatalogError::Conflict` via the SELECT-after-INSERT path.
    #[instrument(skip(self, record), fields(handle = %record.handle))]
    async fn register_author(&self, record: AuthorRecord) -> Result<(), CatalogError> {
        if record.display_name.as_deref() == Some("") {
            return Err(CatalogError::Validation(
                "display_name must not be an empty string; use None instead".to_string(),
            ));
        }

        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let oauth_json = serde_json::to_value(&record.oauth_links)
            .map_err(|e| CatalogError::BackendError(Box::new(e)))?;

        let new_row = NewAuthorRow {
            pubkey: record.pubkey.0.to_vec(),
            handle: record.handle.clone(),
            display_name: record.display_name.clone(),
            oauth_links: oauth_json,
        };

        let handle = record.handle.clone();
        let pubkey = record.pubkey;
        use diesel_async::AsyncConnection as _;
        let tx_result = conn
            .transaction::<(), CatalogTransactionError, _>(async move |conn| {
                diesel::sql_query(
                    "LOCK TABLE authors, handles, publisher_profiles \
                     IN SHARE ROW EXCLUSIVE MODE",
                )
                .execute(conn)
                .await?;
                let publisher_exists = publisher_profiles::table
                    .filter(publisher_profiles::handle.eq(&handle))
                    .select(publisher_profiles::id)
                    .first::<uuid::Uuid>(conn)
                    .await
                    .optional()?;
                if publisher_exists.is_some() {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "author",
                        key: handle.clone(),
                    }));
                }

                // Attempt insert; ON CONFLICT DO NOTHING means no error on duplicate.
                diesel::insert_into(authors::table)
                    .values(&new_row)
                    .on_conflict_do_nothing()
                    .execute(conn)
                    .await?;

                // Reconcile the requested identity against the stored rows after
                // the conflict-resolving insert while namespace writers remain locked.
                let by_handle: Option<AuthorRow> = authors::table
                    .filter(authors::handle.eq(&handle))
                    .select(AuthorRow::as_select())
                    .first(conn)
                    .await
                    .optional()?;
                if let Some(existing) = by_handle {
                    if existing.pubkey != pubkey.0.to_vec() {
                        let owner = vec_to_pubkey(existing.pubkey)
                            .map_err(CatalogTransactionError::Catalog)?;
                        return Err(CatalogTransactionError::Catalog(
                            CatalogError::HandleTaken { owner },
                        ));
                    }
                }

                let by_pubkey: Option<AuthorRow> = authors::table
                    .filter(authors::pubkey.eq(pubkey.0.to_vec()))
                    .select(AuthorRow::as_select())
                    .first(conn)
                    .await
                    .optional()?;
                if by_pubkey.is_some_and(|existing| existing.handle != handle) {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "author",
                        key: pubkey.to_string(),
                    }));
                }
                Ok(())
            })
            .await;
        match tx_result {
            Ok(()) => Ok(()),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => {
                Err(map_diesel_error(error, "author", record.handle))
            }
        }
    }

    /// Look up an author by their Ed25519 public key.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM authors WHERE pubkey = $1 LIMIT 1
    /// ```
    /// Uses the primary key index on `authors(pubkey)`.
    #[instrument(skip(self, pubkey), fields(pubkey = %pubkey))]
    async fn lookup_author(&self, pubkey: &Ed25519PublicKey) -> Result<AuthorRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row: AuthorRow = authors::table
            .filter(authors::pubkey.eq(pubkey.0.to_vec()))
            .select(AuthorRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "author", pubkey.to_string()))?;
        row.into_record()
    }

    /// Look up an author by their unique handle string.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM authors WHERE handle = $1 LIMIT 1
    /// ```
    /// Uses the UNIQUE index on `authors(handle)`.
    #[instrument(skip(self, handle), fields(handle = %handle))]
    async fn lookup_author_by_handle(&self, handle: &str) -> Result<AuthorRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row: AuthorRow = authors::table
            .filter(authors::handle.eq(handle))
            .select(AuthorRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "author", handle.to_string()))?;
        row.into_record()
    }

    /// List all registered authors, ordered by `created_at ASC`.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM authors ORDER BY created_at ASC LIMIT $1 OFFSET $2
    /// ```
    /// Returns an empty `Vec` when `offset` is beyond the total count.
    ///
    /// NOTE: Large offsets cause Postgres to scan and discard many rows.
    /// Keyset pagination by `created_at` and `pubkey` would avoid that cost.
    #[instrument(skip(self))]
    async fn list_authors(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuthorRecord>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let rows: Vec<AuthorRow> = authors::table
            .select(AuthorRow::as_select())
            .order(authors::created_at.asc())
            .limit(i64::from(limit))
            .offset(i64::from(offset))
            .load(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "author", String::new()))?;
        rows.into_iter().map(|r| r.into_record()).collect()
    }

    /// Register a new version of a pack.
    ///
    /// Executed inside a single transaction:
    /// 1. Validate `signature` length is exactly 64 bytes.
    /// 2. Lock and validate either the legacy author or active enrolled
    ///    publisher key, serializing publisher writes with key revocation.
    /// 3. Upsert the parent `packs` row (INSERT ... ON CONFLICT DO NOTHING) to
    ///    ensure the head record exists.
    /// 4. Re-read and lock the stored pack head, then verify that its legacy
    ///    author or publisher identity matches the incoming authority.
    /// 5. INSERT the new `pack_versions` row; a `UniqueViolation` on
    ///    `(pack_name, version)` maps to `CatalogError::Conflict`.
    /// 6. Record successful publisher-key use inside the same transaction.
    /// 7. UPDATE `packs.latest_version` using true semver precedence:
    ///    the stored `latest_version` is fetched inside the transaction and
    ///    compared with [`semver_gt`]; the UPDATE only runs when the new
    ///    version has strictly higher precedence.
    #[instrument(skip(self, record), fields(pack = %record.pack_name, version = %record.version))]
    async fn register_pack_version_with_quota(
        &self,
        record: PackVersionRecord,
        quota: PublishQuota,
    ) -> Result<(), CatalogError> {
        if record.signature.len() != 64 {
            return Err(CatalogError::InvalidArgument(format!(
                "signature must be exactly 64 bytes, got {}",
                record.signature.len()
            )));
        }

        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        // Build values outside the closure to avoid lifetime issues.
        let capability_json: serde_json::Value =
            serde_json::from_str(&record.capability_manifest_json).map_err(|e| {
                CatalogError::InvalidArgument(format!("capability_manifest_json: {e}"))
            })?;

        let status_json = serde_json::to_value(&record.status)
            .map_err(|e| CatalogError::BackendError(Box::new(e)))?;

        let schema_version_i32 = i32::try_from(record.schema_version).map_err(|_| {
            CatalogError::InvalidArgument(format!(
                "schema_version {} exceeds i32::MAX",
                record.schema_version
            ))
        })?;
        let size_bytes_i64 = i64::try_from(record.size_bytes).map_err(|_| {
            CatalogError::InvalidArgument(format!(
                "size_bytes {} exceeds i64::MAX",
                record.size_bytes
            ))
        })?;
        let new_version = NewPackVersionRow {
            pack_name: record.pack_name.clone(),
            version: record.version.clone(),
            content_hash: record.content_hash.as_bytes().to_vec(),
            signature: record.signature.clone(),
            author_pubkey: record.author_pubkey.0.to_vec(),
            publisher_key_id: record.publisher_key_id,
            parent_hash: record.parent_hash.map(|h| h.as_bytes().to_vec()),
            capability_manifest_json: capability_json,
            schema_version: schema_version_i32,
            license: record.license.clone(),
            status: status_json,
            size_bytes: size_bytes_i64,
        };

        let pack_name_clone = record.pack_name.clone();
        let version_clone = record.version.clone();
        // Capture the incoming author bytes for the ownership check inside the tx.
        let incoming_author_bytes = record.author_pubkey.0.to_vec();
        let incoming_publisher_key_id = record.publisher_key_id;
        let incoming_size_bytes = record.size_bytes;

        use diesel_async::AsyncConnection as _;
        let tx_result = conn
            .transaction::<(), CatalogTransactionError, _>(async move |conn| {
                register_pack_version_on_connection(
                    conn,
                    PackRegistrationTransaction {
                        new_version,
                        pack_name: pack_name_clone,
                        version: version_clone,
                        incoming_author: incoming_author_bytes,
                        incoming_publisher_key_id,
                        incoming_size: incoming_size_bytes,
                        quota,
                    },
                )
                .await
            })
            .await;

        match tx_result {
            Ok(()) => Ok(()),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => {
                Err(map_diesel_error(error, "pack", record.pack_name.clone()))
            }
        }
    }

    /// Retrieve the top-level pack record for the given pack name.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM packs WHERE name = $1 LIMIT 1
    /// ```
    /// Uses the primary key index on `packs(name)`.
    #[instrument(skip(self, name), fields(pack = %name))]
    async fn get_pack(&self, name: &str) -> Result<PackRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row: PackRow = packs::table
            .filter(packs::name.eq(name))
            .select(PackRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack", name.to_string()))?;
        row.into_record()
    }

    /// Retrieve a specific version record.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM pack_versions WHERE pack_name = $1 AND version = $2 LIMIT 1
    /// ```
    /// Uses the composite primary key index on `pack_versions(pack_name, version)`.
    #[instrument(skip(self, name, version), fields(pack = %name, version = %version))]
    async fn get_pack_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<PackVersionRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row: PackVersionRow = pack_versions::table
            .filter(
                pack_versions::pack_name
                    .eq(name)
                    .and(pack_versions::version.eq(version)),
            )
            .select(PackVersionRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack_version", format!("{name}@{version}")))?;
        row.into_record()
    }

    /// Retrieve an active version by content hash for signed-download revocation.
    #[instrument(skip(self, content_hash), fields(hash = %content_hash))]
    async fn get_active_pack_version_by_hash(
        &self,
        content_hash: &frameshift_pack::ObjectHash,
    ) -> Result<PackVersionRecord, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let active = serde_json::json!({"kind": "active"});
        let row: PackVersionRow = pack_versions::table
            .filter(
                pack_versions::content_hash
                    .eq(content_hash.as_bytes().to_vec())
                    .and(pack_versions::status.eq(active)),
            )
            .select(PackVersionRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "active_pack_version", content_hash.to_string()))?;
        row.into_record()
    }

    /// List all versions of a pack, ordered by `published_at ASC, version ASC`.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT * FROM pack_versions
    /// WHERE pack_name = $1
    /// ORDER BY published_at ASC, version ASC
    /// ```
    /// First verifies the pack exists (returns `NotFound` if not), then lists versions.
    #[instrument(skip(self, name), fields(pack = %name))]
    async fn list_pack_versions(&self, name: &str) -> Result<Vec<PackVersionRecord>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        // Verify the pack exists.
        let pack_exists: bool = diesel::select(diesel::dsl::exists(
            packs::table.filter(packs::name.eq(name)),
        ))
        .get_result(&mut *conn)
        .await
        .map_err(|e| map_diesel_error(e, "pack", name.to_string()))?;

        if !pack_exists {
            return Err(CatalogError::NotFound {
                kind: "pack",
                key: name.to_string(),
            });
        }

        let rows: Vec<PackVersionRow> = pack_versions::table
            .filter(pack_versions::pack_name.eq(name))
            .select(PackVersionRow::as_select())
            .order(pack_versions::published_at.asc())
            .then_order_by(pack_versions::version.asc())
            .load(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack_version", name.to_string()))?;

        rows.into_iter().map(|r| r.into_record()).collect()
    }

    /// List one bounded page of versions in stable publication order.
    ///
    /// SQL applies `LIMIT` and `OFFSET` after the deterministic
    /// `published_at ASC, version ASC` ordering.
    #[instrument(skip(self, name), fields(pack = %name, limit, offset))]
    async fn list_pack_versions_page(
        &self,
        name: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<PackVersionRecord>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let pack_exists: bool = diesel::select(diesel::dsl::exists(
            packs::table.filter(packs::name.eq(name)),
        ))
        .get_result(&mut *conn)
        .await
        .map_err(|error| map_diesel_error(error, "pack", name.to_string()))?;

        if !pack_exists {
            return Err(CatalogError::NotFound {
                kind: "pack",
                key: name.to_string(),
            });
        }

        let rows: Vec<PackVersionRow> = pack_versions::table
            .filter(pack_versions::pack_name.eq(name))
            .select(PackVersionRow::as_select())
            .order(pack_versions::published_at.asc())
            .then_order_by(pack_versions::version.asc())
            .limit(i64::from(limit))
            .offset(i64::from(offset))
            .load(&mut *conn)
            .await
            .map_err(|error| map_diesel_error(error, "pack_version", name.to_string()))?;

        rows.into_iter().map(|row| row.into_record()).collect()
    }

    /// Search for packs matching the given filters.
    ///
    /// All filters are ANDed together. Sort modes:
    /// - `TopRated`: `ORDER BY total_downloads DESC, name ASC`
    /// - `Recent`: `ORDER BY created_at DESC, name ASC`
    /// - `Trending`: ranks by count of `pack_downloads` rows in the last 7 days,
    ///   `DESC`, with `name ASC` as a deterministic tiebreaker.
    ///
    /// Text query uses `plainto_tsquery('english', $query)` against the GIN FTS
    /// index on `to_tsvector('english', description || ' ' || name)`.
    /// `plainto_tsquery` is used (NOT `to_tsquery`) to safely handle user input
    /// that may contain FTS-special characters.
    ///
    /// Tag filter uses `tags @> ARRAY[$tag]::TEXT[]` (array containment) against
    /// the GIN index on `tags`.
    ///
    /// `target_context` filter adds a second array-containment clause,
    /// `tags @> ARRAY[$ctx]::TEXT[]`, requiring the pack's tags to include the
    /// specified runtime context string. When both `tag` and `target_context`
    /// are set, both `@>` clauses are ANDed (intersection of intersections),
    /// which Postgres resolves via the GIN index efficiently.
    ///
    /// # Tombstone exclusion mechanism
    ///
    /// Every query issued by this method (the plain DSL branches below and
    /// the raw-SQL helpers `search_raw` / `search_trending_raw`)
    /// unconditionally adds `latest_version IS NOT NULL` to its `WHERE`
    /// clause. `latest_version` is recomputed by `tombstone_pack` on every
    /// call to be the newest remaining `Active` version, or `NULL` when the
    /// pack has zero `Active` versions left. So a pack "falls out" of search
    /// exactly when its last `Active` version is tombstoned -- there is no
    /// separate per-version status check here, because `search_packs`
    /// operates on the `packs` head table, not `pack_versions`.
    ///
    /// NOTE: Large offsets degrade because Postgres must scan and skip rows.
    /// Keyset pagination would avoid that scan-and-skip cost.
    #[instrument(skip(self, filters))]
    async fn search_packs(
        &self,
        filters: &PackSearchFilters,
    ) -> Result<Vec<PackSearchResult>, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let limit_i = i64::from(filters.limit);
        let offset_i = i64::from(filters.offset);

        let rows: Vec<PackRow> = match (
            &filters.tag,
            &filters.target_context,
            &filters.author,
            &filters.query,
            &filters.extends,
        ) {
            (None, None, None, None, None) => match &filters.sort {
                SortMode::Trending => {
                    // Trending with no additional filters: LEFT JOIN a 7-day
                    // download count subquery and sort by it.
                    self.search_trending_raw(
                        TrendingParams {
                            tag: None,
                            target_context: None,
                            author: None,
                            query_text: None,
                            extends: None,
                            limit: limit_i,
                            offset: offset_i,
                        },
                        &mut conn,
                    )
                    .await?
                }
                SortMode::TopRated => packs::table
                    // Dead packs (zero Active versions) have latest_version
                    // cleared by tombstone_pack's head recompute; exclude them.
                    .filter(packs::latest_version.is_not_null())
                    .select(PackRow::as_select())
                    .order((packs::total_downloads.desc(), packs::name.asc()))
                    .limit(limit_i)
                    .offset(offset_i)
                    .load(&mut *conn)
                    .await
                    .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
                SortMode::Recent => packs::table
                    // See the TopRated arm above for why this filter exists.
                    .filter(packs::latest_version.is_not_null())
                    .select(PackRow::as_select())
                    .order((packs::created_at.desc(), packs::name.asc()))
                    .limit(limit_i)
                    .offset(offset_i)
                    .load(&mut *conn)
                    .await
                    .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            },
            _ => {
                // For combinations involving GIN tag, target_context, author, FTS,
                // or extends filters, use the appropriate raw-SQL helper.
                match &filters.sort {
                    SortMode::Trending => {
                        // Trending with additional filters: combine the WHERE
                        // clauses from the filter set with the 7-day join.
                        self.search_trending_raw(
                            TrendingParams {
                                tag: filters.tag.as_deref(),
                                target_context: filters.target_context.as_deref(),
                                author: filters.author.as_ref(),
                                query_text: filters.query.as_deref(),
                                extends: filters.extends.as_deref(),
                                limit: limit_i,
                                offset: offset_i,
                            },
                            &mut conn,
                        )
                        .await?
                    }
                    _ => {
                        // For combinations involving GIN tag, target_context, author, FTS,
                        // or extends filters, use the raw-SQL helper which binds params safely
                        // via numbered params.
                        self.search_raw(
                            SearchParams {
                                tag: filters.tag.as_deref(),
                                target_context: filters.target_context.as_deref(),
                                author: filters.author.as_ref(),
                                query_text: filters.query.as_deref(),
                                extends: filters.extends.as_deref(),
                                sort: &filters.sort,
                                limit: limit_i,
                                offset: offset_i,
                            },
                            &mut conn,
                        )
                        .await?
                    }
                }
            }
        };

        Ok(rows
            .into_iter()
            .filter_map(|r| r.into_record().ok())
            .map(|pack| PackSearchResult {
                pack,
                score: 1.0_f32,
            })
            .collect())
    }

    /// Increment the download counter for a specific pack.
    ///
    /// SQL shape:
    /// ```sql
    /// UPDATE packs SET total_downloads = total_downloads + 1
    ///   WHERE name = $1
    ///   RETURNING total_downloads
    /// ```
    /// Uses the primary key index on `packs(name)`. Returns `NotFound` when
    /// the specified version does not exist.
    #[instrument(skip(self, name, version), fields(pack = %name, version = %version))]
    async fn increment_download_counter(
        &self,
        name: &str,
        version: &str,
    ) -> Result<u64, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        // Verify the version exists before incrementing.
        let version_exists: bool = diesel::select(diesel::dsl::exists(
            pack_versions::table.filter(
                pack_versions::pack_name
                    .eq(name)
                    .and(pack_versions::version.eq(version)),
            ),
        ))
        .get_result(&mut *conn)
        .await
        .map_err(|e| map_diesel_error(e, "pack_version", format!("{name}@{version}")))?;

        if !version_exists {
            return Err(CatalogError::NotFound {
                kind: "pack_version",
                key: format!("{name}@{version}"),
            });
        }

        let new_count: i64 = diesel::update(packs::table.filter(packs::name.eq(name)))
            .set(packs::total_downloads.eq(packs::total_downloads + 1))
            .returning(packs::total_downloads)
            .get_result(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack", name.to_string()))?;

        Ok(new_count.max(0) as u64)
    }

    /// Mark a specific pack version as tombstoned and recompute the pack head.
    ///
    /// Executed inside a single transaction:
    /// 1. `UPDATE pack_versions SET status = $1 WHERE pack_name = $2 AND
    ///    version = $3`. The `status` column is set to the JSON serialisation
    ///    of `PackStatus::Tombstone { reason, recorded_at }`. No rows are
    ///    deleted; content-addressed retrieval by hash still works afterwards.
    /// 2. Every remaining version row for the pack is read back and its
    ///    `status` is deserialised. The `Active` versions are compared with
    ///    [`semver_gt`] (the same true-semver-precedence comparator used by
    ///    `register_pack_version`) to find the newest one.
    /// 3. `packs.latest_version` is set to that newest `Active` version, or to
    ///    `NULL` when no `Active` version remains -- this is what makes the
    ///    pack "disappear" from `search_packs` (see its doc for the
    ///    mechanism) while the version rows themselves stay queryable via
    ///    `get_pack_version` / `list_pack_versions` with their tombstoned
    ///    status visible.
    ///
    /// Re-tombstoning an already-tombstoned version is idempotent (last-writer
    /// wins). This differs from some adapters that return `Conflict` on
    /// re-tombstone; the choice here favors operational simplicity. The head
    /// recompute step still runs on every call, which is a harmless no-op when
    /// the newest `Active` version has not changed.
    #[instrument(skip(self, name, version, record), fields(pack = %name, version = %version))]
    async fn tombstone_pack(
        &self,
        name: &str,
        version: &str,
        record: TombstoneRecord,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let status = frameshift_catalog::PackStatus::Tombstone {
            reason: record.reason,
            recorded_at: record.recorded_at,
        };
        let status_json =
            serde_json::to_value(&status).map_err(|e| CatalogError::BackendError(Box::new(e)))?;

        let name_owned = name.to_string();
        let version_owned = version.to_string();

        // Same `TxError` wrapper pattern as `register_pack_version`: diesel-async's
        // `transaction` requires `E: From<diesel::result::Error>`, and `CatalogError`
        // is a cross-crate type we cannot implement that for directly.
        enum TxError {
            Catalog(CatalogError),
            Diesel(diesel::result::Error),
        }
        /// Required by `diesel_async::AsyncConnection::transaction`.
        impl From<diesel::result::Error> for TxError {
            /// Wrap a raw Diesel error in `TxError::Diesel` for transport
            /// through the transaction boundary.
            fn from(e: diesel::result::Error) -> Self {
                TxError::Diesel(e)
            }
        }

        use diesel_async::AsyncConnection as _;
        let tx_result = conn
            .transaction::<(), TxError, _>(async move |conn| {
                let pack_name = name_owned;
                let version = version_owned;

                let rows_affected = diesel::update(
                    pack_versions::table.filter(
                        pack_versions::pack_name
                            .eq(&pack_name)
                            .and(pack_versions::version.eq(&version)),
                    ),
                )
                .set(pack_versions::status.eq(status_json))
                .execute(conn)
                .await
                .map_err(|e| {
                    TxError::Catalog(map_diesel_error(
                        e,
                        "pack_version",
                        format!("{pack_name}@{version}"),
                    ))
                })?;

                if rows_affected == 0 {
                    return Err(TxError::Catalog(CatalogError::NotFound {
                        kind: "pack_version",
                        key: format!("{pack_name}@{version}"),
                    }));
                }

                // Recompute the head: read back every version's (version, status)
                // pair, keep the Active ones, and fold to find the newest by
                // true semver precedence (reuses `register_pack_version`'s
                // `semver_gt` rather than defining another comparator).
                let rows: Vec<(String, serde_json::Value)> = pack_versions::table
                    .filter(pack_versions::pack_name.eq(&pack_name))
                    .select((pack_versions::version, pack_versions::status))
                    .load(conn)
                    .await
                    .map_err(|e| {
                        TxError::Catalog(map_diesel_error(e, "pack_version", pack_name.clone()))
                    })?;

                let newest_active = rows
                    .into_iter()
                    .filter_map(|(v, status_json)| {
                        let status: frameshift_catalog::PackStatus =
                            serde_json::from_value(status_json).ok()?;
                        matches!(status, frameshift_catalog::PackStatus::Active).then_some(v)
                    })
                    .fold(None::<String>, |best, candidate| match best {
                        None => Some(candidate),
                        Some(cur) if semver_gt(&candidate, &cur) => Some(candidate),
                        Some(cur) => Some(cur),
                    });

                // A no-op when the pack head row does not exist (cannot happen
                // via the public API, since `register_pack_version` always
                // creates the head before a version can be tombstoned).
                diesel::update(packs::table.filter(packs::name.eq(&pack_name)))
                    .set(packs::latest_version.eq(newest_active))
                    .execute(conn)
                    .await
                    .map_err(|e| {
                        TxError::Catalog(map_diesel_error(e, "pack", pack_name.clone()))
                    })?;

                Ok(())
            })
            .await;

        match tx_result {
            Ok(()) => Ok(()),
            Err(TxError::Catalog(e)) => Err(e),
            Err(TxError::Diesel(e)) => Err(map_diesel_error(
                e,
                "pack_version",
                format!("{name}@{version}"),
            )),
        }
    }

    /// Retrieve the Ed25519 public key currently mapped to a handle.
    ///
    /// SQL shape:
    /// ```sql
    /// SELECT pubkey FROM handles WHERE handle = $1 LIMIT 1
    /// ```
    /// Uses the primary key index on `handles(handle)`.
    #[instrument(skip(self, handle), fields(handle = %handle))]
    async fn get_handle_pubkey(&self, handle: &str) -> Result<Ed25519PublicKey, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;
        let row: HandleRow = handles::table
            .filter(handles::handle.eq(handle))
            .select(HandleRow::as_select())
            .first(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "handle", handle.to_string()))?;
        vec_to_pubkey(row.pubkey)
    }

    /// Update the public key mapped to an existing handle.
    ///
    /// SQL shape:
    /// ```sql
    /// INSERT INTO handles (handle, pubkey) VALUES ($1, $2)
    ///   ON CONFLICT (handle) DO UPDATE SET pubkey = $2, updated_at = NOW()
    /// ```
    /// Uses the primary key index on `handles(handle)`. Upserts the row so
    /// that ownership can be transferred or established for the first time.
    ///
    /// The caller (HTTP server layer) MUST verify ownership before calling this
    /// method. The catalog does NOT verify that the caller controls the new key.
    #[instrument(skip(self, handle, pubkey), fields(handle = %handle))]
    async fn set_handle_pubkey(
        &self,
        handle: &str,
        pubkey: Ed25519PublicKey,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let new_row = NewHandleRow {
            handle: handle.to_string(),
            pubkey: pubkey.0.to_vec(),
        };

        let handle_key = handle.to_string();
        use diesel_async::AsyncConnection as _;
        let tx_result = conn
            .transaction::<(), CatalogTransactionError, _>(async move |conn| {
                diesel::sql_query(
                    "LOCK TABLE authors, handles, publisher_profiles \
                     IN SHARE ROW EXCLUSIVE MODE",
                )
                .execute(conn)
                .await?;
                let publisher_exists = publisher_profiles::table
                    .filter(publisher_profiles::handle.eq(&handle_key))
                    .select(publisher_profiles::id)
                    .first::<uuid::Uuid>(conn)
                    .await
                    .optional()?;
                if publisher_exists.is_some() {
                    return Err(CatalogTransactionError::Catalog(CatalogError::Conflict {
                        kind: "handle",
                        key: handle_key.clone(),
                    }));
                }
                diesel::insert_into(handles::table)
                    .values(&new_row)
                    .on_conflict(handles::handle)
                    .do_update()
                    .set((
                        handles::pubkey.eq(pubkey.0.to_vec()),
                        handles::updated_at.eq(Utc::now()),
                    ))
                    .execute(conn)
                    .await?;
                Ok(())
            })
            .await;
        match tx_result {
            Ok(()) => Ok(()),
            Err(CatalogTransactionError::Catalog(error)) => Err(error),
            Err(CatalogTransactionError::Diesel(error)) => {
                Err(map_diesel_error(error, "handle", handle.to_string()))
            }
        }
    }

    /// Set the `extends` field on the pack head record.
    ///
    /// SQL shape:
    /// ```sql
    /// UPDATE packs SET extends = $1 WHERE name = $2
    /// ```
    /// Uses the primary key index on `packs(name)`. Returns `NotFound` if the
    /// pack does not exist (0 rows affected).
    #[instrument(skip(self, pack_name, extends), fields(pack = %pack_name))]
    async fn set_pack_extends(
        &self,
        pack_name: &str,
        extends: Option<&str>,
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let rows_affected = diesel::sql_query("UPDATE packs SET extends = $1 WHERE name = $2")
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(
                extends.map(str::to_string),
            )
            .bind::<diesel::sql_types::Text, _>(pack_name.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack", pack_name.to_string()))?;

        if rows_affected == 0 {
            return Err(CatalogError::NotFound {
                kind: "pack",
                key: pack_name.to_string(),
            });
        }

        Ok(())
    }

    /// Set the `description` and `tags` columns on the pack head row.
    ///
    /// SQL shape:
    /// ```sql
    /// UPDATE packs SET description = $1, tags = $2 WHERE name = $3
    /// ```
    /// This is the catalog API for updating the pack metadata columns.
    async fn set_pack_metadata(
        &self,
        name: &str,
        description: &str,
        tags: &[String],
    ) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let rows_affected =
            diesel::sql_query("UPDATE packs SET description = $1, tags = $2 WHERE name = $3")
                .bind::<diesel::sql_types::Text, _>(description.to_string())
                .bind::<diesel::sql_types::Array<diesel::sql_types::Text>, _>(tags.to_vec())
                .bind::<diesel::sql_types::Text, _>(name.to_string())
                .execute(&mut *conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", name.to_string()))?;

        if rows_affected == 0 {
            return Err(CatalogError::NotFound {
                kind: "pack",
                key: name.to_string(),
            });
        }

        Ok(())
    }

    /// Record a single download event for the given pack version.
    ///
    /// SQL shape:
    /// ```sql
    /// INSERT INTO pack_downloads (pack_name, version) VALUES ($1, $2)
    /// ```
    /// The `downloaded_at` column defaults to `NOW()` at the DB level.
    /// This is best-effort: callers SHOULD log and discard errors rather than
    /// surfacing them to end users.
    #[instrument(skip(self, pack_name, version), fields(pack = %pack_name, version = %version))]
    async fn record_download(&self, pack_name: &str, version: &str) -> Result<(), CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let row = NewPackDownloadRow {
            pack_name: pack_name.to_string(),
            version: version.to_string(),
        };

        diesel::insert_into(pack_downloads::table)
            .values(&row)
            .execute(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "pack_download", pack_name.to_string()))?;

        Ok(())
    }

    /// Atomically claim a nonce in PostgreSQL so replays fail across instances.
    #[instrument(skip(self, pubkey, nonce), fields(signer = %pubkey))]
    async fn claim_signed_request_nonce(
        &self,
        pubkey: &Ed25519PublicKey,
        nonce: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, CatalogError> {
        let mut conn = self.pool.get().await.map_err(map_pool_error)?;

        let inserted = diesel::insert_into(signed_request_nonces::table)
            .values((
                signed_request_nonces::pubkey.eq(pubkey.0.to_vec()),
                signed_request_nonces::nonce.eq(nonce),
                signed_request_nonces::expires_at.eq(expires_at),
            ))
            .on_conflict_do_nothing()
            .execute(&mut *conn)
            .await
            .map_err(|e| map_diesel_error(e, "signed_request_nonce", nonce.to_string()))?;
        Ok(inserted == 1)
    }

    /// Return the current health status of this backend.
    ///
    /// Runs `SELECT 1` with a 1-second deadline. Returns `HealthStatus { healthy: true }`
    /// on success. Pool state (connection count, idle count) is included in `detail`.
    ///
    /// This method does NOT itself return `Err`; degraded states are returned
    /// as `Ok(HealthStatus { healthy: false, ... })`.
    #[instrument(skip(self))]
    async fn health(&self) -> Result<HealthStatus, CatalogError> {
        let checkout =
            tokio::time::timeout(std::time::Duration::from_secs(1), self.pool.get()).await;

        let state = self.pool.state();
        let detail = format!(
            "pool: connections={}, idle={}",
            state.connections, state.idle_connections
        );

        match checkout {
            Ok(Ok(mut conn)) => {
                let ping = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    diesel::sql_query("SELECT 1").execute(&mut *conn),
                )
                .await;
                match ping {
                    Ok(Ok(_)) => Ok(HealthStatus {
                        healthy: true,
                        detail,
                    }),
                    Ok(Err(e)) => {
                        error!("health check query failed: {e}");
                        Ok(HealthStatus {
                            healthy: false,
                            detail: format!("SELECT 1 failed: {e}; {detail}"),
                        })
                    }
                    Err(_) => Ok(HealthStatus {
                        healthy: false,
                        detail: format!("SELECT 1 timed out; {detail}"),
                    }),
                }
            }
            Ok(Err(e)) => {
                error!("health check pool checkout failed: {e}");
                Ok(HealthStatus {
                    healthy: false,
                    detail: format!("pool checkout failed: {e}; {detail}"),
                })
            }
            Err(_) => Ok(HealthStatus {
                healthy: false,
                detail: format!("pool checkout timed out; {detail}"),
            }),
        }
    }
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Number of seconds in 7 days, used as the trending window bound.
///
/// Expressed as a constant so the value is clearly documented and appears
/// only once in the SQL strings below (no user-supplied value; safe to embed).
const TRENDING_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Parameters for the trending raw query used in [`PostgresCatalog::search_trending_raw`].
///
/// All optional filter fields work identically to [`SearchParams`]; the sort
/// field is omitted because trending always sorts by 7-day download count DESC.
struct TrendingParams<'a> {
    /// Tag containment filter; `None` means no tag filter.
    pub tag: Option<&'a str>,
    /// Target context filter; `None` means no context filter.
    pub target_context: Option<&'a str>,
    /// Author pubkey filter; `None` means no author filter.
    pub author: Option<&'a Ed25519PublicKey>,
    /// Full-text search query; `None` means no FTS filter.
    pub query_text: Option<&'a str>,
    /// Base persona pack name filter; `None` means no extends filter.
    pub extends: Option<&'a str>,
    /// Maximum number of results (SQL LIMIT).
    pub limit: i64,
    /// Number of results to skip (SQL OFFSET).
    pub offset: i64,
}

/// Parameters for the raw search query used inside [`PostgresCatalog::search_raw`].
///
/// Bundles optional filter values with pagination to stay within clippy's
/// function argument limit (max 7). All `Option` fields default to no filter.
struct SearchParams<'a> {
    /// Tag containment filter; `None` means no tag filter.
    pub tag: Option<&'a str>,
    /// Target context filter; `None` means no context filter.
    ///
    /// When set, adds `tags @> ARRAY[$ctx]::TEXT[]` (array containment)
    /// to the WHERE clause. If both `tag` and `target_context` are set, both
    /// containment clauses are ANDed (intersection of intersections).
    pub target_context: Option<&'a str>,
    /// Author pubkey filter; `None` means no author filter.
    pub author: Option<&'a Ed25519PublicKey>,
    /// Full-text search query; `None` means no FTS filter.
    pub query_text: Option<&'a str>,
    /// Base persona pack name filter; `None` means no extends filter.
    ///
    /// When set, adds `extends = $n` to the WHERE clause so only packs that
    /// extend the named base pack are returned.
    pub extends: Option<&'a str>,
    /// Sort mode to apply.
    pub sort: &'a SortMode,
    /// Maximum number of results (SQL LIMIT).
    pub limit: i64,
    /// Number of results to skip (SQL OFFSET).
    pub offset: i64,
}

/// Private search helpers for [`PostgresCatalog`].
impl PostgresCatalog {
    /// Execute the search query with variable optional filters using raw SQL
    /// with numbered bind parameters.
    ///
    /// Used by `search_packs` for combinations involving GIN tag containment,
    /// author filter, or FTS query text. All user-supplied values are bound via
    /// Diesel's typed bind API; no string interpolation of user values occurs.
    ///
    /// The eight filter combinations (tag x author x query) are enumerated
    /// explicitly so that each call site has fully typed binds -- Diesel's
    /// `sql_query` bind API changes the type at each `.bind()` call, requiring
    /// the full chain to be spelled out statically.
    async fn search_raw(
        &self,
        params: SearchParams<'_>,
        conn: &mut bb8::PooledConnection<
            '_,
            diesel_async::pooled_connection::AsyncDieselConnectionManager<
                diesel_async::AsyncPgConnection,
            >,
        >,
    ) -> Result<Vec<PackRow>, CatalogError> {
        let SearchParams {
            tag,
            target_context,
            author,
            query_text,
            extends,
            sort,
            limit,
            offset,
        } = params;
        let mut bind_idx: usize = 1;
        // `latest_version IS NOT NULL` is unconditional (a literal, not a bind
        // parameter) so it does not shift `bind_idx`. It excludes dead packs
        // (zero Active versions -- see search_packs's doc for the mechanism)
        // from every filtered search, matching the plain-DSL branches in
        // `search_packs` for the unfiltered case.
        let mut where_parts: Vec<String> = vec!["latest_version IS NOT NULL".to_string()];

        if tag.is_some() {
            where_parts.push(format!("tags @> ARRAY[${bind_idx}]::TEXT[]"));
            bind_idx += 1;
        }
        if target_context.is_some() {
            where_parts.push(format!("tags @> ARRAY[${bind_idx}]::TEXT[]"));
            bind_idx += 1;
        }
        if author.is_some() {
            where_parts.push(format!("current_author = ${bind_idx}"));
            bind_idx += 1;
        }
        let fts_param_idx: Option<usize> = if query_text.is_some() {
            let idx = bind_idx;
            where_parts.push(format!(
                "to_tsvector('english', description || ' ' || name) \
                 @@ plainto_tsquery('english', ${idx})"
            ));
            bind_idx += 1;
            Some(idx)
        } else {
            None
        };
        if extends.is_some() {
            where_parts.push(format!("extends = ${bind_idx}"));
            bind_idx += 1;
        }

        // `where_parts` always has at least the latest_version clause above.
        let where_sql = format!("WHERE {}", where_parts.join(" AND "));

        let order_sql = match sort {
            SortMode::TopRated | SortMode::Trending => "ORDER BY total_downloads DESC, name ASC",
            SortMode::Recent => "ORDER BY created_at DESC, name ASC",
        };

        let limit_idx = bind_idx;
        let offset_idx = bind_idx + 1;

        // The FTS parameter index was embedded in `where_parts` above.
        let _ = fts_param_idx;

        let sql = format!(
            "SELECT name, current_author, publisher_id, tags, description, created_at, \
             latest_version, total_downloads, extends \
             FROM packs \
             {where_sql} \
             {order_sql} \
             LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        // Enumerate all 32 filter combinations (tag x target_context x author x query x extends)
        // to satisfy Diesel's static typing for bind parameters.
        // Bind order: tag, target_context, author, query_text, extends, limit, offset.
        let rows: Vec<PackRow> = match (tag, target_context, author, query_text, extends) {
            (None, None, None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
        };

        Ok(rows)
    }

    /// Execute the trending search query, ranking packs by 7-day download count.
    ///
    /// The query LEFT JOINs a `pack_downloads` subquery that counts rows with
    /// `downloaded_at >= NOW() - INTERVAL '7 days'` grouped by `pack_name`.
    /// Results are ordered by that count DESC with `name ASC` as the tiebreaker.
    ///
    /// Optional WHERE filters (tag, target_context, author, FTS, extends) are
    /// ANDed in exactly as in [`search_raw`]. All user-supplied values are bound
    /// via Diesel's typed bind API; the 7-day interval is a constant embedded
    /// as a literal `$n` parameter (not string-interpolated user input).
    ///
    /// Because the filter combinations expand to 32 static branches (matching
    /// the enumeration in `search_raw`), the bind chains are spelled out
    /// explicitly to satisfy Diesel's static type system.
    async fn search_trending_raw(
        &self,
        params: TrendingParams<'_>,
        conn: &mut bb8::PooledConnection<
            '_,
            diesel_async::pooled_connection::AsyncDieselConnectionManager<
                diesel_async::AsyncPgConnection,
            >,
        >,
    ) -> Result<Vec<PackRow>, CatalogError> {
        let TrendingParams {
            tag,
            target_context,
            author,
            query_text,
            extends,
            limit,
            offset,
        } = params;

        // Build numbered WHERE clauses for optional filters.
        // Bind order matches the branch arms below: tag, target_context, author,
        // query_text, extends. The window interval is bound last before limit/offset.
        let mut bind_idx: usize = 1;
        // `p.latest_version IS NOT NULL` is unconditional (a literal, not a bind
        // parameter) so it does not shift `bind_idx`. It excludes dead packs
        // (zero Active versions -- see search_packs's doc for the mechanism)
        // from every trending search, filtered or not.
        let mut where_parts: Vec<String> = vec!["p.latest_version IS NOT NULL".to_string()];

        if tag.is_some() {
            where_parts.push(format!("p.tags @> ARRAY[${bind_idx}]::TEXT[]"));
            bind_idx += 1;
        }
        if target_context.is_some() {
            where_parts.push(format!("p.tags @> ARRAY[${bind_idx}]::TEXT[]"));
            bind_idx += 1;
        }
        if author.is_some() {
            where_parts.push(format!("p.current_author = ${bind_idx}"));
            bind_idx += 1;
        }
        if query_text.is_some() {
            where_parts.push(format!(
                "to_tsvector('english', p.description || ' ' || p.name) \
                 @@ plainto_tsquery('english', ${bind_idx})"
            ));
            bind_idx += 1;
        }
        if extends.is_some() {
            where_parts.push(format!("p.extends = ${bind_idx}"));
            bind_idx += 1;
        }

        // `where_parts` always has at least the latest_version clause above.
        let where_sql = format!("WHERE {}", where_parts.join(" AND "));

        // The subquery interval bound index comes after all filter params.
        let interval_idx = bind_idx;
        let limit_idx = bind_idx + 1;
        let offset_idx = bind_idx + 2;

        // The trending subquery counts pack_downloads rows within the rolling window.
        // `make_interval(secs => $n)` is used instead of string-interpolated INTERVAL
        // so the window duration is a bound parameter (even though it is a constant,
        // keeping it bound makes the pattern consistent with user values above).
        let sql = format!(
            "SELECT p.name, p.current_author, p.publisher_id, p.tags, p.description, p.created_at, \
             p.latest_version, p.total_downloads, p.extends \
             FROM packs p \
             LEFT JOIN ( \
                 SELECT pack_name, COUNT(*) AS dl_count \
                 FROM pack_downloads \
                 WHERE downloaded_at >= NOW() - make_interval(secs => ${interval_idx}) \
                 GROUP BY pack_name \
             ) td ON td.pack_name = p.name \
             {where_sql} \
             ORDER BY COALESCE(td.dl_count, 0) DESC, p.name ASC \
             LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        // Enumerate all 32 filter combinations so each call site has fully typed
        // bind chains. Bind order: tag, target_context, author, query_text, extends,
        // interval_seconds, limit, offset.
        let rows: Vec<PackRow> = match (tag, target_context, author, query_text, extends) {
            (None, None, None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), None, None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, None, Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), Some(q), None) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), None, Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), None, Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), None, Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (None, Some(ctx), Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
            (Some(t), Some(ctx), Some(a), Some(q), Some(ext)) => diesel::sql_query(&sql)
                .bind::<diesel::sql_types::Text, _>(t)
                .bind::<diesel::sql_types::Text, _>(ctx)
                .bind::<diesel::sql_types::Binary, _>(a.0.to_vec())
                .bind::<diesel::sql_types::Text, _>(q)
                .bind::<diesel::sql_types::Text, _>(ext)
                .bind::<diesel::sql_types::BigInt, _>(TRENDING_WINDOW_SECONDS)
                .bind::<diesel::sql_types::BigInt, _>(limit)
                .bind::<diesel::sql_types::BigInt, _>(offset)
                .load(&mut **conn)
                .await
                .map_err(|e| map_diesel_error(e, "pack", String::new()))?,
        };

        Ok(rows)
    }
}

// ── Semver comparison helper ────────────────────────────────────────────────

/// Parse a semver string into `(major, minor, patch, pre_release)`.
///
/// Build metadata (the `+` suffix per semver 2.0.0 §10) is stripped and
/// ignored. Pre-release is everything after the first `-` in the core
/// version string. Returns `None` when the input cannot be parsed as a valid
/// `major.minor.patch` triple.
fn parse_semver(s: &str) -> Option<(u64, u64, u64, Option<String>)> {
    // Strip build metadata suffix (e.g. "+build.1").
    let without_build = s.split('+').next().unwrap_or(s);

    // Split off optional pre-release suffix (e.g. "-rc.1").
    let (core, pre) = if let Some(idx) = without_build.find('-') {
        let (c, p) = without_build.split_at(idx);
        // `p` starts with '-'; drop that leading byte.
        (c, Some(p[1..].to_string()))
    } else {
        (without_build, None)
    };

    // Parse the three numeric components.
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let major = parts[0].parse::<u64>().ok()?;
    let minor = parts[1].parse::<u64>().ok()?;
    let patch = parts[2].parse::<u64>().ok()?;

    Some((major, minor, patch, pre))
}

/// Compare two dot-separated pre-release identifiers per semver 2.0.0 §11
/// rule 4: purely-numeric identifiers compare numerically; a numeric
/// identifier always has LOWER precedence than an alphanumeric one; two
/// alphanumeric identifiers compare using ASCII lexical (byte) ordering.
///
/// An identifier is treated as numeric only when it parses in full as a
/// `u64` (so e.g. `"01"` or `"1a"` are alphanumeric, matching the spec's
/// "identifiers MUST comprise only ASCII alphanumerics" / numeric-only
/// distinction).
fn compare_prerelease_identifier(x: &str, y: &str) -> std::cmp::Ordering {
    match (x.parse::<u64>().ok(), y.parse::<u64>().ok()) {
        (Some(xn), Some(yn)) => xn.cmp(&yn),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => x.cmp(y),
    }
}

/// Compare two full pre-release strings (the part after the first `-`) per
/// semver 2.0.0 §11 rule 4: split on `.`, compare identifier-by-identifier
/// via [`compare_prerelease_identifier`], and -- if every shared identifier
/// is equal -- the pre-release with MORE identifiers has higher precedence
/// (e.g. `1.0.0-alpha` < `1.0.0-alpha.1`).
fn compare_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    let a_ids: Vec<&str> = a.split('.').collect();
    let b_ids: Vec<&str> = b.split('.').collect();
    for i in 0..a_ids.len().max(b_ids.len()) {
        match (a_ids.get(i), b_ids.get(i)) {
            (Some(x), Some(y)) => {
                let ord = compare_prerelease_identifier(x, y);
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            // `a` has more identifiers than `b` (all preceding equal) -- `a` wins.
            (Some(_), None) => return std::cmp::Ordering::Greater,
            // `b` has more identifiers than `a` (all preceding equal) -- `b` wins.
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => unreachable!("loop bound is max(a_ids.len(), b_ids.len())"),
        }
    }
    std::cmp::Ordering::Equal
}

/// Return `true` when `a` has strictly higher semver precedence than `b`.
///
/// Rules (per semver 2.0.0 §11):
/// - Compare major, minor, patch as unsigned integers in order.
/// - A release version (no pre-release suffix) has HIGHER precedence than the
///   same `(major, minor, patch)` with a pre-release tag.
///   Example: `1.0.0 > 1.0.0-rc.1`.
/// - When both have a pre-release tag and the numeric triple is equal, the
///   tags are compared per [`compare_prerelease`] (numeric-aware,
///   dot-identifier precedence -- e.g. `1.0.0-beta.10 > 1.0.0-beta.9`).
///
/// Unparseable versions are treated as lower than any parseable version.
/// If both sides are unparseable, returns `false` (not strictly greater).
///
/// `pub` (not `pub(crate)`) so that other in-workspace `CatalogBackend`
/// implementations -- notably the in-memory mock used by
/// `frameshift-server`'s integration tests -- can recompute a pack head's
/// `latest_version` using the exact same ordering `register_pack_version`
/// and `tombstone_pack` use here, instead of reimplementing (and risking
/// drift from) the comparator.
pub fn semver_gt(a: &str, b: &str) -> bool {
    match (parse_semver(a), parse_semver(b)) {
        // `a` is unparseable -- can never be greater.
        (None, _) => false,
        // `b` is unparseable but `a` is valid -- `a` wins.
        (Some(_), None) => true,
        (Some((ma, mia, pa, pre_a)), Some((mb, mib, pb, pre_b))) => {
            // Numeric major/minor/patch comparison.
            if ma != mb {
                return ma > mb;
            }
            if mia != mib {
                return mia > mib;
            }
            if pa != pb {
                return pa > pb;
            }
            // Same numeric triple -- compare pre-release presence.
            // Release (None) > pre-release (Some) per semver.
            match (pre_a, pre_b) {
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (None, None) => false,
                (Some(pa_str), Some(pb_str)) => {
                    compare_prerelease(&pa_str, &pb_str) == std::cmp::Ordering::Greater
                }
            }
        }
    }
}

#[cfg(test)]
/// Unit tests for the semver comparison helper.
mod semver_tests {
    use super::semver_gt;

    #[test]
    /// 1.10.0 must compare as greater than 1.9.0 (fails under lexicographic ordering).
    fn semver_gt_minor_numeric() {
        assert!(semver_gt("1.10.0", "1.9.0"), "1.10.0 should be > 1.9.0");
    }

    #[test]
    /// 1.0.0 (release) must compare as greater than 1.0.0-rc.1 (pre-release).
    fn semver_gt_release_over_prerelease() {
        assert!(
            semver_gt("1.0.0", "1.0.0-rc.1"),
            "1.0.0 should be > 1.0.0-rc.1"
        );
    }

    #[test]
    /// A version is not greater than itself.
    fn semver_gt_equal_returns_false() {
        assert!(!semver_gt("1.2.3", "1.2.3"));
    }

    #[test]
    /// A larger major wins regardless of minor and patch.
    fn semver_gt_major() {
        assert!(semver_gt("2.0.0", "1.99.99"));
    }

    #[test]
    /// A larger patch wins when major and minor are equal.
    fn semver_gt_patch() {
        assert!(semver_gt("1.2.4", "1.2.3"));
    }

    #[test]
    /// Two identical pre-release strings are not strictly greater.
    fn semver_gt_prerelease_equal_returns_false() {
        assert!(!semver_gt("1.0.0-alpha", "1.0.0-alpha"));
    }

    #[test]
    /// Build metadata suffix is stripped and does not affect comparison.
    fn semver_gt_build_metadata_stripped() {
        assert!(!semver_gt("1.0.0+build.1", "1.0.0+build.2"));
    }

    #[test]
    /// Numeric pre-release identifiers must compare numerically, not
    /// lexically: `beta.10` outranks `beta.9` (regression for F-18).
    fn semver_gt_prerelease_numeric_identifier() {
        assert!(
            semver_gt("1.0.0-beta.10", "1.0.0-beta.9"),
            "1.0.0-beta.10 should be > 1.0.0-beta.9"
        );
    }

    #[test]
    /// The reverse of the above must hold too: `beta.2` does not outrank
    /// `beta.10` under numeric comparison.
    fn semver_gt_prerelease_numeric_identifier_reverse() {
        assert!(
            !semver_gt("1.0.0-beta.2", "1.0.0-beta.10"),
            "1.0.0-beta.2 should not be > 1.0.0-beta.10"
        );
    }

    #[test]
    /// Fewer pre-release identifiers means lower precedence when all
    /// shared identifiers are equal: `alpha` < `alpha.1`.
    fn semver_gt_prerelease_shorter_identifier_list_loses() {
        assert!(
            !semver_gt("1.0.0-alpha", "1.0.0-alpha.1"),
            "1.0.0-alpha should not be > 1.0.0-alpha.1"
        );
        assert!(
            semver_gt("1.0.0-alpha.1", "1.0.0-alpha"),
            "1.0.0-alpha.1 should be > 1.0.0-alpha"
        );
    }

    #[test]
    /// A release version still outranks any pre-release at the same
    /// major.minor.patch, even with numeric-aware pre-release comparison.
    fn semver_gt_release_over_prerelease_numeric() {
        assert!(
            semver_gt("1.0.0", "1.0.0-rc.1"),
            "1.0.0 should be > 1.0.0-rc.1"
        );
    }

    #[test]
    /// Numeric identifiers have lower precedence than alphanumeric ones
    /// per semver 2.0.0 §11 rule 4: `beta.11` (numeric second identifier)
    /// is outranked by `beta.rc1` (alphanumeric second identifier).
    fn semver_gt_prerelease_numeric_below_alphanumeric() {
        assert!(
            !semver_gt("1.0.0-beta.11", "1.0.0-beta.rc1"),
            "1.0.0-beta.11 should not be > 1.0.0-beta.rc1 (numeric < alphanumeric)"
        );
        assert!(
            semver_gt("1.0.0-beta.rc1", "1.0.0-beta.11"),
            "1.0.0-beta.rc1 should be > 1.0.0-beta.11 (alphanumeric > numeric)"
        );
    }
}
