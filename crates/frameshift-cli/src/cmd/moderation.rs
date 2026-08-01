//! Human-operated publication moderation and promotion commands.
//!
//! The CLI reuses the authenticated account session for the exact registry.
//! Authorization, independent-review separation, state transitions, and
//! promotion integrity remain enforced by the server.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use clap::{Args, Subcommand, ValueEnum};
use frameshift_catalog::{
    PublicationAppealCursor, PublicationAppealDisposition, PublicationLifecycleCursor,
    PublicationModerationAction, TombstoneReason,
};
use frameshift_client::moderation::{
    get_moderation_artifact, get_moderation_submission, list_administrator_publication_appeals,
    list_administrator_publication_decisions, moderate_publication_submission,
    promote_publication_submission, resolve_administrator_publication_appeal,
    suspend_publication_publisher, tombstone_publication_release,
};
use uuid::Uuid;

use crate::cmd::keys::resolve_access_token;
use crate::util::{validate_server_url, CliError};

/// Arguments for the `moderation` command group.
#[derive(Debug, Args)]
pub struct ModerationArgs {
    /// Moderation operation to execute.
    #[command(subcommand)]
    pub command: ModerationCommand,
}

/// Supported role-gated publication moderation operations.
#[derive(Debug, Subcommand)]
pub enum ModerationCommand {
    /// Display one quarantined submission and its server validation report.
    Show {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Stable submission UUID returned to the publisher.
        #[arg(long)]
        submission_id: Uuid,
    },
    /// Download one exact quarantine artifact without overwriting an existing file.
    Artifact {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Stable submission UUID returned to the publisher.
        #[arg(long)]
        submission_id: Uuid,
        /// New destination path for the reviewed `.tar.gz` archive.
        #[arg(long)]
        out: PathBuf,
    },
    /// Apply one review decision to a quarantined submission.
    Decide {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Stable submission UUID returned to the publisher.
        #[arg(long)]
        submission_id: Uuid,
        /// Review action to apply.
        #[arg(long, value_enum)]
        action: ModerationActionArg,
        /// Stable bounded private reason code.
        #[arg(long)]
        reason_code: String,
        /// Optional bounded private explanation for the publisher.
        #[arg(long)]
        private_explanation: Option<String>,
        /// Stable decision UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        decision_id: Option<Uuid>,
        /// Stable request UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    /// Promote one approved submission into the public registry.
    Promote {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Approved submission UUID.
        #[arg(long)]
        submission_id: Uuid,
        /// Stable promotion UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        promotion_id: Option<Uuid>,
        /// Stable request UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    /// Suspend one approved publisher under administrator authority.
    SuspendPublisher {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Stable publisher profile UUID.
        #[arg(long)]
        publisher_id: Uuid,
        /// Stable 1-64 character private reason code.
        #[arg(long)]
        reason_code: String,
        /// Stable decision UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        decision_id: Option<Uuid>,
        /// Stable request UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    /// Tombstone one active public release under administrator authority.
    Tombstone {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Public pack name.
        #[arg(long)]
        name: String,
        /// Exact public semantic version.
        #[arg(long)]
        version: String,
        /// Closed public takedown reason category.
        #[arg(long, value_enum)]
        reason: TombstoneReasonArg,
        /// Stable decision UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        decision_id: Option<Uuid>,
        /// Stable request UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    /// List global immutable publication lifecycle evidence.
    Decisions {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// RFC 3339 timestamp from the final record of the preceding page.
        #[arg(long, requires = "before_id")]
        before_created_at: Option<DateTime<Utc>>,
        /// UUID from the final record of the preceding page.
        #[arg(long, requires = "before_created_at")]
        before_id: Option<Uuid>,
        /// Number of newest-first records to return.
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
    },
    /// List global private publication appeal cases.
    Appeals {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// RFC 3339 timestamp from the final record of the preceding page.
        #[arg(long, requires = "before_id")]
        before_created_at: Option<DateTime<Utc>>,
        /// UUID from the final record of the preceding page.
        #[arg(long, requires = "before_created_at")]
        before_id: Option<Uuid>,
        /// Number of newest-first appeal cases to return.
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
    },
    /// Resolve one publication appeal under administrator separation enforcement.
    ResolveAppeal {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Stable appeal UUID.
        #[arg(long)]
        appeal_id: Uuid,
        /// Final appeal disposition.
        #[arg(long, value_enum)]
        disposition: AppealDispositionArg,
        /// Private administrator rationale of at most 4000 characters.
        #[arg(long)]
        rationale: String,
        /// Audited reason for an unavoidable sole-administrator self-resolution.
        #[arg(long)]
        separation_exception_reason: Option<String>,
        /// Stable resolution UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        resolution_id: Option<Uuid>,
        /// Stable request UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        request_id: Option<Uuid>,
    },
}

/// CLI spelling for the server's supported moderation actions.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ModerationActionArg {
    /// Approve the exact reviewed artifact without making it public yet.
    Approve,
    /// Keep the artifact private and request a replacement submission.
    RequestChanges,
    /// Reject the exact reviewed artifact.
    Reject,
}

/// Convert the CLI action spelling into the shared wire action.
impl From<ModerationActionArg> for PublicationModerationAction {
    /// Map one CLI action to the catalog wire enum without changing semantics.
    fn from(value: ModerationActionArg) -> Self {
        match value {
            ModerationActionArg::Approve => Self::Approve,
            ModerationActionArg::RequestChanges => Self::RequestChanges,
            ModerationActionArg::Reject => Self::Reject,
        }
    }
}

/// CLI spelling for the closed public release tombstone reasons.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TombstoneReasonArg {
    /// The pack author requested removal.
    AuthorRequest,
    /// The pack violated platform terms of service.
    TosViolation,
    /// A DMCA takedown notice requires removal.
    Dmca,
}

/// Convert a CLI tombstone reason into the shared wire enum.
impl From<TombstoneReasonArg> for TombstoneReason {
    /// Preserve the selected public reason category exactly.
    fn from(value: TombstoneReasonArg) -> Self {
        match value {
            TombstoneReasonArg::AuthorRequest => Self::AuthorRequest,
            TombstoneReasonArg::TosViolation => Self::TosViolation,
            TombstoneReasonArg::Dmca => Self::Dmca,
        }
    }
}

/// CLI spelling for administrator appeal dispositions.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AppealDispositionArg {
    /// Preserve the original adverse decision.
    Uphold,
    /// Reverse the adverse decision and approve the unchanged submission.
    Overturn,
}

/// Convert a CLI appeal disposition into the shared wire enum.
impl From<AppealDispositionArg> for PublicationAppealDisposition {
    /// Preserve the selected appeal outcome exactly.
    fn from(value: AppealDispositionArg) -> Self {
        match value {
            AppealDispositionArg::Uphold => Self::Uphold,
            AppealDispositionArg::Overturn => Self::Overturn,
        }
    }
}

/// Execute one role-gated moderation operation.
pub fn run_moderation(args: ModerationArgs) -> Result<(), CliError> {
    match args.command {
        ModerationCommand::Show {
            server,
            submission_id,
        } => show(&server, submission_id),
        ModerationCommand::Artifact {
            server,
            submission_id,
            out,
        } => artifact(&server, submission_id, &out),
        ModerationCommand::Decide {
            server,
            submission_id,
            action,
            reason_code,
            private_explanation,
            decision_id,
            request_id,
        } => decide(
            &server,
            submission_id,
            action,
            &reason_code,
            private_explanation.as_deref(),
            decision_id,
            request_id,
        ),
        ModerationCommand::Promote {
            server,
            submission_id,
            promotion_id,
            request_id,
        } => promote(&server, submission_id, promotion_id, request_id),
        ModerationCommand::SuspendPublisher {
            server,
            publisher_id,
            reason_code,
            decision_id,
            request_id,
        } => suspend_publisher(&server, publisher_id, &reason_code, decision_id, request_id),
        ModerationCommand::Tombstone {
            server,
            name,
            version,
            reason,
            decision_id,
            request_id,
        } => tombstone_release(&server, &name, &version, reason, decision_id, request_id),
        ModerationCommand::Decisions {
            server,
            before_created_at,
            before_id,
            limit,
        } => administrator_decisions(
            &server,
            lifecycle_cursor(before_created_at, before_id)?,
            limit,
        ),
        ModerationCommand::Appeals {
            server,
            before_created_at,
            before_id,
            limit,
        } => administrator_appeals(&server, appeal_cursor(before_created_at, before_id)?, limit),
        ModerationCommand::ResolveAppeal {
            server,
            appeal_id,
            disposition,
            rationale,
            separation_exception_reason,
            resolution_id,
            request_id,
        } => resolve_appeal(
            &server,
            appeal_id,
            disposition,
            &rationale,
            separation_exception_reason.as_deref(),
            resolution_id,
            request_id,
        ),
    }
}

/// Print one role-gated submission record as structured JSON.
fn show(server: &str, submission_id: Uuid) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let submission = get_moderation_submission(server, &token, submission_id)?;
    println!("{}", serde_json::to_string_pretty(&submission)?);
    Ok(())
}

/// Download one bounded quarantine artifact to a new atomic destination.
fn artifact(server: &str, submission_id: Uuid, out: &Path) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let bytes = get_moderation_artifact(server, &token, submission_id)?;
    persist_artifact(out, &bytes)?;
    println!("saved reviewed artifact to {}", out.display());
    Ok(())
}

/// Apply one decision while preserving stable retry identifiers in failures.
#[allow(clippy::too_many_arguments)]
fn decide(
    server: &str,
    submission_id: Uuid,
    action: ModerationActionArg,
    reason_code: &str,
    private_explanation: Option<&str>,
    decision_id: Option<Uuid>,
    request_id: Option<Uuid>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let decision_id = decision_id.unwrap_or_else(Uuid::new_v4);
    let request_id = request_id.unwrap_or_else(Uuid::new_v4);
    let decision = moderate_publication_submission(
        server,
        &token,
        submission_id,
        decision_id,
        request_id,
        action.into(),
        reason_code,
        private_explanation,
    )
    .map_err(|error| {
        mutation_error(
            "moderation decision",
            "decision-id",
            error,
            decision_id,
            request_id,
        )
    })?;
    println!("{}", serde_json::to_string_pretty(&decision)?);
    Ok(())
}

/// Promote one approved submission while preserving retry identifiers in failures.
fn promote(
    server: &str,
    submission_id: Uuid,
    promotion_id: Option<Uuid>,
    request_id: Option<Uuid>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let promotion_id = promotion_id.unwrap_or_else(Uuid::new_v4);
    let request_id = request_id.unwrap_or_else(Uuid::new_v4);
    let promotion =
        promote_publication_submission(server, &token, submission_id, promotion_id, request_id)
            .map_err(|error| {
                mutation_error(
                    "publication promotion",
                    "promotion-id",
                    error,
                    promotion_id,
                    request_id,
                )
            })?;
    println!("{}", serde_json::to_string_pretty(&promotion)?);
    Ok(())
}

/// Suspend one publisher while preserving stable retry identifiers in failures.
fn suspend_publisher(
    server: &str,
    publisher_id: Uuid,
    reason_code: &str,
    decision_id: Option<Uuid>,
    request_id: Option<Uuid>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let decision_id = decision_id.unwrap_or_else(Uuid::new_v4);
    let request_id = request_id.unwrap_or_else(Uuid::new_v4);
    let record = suspend_publication_publisher(
        server,
        &token,
        publisher_id,
        decision_id,
        request_id,
        reason_code,
    )
    .map_err(|error| {
        mutation_error(
            "publisher suspension",
            "decision-id",
            error,
            decision_id,
            request_id,
        )
    })?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

/// Tombstone one release while preserving stable retry identifiers in failures.
fn tombstone_release(
    server: &str,
    name: &str,
    version: &str,
    reason: TombstoneReasonArg,
    decision_id: Option<Uuid>,
    request_id: Option<Uuid>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let decision_id = decision_id.unwrap_or_else(Uuid::new_v4);
    let request_id = request_id.unwrap_or_else(Uuid::new_v4);
    let record = tombstone_publication_release(
        server,
        &token,
        name,
        version,
        decision_id,
        request_id,
        reason.into(),
    )
    .map_err(|error| {
        mutation_error(
            "release tombstone",
            "decision-id",
            error,
            decision_id,
            request_id,
        )
    })?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

/// Print one bounded newest-first page of global lifecycle decisions.
fn administrator_decisions(
    server: &str,
    before: Option<PublicationLifecycleCursor>,
    limit: u32,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let records = list_administrator_publication_decisions(server, &token, before, limit)?;
    println!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}

/// Print one bounded newest-first page of global private appeal cases.
fn administrator_appeals(
    server: &str,
    before: Option<PublicationAppealCursor>,
    limit: u32,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let records = list_administrator_publication_appeals(server, &token, before, limit)?;
    println!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}

/// Resolve one appeal while preserving stable retry identifiers in failures.
#[allow(clippy::too_many_arguments)]
fn resolve_appeal(
    server: &str,
    appeal_id: Uuid,
    disposition: AppealDispositionArg,
    rationale: &str,
    separation_exception_reason: Option<&str>,
    resolution_id: Option<Uuid>,
    request_id: Option<Uuid>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let resolution_id = resolution_id.unwrap_or_else(Uuid::new_v4);
    let request_id = request_id.unwrap_or_else(Uuid::new_v4);
    let record = resolve_administrator_publication_appeal(
        server,
        &token,
        appeal_id,
        resolution_id,
        request_id,
        disposition.into(),
        rationale,
        separation_exception_reason,
    )
    .map_err(|error| {
        mutation_error(
            "appeal resolution",
            "resolution-id",
            error,
            resolution_id,
            request_id,
        )
    })?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

/// Construct a lifecycle cursor after Clap has enforced paired flags.
fn lifecycle_cursor(
    created_at: Option<DateTime<Utc>>,
    id: Option<Uuid>,
) -> Result<Option<PublicationLifecycleCursor>, CliError> {
    match (created_at, id) {
        (None, None) => Ok(None),
        (Some(created_at), Some(id)) => Ok(Some(PublicationLifecycleCursor { created_at, id })),
        _ => Err(CliError::Moderation(
            "--before-created-at and --before-id must be supplied together".to_string(),
        )),
    }
}

/// Construct an appeal cursor after Clap has enforced paired flags.
fn appeal_cursor(
    created_at: Option<DateTime<Utc>>,
    id: Option<Uuid>,
) -> Result<Option<PublicationAppealCursor>, CliError> {
    match (created_at, id) {
        (None, None) => Ok(None),
        (Some(created_at), Some(id)) => Ok(Some(PublicationAppealCursor { created_at, id })),
        _ => Err(CliError::Moderation(
            "--before-created-at and --before-id must be supplied together".to_string(),
        )),
    }
}

/// Persist artifact bytes atomically while refusing an existing destination.
fn persist_artifact(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        CliError::Moderation(format!(
            "failed to create artifact staging file beside {}: {error}",
            path.display()
        ))
    })?;
    temporary.write_all(bytes).map_err(|error| {
        CliError::Moderation(format!(
            "failed to write artifact staging file beside {}: {error}",
            path.display()
        ))
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        CliError::Moderation(format!(
            "failed to sync artifact staging file beside {}: {error}",
            path.display()
        ))
    })?;
    temporary.persist_noclobber(path).map_err(|error| {
        CliError::Moderation(format!(
            "refusing to overwrite artifact destination {}: {}",
            path.display(),
            error.error
        ))
    })?;
    Ok(())
}

/// Preserve both mutation identifiers so an ambiguous request can be retried exactly.
fn mutation_error(
    stage: &str,
    operation_flag: &str,
    error: frameshift_client::ClientError,
    operation_id: Uuid,
    request_id: Uuid,
) -> CliError {
    CliError::Moderation(format!(
        "{stage} failed: {error}; retry with --{operation_flag} {operation_id} --request-id {request_id}"
    ))
}

#[cfg(test)]
/// Moderation command policy regression tests.
mod tests {
    use super::*;

    /// Artifact persistence creates the requested file with exact bytes.
    #[test]
    fn artifact_persistence_writes_exact_bytes() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let destination = temporary.path().join("submission.tar.gz");
        persist_artifact(&destination, b"exact reviewed bytes").expect("persist artifact");
        assert_eq!(
            std::fs::read(destination).expect("read artifact"),
            b"exact reviewed bytes"
        );
    }

    /// Artifact persistence never replaces an existing operator file.
    #[test]
    fn artifact_persistence_refuses_existing_destination() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let destination = temporary.path().join("submission.tar.gz");
        std::fs::write(&destination, b"operator data").expect("write existing file");
        let error = persist_artifact(&destination, b"replacement").expect_err("no overwrite");
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(
            std::fs::read(destination).expect("read existing file"),
            b"operator data"
        );
    }

    /// CLI moderation actions map exactly to their shared wire variants.
    #[test]
    fn action_mapping_preserves_all_variants() {
        assert_eq!(
            PublicationModerationAction::from(ModerationActionArg::Approve),
            PublicationModerationAction::Approve
        );
        assert_eq!(
            PublicationModerationAction::from(ModerationActionArg::RequestChanges),
            PublicationModerationAction::RequestChanges
        );
        assert_eq!(
            PublicationModerationAction::from(ModerationActionArg::Reject),
            PublicationModerationAction::Reject
        );
    }

    /// CLI tombstone reasons map exactly to the shared public wire variants.
    #[test]
    fn tombstone_reason_mapping_preserves_all_variants() {
        assert_eq!(
            TombstoneReason::from(TombstoneReasonArg::AuthorRequest),
            TombstoneReason::AuthorRequest
        );
        assert_eq!(
            TombstoneReason::from(TombstoneReasonArg::TosViolation),
            TombstoneReason::TosViolation
        );
        assert_eq!(
            TombstoneReason::from(TombstoneReasonArg::Dmca),
            TombstoneReason::Dmca
        );
    }

    /// CLI appeal dispositions map exactly to the shared wire variants.
    #[test]
    fn appeal_disposition_mapping_preserves_all_variants() {
        assert_eq!(
            PublicationAppealDisposition::from(AppealDispositionArg::Uphold),
            PublicationAppealDisposition::Uphold
        );
        assert_eq!(
            PublicationAppealDisposition::from(AppealDispositionArg::Overturn),
            PublicationAppealDisposition::Overturn
        );
    }
}
