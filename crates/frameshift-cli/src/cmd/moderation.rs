//! Human-operated publication moderation and promotion commands.
//!
//! The CLI reuses the authenticated account session for the exact registry.
//! Authorization, independent-review separation, state transitions, and
//! promotion integrity remain enforced by the server.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use frameshift_catalog::PublicationModerationAction;
use frameshift_client::moderation::{
    get_moderation_artifact, get_moderation_submission, moderate_publication_submission,
    promote_publication_submission,
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
}
