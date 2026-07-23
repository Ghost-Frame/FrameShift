//! Dry-run-first operator CLI for the publisher ownership migration.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser as _;
use frameshift_catalog_postgres::{
    run_ownership_backfill, OwnershipBackfillMode, OwnershipBackfillReport, PostgresCatalogConfig,
};
use secrecy::SecretString;
use serde::Serialize;

/// Command-line arguments for the ownership backfill operator.
#[derive(Debug, clap::Parser)]
#[command(name = "frameshift-ownership-backfill")]
#[command(about = "Validate or apply a private publisher ownership manifest")]
struct OperatorArguments {
    /// Path to the private exact-census JSON manifest.
    manifest: PathBuf,
    /// Apply the validated migration instead of performing a dry-run.
    #[arg(long)]
    apply: bool,
    /// SHA-256 confirmation required for apply mode.
    #[arg(long)]
    confirm_manifest_sha256: Option<String>,
}

/// Successful JSON response written to standard output.
#[derive(Debug, Serialize)]
struct OperatorSuccess {
    /// Stable success indicator.
    ok: bool,
    /// Exact dry-run or apply report.
    report: OwnershipBackfillReport,
}

/// Failed JSON response written to standard error.
#[derive(Debug, Serialize)]
struct OperatorFailure<'a> {
    /// Stable failure indicator.
    ok: bool,
    /// Sanitized operator-facing error.
    error: &'a str,
}

/// Sanitized operator error that never includes the database URL.
#[derive(Debug, thiserror::Error)]
enum OperatorError {
    /// Command-line parsing failed.
    #[error("invalid arguments: {0}")]
    Arguments(String),
    /// The manifest file could not be read.
    #[error("could not read manifest file")]
    ManifestRead,
    /// The database URL environment variable is absent.
    #[error("POSTGRES_URL is required")]
    MissingPostgresUrl,
    /// The transactional backfill failed safely.
    #[error("{0}")]
    Backfill(frameshift_catalog_postgres::OwnershipBackfillError),
}

/// Parse arguments, validate confirmation, and execute the operator command.
async fn execute() -> Result<OperatorSuccess, OperatorError> {
    let arguments = OperatorArguments::try_parse()
        .map_err(|error| OperatorError::Arguments(error.to_string()))?;
    let manifest_bytes = tokio::fs::read(&arguments.manifest)
        .await
        .map_err(|_| OperatorError::ManifestRead)?;

    let mode = if arguments.apply {
        OwnershipBackfillMode::Apply
    } else {
        OwnershipBackfillMode::DryRun
    };

    let postgres_url =
        std::env::var("POSTGRES_URL").map_err(|_| OperatorError::MissingPostgresUrl)?;
    let config = PostgresCatalogConfig {
        url: SecretString::from(postgres_url),
        pool_size: 1,
        connect_timeout: Duration::from_secs(10),
        statement_timeout: Duration::from_secs(120),
    };
    let report = run_ownership_backfill(
        &config,
        &manifest_bytes,
        arguments.confirm_manifest_sha256.as_deref(),
        mode,
    )
    .await
    .map_err(OperatorError::Backfill)?;
    Ok(OperatorSuccess { ok: true, report })
}

/// Serialize a JSON response without exposing serialization internals.
fn response_json<T: Serialize>(response: &T) -> String {
    serde_json::to_string_pretty(response).unwrap_or_else(|_| {
        "{\"ok\":false,\"error\":\"response serialization failed\"}".to_string()
    })
}

/// Run the operator command and emit exactly one JSON document.
#[tokio::main]
async fn main() {
    match execute().await {
        Ok(success) => {
            let output = response_json(&success);
            println!("{output}");
        }
        Err(error) => {
            let message = error.to_string();
            let failure = OperatorFailure {
                ok: false,
                error: &message,
            };
            let output = response_json(&failure);
            eprintln!("{output}");
            std::process::exit(1);
        }
    }
}
