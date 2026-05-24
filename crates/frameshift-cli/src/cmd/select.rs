//! CLI handler for the `frameshift select` subcommand.
//!
//! Runs a read-only persona selection pass for the current project and prints
//! the top-ranked candidates with score, confidence, and rationale.

use std::path::PathBuf;

use clap::Args;
use frameshift_client::Client;
use frameshift_orchestrator::{PolicyWeights, Preferences, SelectionInputs};

use crate::util::CliError;

/// Arguments for the `select` subcommand.
#[derive(Debug, Args)]
pub struct SelectArgs {
    /// Optional task description to steer lexical scoring.
    #[arg(long, value_name = "TEXT")]
    pub task: Option<String>,

    /// Optional path to a persona library (catalog root) to select from.
    ///
    /// When given, the index is built by enumerating immediate subdirectories
    /// of this path (via `PersonaIndex::from_catalog`) instead of the
    /// project-installed personas. Useful for selecting from the full persona
    /// library without first installing anything.
    #[arg(long, value_name = "DIR")]
    pub library: Option<PathBuf>,
}

/// Execute the `select` subcommand.
///
/// Builds `SelectionInputs` from the current working directory and the loaded
/// preferences, calls `orchestrator::select`, and prints the top 5 results in
/// `persona  score  confidence  rationale` format.
///
/// When `--library` is given, the index is built from the given catalog root
/// instead of the project-installed personas.
pub fn run_select(client: &Client, args: SelectArgs) -> Result<(), CliError> {
    let project_root = std::env::current_dir()?;
    let state_dir = client.orchestrator_state_dir(&project_root)?;

    // Load preferences; continue with empty prefs if the file is absent.
    let prefs_path = state_dir.join("automate-prefs.json");
    let prefs = Preferences::load(&prefs_path).unwrap_or_default();

    // When --library is given, use catalog_root mode; otherwise use installed source dirs.
    let (source_dirs, catalog_root) = if let Some(lib) = args.library {
        (vec![], Some(lib))
    } else {
        let dirs = client.installed_persona_source_dirs(&project_root)?;
        (dirs, None)
    };

    let inputs = SelectionInputs {
        project_root: &project_root,
        task_hint: args.task.as_deref(),
        source_dirs,
        catalog_root,
        prefs,
        weights: PolicyWeights::default(),
    };

    let ranked = frameshift_orchestrator::select(&inputs)
        .map_err(|e| CliError::Orchestrator(e.to_string()))?;

    if ranked.is_empty() {
        println!("No personas installed for this project.");
        return Ok(());
    }

    // Print header.
    println!(
        "{:<30} {:>7} {:>10}  rationale",
        "persona", "score", "confidence"
    );
    println!("{}", "-".repeat(80));

    // Print top 5.
    for entry in ranked.iter().take(5) {
        println!(
            "{:<30} {:>7.3} {:>10.3}  {}",
            entry.persona, entry.score, entry.confidence, entry.rationale
        );
    }

    Ok(())
}
