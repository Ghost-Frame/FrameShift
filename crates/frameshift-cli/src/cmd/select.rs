//! CLI handler for the `frameshift select` subcommand.
//!
//! Runs a read-only persona selection pass for the current project and prints
//! the top-ranked candidates with score, confidence, and rationale.

use std::path::PathBuf;

use clap::Args;
use frameshift_client::Client;
use frameshift_orchestrator::{Embedder, PolicyWeights, Preferences, SelectionInputs};

use crate::util::CliError;

/// Build the semantic embedder when the `embeddings` feature is enabled.
///
/// Model download or load failures degrade to `None` with a stderr warning,
/// so selection falls back to the lexical channels instead of failing.
#[cfg(feature = "embeddings")]
fn make_embedder() -> Option<Box<dyn Embedder>> {
    match frameshift_embed_candle::CandleEmbedder::from_hub() {
        // Wrapped in the persistent cache so repeated selections embed each
        // distinct text once instead of re-running the model per invocation.
        Ok(embedder) => Some(Box::new(frameshift_orchestrator::CachedEmbedder::new(
            embedder,
            frameshift_embed_candle::default_cache_path(frameshift_embed_candle::DEFAULT_MODEL_ID),
        ))),
        Err(e) => {
            eprintln!("warning: semantic embeddings unavailable ({e}); using lexical ranking only");
            None
        }
    }
}

/// Without the `embeddings` feature there is never an embedder.
#[cfg(not(feature = "embeddings"))]
fn make_embedder() -> Option<Box<dyn Embedder>> {
    None
}

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

    /// Output format: "table" (default) or "json".
    ///
    /// When "json", emits the full `SelectionOutput` as structured JSON for
    /// host-LLM reranking or programmatic consumption.
    #[arg(long, value_name = "FORMAT", default_value = "table")]
    pub format: String,
}

/// Execute the `select` subcommand.
///
/// Builds `SelectionInputs` from the current working directory and the loaded
/// preferences, then emits results in the requested format.
///
/// - `--format table` (default): prints the top 5 results in
///   `persona  score  confidence  rationale` format.
/// - `--format json`: emits the full `SelectionOutput` as pretty-printed JSON
///   suitable for host-LLM reranking or programmatic consumption.
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

    // Semantic channel: present only when built with the `embeddings` feature
    // and the model loads; otherwise ranking is purely lexical/contextual.
    let embedder = make_embedder();

    if args.format == "json" {
        // Emit the full SelectionOutput as structured JSON.
        let output =
            frameshift_orchestrator::select_rich_with_embedder(&inputs, embedder.as_deref())
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;
        let json = serde_json::to_string_pretty(&output)?;
        println!("{}", json);
        return Ok(());
    }

    // Default: table format using the ranked candidate list.
    let ranked = frameshift_orchestrator::select_with_embedder(&inputs, embedder.as_deref())
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
