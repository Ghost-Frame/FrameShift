//! CLI handler for the `frameshift feedback` subcommand.
//!
//! Records a user override event into the per-project preference store.

use clap::Args;
use frameshift_client::Client;
use frameshift_orchestrator::Preferences;

use crate::util::CliError;

/// Arguments for the `feedback` subcommand.
#[derive(Debug, Args)]
pub struct FeedbackArgs {
    /// The persona that was auto-picked (before override).
    #[arg(long, value_name = "PERSONA")]
    pub auto_pick: Option<String>,

    /// The persona the user chose instead.
    #[arg(long, value_name = "PERSONA")]
    pub chosen: String,

    /// Task description at the time of override.
    #[arg(long, value_name = "TEXT")]
    pub task: Option<String>,

    /// Inferred intent at the time of override.
    #[arg(long, value_name = "INTENT")]
    pub intent: Option<String>,

    /// Reason for the override (from LLM or user).
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
}

/// Execute the `feedback` subcommand.
pub fn run_feedback(client: &Client, args: FeedbackArgs) -> Result<(), CliError> {
    let project_root = std::env::current_dir()?;
    let state_dir = client.orchestrator_state_dir(&project_root)?;
    let prefs_path = state_dir.join("automate-prefs.json");

    let mut prefs = Preferences::load(&prefs_path).unwrap_or_default();

    // Parse intent if provided.
    let intent = args.intent.as_deref().and_then(|s| {
        use frameshift_orchestrator::Intent;
        match s.to_lowercase().as_str() {
            "implementation" => Some(Intent::Implementation),
            "debugging" => Some(Intent::Debugging),
            "review" => Some(Intent::Review),
            "security" => Some(Intent::Security),
            "writing" => Some(Intent::Writing),
            "ops" => Some(Intent::Ops),
            "testing" => Some(Intent::Testing),
            "refactoring" => Some(Intent::Refactoring),
            "performance" => Some(Intent::Performance),
            "design" => Some(Intent::Design),
            _ => None,
        }
    });

    prefs.record_override_with_intent(
        args.auto_pick.as_deref(),
        &args.chosen,
        intent,
    );

    prefs.save(&prefs_path)
        .map_err(|e| CliError::Orchestrator(e.to_string()))?;

    println!(
        "recorded override: {} -> {}{}",
        args.auto_pick.as_deref().unwrap_or("(none)"),
        args.chosen,
        args.intent.as_deref().map_or(String::new(), |i| format!(" (intent: {i})")),
    );

    Ok(())
}
