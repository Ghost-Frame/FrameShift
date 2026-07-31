//! CLI handler for the `frameshift feedback` subcommand.
//!
//! Records a user override event into the per-project preference store.

use std::path::Path;

use clap::Args;
use frameshift_client::Client;
use frameshift_orchestrator::{Intent, Preferences};

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

    // Parse intent if provided.
    let intent = args.intent.as_deref().and_then(parse_intent);

    record_feedback_override(&prefs_path, args.auto_pick.as_deref(), &args.chosen, intent)?;

    println!(
        "recorded override: {} -> {}{}",
        args.auto_pick.as_deref().unwrap_or("(none)"),
        args.chosen,
        args.intent
            .as_deref()
            .map_or(String::new(), |i| format!(" (intent: {i})")),
    );

    Ok(())
}

/// Parse a free-form `--intent` string into the orchestrator's `Intent` enum.
///
/// Returns `None` for any string that does not match a known intent
/// (case-insensitive); the caller treats this the same as "no intent given".
fn parse_intent(s: &str) -> Option<Intent> {
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
}

/// Load preferences from `prefs_path`, record the override, and persist them.
///
/// `Preferences::load` already returns `Ok(default)` when the file is absent
/// (first run for this project); any other failure (unreadable file, corrupt
/// JSON) is propagated here instead of being swallowed, so a subsequent
/// `save()` never silently replaces a corrupt-but-otherwise-present store
/// with fresh defaults and destroys previously learned per-persona bias
/// (F-13). Mirrors `cmd/prefs.rs` and `cmd/use_persona.rs::record_persona_use`.
fn record_feedback_override(
    prefs_path: &Path,
    auto_pick: Option<&str>,
    chosen: &str,
    intent: Option<Intent>,
) -> Result<(), CliError> {
    let mut prefs =
        Preferences::load(prefs_path).map_err(|e| CliError::Orchestrator(e.to_string()))?;
    prefs.record_override_with_intent(auto_pick, chosen, intent);
    prefs
        .save(prefs_path)
        .map_err(|e| CliError::Orchestrator(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
/// Regression tests for the feedback subcommand's handling of the
/// preferences store.
mod tests {
    use super::*;

    /// A corrupt `automate-prefs.json` must make the feedback flow fail
    /// loudly (F-13) instead of silently overwriting the file with fresh
    /// defaults via `unwrap_or_default()` + `save()`. The file's original
    /// (corrupt) bytes must also be left untouched -- proof that `save()`
    /// was never reached.
    #[test]
    fn corrupt_prefs_file_errors_and_is_left_unchanged() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let prefs_path = tmp.path().join("automate-prefs.json");
        let corrupt = "{ this is not valid json";
        std::fs::write(&prefs_path, corrupt).expect("write corrupt prefs");

        let result = record_feedback_override(&prefs_path, Some("rust"), "security", None);

        assert!(
            result.is_err(),
            "corrupt prefs file must surface as an error, not be silently replaced"
        );

        let after = std::fs::read_to_string(&prefs_path).expect("read prefs after call");
        assert_eq!(
            after, corrupt,
            "corrupt prefs file must be left untouched, not overwritten with defaults"
        );
    }

    /// A healthy (or absent) prefs file still records the override normally.
    #[test]
    fn healthy_prefs_file_records_override() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let prefs_path = tmp.path().join("automate-prefs.json");

        record_feedback_override(&prefs_path, Some("rust"), "security", None)
            .expect("record_feedback_override should succeed");

        let prefs = Preferences::load(&prefs_path).expect("load prefs");
        assert!(
            prefs.bias_for("security") > 0.0,
            "chosen persona should be biased upward"
        );
    }
}
