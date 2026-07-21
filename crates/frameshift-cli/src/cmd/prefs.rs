//! CLI handler for the `frameshift prefs <show|bump|decay|reset>` subcommand.
//!
//! Exposes the orchestrator's `Preferences` (per-persona scoring bias) for
//! manual inspection and adjustment. The daemon and selection pipeline both
//! read `automate-prefs.json` -- this command gives users direct control.

use clap::{Args, Subcommand};
use frameshift_client::Client;
use frameshift_orchestrator::Preferences;

use crate::util::CliError;

/// Arguments for the `prefs` subcommand.
#[derive(Debug, Args)]
pub struct PrefsArgs {
    /// Action to perform on preferences.
    #[command(subcommand)]
    pub action: PrefsAction,
}

/// Available preferences actions.
#[derive(Debug, Subcommand)]
pub enum PrefsAction {
    /// Display the current per-persona bias values.
    Show,
    /// Increase a persona's bias (simulates a user override in its favor).
    Bump {
        /// Name of the persona to bump.
        persona: String,
    },
    /// Decrease a persona's bias (simulates a user override away from it).
    Decay {
        /// Name of the persona to decay.
        persona: String,
    },
    /// Clear all recorded preferences, resetting every bias to zero.
    Reset,
}

/// Execute the `prefs` subcommand.
///
/// All operations target `automate-prefs.json` in the project's orchestrator
/// state directory, consistent with the daemon and MCP server.
pub fn run_prefs(client: &Client, args: PrefsArgs) -> Result<(), CliError> {
    let project_root = std::env::current_dir()?;
    let state_dir = client.orchestrator_state_dir(&project_root)?;
    let prefs_path = state_dir.join("automate-prefs.json");

    match args.action {
        PrefsAction::Show => {
            let prefs = Preferences::load(&prefs_path)
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;

            if prefs.bias.is_empty() {
                println!("no preferences recorded");
            } else {
                println!("{:<30} {:>8}", "persona", "bias");
                println!("{}", "-".repeat(40));
                for (name, bias) in &prefs.bias {
                    println!("{name:<30} {bias:>+8.3}");
                }
            }
        }

        PrefsAction::Bump { persona } => {
            let mut prefs = Preferences::load(&prefs_path)
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;
            prefs.record_override(None, &persona);
            prefs
                .save(&prefs_path)
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;
            println!("{}: bias now {:+.3}", persona, prefs.bias_for(&persona));
        }

        PrefsAction::Decay { persona } => {
            let mut prefs = Preferences::load(&prefs_path)
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;
            // Decay is the inverse: treat the given persona as the auto-pick
            // that was overridden in favor of a dummy, reducing its bias.
            prefs.record_override(Some(&persona), "__manual_decay__");
            // Remove the dummy entry created for the "chosen" side.
            prefs.bias.remove("__manual_decay__");
            prefs
                .save(&prefs_path)
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;
            println!("{}: bias now {:+.3}", persona, prefs.bias_for(&persona));
        }

        PrefsAction::Reset => {
            let prefs = Preferences::new();
            prefs
                .save(&prefs_path)
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;
            println!("all preferences cleared");
        }
    }

    Ok(())
}

#[cfg(test)]
/// Command-line parsing and preference workflow tests.
mod tests {
    use super::*;
    use clap::Parser;

    /// Helper command that hosts `PrefsArgs` so clap can parse a full
    /// `frameshift prefs <action> ...` invocation without depending on the
    /// real top-level `Command` enum (which would pull in every other
    /// subcommand's required arguments).
    #[derive(Debug, Parser)]
    #[command(name = "frameshift", no_binary_name = true)]
    struct TestCli {
        #[command(subcommand)]
        action: PrefsAction,
    }

    /// `prefs show` parses with no extra arguments.
    #[test]
    fn parse_show_no_args() {
        let parsed = TestCli::try_parse_from(["show"]).expect("show should parse");
        assert!(matches!(parsed.action, PrefsAction::Show));
    }

    /// `prefs bump <persona>` parses and captures the persona name.
    #[test]
    fn parse_bump_with_persona() {
        let parsed = TestCli::try_parse_from(["bump", "rust"]).expect("bump should parse");
        match parsed.action {
            PrefsAction::Bump { persona } => assert_eq!(persona, "rust"),
            other => panic!("expected Bump, got {other:?}"),
        }
    }

    /// `prefs decay <persona>` parses and captures the persona name.
    #[test]
    fn parse_decay_with_persona() {
        let parsed = TestCli::try_parse_from(["decay", "frontend"]).expect("decay should parse");
        match parsed.action {
            PrefsAction::Decay { persona } => assert_eq!(persona, "frontend"),
            other => panic!("expected Decay, got {other:?}"),
        }
    }

    /// `prefs reset` parses with no extra arguments.
    #[test]
    fn parse_reset_no_args() {
        let parsed = TestCli::try_parse_from(["reset"]).expect("reset should parse");
        assert!(matches!(parsed.action, PrefsAction::Reset));
    }

    /// `prefs bump` without a persona name is a parse error.
    #[test]
    fn parse_bump_requires_persona() {
        assert!(
            TestCli::try_parse_from(["bump"]).is_err(),
            "bump without persona must fail"
        );
    }
}
