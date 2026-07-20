//! CLI handler for the `frameshift automate <on|off|status|lock|unlock>` subcommand.
//!
//! Manages automate-mode state files under the project's orchestrator state directory.
//! Automate mode is OFF by default; callers must explicitly turn it on.

use clap::{Args, Subcommand};
use frameshift_client::Client;
use frameshift_orchestrator::{AuditLog, Mode, ModeState};

use crate::util::CliError;

/// Arguments for the `automate` subcommand.
#[derive(Debug, Args)]
pub struct AutomateArgs {
    /// Action to perform.
    #[command(subcommand)]
    pub action: AutomateAction,
}

/// Available automate actions.
#[derive(Debug, Subcommand)]
pub enum AutomateAction {
    /// Enable automate mode for this project (does NOT auto-select a persona).
    On {
        /// Switching sensitivity from 0.0 (stable) to 1.0 (responsive). Default: 0.5.
        #[arg(long, value_name = "VALUE")]
        sensitivity: Option<f32>,
    },
    /// Disable automate mode for this project.
    Off,
    /// Print the current mode, active persona, and recent audit transitions.
    Status,
    /// Lock the current persona; the daemon will not auto-switch while locked.
    Lock,
    /// Unlock the persona, allowing the daemon to auto-switch again.
    Unlock,
}

/// Execute the `automate` subcommand.
///
/// All state files are written under `orchestrator_state_dir` so that the
/// daemon, CLI, and MCP server all read/write the same location.
pub fn run_automate(client: &Client, args: AutomateArgs) -> Result<(), CliError> {
    let project_root = std::env::current_dir()?;
    let state_dir = client.orchestrator_state_dir(&project_root)?;

    let mode_path = state_dir.join("automate.json");
    let audit_path = state_dir.join("automate-audit.jsonl");

    match args.action {
        AutomateAction::On { sensitivity } => {
            let state = ModeState {
                mode: Mode::On,
                sensitivity: sensitivity.unwrap_or(0.5),
            };
            state
                .save(&mode_path)
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;
            println!("automate mode: on (sensitivity: {:.1})", state.sensitivity);
        }

        AutomateAction::Off => {
            let state = ModeState {
                mode: Mode::Off,
                sensitivity: 0.5,
            };
            state
                .save(&mode_path)
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;
            println!("automate mode: off");
        }

        AutomateAction::Status => {
            // Load mode state (defaults to Off if file absent).
            let mode_state =
                ModeState::load(&mode_path).map_err(|e| CliError::Orchestrator(e.to_string()))?;

            // Failure-aware active persona: mark a persona whose marker
            // survived a failed sync so status never claims a healthy active
            // persona that has no materialized content.
            let active = match client.active_persona_state(&project_root) {
                Ok(frameshift_client::ActivePersonaState::Materialized(name)) => name,
                Ok(frameshift_client::ActivePersonaState::Unmaterialized(name)) => {
                    format!("{name} (not materialized -- run `frameshift sync`)")
                }
                Ok(frameshift_client::ActivePersonaState::None) | Err(_) => String::from("(none)"),
            };

            // Check lock marker.
            let lock_path = state_dir.join("automate-lock.json");
            let locked = lock_path.exists();

            println!(
                "mode: {}{}",
                match mode_state.mode {
                    Mode::On => "on",
                    Mode::Off => "off",
                },
                if locked { "  [locked]" } else { "" }
            );
            println!("sensitivity: {:.1}", mode_state.sensitivity);
            println!("active persona: {}", active);

            // Print last 5 audit transitions.
            let audit =
                AuditLog::load(&audit_path).map_err(|e| CliError::Orchestrator(e.to_string()))?;
            let recent = audit.recent(5);
            if recent.is_empty() {
                println!("no transitions recorded");
            } else {
                println!("recent transitions:");
                for t in recent {
                    let from = t.from.as_deref().unwrap_or("(none)");
                    println!(
                        "  {} {} -> {} (confidence {:.2}): {}",
                        t.timestamp, from, t.to, t.confidence, t.rationale
                    );
                }
            }
        }

        AutomateAction::Lock => {
            // Persist a lock marker file alongside the mode state.
            let lock_path = state_dir.join("automate-lock.json");
            if let Some(parent) = lock_path.parent() {
                std::fs::create_dir_all(parent).map_err(CliError::Io)?;
            }
            let lock_content = serde_json::json!({"locked": true}).to_string();
            std::fs::write(&lock_path, lock_content).map_err(CliError::Io)?;
            println!("persona locked; daemon will not auto-switch");
        }

        AutomateAction::Unlock => {
            let lock_path = state_dir.join("automate-lock.json");
            if lock_path.exists() {
                std::fs::remove_file(&lock_path).map_err(CliError::Io)?;
            }
            println!("persona unlocked; daemon may auto-switch");
        }
    }

    Ok(())
}
