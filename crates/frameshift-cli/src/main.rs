//! `frameshift` CLI entry point.
//!
//! Dispatches to subcommand modules via clap derive. Existing M0 subcommands
//! (`install`, `activate`, `sync`, `gc`, `project-id`) are preserved verbatim.
//! New M1 subcommands (`rule`, `skill`, `diff`, `render`, `migrate`) are
//! wired here. M2 subcommands (`verify`, `publish`) are fully implemented.

mod cmd;
mod util;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use frameshift_client::{Client, InstallRequest, InstallSource, PersonaSpec};

use cmd::automate::AutomateArgs;
use cmd::diff::DiffArgs;
use cmd::feedback::FeedbackArgs;
use cmd::grow::GrowArgs;
use cmd::migrate::MigrateArgs;
use cmd::prefs::PrefsArgs;
use cmd::publish::PublishArgs;
use cmd::register::RegisterArgs;
use cmd::render::RenderArgs;
use cmd::rule::{RuleArgs, RuleCommand};
use cmd::search::SearchArgs;
use cmd::select::SelectArgs;
use cmd::skill::{SkillArgs, SkillCommand};
use cmd::use_persona::UseArgs;
use cmd::verify::VerifyArgs;
use util::CliError;

/// Frameshift persona engine CLI.
#[derive(Debug, Parser)]
#[command(name = "frameshift", version, about = "Frameshift persona engine CLI")]
struct Cli {
    /// The subcommand to execute.
    #[command(subcommand)]
    command: Command,
}

/// All top-level subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    // ------------------------------------------------------------------
    // M0 subcommands -- original install/activate/sync/gc/project-id
    // ------------------------------------------------------------------
    /// Install a persona pack into the central store.
    Install {
        /// Persona spec in `<name>@<version>` format.
        spec: String,
        /// Install from a local pack directory instead of the registry.
        #[arg(long, value_name = "PATH")]
        from_path: Option<PathBuf>,
    },

    /// Activate an installed persona for this project.
    Activate {
        /// Name of the persona to activate.
        persona: String,
    },

    /// Remove an installed persona from this project.
    Uninstall {
        /// Name of the persona to uninstall.
        persona: String,
    },

    /// List personas installed for this project.
    List,

    /// Sync the central store with the current lockfile.
    Sync,

    /// Remove unreferenced entries from the central cache.
    Gc,

    /// Print the project ID for the current directory.
    #[command(name = "project-id")]
    ProjectId,

    // ------------------------------------------------------------------
    // M1 subcommands -- new persona source manipulation
    // ------------------------------------------------------------------
    /// Add or remove a rule in a persona source.
    Rule(RuleArgs),

    /// Add or remove a skill in a persona source.
    Skill(SkillArgs),

    /// Show the semantic diff between two personas.
    Diff(DiffArgs),

    /// Render a persona source to markdown.
    Render(RenderArgs),

    /// Migrate legacy project files to the central store.
    Migrate(MigrateArgs),

    /// Append to a persona's local growth log.
    Grow(GrowArgs),

    // ------------------------------------------------------------------
    // M2 -- verify and publish
    // ------------------------------------------------------------------
    /// Verify a persona source against conformance rules.
    Verify(VerifyArgs),

    /// Publish a persona pack to a directory or registry.
    Publish(PublishArgs),

    /// Register this machine's author key under a handle at the registry.
    Register(RegisterArgs),

    /// Search the registry's pack catalog.
    Search(SearchArgs),

    // ------------------------------------------------------------------
    // M3 -- orchestrator: select, use, automate
    // ------------------------------------------------------------------
    /// Rank installed personas for the current project context (read-only).
    Select(SelectArgs),

    /// Activate a persona and print its rendered output.
    Use(UseArgs),

    /// Manage automate-mode state (on/off/status/lock/unlock).
    Automate(AutomateArgs),

    /// View and adjust per-persona preference biases.
    Prefs(PrefsArgs),

    /// Record a persona selection override for preference learning.
    Feedback(FeedbackArgs),
}

/// Typed run-level error that carries an exit code alongside a message.
///
/// This lets `main` choose the right exit code (1 for general errors, 2 for
/// not-implemented stubs) without string-matching on the error message.
#[derive(Debug)]
enum RunError {
    /// General failure -- prints the message and exits 1.
    General(String),
    /// Feature not implemented -- prints the message and exits 2.
    NotImplemented(String),
}

impl std::fmt::Display for RunError {
    /// Format the run error for printing to stderr.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::General(msg) | RunError::NotImplemented(msg) => f.write_str(msg),
        }
    }
}

impl From<CliError> for RunError {
    /// Convert a `CliError` into a `RunError`, preserving the exit-code
    /// distinction for `NotImplemented` vs all other errors.
    fn from(e: CliError) -> Self {
        if matches!(e, CliError::NotImplemented(_)) {
            RunError::NotImplemented(e.to_string())
        } else {
            RunError::General(e.to_string())
        }
    }
}

/// Top-level entry point. Parses args and delegates to `run()`.
///
/// Exit codes:
/// - 0: success
/// - 1: general error (I/O, parse, patch conflict, etc.)
/// - 2: feature not yet implemented (M2+ stubs)
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunError::NotImplemented(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
        Err(RunError::General(msg)) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

/// Build a `Client` using the default central data root.
///
/// Fails with a `RunError::General` if the data root cannot be determined
/// (e.g., `$HOME` is not set).
fn make_client() -> Result<Client, RunError> {
    Client::with_default_data_root().map_err(|e| RunError::General(e.to_string()))
}

/// Execute the parsed subcommand.
///
/// All M0 subcommands share the pattern: build a client, call the appropriate
/// method, print a short confirmation message. M1 subcommands delegate to
/// their `cmd::*` modules. M2 subcommands (`verify`, `publish`) delegate to
/// their respective fully-implemented modules.
fn run() -> Result<(), RunError> {
    let cli = Cli::parse();

    match cli.command {
        // ------------------------------------------------------------------
        // M0 -- install
        // ------------------------------------------------------------------
        Command::Install { spec, from_path } => {
            let client = make_client()?;
            let (name, version) =
                PersonaSpec::parse_loose(&spec).map_err(|e| RunError::General(e.to_string()))?;
            let source = match from_path {
                Some(path) => InstallSource::LocalPath(path),
                None => InstallSource::Registry,
            };
            // A bare name (no `@version`) resolves to the registry's latest
            // published version; local-path installs require an explicit
            // version since there is no registry to resolve against.
            let version = match (version, &source) {
                (Some(version), _) => version,
                (None, InstallSource::Registry) => client
                    .resolve_latest_version(&name)
                    .map_err(|e| RunError::General(e.to_string()))?,
                (None, InstallSource::LocalPath(_)) => {
                    return Err(RunError::General(
                        "local installs require an explicit version".to_string(),
                    ));
                }
            };
            let spec = PersonaSpec { name, version };
            let report = client
                .install(InstallRequest {
                    project_root: current_dir()?,
                    spec,
                    source,
                })
                .map_err(|e| RunError::General(e.to_string()))?;
            println!(
                "installed {}@{} ({})",
                report.persona.name, report.persona.version, report.persona.hash
            );
            Ok(())
        }

        // ------------------------------------------------------------------
        // M0 -- activate
        // ------------------------------------------------------------------
        Command::Activate { persona } => {
            let client = make_client()?;
            client
                .activate(&current_dir()?, &persona)
                .map_err(|e| RunError::General(e.to_string()))?;
            println!("activated {persona}");
            Ok(())
        }

        // ------------------------------------------------------------------
        // M0 -- uninstall
        // ------------------------------------------------------------------
        Command::Uninstall { persona } => {
            let client = make_client()?;
            client
                .uninstall(&current_dir()?, &persona)
                .map_err(|e| RunError::General(e.to_string()))?;
            println!("uninstalled {persona}");
            Ok(())
        }

        // ------------------------------------------------------------------
        // M0 -- list
        // ------------------------------------------------------------------
        Command::List => {
            let client = make_client()?;
            let project_root = current_dir()?;
            let personas = client
                .list_personas(&project_root)
                .map_err(|e| RunError::General(e.to_string()))?;
            let active = client
                .active_persona(&project_root)
                .map_err(|e| RunError::General(e.to_string()))?;
            for persona in personas {
                let marker = if active.as_deref() == Some(persona.name.as_str()) {
                    " *"
                } else {
                    ""
                };
                let short_hash = &persona.hash[..persona.hash.len().min(12)];
                println!(
                    "{}@{}  {}{}",
                    persona.name, persona.version, short_hash, marker
                );
            }
            Ok(())
        }

        // ------------------------------------------------------------------
        // M0 -- sync
        // ------------------------------------------------------------------
        Command::Sync => {
            let client = make_client()?;
            let report = client
                .sync(&current_dir()?)
                .map_err(|e| RunError::General(e.to_string()))?;
            println!("synced {} persona(s)", report.personas.len());
            Ok(())
        }

        // ------------------------------------------------------------------
        // M0 -- gc
        // ------------------------------------------------------------------
        Command::Gc => {
            let client = make_client()?;
            let report = client.gc().map_err(|e| RunError::General(e.to_string()))?;
            println!("removed {} cache entries", report.removed_hashes.len());
            Ok(())
        }

        // ------------------------------------------------------------------
        // M0 -- project-id
        // ------------------------------------------------------------------
        Command::ProjectId => {
            let client = make_client()?;
            println!(
                "{}",
                client
                    .project_id(&current_dir()?)
                    .map_err(|e| RunError::General(e.to_string()))?
            );
            Ok(())
        }

        // ------------------------------------------------------------------
        // M1 -- rule add / remove
        // ------------------------------------------------------------------
        Command::Rule(rule_args) => {
            let client = make_client()?;
            match rule_args.command {
                RuleCommand::Add(args) => cmd::rule::run_add(&client, args).map_err(RunError::from),
                RuleCommand::Remove(args) => {
                    cmd::rule::run_remove(&client, args).map_err(RunError::from)
                }
            }
        }

        // ------------------------------------------------------------------
        // M1 -- skill add / remove
        // ------------------------------------------------------------------
        Command::Skill(skill_args) => {
            let client = make_client()?;
            match skill_args.command {
                SkillCommand::Add(args) => {
                    cmd::skill::run_add(&client, args).map_err(RunError::from)
                }
                SkillCommand::Remove(args) => {
                    cmd::skill::run_remove(&client, args).map_err(RunError::from)
                }
            }
        }

        // ------------------------------------------------------------------
        // M1 -- diff
        // ------------------------------------------------------------------
        Command::Diff(args) => {
            let client = make_client()?;
            cmd::diff::run_diff(&client, args).map_err(RunError::from)
        }

        // ------------------------------------------------------------------
        // M1 -- render
        // ------------------------------------------------------------------
        Command::Render(args) => {
            let client = make_client()?;
            cmd::render::run_render(&client, args).map_err(RunError::from)
        }

        // ------------------------------------------------------------------
        // M1 -- migrate
        // ------------------------------------------------------------------
        Command::Migrate(args) => {
            let client = make_client()?;
            cmd::migrate::run_migrate(&client, args).map_err(RunError::from)
        }

        // ------------------------------------------------------------------
        // M2 -- grow
        // ------------------------------------------------------------------
        Command::Grow(args) => cmd::grow::run(args).map_err(RunError::from),

        // ------------------------------------------------------------------
        // M2 -- verify and publish
        // ------------------------------------------------------------------
        Command::Verify(args) => cmd::verify::run_verify(args).map_err(RunError::from),
        Command::Publish(args) => cmd::publish::run_publish(args).map_err(RunError::from),
        Command::Register(args) => cmd::register::run_register(args).map_err(RunError::from),
        Command::Search(args) => cmd::search::run_search(args).map_err(RunError::from),

        // ------------------------------------------------------------------
        // M3 -- orchestrator: select, use, automate
        // ------------------------------------------------------------------
        Command::Select(args) => {
            let client = make_client()?;
            cmd::select::run_select(&client, args).map_err(RunError::from)
        }

        Command::Use(args) => {
            let client = make_client()?;
            cmd::use_persona::run_use(&client, args).map_err(RunError::from)
        }

        Command::Automate(args) => {
            let client = make_client()?;
            cmd::automate::run_automate(&client, args).map_err(RunError::from)
        }

        Command::Prefs(args) => {
            let client = make_client()?;
            cmd::prefs::run_prefs(&client, args).map_err(RunError::from)
        }

        Command::Feedback(args) => {
            let client = make_client()?;
            cmd::feedback::run_feedback(&client, args).map_err(RunError::from)
        }
    }
}

/// Return the current working directory as a `PathBuf`.
///
/// Maps the `io::Error` to a `RunError::General` so callers can use `?` in `run()`.
fn current_dir() -> Result<PathBuf, RunError> {
    std::env::current_dir().map_err(|e| RunError::General(e.to_string()))
}
