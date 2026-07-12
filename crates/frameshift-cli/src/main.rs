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
use tracing_subscriber::EnvFilter;

use frameshift_client::{Client, InstallRequest, InstallSource, PersonaSpec};

use cmd::automate::AutomateArgs;
use cmd::config::ConfigArgs;
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
use cmd::vault::VaultArgs;
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

    /// Get or set a key in the current project's central config.toml.
    Config(ConfigArgs),

    // ------------------------------------------------------------------
    // Vault: {{token}} values for templated packs
    // ------------------------------------------------------------------
    /// Manage this project's vault of `{{token}}` values for templated packs.
    Vault(VaultArgs),
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

/// Human-readable rendering used when printing the error to stderr.
impl std::fmt::Display for RunError {
    /// Format the run error for printing to stderr.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::General(msg) | RunError::NotImplemented(msg) => f.write_str(msg),
        }
    }
}

/// Bridge from the command layer's `CliError` into the process-level
/// `RunError`.
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
    // Initialize structured tracing output (mirrors frameshift-daemon/mcp/server).
    // Silent by default (`RUST_LOG` unset -> only ERROR-level events surface);
    // set `RUST_LOG=warn` to see best-effort warnings such as a failed
    // telemetry send or selection-history write.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

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

/// Build a `Client` using the default central data root, with the CLI's
/// vault provider attached (see [`cli_open_vault`]).
///
/// The provider is attached unconditionally: it costs nothing for the many
/// subcommands that never render a templated pack, since
/// `frameshift_client::VaultProvider::open_vault` is only invoked when a
/// pack actually ships `pack.template.toml`.
///
/// Fails with a `RunError::General` if the data root cannot be determined
/// (e.g., `$HOME` is not set).
fn make_client() -> Result<Client, RunError> {
    Client::with_default_data_root_and_vault(Some(cli_vault_provider()))
        .map_err(|e| RunError::General(e.to_string()))
}

/// Build the CLI's [`frameshift_client::VaultProvider`]: passphrase from
/// `FRAMESHIFT_VAULT_PASSPHRASE`, or (only when stdin is an interactive
/// terminal) a hidden `rpassword` prompt. See [`cmd::vault::resolve_passphrase`],
/// which this delegates to so the `frameshift vault` subcommands and this
/// render-time provider resolve the passphrase identically.
fn cli_vault_provider() -> std::sync::Arc<dyn frameshift_client::VaultProvider> {
    std::sync::Arc::new(cli_open_vault)
}

/// Open the vault at `vault_path` using the CLI's passphrase-resolution
/// policy. Matches the `frameshift_client::VaultProvider` signature so it
/// can be used directly via the blanket `Fn` impl.
fn cli_open_vault(
    vault_path: &std::path::Path,
) -> Result<frameshift_client::VaultData, frameshift_client::VaultError> {
    let passphrase = cmd::vault::resolve_passphrase()?;
    frameshift_client::open_vault_with_passphrase(vault_path, passphrase)
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
            // Surface the additive, warn-only cross-version conformance
            // comparison computed during install. `report.conformance_upgrade`
            // is `None` for a fresh install; installation has already
            // succeeded by this point regardless of what the decision says.
            if let Some(decision) = &report.conformance_upgrade {
                if let Some(message) = conformance_upgrade_warning(&report.persona.name, decision) {
                    eprintln!("warning: {message}");
                }
            }
            Ok(())
        }

        // ------------------------------------------------------------------
        // M0 -- activate
        // ------------------------------------------------------------------
        Command::Activate { persona } => {
            let client = make_client()?;
            let project_root = current_dir()?;
            client
                .activate(&project_root, &persona)
                .map_err(|e| RunError::General(e.to_string()))?;
            // A soft memory requirement activates fine but deserves a heads-up.
            if let Ok(status) = client.memory_requirement_status(&project_root, &persona) {
                if status.soft_unmet() {
                    eprintln!(
                        "warning: {persona} works best with a memory adapter \
                         (memory_required = \"soft\") but this project declares none"
                    );
                }
            }
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

        Command::Config(args) => {
            let client = make_client()?;
            cmd::config::run_config(&client, args).map_err(RunError::from)
        }

        Command::Vault(args) => {
            let client = make_client()?;
            cmd::vault::run_vault(&client, args).map_err(RunError::from)
        }
    }
}

/// Return the current working directory as a `PathBuf`.
///
/// Maps the `io::Error` to a `RunError::General` so callers can use `?` in `run()`.
fn current_dir() -> Result<PathBuf, RunError> {
    std::env::current_dir().map_err(|e| RunError::General(e.to_string()))
}

/// Build the human-readable warning message for a cross-version
/// conformance-baseline comparison that is not clean, per
/// `frameshift_conformance::CrossVersionDecision` (re-exported as
/// `frameshift_client::CrossVersionDecision`). Returns `None` for `Pass` and
/// `MissingBaseline`, which are expected, non-fatal outcomes with nothing to
/// report.
///
/// Returning a message rather than printing directly keeps this testable
/// without capturing stderr. This is purely informational: `Client::install`
/// has already committed the install by the time the caller prints this.
/// An `IntegrityFailure` normally fails the install with
/// `ClientError::ConformanceIntegrityFailure` before any report exists, so
/// its arm here is only reached when the operator overrode the block with
/// `FRAMESHIFT_ALLOW_CONFORMANCE_INTEGRITY_FAILURE=1` -- see
/// `enforce_conformance_integrity` in `frameshift-client/src/lib.rs`.
fn conformance_upgrade_warning(
    persona: &str,
    decision: &frameshift_client::CrossVersionDecision,
) -> Option<String> {
    use frameshift_client::CrossVersionDecision;
    match decision {
        CrossVersionDecision::Pass | CrossVersionDecision::MissingBaseline { .. } => None,
        CrossVersionDecision::Regression { delta } => Some(format!(
            "{persona}'s conformance baseline dropped by {delta:.3} relative to the \
             version it replaced (install not blocked)"
        )),
        CrossVersionDecision::IntegrityFailure {
            declared_hash,
            actual_hash,
        } => Some(format!(
            "{persona}'s shipped conformance baseline failed integrity verification \
             (declared hash {declared_hash}, actual {actual_hash:?}); installed anyway \
             because FRAMESHIFT_ALLOW_CONFORMANCE_INTEGRITY_FAILURE=1 is set"
        )),
        CrossVersionDecision::InvalidScore => Some(format!(
            "{persona}'s conformance baseline score is invalid; cannot evaluate this \
             upgrade (install not blocked)"
        )),
    }
}

/// Unit tests for `conformance_upgrade_warning`'s per-variant messaging.
#[cfg(test)]
mod conformance_warning_tests {
    use super::*;
    use frameshift_client::CrossVersionDecision;

    /// `Pass` and `MissingBaseline` are expected, non-fatal outcomes: no
    /// message should be printed for either.
    #[test]
    fn no_message_for_clean_outcomes() {
        assert!(conformance_upgrade_warning("rust", &CrossVersionDecision::Pass).is_none());
        assert!(conformance_upgrade_warning(
            "rust",
            &CrossVersionDecision::MissingBaseline {
                installed_present: true,
                incoming_present: false,
            }
        )
        .is_none());
    }

    /// Every non-clean variant produces a message naming the persona.
    /// Regression/InvalidScore state the install was not blocked;
    /// IntegrityFailure (only printable under the operator override, since
    /// it otherwise fails the install) names the override variable.
    #[test]
    fn message_for_every_non_clean_variant() {
        let regression =
            conformance_upgrade_warning("rust", &CrossVersionDecision::Regression { delta: 0.2 })
                .unwrap();
        assert!(regression.contains("rust"));
        assert!(regression.contains("not blocked"));

        let integrity = conformance_upgrade_warning(
            "rust",
            &CrossVersionDecision::IntegrityFailure {
                declared_hash: "abc".to_string(),
                actual_hash: Some("tampered".to_string()),
            },
        )
        .unwrap();
        assert!(integrity.contains("rust"));
        assert!(integrity.contains("FRAMESHIFT_ALLOW_CONFORMANCE_INTEGRITY_FAILURE"));

        let invalid =
            conformance_upgrade_warning("rust", &CrossVersionDecision::InvalidScore).unwrap();
        assert!(invalid.contains("rust"));
        assert!(invalid.contains("not blocked"));
    }
}
