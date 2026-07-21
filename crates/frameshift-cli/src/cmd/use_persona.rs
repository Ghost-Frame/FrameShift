//! CLI handler for the `frameshift use <name>` subcommand.
//!
//! Activates the named persona and prints its selected target content
//! to stdout so callers can pipe or review it immediately.

use std::path::{Path, PathBuf};

use clap::Args;
use frameshift_client::{Client, ClientError, InstallRequest, InstallSource, PersonaSpec};
use frameshift_orchestrator::Preferences;

use crate::cmd::render::RenderTargetArg;
use crate::util::CliError;

/// Arguments for the `use` subcommand.
#[derive(Debug, Args)]
pub struct UseArgs {
    /// Name of the persona to activate.
    pub name: String,

    /// Optional path to a persona library directory.
    ///
    /// When given and the persona is not yet installed for the current project,
    /// it is installed on demand from `<DIR>/<name>` before activation. If the
    /// persona is already installed, this flag is ignored and the installed copy
    /// is used.
    #[arg(long, value_name = "DIR")]
    pub from: Option<PathBuf>,

    /// Agent platform to render for: claude, codex, gemini, or generic.
    #[arg(long, default_value = "generic")]
    pub target: RenderTargetArg,
}

/// Execute the `use` subcommand.
///
/// When `--from <DIR>` is given and the persona is not yet installed, installs
/// it from `<DIR>/<name>` first. Then activates the persona (syncs the lock
/// first, then writes the active marker) and reads and prints the rendered
/// output for the selected agent target.
pub fn run_use(client: &Client, args: UseArgs) -> Result<(), CliError> {
    // Reject unsafe names before `args.name` is joined to `--from` (or any
    // central-store path); consistent with every other subcommand.
    crate::util::validate_persona_name(&args.name)?;

    let project_root = std::env::current_dir()?;

    // If --from is given, check if already installed; if not, install first.
    if let Some(lib_dir) = &args.from {
        let installed = client.installed_persona_source_dirs(&project_root)?;
        let already_installed = installed.iter().any(|d| {
            // Source dirs are: <state>/personas/<name>/source -- check grandparent name.
            d.parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy() == args.name.as_str())
                .unwrap_or(false)
        });

        if !already_installed {
            // Determine version from pack.toml if available; fall back to "0.1.0".
            let persona_dir = lib_dir.join(&args.name);
            let version = read_pack_version(&persona_dir).unwrap_or_else(|| "0.1.0".to_string());

            let report = client
                .install(InstallRequest {
                    project_root: project_root.clone(),
                    spec: PersonaSpec {
                        name: args.name.clone(),
                        version,
                    },
                    source: InstallSource::LocalPath(persona_dir),
                })
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;

            // Other locked personas failing to materialize is advisory for
            // THIS install, but the user should know their state degraded.
            for failure in &report.materialize_failures {
                eprintln!(
                    "warning: persona {} failed to materialize and was skipped: {}",
                    failure.persona, failure.error
                );
            }
        }
    }

    // Activate the persona (syncs the lock first, then writes the active marker).
    client
        .activate(&project_root, &args.name)
        .map_err(|e| match e {
            ClientError::PersonaNotInstalled(name) => CliError::PersonaNotFound { name },
            other => CliError::Orchestrator(other.to_string()),
        })?;

    // A soft memory requirement activates fine but deserves a heads-up.
    if let Ok(status) = client.memory_requirement_status(&project_root, &args.name) {
        if status.soft_unmet() {
            eprintln!(
                "warning: {} works best with a memory adapter (memory_required = \"soft\") \
                 but this project declares none",
                args.name
            );
        }
    }

    // Learn from the explicit choice: nudge future automatic selection toward
    // the persona the user activated. This writes the same `automate-prefs.json`
    // that `select` and the daemon read, so the bias actually closes the loop.
    // Best-effort -- activation has already succeeded, so a preferences failure
    // must not fail the command.
    if let Ok(state_dir) = client.orchestrator_state_dir(&project_root) {
        let prefs_path = state_dir.join("automate-prefs.json");
        if let Err(e) = record_persona_use(&prefs_path, &args.name) {
            eprintln!("warning: could not record persona preference: {e}");
        }
    }

    // Record this activation to the local selection-history audit log and
    // (only if the project has opted in) send anonymous selection telemetry.
    record_use_selection_and_telemetry(client, &project_root, &args.name);

    // Read and print the rendered persona for the requested agent target.
    let rendered = client.rendered_persona(&project_root, &args.name, args.target.as_str())?;
    println!("{}", rendered);

    Ok(())
}

/// Read the `version` field from `<persona_dir>/pack.toml`, returning `None`
/// on any error or if the field is absent. Used for on-demand installation
/// so the install spec version matches the actual pack manifest.
fn read_pack_version(persona_dir: &Path) -> Option<String> {
    let pack_path = persona_dir.join("pack.toml");
    let raw = std::fs::read_to_string(&pack_path).ok()?;
    // Simple line-scan to avoid pulling in full toml dep here (already in orchestrator).
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("version") {
            if let Some(val) = trimmed.split_once('=').map(|x| x.1) {
                let version = val.trim().trim_matches('"').trim_matches('\'').to_string();
                if !version.is_empty() {
                    return Some(version);
                }
            }
        }
    }
    None
}

/// Record that the user explicitly activated `persona`, nudging future
/// automatic selection toward it.
///
/// Loads the shared `automate-prefs.json` (the same store `select` and the
/// daemon read), bumps the persona's bias via [`Preferences::record_override`]
/// (with no auto-pick to penalize -- an explicit `use` is a positive signal,
/// not a correction of a specific automatic pick), and persists it atomically.
fn record_persona_use(prefs_path: &Path, persona: &str) -> Result<(), String> {
    let mut prefs = Preferences::load(prefs_path).map_err(|e| e.to_string())?;
    prefs.record_override(None, persona);
    prefs.save(prefs_path).map_err(|e| e.to_string())
}

/// Record `persona`'s explicit activation to the local selection-history
/// audit log and, only if the project has opted in, send anonymous selection
/// telemetry for it.
///
/// Mirrors the activation contract shared by every FrameShift client
/// surface: a session id of `"<surface>:<pid>"`, `auto = false` since this
/// is an explicit user choice (not an automatic pick), and no rationale.
/// `Client::send_telemetry_for_persona`
/// no-ops internally unless `ProjectConfig.telemetry_opt_in` is set, so a
/// stock CLI invocation never phones home.
///
/// Both calls are best-effort: `run_use` has already committed the activation
/// by the time this runs, so a history-log or telemetry failure must never
/// fail the command. Failures are logged via `tracing::warn!` and swallowed.
fn record_use_selection_and_telemetry(client: &Client, project_root: &Path, persona: &str) {
    let session = format!("cli:{}", std::process::id());
    let history_result =
        client.record_selection_event(project_root, persona, &session, false, None);
    if let Err(error) = history_result {
        tracing::warn!(persona, %error, "record_selection_event failed");
    }
    if let Err(error) = client.send_telemetry_for_persona(project_root, persona, &session) {
        tracing::warn!(persona, %error, "send_telemetry_for_persona failed");
    }
}

#[cfg(test)]
/// Tests for persona activation, preference updates, and telemetry recording.
mod tests {
    use super::*;
    use frameshift_client::ClientOptions;
    use tempfile::TempDir;

    /// Recording a use bumps the persona's bias and persists it to the shared
    /// preferences file so later selection can read it back.
    #[test]
    fn record_persona_use_biases_persona() {
        let tmp = TempDir::new().unwrap();
        let prefs_path = tmp.path().join("automate-prefs.json");

        record_persona_use(&prefs_path, "rust").unwrap();

        let prefs = Preferences::load(&prefs_path).unwrap();
        assert!(
            prefs.bias_for("rust") > 0.0,
            "an explicit `use` should bias the persona upward"
        );
    }

    /// Repeated uses accumulate bias (capped by the feedback layer) and never
    /// error on an existing preferences file.
    #[test]
    fn repeated_use_accumulates_and_persists() {
        let tmp = TempDir::new().unwrap();
        let prefs_path = tmp.path().join("automate-prefs.json");

        record_persona_use(&prefs_path, "rust").unwrap();
        let first = Preferences::load(&prefs_path).unwrap().bias_for("rust");
        record_persona_use(&prefs_path, "rust").unwrap();
        let second = Preferences::load(&prefs_path).unwrap().bias_for("rust");

        assert!(second >= first, "bias should not decrease on repeated use");
    }

    /// record_use_selection_and_telemetry appends exactly one local
    /// selection-history event for the activated persona (`auto = false`,
    /// matching an explicit user choice), and never panics or errors even
    /// though telemetry stays disabled -- the default `telemetry_opt_in =
    /// false` makes `send_telemetry_for_persona` a silent no-op with no
    /// network access attempted.
    #[test]
    fn record_use_selection_and_telemetry_writes_history_event() {
        let tmp = TempDir::new().unwrap();
        let client = Client::new(ClientOptions {
            data_root: tmp.path().join("data"),
            config_root: None,
            vault: None,
        });
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();

        record_use_selection_and_telemetry(&client, &project_root, "rust");

        let state_dir = client.orchestrator_state_dir(&project_root).unwrap();
        let history_path = state_dir.join(frameshift_client::SELECTION_HISTORY_FILENAME);
        let raw = std::fs::read_to_string(&history_path).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 1, "expected exactly one recorded event");
        assert!(lines[0].contains("\"persona\":\"rust\""));
        assert!(lines[0].contains("\"auto\":false"));
    }
}
