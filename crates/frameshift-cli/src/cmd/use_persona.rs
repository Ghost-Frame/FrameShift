//! CLI handler for the `frameshift use <name>` subcommand.
//!
//! Activates the named persona and prints the rendered claude-target content
//! to stdout so callers can pipe or review it immediately.

use std::path::{Path, PathBuf};

use clap::Args;
use frameshift_client::{Client, ClientError, InstallRequest, InstallSource, PersonaSpec};

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
}

/// Execute the `use` subcommand.
///
/// When `--from <DIR>` is given and the persona is not yet installed, installs
/// it from `<DIR>/<name>` first. Then activates the persona (syncs the lock
/// first, then writes the active marker) and reads and prints the rendered
/// output for the `claude` target.
pub fn run_use(client: &Client, args: UseArgs) -> Result<(), CliError> {
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

            client
                .install(InstallRequest {
                    project_root: project_root.clone(),
                    spec: PersonaSpec {
                        name: args.name.clone(),
                        version,
                    },
                    source: InstallSource::LocalPath(persona_dir),
                })
                .map_err(|e| CliError::Orchestrator(e.to_string()))?;
        }
    }

    // Activate the persona (syncs the lock first, then writes the active marker).
    client.activate(&project_root, &args.name).map_err(|e| {
        match e {
            ClientError::PersonaNotInstalled(name) => CliError::PersonaNotFound { name },
            other => CliError::Orchestrator(other.to_string()),
        }
    })?;

    // Read and print the rendered persona for the claude target.
    let rendered = client.rendered_persona(&project_root, &args.name, "claude")?;
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
            if let Some(val) = trimmed.splitn(2, '=').nth(1) {
                let version = val.trim().trim_matches('"').trim_matches('\'').to_string();
                if !version.is_empty() {
                    return Some(version);
                }
            }
        }
    }
    None
}
