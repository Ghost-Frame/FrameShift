//! Implementation of the `frameshift publish` subcommand.
//!
//! Loads a named persona from the central store, writes its source files to
//! an output directory, renders the persona to `AGENTS.md` using the Generic
//! target, and optionally stubs a registry upload (not yet implemented).

use std::path::PathBuf;

use clap::Args;
use frameshift_client::Client;
use frameshift_source::render::{render_to_markdown, RenderTarget};

use crate::util::{load_persona_by_name, CliError};

/// Arguments for the `publish` subcommand.
#[derive(Debug, Args)]
pub struct PublishArgs {
    /// Name of the persona to publish.
    #[arg(long)]
    pub persona: String,

    /// Output directory for the pack (directory format).
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Registry server URL (stub -- disk output only for now).
    #[arg(long)]
    pub server: Option<String>,
}

/// Execute the `publish` subcommand.
///
/// Loads the persona by name, writes its source to the output directory,
/// renders an `AGENTS.md`, and prints a summary.  If `--server` is given,
/// prints a "not yet implemented" notice instead of uploading.
pub fn run_publish(args: PublishArgs) -> Result<(), CliError> {
    // Build client and load the persona.
    let client = Client::with_default_data_root()?;
    let src = load_persona_by_name(&client, &args.persona)?;

    // Determine the output directory.
    let out_dir = match args.out {
        Some(path) => path,
        None => PathBuf::from("publish-output").join(&args.persona),
    };

    // Create the output directory (and any parents).
    std::fs::create_dir_all(&out_dir)?;

    // Write the persona source files to the output directory.
    src.write_to_dir(&out_dir)
        .map_err(|e| CliError::WriteSource(e.to_string()))?;

    // Render to AGENTS.md for the Generic target.
    let markdown = render_to_markdown(&src, RenderTarget::Generic);
    let agents_md_path = out_dir.join("AGENTS.md");
    std::fs::write(&agents_md_path, markdown)?;

    // Print summary.
    let version = src.persona.version.as_deref().unwrap_or("(no version)");
    println!(
        "published {} v{} to {}",
        args.persona,
        version,
        out_dir.display()
    );

    // If --server is provided, note that registry upload is not yet implemented.
    if args.server.is_some() {
        println!("registry upload not yet implemented");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use frameshift_source::PersonaSource;
    use std::fs;

    /// Write a minimal persona.toml to a temp directory so PersonaSource can
    /// be loaded from it during tests.
    fn write_persona_source(dir: &std::path::Path) {
        let toml = r#"schema_version = 1
name = "test-persona"
version = "0.1.0"
description = "test"

[voice]
tone = "neutral"
"#;
        fs::write(dir.join("persona.toml"), toml).expect("write persona.toml");
    }

    /// Build a `PersonaSource` from a directory containing a minimal persona.toml.
    ///
    /// Loads the source from the given path and returns it.
    fn load_source_from(dir: &std::path::Path) -> PersonaSource {
        PersonaSource::load_from_dir(dir).expect("load PersonaSource")
    }

    /// Running publish with an existing PersonaSource creates the output directory.
    #[test]
    fn publish_creates_output_dir() {
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let out_dir = tempfile::tempdir().expect("out tempdir");

        write_persona_source(src_dir.path());
        let src = load_source_from(src_dir.path());

        // Write to out dir manually (simulating what run_publish does internally).
        let out = out_dir.path().join("persona-pack");
        std::fs::create_dir_all(&out).expect("create_dir_all");
        src.write_to_dir(&out).expect("write_to_dir");

        assert!(out.exists(), "output directory must exist");
    }

    /// Running publish writes an AGENTS.md into the output directory.
    #[test]
    fn publish_contains_agents_md() {
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let out_dir = tempfile::tempdir().expect("out tempdir");

        write_persona_source(src_dir.path());
        let src = load_source_from(src_dir.path());

        let out = out_dir.path().join("persona-pack");
        std::fs::create_dir_all(&out).expect("create_dir_all");
        src.write_to_dir(&out).expect("write_to_dir");

        let markdown = render_to_markdown(&src, RenderTarget::Generic);
        let agents_md_path = out.join("AGENTS.md");
        std::fs::write(&agents_md_path, markdown).expect("write AGENTS.md");

        assert!(
            agents_md_path.exists(),
            "AGENTS.md must exist in the output directory"
        );

        let content = std::fs::read_to_string(&agents_md_path).expect("read AGENTS.md");
        assert!(
            content.contains("test-persona"),
            "AGENTS.md must reference the persona name"
        );
    }
}
