//! `frameshift migrate` subcommand.
//!
//! Triggers the legacy-file migration shim that moves pre-WS-1 project files
//! (`frameshift.toml`, `frameshift.lock`) from the project root into the
//! central store. The migration is normally triggered as a side-effect of
//! `client.project_paths()`; this command makes it explicit and prints a
//! human-readable summary of what was moved.
//!
//! It also migrates each installed persona's legacy `growth.md` to the
//! structured `growth.jsonl` format via `frameshift_growth::migrate_growth_md`.

use clap::Args;

use frameshift_client::Client;

use crate::util::CliError;

/// Arguments for the `migrate` subcommand.
///
/// This subcommand takes no arguments; it operates on the current working
/// directory as the project root.
#[derive(Debug, Args)]
pub struct MigrateArgs {}

/// Execute the `migrate` subcommand.
///
/// Calls `client.project_paths(cwd)` which internally invokes
/// `migrate_legacy_project_files`. The migration shim copies any legacy
/// `frameshift.toml` / `frameshift.lock` from the project root into the
/// central store (if the central equivalents do not yet exist) and removes
/// the originals.
///
/// Because the migration side-effect is wired inside `project_paths`,
/// we do not need direct access to the private `migrate_legacy_project_files`
/// function -- calling `project_paths` is sufficient.
///
/// After the legacy-file migration, this also walks every persona installed
/// for the current project and migrates its legacy `growth.md` to the
/// structured `growth.jsonl` format via `frameshift_growth::migrate_growth_md`.
/// This step is idempotent: a persona is only migrated when its `growth.md`
/// exists and its `growth.jsonl` does not yet exist, so re-running `migrate`
/// never re-appends already-migrated entries.
pub fn run_migrate(client: &Client, _args: MigrateArgs) -> Result<(), CliError> {
    let cwd = std::env::current_dir().map_err(|source| frameshift_client::ClientError::Io {
        path: std::path::PathBuf::from("."),
        source,
    })?;

    // project_paths triggers migrate_legacy_project_files internally.
    // We capture the paths for reporting purposes.
    let paths = client.project_paths(&cwd)?;

    println!("migrate: project id {}", paths.project_id);
    println!("  central store: {}", paths.project_state_dir.display());
    println!("  legacy files checked and migrated if present");

    // Migrate each installed persona's growth.md -> growth.jsonl, skipping
    // any persona that has already been migrated (growth.jsonl present).
    let personas = client.list_personas(&cwd)?;
    let persona_names: Vec<String> = personas.into_iter().map(|p| p.name).collect();
    let migrated = migrate_persona_growth_logs(client, &paths.project_id, &persona_names)?;

    if migrated.is_empty() {
        println!("  growth: nothing to migrate");
    } else {
        for (name, count) in &migrated {
            println!("  growth: migrated {count} entries for persona '{name}'");
        }
    }

    Ok(())
}

/// Migrate the legacy `growth.md` for each name in `persona_names` to the
/// structured `growth.jsonl` format, skipping any persona whose `growth.md`
/// is absent or whose `growth.jsonl` already exists.
///
/// Returns the `(persona_name, migrated_entry_count)` pairs for personas that
/// were actually migrated by this call -- an empty vector means nothing was
/// migrated (either nothing to migrate, or everything was already migrated by
/// a previous run). Skipping personas with a pre-existing `growth.jsonl` is
/// what makes repeated `migrate` invocations idempotent: `migrate_growth_md`
/// itself appends every parsed entry unconditionally, so calling it again on
/// an already-migrated persona would duplicate every entry.
fn migrate_persona_growth_logs(
    client: &Client,
    project_id: &str,
    persona_names: &[String],
) -> Result<Vec<(String, usize)>, CliError> {
    let mut migrated = Vec::new();
    for name in persona_names {
        let persona_dir = client
            .data_root()
            .join("projects")
            .join(project_id)
            .join("personas")
            .join(name);
        let md_path = persona_dir.join("growth.md");
        let jsonl_path = persona_dir.join("growth.jsonl");

        if !md_path.exists() || jsonl_path.exists() {
            continue;
        }

        let count = frameshift_growth::migrate_growth_md(client.data_root(), project_id, name)
            .map_err(|e| CliError::Growth(e.to_string()))?;
        migrated.push((name.clone(), count));
    }
    Ok(migrated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frameshift_client::ClientOptions;
    use std::fs;
    use tempfile::TempDir;

    /// Builds a `Client` backed by a fresh temp data root and writes a legacy
    /// `growth.md` for `persona` under `project_id` with two entries.
    fn client_with_legacy_growth_md(project_id: &str, persona: &str) -> (TempDir, Client) {
        let tmp = TempDir::new().unwrap();
        let client = Client::new(ClientOptions {
            data_root: tmp.path().join("data"),
            config_root: None,
        });
        let persona_dir = client
            .data_root()
            .join("projects")
            .join(project_id)
            .join("personas")
            .join(persona);
        fs::create_dir_all(&persona_dir).unwrap();
        fs::write(
            persona_dir.join("growth.md"),
            "---\n<!-- growth: 2026-01-01T00:00:00Z -->\n\nfirst\n\n---\n<!-- growth: 2026-01-02T00:00:00Z -->\n\nsecond\n\n",
        )
        .unwrap();
        (tmp, client)
    }

    /// A persona with a legacy `growth.md` and no `growth.jsonl` yet is
    /// migrated, and the returned count matches the number of parsed entries.
    #[test]
    fn migrates_persona_with_legacy_growth_md() {
        let (_tmp, client) = client_with_legacy_growth_md("proj1", "rust");

        let migrated =
            migrate_persona_growth_logs(&client, "proj1", &["rust".to_string()]).unwrap();

        assert_eq!(migrated, vec![("rust".to_string(), 2)]);
        let jsonl_path = client
            .data_root()
            .join("projects/proj1/personas/rust/growth.jsonl");
        assert!(jsonl_path.exists());
    }

    /// Running the migration twice does not duplicate entries: the second
    /// call sees the `growth.jsonl` already present and skips the persona.
    #[test]
    fn migration_is_idempotent() {
        let (_tmp, client) = client_with_legacy_growth_md("proj1", "rust");

        migrate_persona_growth_logs(&client, "proj1", &["rust".to_string()]).unwrap();
        let second = migrate_persona_growth_logs(&client, "proj1", &["rust".to_string()]).unwrap();

        assert!(
            second.is_empty(),
            "second migration run must skip an already-migrated persona"
        );
        let entries = frameshift_growth::read_entries(
            client.data_root(),
            "proj1",
            "rust",
            frameshift_growth::Scope::Project,
        )
        .unwrap();
        assert_eq!(entries.len(), 2, "entries must not be duplicated");
    }

    /// A persona with no `growth.md` at all is skipped without error.
    #[test]
    fn skips_persona_with_no_legacy_growth_md() {
        let tmp = TempDir::new().unwrap();
        let client = Client::new(ClientOptions {
            data_root: tmp.path().join("data"),
            config_root: None,
        });

        let migrated =
            migrate_persona_growth_logs(&client, "proj1", &["rust".to_string()]).unwrap();
        assert!(migrated.is_empty());
    }
}
