//! `frameshift skill` subcommand group.
//!
//! Exposes two subcommands:
//! - `skill add <persona> --id <id> --text <text>` (maps to `invoke_when`)
//! - `skill remove <persona> --id <id>`
//!
//! Both commands load the named persona from the central store, apply a typed
//! `PatchOp`, and write the result back.

use clap::{Args, Subcommand};

use frameshift_client::Client;
use frameshift_source::{apply_patch, PatchOp, Skill};

use crate::util::{load_persona_by_name, write_persona_by_name, CliError};

/// Subcommand group for skill mutations.
#[derive(Debug, Args)]
pub struct SkillArgs {
    /// The skill subcommand to execute.
    #[command(subcommand)]
    pub command: SkillCommand,
}

/// Available skill subcommands.
#[derive(Debug, Subcommand)]
pub enum SkillCommand {
    /// Add a new skill entry to a persona.
    Add(SkillAddArgs),
    /// Remove an existing skill entry from a persona.
    Remove(SkillRemoveArgs),
}

/// Arguments for `skill add`.
#[derive(Debug, Args)]
pub struct SkillAddArgs {
    /// Name of the persona to modify (must exist in the central store).
    pub persona: String,

    /// Machine-readable identifier for the new skill (e.g. `test-driven-development`).
    #[arg(long)]
    pub id: String,

    /// Free-text description of when this skill should be invoked (stored as `invoke_when`).
    #[arg(long)]
    pub text: String,
}

/// Arguments for `skill remove`.
#[derive(Debug, Args)]
pub struct SkillRemoveArgs {
    /// Name of the persona to modify (must exist in the central store).
    pub persona: String,

    /// Identifier of the skill to remove.
    #[arg(long)]
    pub id: String,
}

/// Execute the `skill add` subcommand.
///
/// Loads the named persona, constructs a `Skill` from the CLI arguments
/// (with `mandatory = false` as the default; mandatory skills can be set
/// by editing the source TOML directly), applies `PatchOp::SkillAdd`, and
/// writes the patched source back to disk.
pub fn run_add(client: &Client, args: SkillAddArgs) -> Result<(), CliError> {
    let src = load_persona_by_name(client, &args.persona)?;
    // Destructure args.  `id` is cloned once for the confirmation message;
    // the original is moved into the Skill struct (one allocation total).
    let SkillAddArgs { persona, id, text } = args;
    let id_display = id.clone();
    let skill = Skill {
        id,
        invoke_when: text,
        mandatory: false,
    };
    let patched = apply_patch(src, vec![PatchOp::SkillAdd(skill)])?;
    write_persona_by_name(client, &persona, &patched)?;
    println!("added skill '{id_display}' to persona '{persona}'");
    Ok(())
}

/// Execute the `skill remove` subcommand.
///
/// Loads the named persona, applies `PatchOp::SkillRemove`, and writes back.
pub fn run_remove(client: &Client, args: SkillRemoveArgs) -> Result<(), CliError> {
    let src = load_persona_by_name(client, &args.persona)?;
    // Destructure args.  `id` is moved into the PatchOp; a single clone is
    // made for the confirmation message (one allocation total, not two).
    let SkillRemoveArgs { persona, id } = args;
    let id_display = id.clone();
    let patched = apply_patch(src, vec![PatchOp::SkillRemove { id }])?;
    write_persona_by_name(client, &persona, &patched)?;
    println!("removed skill '{id_display}' from persona '{persona}'");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration test: add a skill to a temp persona dir and verify it persists.
    #[test]
    fn run_add_creates_skill_on_disk() {
        use frameshift_client::{Client, ClientOptions};
        use frameshift_source::persona::Persona;
        use frameshift_source::PersonaSource;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_root = tmp.path().to_path_buf();
        let persona_dir = data_root.join("personas-private").join("sp1");
        let src = PersonaSource::new(Persona::new("sp1"));
        src.write_to_dir(&persona_dir).expect("write");

        let client = Client::new(ClientOptions {
            data_root,
            config_root: None,
            vault: None,
        });
        let args = SkillAddArgs {
            persona: "sp1".to_string(),
            id: "brainstorming".to_string(),
            text: "before any creative or design work".to_string(),
        };
        run_add(&client, args).expect("run_add should succeed");

        let loaded = PersonaSource::load_from_dir(&persona_dir).expect("reload");
        assert_eq!(loaded.skills.skills.len(), 1);
        assert_eq!(loaded.skills.skills[0].id, "brainstorming");
        assert_eq!(
            loaded.skills.skills[0].invoke_when,
            "before any creative or design work"
        );
    }

    /// Integration test: remove a skill from a temp persona dir.
    #[test]
    fn run_remove_deletes_skill_on_disk() {
        use frameshift_client::{Client, ClientOptions};
        use frameshift_source::patterns::PatternSet;
        use frameshift_source::rules::RuleSet;
        use frameshift_source::skills::SkillSet;
        use frameshift_source::{PersonaSource, Skill};

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_root = tmp.path().to_path_buf();
        let persona_dir = data_root.join("personas-private").join("sp2");

        let src = PersonaSource {
            persona: frameshift_source::persona::Persona::new("sp2"),
            rules: RuleSet::default(),
            skills: SkillSet {
                skills: vec![Skill {
                    id: "brainstorming".to_string(),
                    invoke_when: "always".to_string(),
                    mandatory: false,
                }],
            },
            patterns: PatternSet::default(),
        };
        src.write_to_dir(&persona_dir).expect("write");

        let client = Client::new(ClientOptions {
            data_root,
            config_root: None,
            vault: None,
        });
        let args = SkillRemoveArgs {
            persona: "sp2".to_string(),
            id: "brainstorming".to_string(),
        };
        run_remove(&client, args).expect("run_remove should succeed");

        let loaded = PersonaSource::load_from_dir(&persona_dir).expect("reload");
        assert!(loaded.skills.skills.is_empty(), "skill should be removed");
    }

    /// Verify that adding a duplicate skill id returns an error.
    #[test]
    fn run_add_duplicate_id_errors() {
        use frameshift_client::{Client, ClientOptions};
        use frameshift_source::patterns::PatternSet;
        use frameshift_source::rules::RuleSet;
        use frameshift_source::skills::SkillSet;
        use frameshift_source::{PersonaSource, Skill};

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_root = tmp.path().to_path_buf();
        let persona_dir = data_root.join("personas-private").join("dup-skill");

        let src = PersonaSource {
            persona: frameshift_source::persona::Persona::new("dup-skill"),
            rules: RuleSet::default(),
            skills: SkillSet {
                skills: vec![Skill {
                    id: "brainstorming".to_string(),
                    invoke_when: "always".to_string(),
                    mandatory: false,
                }],
            },
            patterns: PatternSet::default(),
        };
        src.write_to_dir(&persona_dir).expect("write");

        let client = Client::new(ClientOptions {
            data_root,
            config_root: None,
            vault: None,
        });
        let args = SkillAddArgs {
            persona: "dup-skill".to_string(),
            id: "brainstorming".to_string(),
            text: "duplicate".to_string(),
        };
        let err = run_add(&client, args).expect_err("should fail");
        assert!(
            err.to_string().contains("already exists"),
            "expected duplicate error, got: {err}"
        );
    }
}
