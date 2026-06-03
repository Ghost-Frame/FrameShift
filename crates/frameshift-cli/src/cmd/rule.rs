//! `frameshift rule` subcommand group.
//!
//! Exposes two subcommands:
//! - `rule add <persona> --id <id> --layer <L1|L2|L3> --text <text>`
//! - `rule remove <persona> --id <id>`
//!
//! Both commands load the named persona from the central store, apply a typed
//! `PatchOp`, and write the result back to disk atomically (via `write_to_dir`).

use clap::{Args, Subcommand};

use frameshift_client::Client;
use frameshift_source::{apply_patch, Layer, PatchOp, Rule};

use crate::util::{load_persona_by_name, write_persona_by_name, CliError};

/// Subcommand group for rule mutations.
#[derive(Debug, Args)]
pub struct RuleArgs {
    /// The rule subcommand to execute.
    #[command(subcommand)]
    pub command: RuleCommand,
}

/// Available rule subcommands.
#[derive(Debug, Subcommand)]
pub enum RuleCommand {
    /// Add a new rule to a persona's rule set.
    Add(RuleAddArgs),
    /// Remove an existing rule from a persona's rule set.
    Remove(RuleRemoveArgs),
}

/// Arguments for `rule add`.
#[derive(Debug, Args)]
pub struct RuleAddArgs {
    /// Name of the persona to modify (must exist in the central store).
    pub persona: String,

    /// Machine-readable identifier for the new rule (e.g. `no-rolling-crypto`).
    #[arg(long)]
    pub id: String,

    /// Enforcement layer: L1 (hard constraint), L2 (contextual default), or L3 (preference).
    #[arg(long)]
    pub layer: LayerArg,

    /// Human-readable statement of the rule.
    #[arg(long)]
    pub text: String,
}

/// Arguments for `rule remove`.
#[derive(Debug, Args)]
pub struct RuleRemoveArgs {
    /// Name of the persona to modify (must exist in the central store).
    pub persona: String,

    /// Identifier of the rule to remove.
    #[arg(long)]
    pub id: String,
}

/// Clap-compatible wrapper for `frameshift_source::Layer`.
///
/// `Layer` itself does not implement `clap::ValueEnum` (it lives in a
/// library crate we cannot modify), so this newtype bridges the gap with
/// a manual `FromStr` impl.
#[derive(Debug, Clone, Copy)]
pub struct LayerArg(pub Layer);

impl std::str::FromStr for LayerArg {
    type Err = String;

    /// Parse "L1", "L2", or "L3" (case-insensitive) into a `Layer`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "L1" => Ok(LayerArg(Layer::L1)),
            "L2" => Ok(LayerArg(Layer::L2)),
            "L3" => Ok(LayerArg(Layer::L3)),
            _ => Err(format!("invalid layer '{s}'; expected one of: L1, L2, L3")),
        }
    }
}

/// Execute the `rule add` subcommand.
///
/// Loads the named persona, constructs a `Rule` from the CLI arguments,
/// applies a `PatchOp::RuleAdd`, and writes the patched source back to disk.
/// Returns an error string on failure; the caller prints to stderr and exits 1.
pub fn run_add(client: &Client, args: RuleAddArgs) -> Result<(), CliError> {
    let src = load_persona_by_name(client, &args.persona)?;
    // Destructure args to move each field exactly once with no redundant clones.
    // `id` is cloned into the Rule; the original is kept for the confirmation
    // message.  This is the single allocation the reviewer asked us to minimise.
    let RuleAddArgs {
        persona,
        id,
        layer,
        text,
    } = args;
    let rule = Rule {
        id: id.clone(),
        layer: layer.0,
        text,
        reasoning: None,
        override_inherited: false,
    };
    let patched = apply_patch(src, vec![PatchOp::RuleAdd(rule)])?;
    write_persona_by_name(client, &persona, &patched)?;
    println!("added rule '{id}' to persona '{persona}'");
    Ok(())
}

/// Execute the `rule remove` subcommand.
///
/// Loads the named persona, applies `PatchOp::RuleRemove`, and writes back.
pub fn run_remove(client: &Client, args: RuleRemoveArgs) -> Result<(), CliError> {
    let src = load_persona_by_name(client, &args.persona)?;
    // Destructure args.  `id` is moved into the PatchOp; a single clone is
    // made for the confirmation message (one allocation total, not two).
    let RuleRemoveArgs { persona, id } = args;
    let id_display = id.clone();
    let patched = apply_patch(src, vec![PatchOp::RuleRemove { id }])?;
    write_persona_by_name(client, &persona, &patched)?;
    println!("removed rule '{id_display}' from persona '{persona}'");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that LayerArg parses all three valid layer strings.
    #[test]
    fn layer_arg_parses_all_variants() {
        for (input, expected) in [
            ("L1", Layer::L1),
            ("L2", Layer::L2),
            ("L3", Layer::L3),
            ("l1", Layer::L1),
            ("l2", Layer::L2),
            ("l3", Layer::L3),
        ] {
            let parsed: LayerArg = input.parse().expect("should parse");
            assert_eq!(parsed.0, expected, "mismatch for input '{input}'");
        }
    }

    /// Verify that LayerArg rejects unrecognized strings.
    #[test]
    fn layer_arg_rejects_invalid_input() {
        for bad in ["", "L4", "l0", "layer1", "one"] {
            assert!(bad.parse::<LayerArg>().is_err(), "should reject '{bad}'");
        }
    }

    /// Integration test: add a rule to a temp persona dir and read it back.
    #[test]
    fn run_add_creates_rule_on_disk() {
        use frameshift_client::{Client, ClientOptions};
        use frameshift_source::persona::Persona;
        use frameshift_source::PersonaSource;

        // Build a temp data root and write a minimal persona.
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_root = tmp.path().to_path_buf();
        let persona_dir = data_root.join("personas-private").join("test-persona");
        let src = PersonaSource::new(Persona::new("test-persona"));
        src.write_to_dir(&persona_dir)
            .expect("write initial source");

        let client = Client::new(ClientOptions {
            data_root,
            config_root: None,
        });
        let args = RuleAddArgs {
            persona: "test-persona".to_string(),
            id: "no-panic".to_string(),
            layer: LayerArg(Layer::L1),
            text: "Never call unwrap in library code.".to_string(),
        };
        run_add(&client, args).expect("run_add should succeed");

        // Reload and verify the rule is present.
        let loaded = PersonaSource::load_from_dir(&persona_dir).expect("reload");
        assert_eq!(loaded.rules.rules.len(), 1);
        assert_eq!(loaded.rules.rules[0].id, "no-panic");
        assert_eq!(loaded.rules.rules[0].layer, Layer::L1);
    }

    /// Integration test: remove a rule from a temp persona dir.
    #[test]
    fn run_remove_deletes_rule_on_disk() {
        use frameshift_client::{Client, ClientOptions};
        use frameshift_source::patterns::PatternSet;
        use frameshift_source::rules::RuleSet;
        use frameshift_source::skills::SkillSet;
        use frameshift_source::{PersonaSource, Rule};

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_root = tmp.path().to_path_buf();
        let persona_dir = data_root.join("personas-private").join("p2");

        // Create a source with one rule pre-installed.
        let src = PersonaSource {
            persona: frameshift_source::persona::Persona::new("p2"),
            rules: RuleSet {
                rules: vec![Rule {
                    id: "r1".to_string(),
                    layer: Layer::L1,
                    text: "rule one".to_string(),
                    reasoning: None,
                    override_inherited: false,
                }],
            },
            skills: SkillSet::default(),
            patterns: PatternSet::default(),
        };
        src.write_to_dir(&persona_dir).expect("write");

        let client = Client::new(ClientOptions {
            data_root,
            config_root: None,
        });
        let args = RuleRemoveArgs {
            persona: "p2".to_string(),
            id: "r1".to_string(),
        };
        run_remove(&client, args).expect("run_remove should succeed");

        let loaded = PersonaSource::load_from_dir(&persona_dir).expect("reload");
        assert!(loaded.rules.rules.is_empty(), "rule should be removed");
    }

    /// Verify that adding a duplicate rule id returns an error.
    #[test]
    fn run_add_duplicate_id_errors() {
        use frameshift_client::{Client, ClientOptions};
        use frameshift_source::patterns::PatternSet;
        use frameshift_source::rules::RuleSet;
        use frameshift_source::skills::SkillSet;
        use frameshift_source::{PersonaSource, Rule};

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_root = tmp.path().to_path_buf();
        let persona_dir = data_root.join("personas-private").join("dup");

        let src = PersonaSource {
            persona: frameshift_source::persona::Persona::new("dup"),
            rules: RuleSet {
                rules: vec![Rule {
                    id: "existing".to_string(),
                    layer: Layer::L1,
                    text: "existing rule".to_string(),
                    reasoning: None,
                    override_inherited: false,
                }],
            },
            skills: SkillSet::default(),
            patterns: PatternSet::default(),
        };
        src.write_to_dir(&persona_dir).expect("write");

        let client = Client::new(ClientOptions {
            data_root,
            config_root: None,
        });
        let args = RuleAddArgs {
            persona: "dup".to_string(),
            id: "existing".to_string(),
            layer: LayerArg(Layer::L2),
            text: "duplicate".to_string(),
        };
        let err = run_add(&client, args).expect_err("should fail");
        assert!(
            err.to_string().contains("already exists"),
            "expected duplicate error, got: {err}"
        );
    }
}
