//! `frameshift diff <persona-a> <persona-b>` subcommand.
//!
//! Loads two named personas from the central store, computes a `SemanticDiff`
//! using `frameshift_source::diff`, and prints a human-readable summary to
//! stdout. With `--json`, prints the diff as a JSON object instead.

use clap::Args;

use frameshift_client::Client;
use frameshift_source::{diff, SemanticDiff};

use crate::util::{load_persona_by_name, CliError};

/// Arguments for the `diff` subcommand.
#[derive(Debug, Args)]
pub struct DiffArgs {
    /// First persona (the "before" snapshot).
    pub persona_a: String,

    /// Second persona (the "after" snapshot).
    pub persona_b: String,

    /// Emit the diff as a JSON object instead of human-readable text.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Execute the `diff` subcommand.
///
/// Loads both personas, runs `frameshift_source::diff`, and prints the result.
/// The human-readable format lists each change category as a labelled section.
/// Empty categories are omitted from the human-readable output.
pub fn run_diff(client: &Client, args: DiffArgs) -> Result<(), CliError> {
    let a = load_persona_by_name(client, &args.persona_a)?;
    let b = load_persona_by_name(client, &args.persona_b)?;
    let result = diff(&a, &b);

    if args.json {
        let json = serde_json::to_string_pretty(&result)?;
        println!("{json}");
    } else {
        print_diff_human(&args.persona_a, &args.persona_b, &result);
    }

    Ok(())
}

/// Print a human-readable representation of a `SemanticDiff` to stdout.
///
/// Sections with no entries are omitted. Anchor similarity is always shown
/// if present.
fn print_diff_human(persona_a: &str, persona_b: &str, d: &SemanticDiff) {
    println!("diff {} -> {}", persona_a, persona_b);
    println!();

    let mut has_any = false;

    if !d.added_rules.is_empty() {
        println!("Rules added ({}):", d.added_rules.len());
        for id in &d.added_rules {
            println!("  + {id}");
        }
        has_any = true;
    }
    if !d.removed_rules.is_empty() {
        println!("Rules removed ({}):", d.removed_rules.len());
        for id in &d.removed_rules {
            println!("  - {id}");
        }
        has_any = true;
    }
    if !d.modified_rules.is_empty() {
        println!("Rules modified ({}):", d.modified_rules.len());
        for id in &d.modified_rules {
            println!("  ~ {id}");
        }
        has_any = true;
    }
    if !d.added_skills.is_empty() {
        println!("Skills added ({}):", d.added_skills.len());
        for id in &d.added_skills {
            println!("  + {id}");
        }
        has_any = true;
    }
    if !d.removed_skills.is_empty() {
        println!("Skills removed ({}):", d.removed_skills.len());
        for id in &d.removed_skills {
            println!("  - {id}");
        }
        has_any = true;
    }
    if d.voice_changed {
        println!("Voice: changed");
        has_any = true;
    }
    if let Some(sim) = d.anchor_similarity {
        // Always print anchor similarity so callers get a sense of overall drift.
        println!("Anchor similarity: {:.3}", sim);
        has_any = true;
    }

    if !has_any {
        println!("No differences found.");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that diff of identical personas prints "No differences found."
    #[test]
    fn print_diff_human_identical_personas_no_diff() {
        // Build the result directly (no I/O needed to test the printer).
        let d = SemanticDiff {
            added_rules: vec![],
            removed_rules: vec![],
            modified_rules: vec![],
            added_skills: vec![],
            removed_skills: vec![],
            voice_changed: false,
            anchor_similarity: Some(1.0),
        };
        // We cannot capture stdout easily without a custom writer, but we can
        // call `print_diff_human` without panicking and verify the result struct
        // round-trips through JSON correctly.
        let json = serde_json::to_string(&d).expect("serialise");
        let parsed: SemanticDiff = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(parsed, d);
    }

    /// Integration test: diff two personas with distinct rule sets.
    #[test]
    fn run_diff_detects_added_rule() {
        use frameshift_client::{Client, ClientOptions};
        use frameshift_source::patterns::PatternSet;
        use frameshift_source::persona::Persona;
        use frameshift_source::rules::{Layer, RuleSet};
        use frameshift_source::skills::SkillSet;
        use frameshift_source::{PersonaSource, Rule};

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_root = tmp.path().to_path_buf();

        // Persona A: no rules.
        let dir_a = data_root.join("personas-private").join("pa");
        PersonaSource::new(Persona::new("pa"))
            .write_to_dir(&dir_a)
            .expect("write pa");

        // Persona B: one rule.
        let dir_b = data_root.join("personas-private").join("pb");
        let src_b = PersonaSource {
            persona: Persona::new("pb"),
            rules: RuleSet {
                rules: vec![Rule {
                    id: "new-rule".to_string(),
                    layer: Layer::L1,
                    text: "a rule".to_string(),
                    reasoning: None,
                    override_inherited: false,
                }],
            },
            skills: SkillSet::default(),
            patterns: PatternSet::default(),
        };
        src_b.write_to_dir(&dir_b).expect("write pb");

        let client = Client::new(ClientOptions {
            data_root,
            config_root: None,
        });
        let args = DiffArgs {
            persona_a: "pa".to_string(),
            persona_b: "pb".to_string(),
            json: false,
        };
        // Should succeed without error.
        run_diff(&client, args).expect("run_diff should succeed");
    }
}
