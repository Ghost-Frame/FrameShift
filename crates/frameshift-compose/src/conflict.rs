use crate::composed::{ComposedPersona, Layer};

/// A conflict detected during composition.
///
/// These are informational warnings emitted after a successful merge -- they
/// do NOT prevent composition from completing. Hard violations (e.g. a mixin
/// overriding an L1 rule without permission) are errors returned during merge,
/// not conflicts reported here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conflict {
    /// Two or more layers declared a rule with the same id. The last-write-wins
    /// layer is the effective contributor after merge.
    RuleIdCollision { id: String, layers: Vec<Layer> },

    /// Two or more layers declared a skill with the same id.
    SkillIdCollision { id: String, layers: Vec<Layer> },

    /// The voice block disagrees across layers (reserved for future use).
    VoiceMismatch { layers: Vec<Layer> },

    /// A stack item is contradicted by an anti-pattern whose text mentions the same item.
    ///
    /// This means the composed persona simultaneously tells the agent to use a
    /// particular library/tool (via a `stack` entry) and to avoid it (via an
    /// `antipattern` whose `text` field contains the stack item as a substring).
    PatternContradiction {
        /// The stack item that conflicts (e.g. `"ed25519-dalek"`).
        stack_item: String,
        /// The stack category the item belongs to (e.g. `"signing"`).
        stack_category: String,
        /// The id of the anti-pattern that contradicts the stack item.
        antipattern_id: String,
    },
}

/// Inspect a composed persona and report id-collision conflicts.
///
/// Walks the provenanced rule and skill lists to find entries where the same
/// `id` appears in rules/skills sourced from different layers. Each such
/// collision is reported as a `Conflict::RuleIdCollision` or
/// `Conflict::SkillIdCollision`.
///
/// This function accepts the already-merged `ComposedPersona` rather than raw
/// `PersonaSource` slices so it can work with the provenance data that the
/// merge step attached. Callers that want pre-merge conflict detection should
/// call `merge_layers` first and then pass the result here.
pub fn detect_conflicts(composed: &ComposedPersona) -> Vec<Conflict> {
    let mut conflicts: Vec<Conflict> = Vec::new();

    // Collect all rule ids that appear more than once in different layers.
    // Because merge uses last-write-wins, the final Vec only contains one
    // entry per id -- but during an earlier draft or if the caller preserved
    // duplicates, we still detect them.
    //
    // In practice, the most useful check here is: scan for rule ids whose
    // provenance layer is NOT the root (i.e., they came from a base or mixin
    // but a later layer also supplied the same id). We surface this for
    // diagnostic rendering.
    detect_rule_collisions(composed, &mut conflicts);
    detect_skill_collisions(composed, &mut conflicts);
    detect_pattern_contradictions(composed, &mut conflicts);

    conflicts
}

/// Report rule id collisions captured during merge.
///
/// Collisions cannot be recovered by scanning `composed.rules`: the merge
/// resolves them by last-write-wins, leaving a single entry per id. They are
/// therefore recorded at merge time in `composed.rule_collisions`, which this
/// reads. (The earlier implementation scanned the collapsed list and so was
/// always a no-op, since every id appeared exactly once.)
fn detect_rule_collisions(composed: &ComposedPersona, out: &mut Vec<Conflict>) {
    for collision in &composed.rule_collisions {
        out.push(Conflict::RuleIdCollision {
            id: collision.id.clone(),
            layers: collision.layers.clone(),
        });
    }
}

/// Report skill id collisions captured during merge (see `detect_rule_collisions`).
fn detect_skill_collisions(composed: &ComposedPersona, out: &mut Vec<Conflict>) {
    for collision in &composed.skill_collisions {
        out.push(Conflict::SkillIdCollision {
            id: collision.id.clone(),
            layers: collision.layers.clone(),
        });
    }
}

/// Scan for stack items that are directly contradicted by anti-pattern text.
///
/// For each item in each `StackCategory`, performs a case-insensitive substring
/// search across every `AntiPattern.text`. A match means the composed persona
/// simultaneously endorses and forbids the same item. Items shorter than 3
/// characters are skipped to avoid false positives from short strings that
/// commonly appear in unrelated contexts.
fn detect_pattern_contradictions(composed: &ComposedPersona, out: &mut Vec<Conflict>) {
    for stack_cat in &composed.patterns.stack {
        for item in &stack_cat.items {
            // Skip very short items -- they match too broadly to be meaningful.
            if item.len() < 3 {
                continue;
            }
            let item_lower = item.to_lowercase();
            for antipattern in &composed.patterns.antipatterns {
                if antipattern.text.to_lowercase().contains(&item_lower) {
                    out.push(Conflict::PatternContradiction {
                        stack_item: item.clone(),
                        stack_category: stack_cat.category.clone(),
                        antipattern_id: antipattern.id.clone(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frameshift_source::{AntiPattern, PatternSet, Persona, StackCategory};

    use crate::composed::ComposedPersona;

    /// Builds a minimal `ComposedPersona` with the given `PatternSet` and no
    /// rules/skills/collisions.
    fn persona_with_patterns(patterns: PatternSet) -> ComposedPersona {
        ComposedPersona {
            persona: Persona::new("test"),
            rules: vec![],
            skills: vec![],
            patterns,
            rule_collisions: vec![],
            skill_collisions: vec![],
        }
    }

    #[test]
    fn rule_and_skill_collisions_are_reported() {
        use crate::composed::IdCollision;
        // A rule id contributed by base + root, and a skill id by two mixins.
        let composed = ComposedPersona {
            persona: Persona::new("test"),
            rules: vec![],
            skills: vec![],
            patterns: PatternSet::default(),
            rule_collisions: vec![IdCollision {
                id: "no-unwrap".to_string(),
                layers: vec![Layer::Base("rust".to_string()), Layer::Root],
            }],
            skill_collisions: vec![IdCollision {
                id: "tdd".to_string(),
                layers: vec![Layer::Mixin("a".to_string()), Layer::Mixin("b".to_string())],
            }],
        };

        let conflicts = detect_conflicts(&composed);
        assert!(conflicts.contains(&Conflict::RuleIdCollision {
            id: "no-unwrap".to_string(),
            layers: vec![Layer::Base("rust".to_string()), Layer::Root],
        }));
        assert!(conflicts.contains(&Conflict::SkillIdCollision {
            id: "tdd".to_string(),
            layers: vec![Layer::Mixin("a".to_string()), Layer::Mixin("b".to_string()),],
        }));
    }

    #[test]
    fn stack_item_contradicted_by_antipattern() {
        // Stack endorses ed25519-dalek; antipattern text mentions it explicitly.
        let composed = persona_with_patterns(PatternSet {
            schema_version: 1,
            stack: vec![StackCategory {
                category: "signing".to_string(),
                items: vec!["ed25519-dalek".to_string()],
            }],
            antipatterns: vec![AntiPattern {
                id: "no-dalek".to_string(),
                text: "Do not use ed25519-dalek in this context.".to_string(),
                use_instead: None,
                reasoning: None,
            }],
            examples: vec![],
            patterns: vec![],
        });

        let conflicts = detect_conflicts(&composed);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(
            conflicts[0],
            Conflict::PatternContradiction {
                stack_item: "ed25519-dalek".to_string(),
                stack_category: "signing".to_string(),
                antipattern_id: "no-dalek".to_string(),
            }
        );
    }

    #[test]
    fn no_contradiction_when_items_dont_overlap() {
        // Stack endorses ed25519-dalek; antipattern only mentions openssl -- no contradiction.
        let composed = persona_with_patterns(PatternSet {
            schema_version: 1,
            stack: vec![StackCategory {
                category: "signing".to_string(),
                items: vec!["ed25519-dalek".to_string()],
            }],
            antipatterns: vec![AntiPattern {
                id: "no-openssl".to_string(),
                text: "Do not use openssl for signing operations.".to_string(),
                use_instead: None,
                reasoning: None,
            }],
            examples: vec![],
            patterns: vec![],
        });

        let conflicts = detect_conflicts(&composed);
        assert!(
            conflicts.is_empty(),
            "expected no conflicts but got: {conflicts:?}"
        );
    }

    #[test]
    fn short_stack_items_are_skipped() {
        // Stack item "ed" is only 2 characters -- must NOT trigger a match even
        // though the antipattern text contains "ed" as a substring.
        let composed = persona_with_patterns(PatternSet {
            schema_version: 1,
            stack: vec![StackCategory {
                category: "signing".to_string(),
                items: vec!["ed".to_string()],
            }],
            antipatterns: vec![AntiPattern {
                id: "no-dalek".to_string(),
                text: "Do not use ed25519-dalek.".to_string(),
                use_instead: None,
                reasoning: None,
            }],
            examples: vec![],
            patterns: vec![],
        });

        let conflicts = detect_conflicts(&composed);
        assert!(
            conflicts.is_empty(),
            "short stack item 'ed' should not match; got: {conflicts:?}"
        );
    }

    #[test]
    fn case_insensitive_match() {
        // Stack item "OpenSSL" should match antipattern text "do not use openssl" (different case).
        let composed = persona_with_patterns(PatternSet {
            schema_version: 1,
            stack: vec![StackCategory {
                category: "tls".to_string(),
                items: vec!["OpenSSL".to_string()],
            }],
            antipatterns: vec![AntiPattern {
                id: "no-openssl".to_string(),
                text: "Do not use openssl for TLS.".to_string(),
                use_instead: None,
                reasoning: None,
            }],
            examples: vec![],
            patterns: vec![],
        });

        let conflicts = detect_conflicts(&composed);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(
            conflicts[0],
            Conflict::PatternContradiction {
                stack_item: "OpenSSL".to_string(),
                stack_category: "tls".to_string(),
                antipattern_id: "no-openssl".to_string(),
            }
        );
    }
}
