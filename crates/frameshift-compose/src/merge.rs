use frameshift_source::{PatternSet, PersonaSource};

use crate::composed::{
    ComposedPersona, IdCollision, Layer, Provenance, ProvenancedRule, ProvenancedSkill,
};
use crate::error::ComposeError;

/// The order in which composition layers are stacked.
///
/// `BaseFirst` means: base (extends) at the bottom, mixins in declared order
/// above, root persona at the top. Later layers override earlier ones on
/// ID collision, subject to L1 protection rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOrder {
    /// Stack layers base-first: base -> mixins -> root.
    BaseFirst,
}

/// A single layer in the composition stack with its typed identity.
///
/// Carries a reference to the `PersonaSource` and the `Layer` enum value
/// so merge logic can emit correct provenance and enforce L1 protection.
pub struct MergeLayer<'a> {
    /// The persona source data for this layer.
    pub source: &'a PersonaSource,
    /// The identity of this layer in the composition stack.
    pub layer: Layer,
}

/// Merge a typed slice of `MergeLayer` entries into a single `ComposedPersona`.
///
/// Layers are applied in slice order (first = bottom, last = top). The
/// `persona` block of the last layer wins for top-level metadata.
///
/// **L1 protection (SD6):** If a layer with `Layer::Mixin(_)` introduces a
/// rule whose `id` matches an existing L1 rule, `ComposeError::L1Override` is
/// returned. For `Layer::Root`, the same check applies unless the incoming rule
/// has `override_inherited = true`.
///
/// Skills use last-write-wins with no L1 protection.
/// Patterns are concatenated from all layers in order.
pub fn merge_layers(layers: &[MergeLayer<'_>]) -> Result<ComposedPersona, ComposeError> {
    if layers.is_empty() {
        return Err(ComposeError::Unresolved {
            spec: "<empty>".to_string(),
            reason: "merge_layers called with no layers".to_string(),
        });
    }

    // Capture the root persona up front. Safe: empty check above guarantees at
    // least one element, so `last()` will always return `Some`.
    let root_persona = layers[layers.len() - 1].source.persona.clone();

    let mut rules: Vec<ProvenancedRule> = Vec::new();
    let mut skills: Vec<ProvenancedSkill> = Vec::new();
    let mut combined_patterns = PatternSet::default();

    // Track every layer that contributes each rule/skill id so collisions (same
    // id from more than one layer) survive the last-write-wins merge below and
    // can be surfaced as diagnostics. Without this, the collapsed result holds
    // one entry per id and the collision is unrecoverable.
    let mut rule_layer_map: std::collections::BTreeMap<String, Vec<Layer>> =
        std::collections::BTreeMap::new();
    let mut skill_layer_map: std::collections::BTreeMap<String, Vec<Layer>> =
        std::collections::BTreeMap::new();

    for merge_layer in layers {
        let provenance = Provenance {
            layer: merge_layer.layer.clone(),
        };

        for rule in merge_layer.source.rules.rules.iter() {
            let id = &rule.id;

            // Record this layer's contribution to the id before resolving the
            // collision, so every contributing layer is counted.
            rule_layer_map
                .entry(rule.id.clone())
                .or_default()
                .push(merge_layer.layer.clone());

            if let Some(existing_idx) = rules.iter().position(|p| &p.rule.id == id) {
                let existing = &rules[existing_idx];

                // L1 protection: only allow overriding an L1 rule from a prior
                // layer under specific conditions.
                if existing.rule.layer == frameshift_source::Layer::L1 {
                    let allowed = match &merge_layer.layer {
                        // Root can override an inherited L1 rule only when the
                        // incoming rule explicitly opts in.
                        Layer::Root => rule.override_inherited,
                        // Mixins can never override an L1 rule.
                        Layer::Mixin(_) => false,
                        // Base layers shouldn't appear after another base, but
                        // treat them permissively (no L1 protection against
                        // base-on-base, which is a resolver concern).
                        Layer::Base(_) => true,
                    };

                    if !allowed {
                        let base_layer_desc = layer_description(&existing.provenance.layer);
                        let mixin_layer_desc = layer_description(&merge_layer.layer);
                        return Err(ComposeError::L1Override {
                            rule_id: id.clone(),
                            base_layer: base_layer_desc,
                            mixin_layer: mixin_layer_desc,
                        });
                    }
                }

                rules[existing_idx] = ProvenancedRule {
                    rule: rule.clone(),
                    provenance: provenance.clone(),
                };
            } else {
                rules.push(ProvenancedRule {
                    rule: rule.clone(),
                    provenance: provenance.clone(),
                });
            }
        }

        for skill in merge_layer.source.skills.skills.iter() {
            let id = &skill.id;
            // Record this layer's contribution to the id (see rule loop above).
            skill_layer_map
                .entry(skill.id.clone())
                .or_default()
                .push(merge_layer.layer.clone());
            if let Some(existing) = skills.iter_mut().find(|p| &p.skill.id == id) {
                // Skills: last-write-wins, no L1 protection.
                *existing = ProvenancedSkill {
                    skill: skill.clone(),
                    provenance: provenance.clone(),
                };
            } else {
                skills.push(ProvenancedSkill {
                    skill: skill.clone(),
                    provenance: provenance.clone(),
                });
            }
        }

        // Patterns: concatenate from all layers.
        let src_patterns = &merge_layer.source.patterns;
        combined_patterns
            .stack
            .extend(src_patterns.stack.iter().cloned());
        combined_patterns
            .antipatterns
            .extend(src_patterns.antipatterns.iter().cloned());
        combined_patterns
            .examples
            .extend(src_patterns.examples.iter().cloned());
        combined_patterns
            .patterns
            .extend(src_patterns.patterns.iter().cloned());
    }

    // An id contributed by more than one layer is a collision (diagnostic only;
    // the merge already resolved it by last-write-wins above).
    let rule_collisions = collisions_from_map(rule_layer_map);
    let skill_collisions = collisions_from_map(skill_layer_map);

    Ok(ComposedPersona {
        persona: root_persona,
        rules,
        skills,
        patterns: combined_patterns,
        rule_collisions,
        skill_collisions,
    })
}

/// Convert an id -> contributing-layers map into the collision list: only ids
/// supplied by more than one layer are collisions.
fn collisions_from_map(map: std::collections::BTreeMap<String, Vec<Layer>>) -> Vec<IdCollision> {
    map.into_iter()
        .filter(|(_, layers)| layers.len() > 1)
        .map(|(id, layers)| IdCollision { id, layers })
        .collect()
}

/// Returns a human-readable description of a composition layer for error messages.
fn layer_description(layer: &Layer) -> String {
    match layer {
        Layer::Base(name) => format!("base '{name}'"),
        Layer::Mixin(name) => format!("mixin '{name}'"),
        Layer::Root => "root".to_string(),
    }
}

/// Merge a list of persona source layers into a single `ComposedPersona`.
///
/// Compatibility shim over `merge_layers` -- tags the first element as the
/// root and all subsequent elements as additional `Base` layers with index-
/// based names. This is intentionally simplified; production callers should
/// use `merge_layers` directly with proper `Layer` tags.
///
/// The `MergeOrder::BaseFirst` variant means the first element of `layers` is
/// treated as the root persona (its `Persona` block wins for metadata). Each
/// subsequent layer is composed in above it.
pub fn merge_sources(
    order: MergeOrder,
    layers: &[&PersonaSource],
) -> Result<ComposedPersona, ComposeError> {
    match order {
        MergeOrder::BaseFirst => {
            if layers.is_empty() {
                return Err(ComposeError::Unresolved {
                    spec: "<empty>".to_string(),
                    reason: "merge_sources called with no layers".to_string(),
                });
            }
            // First element is the root persona; rest are treated as extra
            // base-tagged layers for backward compat with WS-5 callers.
            let mut merge_layers_vec: Vec<MergeLayer<'_>> = Vec::with_capacity(layers.len());
            for (i, src) in layers.iter().enumerate() {
                let layer = if i == 0 {
                    Layer::Root
                } else {
                    Layer::Base(format!("layer-{i}"))
                };
                merge_layers_vec.push(MergeLayer { source: src, layer });
            }
            merge_layers(&merge_layers_vec)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frameshift_source::{
        Layer as SourceLayer, PatternSet, Persona, PersonaSource, Rule, RuleSet,
    };

    use crate::composed::Layer as ComposeLayer;

    /// Builds a minimal `PersonaSource` with the given name and no rules/skills/patterns.
    fn empty_fixture(name: &str) -> PersonaSource {
        PersonaSource::new(Persona::new(name))
    }

    /// Builds a `Rule` with the given id and layer; other fields are defaults.
    fn make_rule(id: &str, layer: SourceLayer, override_inherited: bool) -> Rule {
        Rule {
            id: id.to_string(),
            layer,
            text: format!("rule text for {id}"),
            reasoning: None,
            override_inherited,
        }
    }

    /// Builds a `PersonaSource` with a single rule.
    fn fixture_with_rule(name: &str, rule: Rule) -> PersonaSource {
        let mut src = empty_fixture(name);
        src.rules = RuleSet { rules: vec![rule] };
        src
    }

    #[test]
    fn merge_two_empty_sources_yields_empty_composed() {
        let a = empty_fixture("base");
        let b = empty_fixture("root");
        let composed =
            merge_sources(MergeOrder::BaseFirst, &[&a, &b]).expect("empty merge should succeed");
        assert!(composed.rules.is_empty());
        assert!(composed.skills.is_empty());
        assert!(composed.patterns.stack.is_empty());
    }

    #[test]
    fn mixin_cannot_override_base_l1_rule() {
        // Base has L1 rule "no-panic"; mixin tries to override it.
        let base = fixture_with_rule("base", make_rule("no-panic", SourceLayer::L1, false));
        let mixin = fixture_with_rule("mixin", make_rule("no-panic", SourceLayer::L1, false));

        let layers = vec![
            MergeLayer {
                source: &base,
                layer: ComposeLayer::Base("base".to_string()),
            },
            MergeLayer {
                source: &mixin,
                layer: ComposeLayer::Mixin("mixin".to_string()),
            },
        ];

        let err = merge_layers(&layers).expect_err("mixin should not be allowed to override L1");
        assert!(
            matches!(&err, ComposeError::L1Override { rule_id, .. } if rule_id == "no-panic"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn root_can_override_base_l1_with_explicit_flag() {
        // Base has L1 rule "no-panic"; root overrides it with override_inherited=true.
        let base = fixture_with_rule("base", make_rule("no-panic", SourceLayer::L1, false));
        let root = fixture_with_rule("root", make_rule("no-panic", SourceLayer::L1, true));

        let layers = vec![
            MergeLayer {
                source: &base,
                layer: ComposeLayer::Base("base".to_string()),
            },
            MergeLayer {
                source: &root,
                layer: ComposeLayer::Root,
            },
        ];

        let composed = merge_layers(&layers).expect("root with override_inherited should succeed");
        assert_eq!(composed.rules.len(), 1);
        assert_eq!(composed.rules[0].rule.id, "no-panic");
        assert!(composed.rules[0].rule.override_inherited);
    }

    #[test]
    fn root_cannot_override_base_l1_without_flag() {
        // Base has L1 rule "no-panic"; root tries to override without the flag.
        let base = fixture_with_rule("base", make_rule("no-panic", SourceLayer::L1, false));
        let root = fixture_with_rule("root", make_rule("no-panic", SourceLayer::L1, false));

        let layers = vec![
            MergeLayer {
                source: &base,
                layer: ComposeLayer::Base("base".to_string()),
            },
            MergeLayer {
                source: &root,
                layer: ComposeLayer::Root,
            },
        ];

        let err =
            merge_layers(&layers).expect_err("root without override_inherited should fail for L1");
        assert!(
            matches!(&err, ComposeError::L1Override { rule_id, .. } if rule_id == "no-panic"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn l2_rules_can_be_overridden_by_mixin() {
        // Base has L2 rule "prefer-snake-case"; mixin overrides it.
        let base = fixture_with_rule(
            "base",
            make_rule("prefer-snake-case", SourceLayer::L2, false),
        );
        let mixin = fixture_with_rule(
            "mixin",
            make_rule("prefer-snake-case", SourceLayer::L2, false),
        );

        let layers = vec![
            MergeLayer {
                source: &base,
                layer: ComposeLayer::Base("base".to_string()),
            },
            MergeLayer {
                source: &mixin,
                layer: ComposeLayer::Mixin("mixin".to_string()),
            },
        ];

        let composed = merge_layers(&layers).expect("L2 rule override by mixin should succeed");
        assert_eq!(composed.rules.len(), 1);
        assert_eq!(composed.rules[0].rule.id, "prefer-snake-case");
        // Provenance should be the mixin layer.
        assert_eq!(
            composed.rules[0].provenance.layer,
            ComposeLayer::Mixin("mixin".to_string())
        );
    }

    #[test]
    fn patterns_are_merged_by_concatenation() {
        use frameshift_source::patterns::StackCategory;

        let mut base = empty_fixture("base");
        base.patterns = PatternSet {
            schema_version: 1,
            stack: vec![StackCategory {
                category: "signing".to_string(),
                items: vec!["ed25519-dalek".to_string()],
            }],
            antipatterns: vec![],
            examples: vec![],
            patterns: vec![],
        };

        let mut mixin = empty_fixture("mixin");
        mixin.patterns = PatternSet {
            schema_version: 1,
            stack: vec![StackCategory {
                category: "hashing".to_string(),
                items: vec!["blake3".to_string()],
            }],
            antipatterns: vec![],
            examples: vec![],
            patterns: vec![],
        };

        let layers = vec![
            MergeLayer {
                source: &base,
                layer: ComposeLayer::Base("base".to_string()),
            },
            MergeLayer {
                source: &mixin,
                layer: ComposeLayer::Mixin("mixin".to_string()),
            },
        ];

        let composed = merge_layers(&layers).expect("pattern merge should succeed");
        assert_eq!(composed.patterns.stack.len(), 2);
        assert_eq!(composed.patterns.stack[0].category, "signing");
        assert_eq!(composed.patterns.stack[1].category, "hashing");
    }
}
