use frameshift_source::{PatternSet, Persona, PersonaSource, Rule, RuleSet, Skill, SkillSet};
use serde::{Deserialize, Serialize};

/// Identifies a composition layer that contributed a rule or skill.
///
/// `Base` is the persona named in `extends`; `Mixin(name)` is one of the
/// declared mixins; `Root` is the persona that initiated composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Layer {
    Base(String),
    Mixin(String),
    Root,
}

/// Provenance tag attached to each merged rule/skill so consumers can tell
/// which layer in the composition stack contributed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub layer: Layer,
}

/// A rule paired with the layer that contributed it.
#[derive(Debug, Clone)]
pub struct ProvenancedRule {
    pub rule: Rule,
    pub provenance: Provenance,
}

/// A skill paired with the layer that contributed it.
#[derive(Debug, Clone)]
pub struct ProvenancedSkill {
    pub skill: Skill,
    pub provenance: Provenance,
}

/// An id collision recorded during merge: more than one layer supplied a rule
/// or skill with the same id.
///
/// The merge resolves collisions by last-write-wins, leaving a single entry per
/// id in the merged list, so this record is the only surviving evidence that the
/// earlier layers also contributed the id. It is captured at merge time because
/// it cannot be reconstructed from the collapsed result afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdCollision {
    /// The colliding rule or skill id.
    pub id: String,
    /// Every layer that contributed this id, in merge order.
    pub layers: Vec<Layer>,
}

/// The merged result of composing a root persona with its base + mixins.
///
/// Same shape as `PersonaSource` from `frameshift-source`, but every rule
/// and skill carries provenance so callers can render "rule X came from
/// mixin Y" diagnostics. Patterns are merged by concatenation.
#[derive(Debug, Clone)]
pub struct ComposedPersona {
    /// Core persona metadata from the root layer.
    pub persona: Persona,
    /// Merged rules with provenance tags.
    pub rules: Vec<ProvenancedRule>,
    /// Merged skills with provenance tags.
    pub skills: Vec<ProvenancedSkill>,
    /// Merged patterns from all layers (concatenated, no deduplication).
    pub patterns: PatternSet,
    /// Rule id collisions observed during merge (diagnostic only; the merge
    /// itself resolves them by last-write-wins). Empty when no id was supplied
    /// by more than one layer.
    pub rule_collisions: Vec<IdCollision>,
    /// Skill id collisions observed during merge (diagnostic only).
    pub skill_collisions: Vec<IdCollision>,
}

impl ComposedPersona {
    /// Collapses a composed (provenance-tagged) persona back into a plain
    /// `PersonaSource` by discarding provenance and collision diagnostics.
    ///
    /// This is the bridge back to `frameshift-source`'s render pipeline
    /// (`render_to_markdown`), which operates on `PersonaSource` and knows
    /// nothing about composition layers or provenance.
    pub fn into_source(self) -> PersonaSource {
        PersonaSource {
            persona: self.persona,
            rules: RuleSet {
                rules: self.rules.into_iter().map(|p| p.rule).collect(),
            },
            skills: SkillSet {
                skills: self.skills.into_iter().map(|p| p.skill).collect(),
            },
            patterns: self.patterns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `into_source` must collapse provenance-tagged rules/skills into a plain
    /// `RuleSet`/`SkillSet` while preserving persona metadata and patterns, and
    /// must drop collision diagnostics (they have no place in `PersonaSource`).
    #[test]
    fn into_source_collapses_provenance() {
        let persona = Persona::new("demo");
        let rule = Rule {
            id: "r1".to_string(),
            layer: frameshift_source::Layer::L1,
            text: "rule one".to_string(),
            reasoning: None,
            override_inherited: false,
        };
        let skill = Skill {
            id: "s1".to_string(),
            invoke_when: "always".to_string(),
            mandatory: false,
        };

        let composed = ComposedPersona {
            persona: persona.clone(),
            rules: vec![ProvenancedRule {
                rule: rule.clone(),
                provenance: Provenance { layer: Layer::Root },
            }],
            skills: vec![ProvenancedSkill {
                skill: skill.clone(),
                provenance: Provenance { layer: Layer::Root },
            }],
            patterns: PatternSet::default(),
            rule_collisions: vec![IdCollision {
                id: "r1".to_string(),
                layers: vec![Layer::Root],
            }],
            skill_collisions: Vec::new(),
        };

        let src = composed.into_source();
        assert_eq!(src.persona, persona);
        assert_eq!(src.rules.rules, vec![rule]);
        assert_eq!(src.skills.skills, vec![skill]);
        assert_eq!(src.patterns, PatternSet::default());
    }
}
