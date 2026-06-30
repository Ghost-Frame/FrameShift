use frameshift_source::PersonaSource;

use crate::composed::{ComposedPersona, Layer};
use crate::error::ComposeError;
use crate::merge::{merge_layers, MergeLayer};
use crate::resolver::SourceResolver;

/// Orchestrates composition of a root persona with its `extends` base and
/// `mixins`, using a `SourceResolver` to fetch each layer by spec.
///
/// The composer is generic over the resolver so test code can plug in an
/// in-memory implementation and production can use `LocalResolver` (or, in
/// M1+, a cache-backed resolver).
pub struct Composer<R: SourceResolver> {
    /// The resolver used to fetch persona sources by spec string.
    resolver: R,
}

impl<R: SourceResolver> Composer<R> {
    /// Creates a new `Composer` backed by the given `SourceResolver`.
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Returns a reference to the underlying resolver.
    pub fn resolver(&self) -> &R {
        &self.resolver
    }

    /// Compose `root` with its declared `extends` base and `mixins`.
    ///
    /// Layer order is: base (if any) -> mixins (in declared order) -> root.
    /// Each layer overrides previous on rule/skill id collision, subject to
    /// SD6 L1 protection: mixins cannot override L1 rules from the base, and
    /// the root can only override inherited L1 rules when the rule carries
    /// `override_inherited = true`.
    ///
    /// Returns `ComposeError::L1Override` if any layer violates the SD6
    /// constraint. Returns `ComposeError::Unresolved` if any spec cannot be
    /// resolved by the underlying resolver.
    pub fn compose(
        &self,
        root: PersonaSource,
        extends: Option<String>,
        mixins: &[String],
    ) -> Result<ComposedPersona, ComposeError> {
        // 1. Resolve the base persona if `extends` is declared.
        let base = extends
            .as_deref()
            .map(|spec| self.resolver.resolve(spec))
            .transpose()?;

        // 2. Resolve each mixin in declaration order.
        let resolved_mixins: Vec<PersonaSource> = mixins
            .iter()
            .map(|spec| self.resolver.resolve(spec))
            .collect::<Result<Vec<_>, _>>()?;

        // 3. Build the typed layer stack: base -> mixins -> root.
        let mut layers: Vec<MergeLayer<'_>> = Vec::new();

        if let Some(ref base_src) = base {
            let base_name = extends.as_deref().unwrap_or("<base>");
            layers.push(MergeLayer {
                source: base_src,
                layer: Layer::Base(base_name.to_string()),
            });
        }

        for (i, mixin_src) in resolved_mixins.iter().enumerate() {
            layers.push(MergeLayer {
                source: mixin_src,
                layer: Layer::Mixin(mixins[i].clone()),
            });
        }

        // Root is pushed last so it sits on top of the stack.
        layers.push(MergeLayer {
            source: &root,
            layer: Layer::Root,
        });

        // 4. Merge all layers with L1 protection.
        merge_layers(&layers)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use frameshift_source::{Layer as SourceLayer, Persona, PersonaSource, Rule, RuleSet};

    use super::*;
    use crate::error::ComposeError;

    /// In-memory resolver for tests: maps spec strings to pre-built sources.
    struct MapResolver {
        /// Map from spec string to the persona source it resolves to.
        map: HashMap<String, PersonaSource>,
    }

    impl MapResolver {
        /// Constructs a new empty `MapResolver`.
        fn new() -> Self {
            Self {
                map: HashMap::new(),
            }
        }

        /// Registers a spec -> source mapping.
        fn insert(&mut self, spec: impl Into<String>, src: PersonaSource) {
            self.map.insert(spec.into(), src);
        }
    }

    impl SourceResolver for MapResolver {
        fn resolve(&self, spec: &str) -> Result<PersonaSource, ComposeError> {
            self.map
                .get(spec)
                .cloned()
                .ok_or_else(|| ComposeError::Unresolved {
                    spec: spec.to_string(),
                    reason: "not in test map".to_string(),
                })
        }
    }

    /// Builds a `Rule` with the given id and layer.
    fn make_rule(id: &str, layer: SourceLayer, override_inherited: bool) -> Rule {
        Rule {
            id: id.to_string(),
            layer,
            text: format!("text for {id}"),
            reasoning: None,
            override_inherited,
        }
    }

    /// Builds a `PersonaSource` with the given name and a single rule.
    fn source_with_rule(name: &str, rule: Rule) -> PersonaSource {
        let mut src = PersonaSource::new(Persona::new(name));
        src.rules = RuleSet { rules: vec![rule] };
        src
    }

    #[test]
    fn compose_no_base_no_mixins_succeeds() {
        let resolver = MapResolver::new();
        let composer = Composer::new(resolver);
        let root = PersonaSource::new(Persona::new("root"));

        let composed = composer
            .compose(root, None, &[])
            .expect("trivial compose should succeed");

        assert_eq!(composed.persona.name, "root");
        assert!(composed.rules.is_empty());
    }

    #[test]
    fn compose_with_base_inherits_rules() {
        let mut resolver = MapResolver::new();
        resolver.insert(
            "base",
            source_with_rule("base", make_rule("no-panic", SourceLayer::L1, false)),
        );

        let composer = Composer::new(resolver);
        let root = PersonaSource::new(Persona::new("root"));

        let composed = composer
            .compose(root, Some("base".to_string()), &[])
            .expect("compose with base should succeed");

        assert_eq!(composed.rules.len(), 1);
        assert_eq!(composed.rules[0].rule.id, "no-panic");
    }

    #[test]
    fn compose_mixin_cannot_override_base_l1() {
        let mut resolver = MapResolver::new();
        resolver.insert(
            "base",
            source_with_rule("base", make_rule("no-panic", SourceLayer::L1, false)),
        );
        resolver.insert(
            "strict-mixin",
            source_with_rule(
                "strict-mixin",
                make_rule("no-panic", SourceLayer::L1, false),
            ),
        );

        let composer = Composer::new(resolver);
        let root = PersonaSource::new(Persona::new("root"));

        let err = composer
            .compose(
                root,
                Some("base".to_string()),
                &["strict-mixin".to_string()],
            )
            .expect_err("mixin L1 override should fail");

        assert!(
            matches!(&err, ComposeError::L1Override { rule_id, .. } if rule_id == "no-panic"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn compose_root_overrides_base_l1_with_flag() {
        let mut resolver = MapResolver::new();
        resolver.insert(
            "base",
            source_with_rule("base", make_rule("no-panic", SourceLayer::L1, false)),
        );

        let composer = Composer::new(resolver);
        let root = source_with_rule("root", make_rule("no-panic", SourceLayer::L1, true));

        let composed = composer
            .compose(root, Some("base".to_string()), &[])
            .expect("root with override_inherited should succeed");

        assert_eq!(composed.rules.len(), 1);
        assert!(composed.rules[0].rule.override_inherited);
    }

    #[test]
    fn compose_unresolved_spec_returns_error() {
        let resolver = MapResolver::new();
        let composer = Composer::new(resolver);
        let root = PersonaSource::new(Persona::new("root"));

        let err = composer
            .compose(root, Some("nonexistent".to_string()), &[])
            .expect_err("unresolved spec should fail");

        assert!(
            matches!(&err, ComposeError::Unresolved { spec, .. } if spec == "nonexistent"),
            "unexpected error: {err}"
        );
    }
}
