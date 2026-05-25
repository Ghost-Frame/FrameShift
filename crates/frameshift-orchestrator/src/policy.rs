//! Scoring policy: rank personas against a context signal.

use crate::context::ContextSignal;
use crate::feedback::Preferences;
use crate::index::PersonaIndex;

/// Weights controlling the relative contribution of each scoring component.
///
/// Values should sum to 1.0 for predictable score magnitudes, but this is
/// not enforced; they are applied independently and then blended.
#[derive(Debug, Clone)]
pub struct PolicyWeights {
    /// Weight for language overlap scoring.
    pub language: f32,
    /// Weight for lexical (task-token vs. keyword) overlap scoring.
    pub lexical: f32,
    /// Weight for intent alignment scoring.
    pub intent: f32,
    /// Weight for capability heuristic scoring.
    pub capability: f32,
}

impl Default for PolicyWeights {
    /// Returns the default weights: language 0.3, lexical 0.25, intent 0.3, capability 0.15.
    fn default() -> Self {
        PolicyWeights {
            language: 0.3,
            lexical: 0.25,
            intent: 0.3,
            capability: 0.15,
        }
    }
}

/// The raw, per-component scores that contributed to a final blended score.
#[derive(Debug, Clone)]
pub struct ScoreComponents {
    /// Language overlap component (0..1).
    pub language: f32,
    /// Lexical overlap component (0..1), after any anti-keyword penalty.
    pub lexical: f32,
    /// Intent alignment component (0..1).
    pub intent: f32,
    /// Capability heuristic component (0..1).
    pub capability: f32,
}

/// A scored persona with rationale and confidence information.
#[derive(Debug, Clone)]
pub struct Scored {
    /// The persona's canonical name.
    pub persona: String,

    /// Blended score in [0.0, 1.0] after applying weights and preference bias.
    pub score: f32,

    /// Confidence in [0.0, 1.0], derived from the absolute score and the margin
    /// over the second-ranked candidate. Only meaningful relative to the ranking.
    pub confidence: f32,

    /// Human-readable explanation of why this score was assigned.
    pub rationale: String,

    /// Per-component raw scores before blending.
    pub components: ScoreComponents,
}

/// Rank all personas in `index` for the given `ctx`.
///
/// Scoring:
/// - Language score: sum of `ctx.languages` weights for languages present in
///   the persona profile, normalized to [0.0, 1.0].
/// - Lexical score: fraction of `ctx.task_tokens` that appear in persona
///   keywords; 0.0 if there are no task tokens.
/// - Capability score: small bonus if the persona has no required tools and
///   no network egress (i.e. "safe" / simple persona).
/// - Per-persona preference bias from `prefs` is added after blending and
///   clamped to [0.0, 1.0].
///
/// Returns results sorted descending by blended score. Confidence is computed
/// after sorting based on the top-vs-runner-up gap and absolute score.
pub fn rank(
    ctx: &ContextSignal,
    index: &PersonaIndex,
    weights: &PolicyWeights,
    prefs: &Preferences,
) -> Vec<Scored> {
    // Precompute IDF for each task token: tokens that appear in fewer persona
    // keyword sets are weighted higher (rare tokens are more discriminating).
    // idf[tok] = log2(n_personas / (df + 1) + 1), clamped to [0, ∞).
    let n_personas = index.profiles.len().max(1) as f32;
    let idf_weights: std::collections::HashMap<&str, f32> = if ctx.task_tokens.is_empty() {
        std::collections::HashMap::new()
    } else {
        ctx.task_tokens
            .iter()
            .map(|tok| {
                let df = index
                    .profiles
                    .iter()
                    .filter(|p| p.keywords.contains(tok))
                    .count() as f32;
                let idf = (n_personas / (df + 1.0) + 1.0).log2();
                (tok.as_str(), idf)
            })
            .collect()
    };
    // Maximum possible IDF sum (all tokens have df=0, i.e., unique per persona).
    let max_idf_sum: f32 = idf_weights.values().sum::<f32>().max(f32::EPSILON);

    let mut scored: Vec<Scored> = index
        .profiles
        .iter()
        .map(|profile| {
            // Language score: IDF-style precision -- reward personas whose language
            // set PRECISELY covers the context languages rather than broadly.
            // matching_langs / persona_lang_count gives higher scores to specialist
            // personas (fewer languages, tighter match) than generalist ones.
            // Blended 50/50 with the recall-side (lang_sum / ctx.lang_count) to
            // balance precision and recall.
            let matching_lang_sum: f32 = ctx
                .languages
                .iter()
                .filter(|(lang, _)| profile.languages.contains(*lang))
                .map(|(_, weight)| weight)
                .sum();
            let persona_lang_count = profile.languages.len().max(1) as f32;
            let lang_score = if ctx.languages.is_empty() {
                0.0
            } else {
                // Recall: fraction of context languages covered by this persona.
                let recall = (matching_lang_sum / ctx.languages.len() as f32).min(1.0);
                // Precision: fraction of persona's languages that are in the context.
                let precision = (matching_lang_sum / persona_lang_count).min(1.0);
                // F1-style blend: harmonic mean of precision and recall.
                if precision + recall > 0.0 {
                    2.0 * precision * recall / (precision + recall)
                } else {
                    0.0
                }
            };

            // Lexical score: IDF-weighted sum of task token hits normalized to [0.0, 1.0].
            // Rare task tokens (appearing in fewer personas) contribute more weight than
            // common tokens, rewarding specialist personas over generalist ones.
            let lex_score = if ctx.task_tokens.is_empty() {
                0.0
            } else {
                let hit_idf_sum: f32 = ctx
                    .task_tokens
                    .iter()
                    .filter(|tok| profile.keywords.contains(*tok))
                    .map(|tok| idf_weights.get(tok.as_str()).copied().unwrap_or(0.0))
                    .sum();
                (hit_idf_sum / max_idf_sum).min(1.0)
            };

            // Intent score: how well the persona's declared intents match the task intent.
            let intent_score = if let Some(task_intent) = ctx.inferred_intent {
                if profile.primary_intents.is_empty() {
                    0.0
                } else {
                    profile.primary_intents
                        .iter()
                        .map(|pi| crate::intent::relatedness(*pi, task_intent))
                        .fold(0.0_f32, f32::max)
                }
            } else {
                0.0
            };

            // Anti-keyword penalty: penalize lexical score if task tokens match anti-keywords.
            let anti_hit_count = if profile.anti_keywords.is_empty() {
                0
            } else {
                ctx.task_tokens
                    .iter()
                    .filter(|t| profile.anti_keywords.contains(t))
                    .count()
            };
            let lex_score = if anti_hit_count > 0 && !ctx.task_tokens.is_empty() {
                let penalty = (anti_hit_count as f32 / ctx.task_tokens.len() as f32) * 0.5;
                (lex_score - penalty).max(0.0)
            } else {
                lex_score
            };

            // Capability score: prefer personas with no required tools and no network egress.
            let cap_score = if profile.required_tools.is_empty() && !profile.network_egress {
                1.0
            } else if profile.required_tools.is_empty() || !profile.network_egress {
                0.5
            } else {
                0.0
            };

            // Blended score.
            let blended = weights.language * lang_score
                + weights.lexical * lex_score
                + weights.intent * intent_score
                + weights.capability * cap_score;

            // Apply preference bias and clamp.
            let bias = prefs.bias_for(&profile.name);
            let final_score = (blended + bias).clamp(0.0, 1.0);

            // Build rationale string.
            let mut rationale_parts: Vec<String> = Vec::new();
            if lang_score > 0.0 {
                let matched_langs: Vec<&str> = ctx
                    .languages
                    .keys()
                    .filter(|l| profile.languages.contains(*l))
                    .map(|l| l.as_str())
                    .collect();
                rationale_parts.push(format!(
                    "languages {{{}}}: lang_score={:.2}",
                    matched_langs.join(","),
                    lang_score
                ));
            }
            if lex_score > 0.0 {
                let hit_tokens: Vec<&str> = ctx
                    .task_tokens
                    .iter()
                    .filter(|tok| profile.keywords.contains(*tok))
                    .map(|t| t.as_str())
                    .collect();
                rationale_parts.push(format!(
                    "task tokens [{}] hit persona keywords: lex_score={:.2}",
                    hit_tokens.join(","),
                    lex_score
                ));
            }
            if intent_score > 0.0 {
                rationale_parts.push(format!("intent_score={:.2}", intent_score));
            }
            if cap_score > 0.0 {
                rationale_parts.push(format!("cap_score={:.2}", cap_score));
            }
            if bias.abs() > f32::EPSILON {
                rationale_parts.push(format!("pref_bias={:.3}", bias));
            }
            let rationale = if rationale_parts.is_empty() {
                format!("{}: no signal matched", profile.name)
            } else {
                format!(
                    "{} {:.2}: {}",
                    profile.name,
                    final_score,
                    rationale_parts.join("; ")
                )
            };

            let components = ScoreComponents {
                language: lang_score,
                lexical: lex_score,
                intent: intent_score,
                capability: cap_score,
            };

            Scored {
                persona: profile.name.clone(),
                score: final_score,
                confidence: 0.0, // filled in after sort
                rationale,
                components,
            }
        })
        .collect();

    // Sort descending by score.
    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Compute confidence for the top entry based on absolute score and margin.
    if let Some(top) = scored.first_mut() {
        top.confidence = top.score; // absolute component
    }
    if scored.len() >= 2 {
        let top_score = scored[0].score;
        let second_score = scored[1].score;
        let margin = (top_score - second_score).clamp(0.0, 1.0);
        // Blend absolute score and margin equally for confidence.
        scored[0].confidence = (top_score * 0.5 + margin * 0.5).clamp(0.0, 1.0);
    }

    scored
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{PersonaIndex, PersonaProfile};
    use std::collections::BTreeSet;

    /// Build a minimal PersonaProfile with given languages and keywords.
    fn make_profile(name: &str, languages: &[&str], keywords: &[&str]) -> PersonaProfile {
        PersonaProfile {
            name: name.to_string(),
            description: None,
            languages: languages
                .iter()
                .map(|l| l.to_string())
                .collect::<BTreeSet<_>>(),
            keywords: keywords.iter().map(|k| k.to_string()).collect(),
            required_tools: vec![],
            network_egress: false,
            primary_intents: vec![],
            anti_keywords: vec![],
        }
    }

    /// Build a ContextSignal with given languages and task tokens.
    fn make_ctx(languages: &[(&str, f32)], task_tokens: &[&str]) -> ContextSignal {
        use std::collections::BTreeMap;
        ContextSignal {
            project_name: "test".to_string(),
            languages: languages
                .iter()
                .map(|(l, w)| (l.to_string(), *w))
                .collect::<BTreeMap<_, _>>(),
            frameworks: vec![],
            task_tokens: task_tokens.iter().map(|t| t.to_string()).collect(),
            inferred_intent: None,
        }
    }

    /// A rust-heavy context ranks a rust persona above an unrelated one.
    #[test]
    fn rust_context_ranks_rust_persona_first() {
        let rust_profile = make_profile(
            "rust-expert",
            &["rust"],
            &["rust", "cargo", "clippy", "memory"],
        );
        let web_profile = make_profile(
            "web-designer",
            &["javascript", "typescript"],
            &["react", "css", "html", "frontend"],
        );
        let index = PersonaIndex {
            profiles: vec![rust_profile, web_profile],
        };

        let ctx = make_ctx(&[("rust", 1.0), ("toml", 0.2)], &["clippy", "lint"]);
        let weights = PolicyWeights::default();
        let prefs = Preferences::new();
        let ranked = rank(&ctx, &index, &weights, &prefs);

        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].persona, "rust-expert");
        assert!(ranked[0].score > ranked[1].score);
        assert!(!ranked[0].rationale.is_empty());
    }

    /// No-task-tokens: lexical score is zero for all; language score drives ranking.
    #[test]
    fn no_task_tokens_uses_language_score() {
        let rust_profile = make_profile("rust-expert", &["rust"], &["rust", "cargo"]);
        let py_profile = make_profile("python-dev", &["python"], &["python", "django"]);
        let index = PersonaIndex {
            profiles: vec![rust_profile, py_profile],
        };

        let ctx = make_ctx(&[("rust", 1.0)], &[]);
        let weights = PolicyWeights::default();
        let prefs = Preferences::new();
        let ranked = rank(&ctx, &index, &weights, &prefs);

        assert_eq!(ranked[0].persona, "rust-expert");
    }

    /// Preference bias nudges the score.
    #[test]
    fn preference_bias_nudges_score() {
        let a = make_profile("alpha", &["rust"], &["rust"]);
        let b = make_profile("beta", &["rust"], &["rust"]);
        let index = PersonaIndex {
            profiles: vec![a, b],
        };

        let ctx = make_ctx(&[("rust", 1.0)], &[]);
        let weights = PolicyWeights::default();
        let mut prefs = Preferences::new();
        // Strongly bias beta.
        for _ in 0..4 {
            prefs.record_override(Some("alpha"), "beta");
        }

        let ranked = rank(&ctx, &index, &weights, &prefs);
        assert_eq!(ranked[0].persona, "beta");
    }

    /// Empty index returns empty result.
    #[test]
    fn empty_index_returns_empty() {
        let index = PersonaIndex { profiles: vec![] };
        let ctx = make_ctx(&[("rust", 1.0)], &["foo"]);
        let ranked = rank(&ctx, &index, &PolicyWeights::default(), &Preferences::new());
        assert!(ranked.is_empty());
    }

    /// A persona whose primary_intents match the inferred task intent scores higher.
    #[test]
    fn intent_match_boosts_score() {
        use crate::intent::Intent;

        let mut rust = make_profile("rust-expert", &["rust"], &["rust", "cargo"]);
        rust.primary_intents = vec![Intent::Implementation, Intent::Debugging];

        let mut perf = make_profile("perf-expert", &["rust"], &["rust", "profiling"]);
        perf.primary_intents = vec![Intent::Performance];

        let index = PersonaIndex { profiles: vec![rust, perf] };
        let ctx = ContextSignal {
            project_name: "test".to_string(),
            languages: {
                let mut m = std::collections::BTreeMap::new();
                m.insert("rust".to_string(), 1.0);
                m
            },
            frameworks: vec![],
            task_tokens: vec!["debugging".to_string(), "error".to_string()],
            inferred_intent: Some(Intent::Debugging),
        };

        let ranked = rank(&ctx, &index, &PolicyWeights::default(), &Preferences::new());
        assert_eq!(ranked[0].persona, "rust-expert", "debugging intent should boost rust-expert");
    }

    /// Anti-keywords penalize the lexical score when task tokens match the blacklist.
    #[test]
    fn anti_keywords_penalize_score() {
        let mut persona_a = make_profile("backend", &["rust"], &["rust", "api"]);
        persona_a.anti_keywords = vec!["css".to_string(), "frontend".to_string()];

        let persona_b = make_profile("frontend", &["typescript"], &["react", "css"]);

        let index = PersonaIndex { profiles: vec![persona_a, persona_b] };
        let ctx = make_ctx(&[("rust", 1.0)], &["css", "styling", "frontend"]);

        let ranked = rank(&ctx, &index, &PolicyWeights::default(), &Preferences::new());
        let backend_entry = ranked.iter().find(|s| s.persona == "backend").unwrap();
        assert!(backend_entry.components.lexical < 0.3, "anti-keywords should penalize lexical score");
    }
}
