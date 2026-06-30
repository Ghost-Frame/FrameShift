use crate::bundle::TestBundle;
use crate::case::{ExpectedBehavior, ScorerKind, TestCase};

/// A 0.0..=1.0 score; 0 = total failure, 1 = perfect.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Score(pub f32);

impl Score {
    /// The lowest possible score: the response completely failed the test.
    pub const ZERO: Score = Score(0.0);
    /// The highest possible score: the response perfectly satisfied the test.
    pub const PERFECT: Score = Score(1.0);
}

/// Score a single test case against a response string.
///
/// Returns [`Score::PERFECT`] when the response satisfies the expected behavior,
/// and [`Score::ZERO`] for any mismatch, parse failure, or unsupported pairing.
/// The `Caller` variant always returns [`Score::ZERO`] here -- use
/// [`crate::caller::score_bundle_with_caller`] to delegate those cases to a
/// [`crate::caller::CallerScorer`] implementation.
pub fn score_test(test: &TestCase, response: &str) -> Score {
    match test.scorer {
        ScorerKind::Substring => match &test.expected {
            ExpectedBehavior::Contains { value } => {
                if response.contains(value.as_str()) {
                    Score::PERFECT
                } else {
                    Score::ZERO
                }
            }
            _ => Score::ZERO,
        },
        ScorerKind::Regex => match &test.expected {
            ExpectedBehavior::Matches { pattern } => match regex::Regex::new(pattern) {
                Ok(re) => {
                    if re.is_match(response) {
                        Score::PERFECT
                    } else {
                        Score::ZERO
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        pattern = %pattern,
                        "invalid regex in test case {}",
                        test.id
                    );
                    Score::ZERO
                }
            },
            _ => Score::ZERO,
        },
        ScorerKind::ExactJson => match &test.expected {
            ExpectedBehavior::JsonShape { shape } => {
                match serde_json::from_str::<serde_json::Value>(response) {
                    Ok(parsed) => {
                        if parsed == *shape {
                            Score::PERFECT
                        } else {
                            Score::ZERO
                        }
                    }
                    Err(_) => Score::ZERO,
                }
            }
            _ => Score::ZERO,
        },
        ScorerKind::Caller => {
            tracing::warn!(
                test_id = %test.id,
                "score_test called with Caller scorer; returning ZERO -- use score_bundle_with_caller instead"
            );
            Score::ZERO
        }
    }
}

/// Average per-test score across the bundle's declared test set.
///
/// Scoring iterates the bundle's canonical `tests` and matches each to a
/// response by test id. This closes two gaming vectors in the prior
/// average-over-results implementation:
///
/// - A test with no corresponding result scores [`Score::ZERO`], so omitting a
///   failing test from the results cannot raise the average.
/// - Only the first response per test id is counted, so padding the results
///   with extra passing entries (or duplicating one) cannot raise it either.
///
/// Each test is scored with the bundle's authoritative [`TestCase`], never a
/// client-supplied one carried alongside the response. Empty bundles score
/// [`Score::ZERO`].
pub fn bundle_score(bundle: &TestBundle, results: &[(TestCase, String)]) -> Score {
    if bundle.tests.is_empty() {
        return Score::ZERO;
    }
    // First response wins per id, so duplicate result entries cannot skew the average.
    let responses = first_response_per_id(results);
    let total: f32 = bundle
        .tests
        .iter()
        .map(|test| match responses.get(test.id.as_str()) {
            Some(response) => score_test(test, response).0,
            None => Score::ZERO.0,
        })
        .sum();
    Score(total / bundle.tests.len() as f32)
}

/// Build an id -> response map from runner results, keeping only the first
/// response seen for each test id. Shared by [`bundle_score`] and
/// [`crate::caller::score_bundle_with_caller`] so both resist omitted and
/// duplicated result entries identically.
pub(crate) fn first_response_per_id(
    results: &[(TestCase, String)],
) -> std::collections::HashMap<&str, &str> {
    let mut responses: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for (case, response) in results {
        responses
            .entry(case.id.as_str())
            .or_insert(response.as_str());
    }
    responses
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::TestBundle;
    use crate::caller::{score_bundle_with_caller, CallerScorer};
    use crate::case::{ExpectedBehavior, ScorerKind, TestCase};

    /// Build a minimal TestCase with the given id, expected behavior, and scorer.
    fn make_case(id: &str, expected: ExpectedBehavior, scorer: ScorerKind) -> TestCase {
        TestCase {
            id: id.to_string(),
            prompt: "prompt".to_string(),
            expected,
            scorer,
        }
    }

    /// Build a minimal TestBundle for use in bundle-level tests.
    fn make_bundle() -> TestBundle {
        TestBundle {
            name: "test".to_string(),
            version: "0.1.0".to_string(),
            tests: vec![],
        }
    }

    // -- Regex scorer tests --

    #[test]
    /// Regex that appears as a substring of the response scores PERFECT.
    fn regex_scorer_matches_substring() {
        let case = make_case(
            "t1",
            ExpectedBehavior::Matches {
                pattern: "hello".to_string(),
            },
            ScorerKind::Regex,
        );
        assert_eq!(score_test(&case, "say hello"), Score::PERFECT);
    }

    #[test]
    /// Regex that does not match any part of the response scores ZERO.
    fn regex_scorer_no_match() {
        let case = make_case(
            "t2",
            ExpectedBehavior::Matches {
                pattern: "goodbye".to_string(),
            },
            ScorerKind::Regex,
        );
        assert_eq!(score_test(&case, "hello"), Score::ZERO);
    }

    #[test]
    /// Anchored regex `^hello` does not match "say hello" (anchor blocks it).
    fn regex_scorer_anchored() {
        let case = make_case(
            "t3",
            ExpectedBehavior::Matches {
                pattern: "^hello".to_string(),
            },
            ScorerKind::Regex,
        );
        assert_eq!(score_test(&case, "say hello"), Score::ZERO);
    }

    #[test]
    /// An invalid regex pattern scores ZERO without panicking.
    fn regex_scorer_invalid_pattern() {
        let case = make_case(
            "t4",
            ExpectedBehavior::Matches {
                pattern: "[unclosed".to_string(),
            },
            ScorerKind::Regex,
        );
        assert_eq!(score_test(&case, "anything"), Score::ZERO);
    }

    // -- ExactJson scorer tests --

    #[test]
    /// Response JSON that is byte-for-byte equal to the shape scores PERFECT.
    fn exact_json_equal() {
        let shape: serde_json::Value = serde_json::json!({"x": 1});
        let case = make_case(
            "j1",
            ExpectedBehavior::JsonShape { shape },
            ScorerKind::ExactJson,
        );
        assert_eq!(score_test(&case, r#"{"x":1}"#), Score::PERFECT);
    }

    #[test]
    /// Response JSON that differs from the shape scores ZERO.
    fn exact_json_not_equal() {
        let shape: serde_json::Value = serde_json::json!({"x": 1});
        let case = make_case(
            "j2",
            ExpectedBehavior::JsonShape { shape },
            ScorerKind::ExactJson,
        );
        assert_eq!(score_test(&case, r#"{"x":2}"#), Score::ZERO);
    }

    #[test]
    /// A response that is not valid JSON scores ZERO.
    fn exact_json_invalid_response() {
        let shape: serde_json::Value = serde_json::json!({"x": 1});
        let case = make_case(
            "j3",
            ExpectedBehavior::JsonShape { shape },
            ScorerKind::ExactJson,
        );
        assert_eq!(score_test(&case, "not json"), Score::ZERO);
    }

    #[test]
    /// A JSON number response does not match a JSON object shape.
    fn exact_json_type_mismatch() {
        let shape: serde_json::Value = serde_json::json!({"x": 1});
        let case = make_case(
            "j4",
            ExpectedBehavior::JsonShape { shape },
            ScorerKind::ExactJson,
        );
        assert_eq!(score_test(&case, "1"), Score::ZERO);
    }

    // -- Caller scorer tests --

    #[test]
    /// score_test with ScorerKind::Caller always returns ZERO.
    fn caller_returns_zero_in_score_test() {
        let case = make_case(
            "c1",
            ExpectedBehavior::Custom {
                id: "my-judge".to_string(),
            },
            ScorerKind::Caller,
        );
        assert_eq!(score_test(&case, "any response"), Score::ZERO);
    }

    /// A mock CallerScorer that always returns PERFECT for use in tests.
    struct AlwaysPerfect;

    impl CallerScorer for AlwaysPerfect {
        /// Always returns PERFECT regardless of the test case or response.
        fn score(&self, _test: &TestCase, _response: &str) -> Score {
            Score::PERFECT
        }
    }

    #[test]
    /// score_bundle_with_caller delegates Caller cases to the CallerScorer.
    fn bundle_with_caller_trait() {
        // The case must be part of the bundle's canonical test set to be scored.
        let mut bundle = make_bundle();
        bundle.tests.push(make_case(
            "c2",
            ExpectedBehavior::Custom {
                id: "judge".to_string(),
            },
            ScorerKind::Caller,
        ));
        let results = vec![(
            make_case(
                "c2",
                ExpectedBehavior::Custom {
                    id: "judge".to_string(),
                },
                ScorerKind::Caller,
            ),
            "response".to_string(),
        )];
        let scorer = AlwaysPerfect;
        let score = score_bundle_with_caller(&bundle, &results, &scorer);
        assert_eq!(score, Score::PERFECT);
    }

    #[test]
    /// Omitting a failing test's result cannot inflate the score: the bundle
    /// declares two substring tests, but only the passing one is reported. The
    /// missing one must score ZERO, yielding 0.5 rather than a gamed 1.0.
    fn omitted_result_scores_zero() {
        let pass = make_case(
            "p",
            ExpectedBehavior::Contains {
                value: "ok".to_string(),
            },
            ScorerKind::Substring,
        );
        let fail = make_case(
            "f",
            ExpectedBehavior::Contains {
                value: "ok".to_string(),
            },
            ScorerKind::Substring,
        );
        let mut bundle = make_bundle();
        bundle.tests.push(pass.clone());
        bundle.tests.push(fail);
        // Only the passing test's result is supplied; the failing one is omitted.
        let results = vec![(pass, "ok".to_string())];
        assert_eq!(bundle_score(&bundle, &results), Score(0.5));
    }

    #[test]
    /// Duplicated passing results cannot inflate the score: a single declared
    /// test scored against three identical passing results still yields 1.0
    /// (counted once), and padding does not change the denominator.
    fn duplicated_results_counted_once() {
        let pass = make_case(
            "p",
            ExpectedBehavior::Contains {
                value: "ok".to_string(),
            },
            ScorerKind::Substring,
        );
        let mut bundle = make_bundle();
        bundle.tests.push(pass.clone());
        let results = vec![
            (pass.clone(), "ok".to_string()),
            (pass.clone(), "ok".to_string()),
            (pass, "ok".to_string()),
        ];
        assert_eq!(bundle_score(&bundle, &results), Score::PERFECT);
    }
}
