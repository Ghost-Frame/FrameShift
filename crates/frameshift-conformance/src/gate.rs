use crate::score::Score;
use frameshift_pack::ConformanceBaseline;

/// Decision returned by [`RegressionGate::evaluate_upgrade`].
#[derive(Debug, Clone, PartialEq)]
pub enum GateDecision {
    /// Upgrade clears the baseline.
    Pass,
    /// New score is below the old baseline by `delta` (positive value).
    FailRegression { delta: f32 },
    /// Bundle hash changed, so the baseline cannot be compared directly.
    FailBundleChanged,
    /// A score was non-finite or outside `0.0..=1.0`; the gate fails closed
    /// rather than letting a malformed baseline or buggy scorer slip through.
    FailInvalidScore,
}

/// Stateless evaluator. The runtime constructs one per upgrade attempt.
pub struct RegressionGate;

impl RegressionGate {
    /// Compare a new run's score against the baseline shipped with the
    /// previous pack version.
    ///
    /// Rules:
    /// 1. If the bundle hash changed, fail with [`GateDecision::FailBundleChanged`].
    ///    Comparing scores across different bundles is meaningless.
    /// 2. Otherwise if `new_score < old_baseline.score`, fail regression.
    /// 3. Otherwise pass.
    pub fn evaluate_upgrade(
        old_baseline: &ConformanceBaseline,
        new_score: Score,
        new_bundle_hash: &str,
    ) -> GateDecision {
        // Fail closed on non-finite or out-of-range scores: a NaN comparison
        // returns false and would otherwise fall through to Pass, letting a
        // malformed baseline or buggy custom scorer bypass regression blocking.
        let valid = |s: f32| s.is_finite() && (0.0..=1.0).contains(&s);
        if !valid(old_baseline.score) || !valid(new_score.0) {
            return GateDecision::FailInvalidScore;
        }
        if old_baseline.bundle_hash != new_bundle_hash {
            return GateDecision::FailBundleChanged;
        }
        if new_score.0 < old_baseline.score {
            return GateDecision::FailRegression {
                delta: old_baseline.score - new_score.0,
            };
        }
        GateDecision::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline(score: f32, hash: &str) -> ConformanceBaseline {
        ConformanceBaseline {
            score,
            bundle_hash: hash.to_string(),
        }
    }

    /// Non-finite or out-of-range scores fail closed.
    #[test]
    fn gate_fails_closed_on_invalid_score() {
        let nan_baseline = baseline(f32::NAN, "abc");
        assert_eq!(
            RegressionGate::evaluate_upgrade(&nan_baseline, Score(0.9), "abc"),
            GateDecision::FailInvalidScore
        );
        let ok_baseline = baseline(0.8, "abc");
        assert_eq!(
            RegressionGate::evaluate_upgrade(&ok_baseline, Score(f32::INFINITY), "abc"),
            GateDecision::FailInvalidScore
        );
        assert_eq!(
            RegressionGate::evaluate_upgrade(&ok_baseline, Score(1.5), "abc"),
            GateDecision::FailInvalidScore
        );
    }

    #[test]
    fn gate_passes_when_score_meets_baseline() {
        let b = baseline(0.8, "abc");
        let decision = RegressionGate::evaluate_upgrade(&b, Score(0.85), "abc");
        assert_eq!(decision, GateDecision::Pass);

        let decision_eq = RegressionGate::evaluate_upgrade(&b, Score(0.8), "abc");
        assert_eq!(decision_eq, GateDecision::Pass);
    }

    #[test]
    fn gate_fails_on_regression() {
        let b = baseline(0.9, "abc");
        let decision = RegressionGate::evaluate_upgrade(&b, Score(0.7), "abc");
        match decision {
            GateDecision::FailRegression { delta } => {
                assert!((delta - 0.2).abs() < 1e-6, "delta was {delta}");
            }
            other => panic!("expected FailRegression, got {other:?}"),
        }
    }

    #[test]
    fn gate_fails_on_bundle_change() {
        let b = baseline(0.5, "abc");
        let decision = RegressionGate::evaluate_upgrade(&b, Score(1.0), "xyz");
        assert_eq!(decision, GateDecision::FailBundleChanged);
    }
}
