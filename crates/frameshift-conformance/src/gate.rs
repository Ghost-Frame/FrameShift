use frameshift_pack::ConformanceBaseline;

/// Decision returned by [`RegressionGate::evaluate_cross_version`].
///
/// Compares two already-*shipped* baselines directly -- the conformance
/// score each pack version asserts about itself at publish time -- without
/// re-running any conformance tests. It answers "does the pack version we
/// are about to install over an existing install claim to be at least as
/// good as the one it replaces, and is that claim trustworthy?"
#[derive(Debug, Clone, PartialEq)]
pub enum CrossVersionDecision {
    /// The incoming version's shipped baseline meets or exceeds the
    /// installed version's shipped baseline, and the incoming baseline's
    /// integrity check passed.
    Pass,
    /// The incoming version's baseline score is below the installed
    /// version's baseline score by `delta` (positive value).
    Regression {
        /// `installed_baseline.score - incoming_baseline.score`, always positive.
        delta: f32,
    },
    /// The incoming pack's declared `conformance_baseline.bundle_hash` does not
    /// match the hash actually computed from its own shipped
    /// `conformance/bundle.toml`, or no such bundle is shipped at all (in
    /// which case `actual_hash` is `None`). Either way the incoming pack's
    /// claimed score cannot be verified against the bundle it was supposedly
    /// measured on, so it must not be trusted to pass an upgrade -- checked
    /// and reported before any score comparison, independent of whether the
    /// installed version has a baseline to compare against.
    IntegrityFailure {
        /// The bundle hash declared in the incoming pack's `pack.toml`.
        declared_hash: String,
        /// The hash actually computed from the incoming pack's shipped
        /// bundle, or `None` if the incoming pack ships no
        /// `conformance/bundle.toml` at all.
        actual_hash: Option<String>,
    },
    /// The installed version, the incoming version, or both ship no
    /// `[conformance_baseline]`, so there is nothing to compare.
    ///
    /// This is explicitly non-fatal: shipping a conformance baseline is
    /// optional, and an upgrade must never be blocked merely because
    /// historical baseline data happens to be absent on one or both sides.
    MissingBaseline {
        /// Whether the currently-installed version ships a baseline.
        installed_present: bool,
        /// Whether the incoming version ships a baseline.
        incoming_present: bool,
    },
    /// A baseline score was non-finite or outside `0.0..=1.0`; the gate fails
    /// closed rather than letting a malformed baseline slip through.
    InvalidScore,
}

/// Stateless evaluator. The runtime constructs one per upgrade attempt.
pub struct RegressionGate;

impl RegressionGate {
    /// Compare the *shipped* conformance baselines of an already-installed
    /// pack version and the incoming version about to replace it, without
    /// re-running any conformance tests.
    ///
    /// Evaluation order (first match wins):
    ///
    /// 1. **Integrity** -- if `incoming_baseline` is present, its declared
    ///    `bundle_hash` must equal `incoming_actual_bundle_hash` (the hash
    ///    actually computed from the incoming pack's own shipped
    ///    `conformance/bundle.toml`). A mismatch, or no bundle shipped at all
    ///    (`incoming_actual_bundle_hash` is `None`), yields
    ///    [`CrossVersionDecision::IntegrityFailure`] immediately -- an
    ///    unverifiable claim is rejected regardless of whether the installed
    ///    version has a baseline to compare against.
    /// 2. **Missing baseline** -- if either side has no baseline (including
    ///    the incoming side having passed step 1 vacuously because it has no
    ///    baseline to check), yields [`CrossVersionDecision::MissingBaseline`].
    ///    Not fatal: baselines are optional.
    /// 3. **Score validity** -- both scores must be finite and within
    ///    `0.0..=1.0`, else [`CrossVersionDecision::InvalidScore`] (fail closed).
    /// 4. **Regression** -- `incoming_baseline.score < installed_baseline.score`
    ///    yields [`CrossVersionDecision::Regression`]; otherwise
    ///    [`CrossVersionDecision::Pass`].
    pub fn evaluate_cross_version(
        installed_baseline: Option<&ConformanceBaseline>,
        incoming_baseline: Option<&ConformanceBaseline>,
        incoming_actual_bundle_hash: Option<&str>,
    ) -> CrossVersionDecision {
        let Some(incoming) = incoming_baseline else {
            return CrossVersionDecision::MissingBaseline {
                installed_present: installed_baseline.is_some(),
                incoming_present: false,
            };
        };

        // Integrity check takes priority: an incoming baseline that cannot be
        // verified against its own shipped bundle is untrustworthy on its own
        // terms, independent of whether we even have an installed baseline
        // to compare it to.
        match incoming_actual_bundle_hash {
            Some(actual) if actual == incoming.bundle_hash => {}
            other => {
                return CrossVersionDecision::IntegrityFailure {
                    declared_hash: incoming.bundle_hash.clone(),
                    actual_hash: other.map(str::to_string),
                };
            }
        }

        let Some(installed) = installed_baseline else {
            return CrossVersionDecision::MissingBaseline {
                installed_present: false,
                incoming_present: true,
            };
        };

        // Fail closed on non-finite or out-of-range scores: a NaN comparison
        // returns false and would otherwise fall through to Pass, letting a
        // malformed baseline slip through.
        let valid = |s: f32| s.is_finite() && (0.0..=1.0).contains(&s);
        if !valid(installed.score) || !valid(incoming.score) {
            return CrossVersionDecision::InvalidScore;
        }

        if incoming.score < installed.score {
            return CrossVersionDecision::Regression {
                delta: installed.score - incoming.score,
            };
        }

        CrossVersionDecision::Pass
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

    /// Incoming score above the installed baseline, with a verified bundle,
    /// passes.
    #[test]
    fn cross_version_passes_when_incoming_exceeds_installed() {
        let installed = baseline(0.7, "abc");
        let incoming = baseline(0.9, "abc");
        let decision =
            RegressionGate::evaluate_cross_version(Some(&installed), Some(&incoming), Some("abc"));
        assert_eq!(decision, CrossVersionDecision::Pass);
    }

    /// An equal score also passes (not a regression).
    #[test]
    fn cross_version_passes_when_incoming_equals_installed() {
        let installed = baseline(0.7, "abc");
        let incoming = baseline(0.7, "abc");
        let decision =
            RegressionGate::evaluate_cross_version(Some(&installed), Some(&incoming), Some("abc"));
        assert_eq!(decision, CrossVersionDecision::Pass);
    }

    /// Incoming score below the installed baseline reports a regression with
    /// the correct positive delta.
    #[test]
    fn cross_version_reports_regression() {
        let installed = baseline(0.9, "abc");
        let incoming = baseline(0.7, "abc");
        let decision =
            RegressionGate::evaluate_cross_version(Some(&installed), Some(&incoming), Some("abc"));
        match decision {
            CrossVersionDecision::Regression { delta } => {
                assert!((delta - 0.2).abs() < 1e-6, "delta was {delta}");
            }
            other => panic!("expected Regression, got {other:?}"),
        }
    }

    /// The incoming pack's declared bundle_hash not matching its own actual
    /// shipped bundle hash is an integrity failure, even though the score
    /// would otherwise pass.
    #[test]
    fn cross_version_integrity_failure_on_hash_mismatch() {
        let installed = baseline(0.5, "abc");
        let incoming = baseline(0.9, "abc");
        let decision = RegressionGate::evaluate_cross_version(
            Some(&installed),
            Some(&incoming),
            Some("tampered"),
        );
        assert_eq!(
            decision,
            CrossVersionDecision::IntegrityFailure {
                declared_hash: "abc".to_string(),
                actual_hash: Some("tampered".to_string()),
            }
        );
    }

    /// An incoming baseline with no shipped bundle at all (no
    /// `conformance/bundle.toml`) is also an integrity failure -- a claimed
    /// score with nothing to verify it against is untrustworthy.
    #[test]
    fn cross_version_integrity_failure_on_missing_bundle() {
        let installed = baseline(0.5, "abc");
        let incoming = baseline(0.9, "abc");
        let decision =
            RegressionGate::evaluate_cross_version(Some(&installed), Some(&incoming), None);
        assert_eq!(
            decision,
            CrossVersionDecision::IntegrityFailure {
                declared_hash: "abc".to_string(),
                actual_hash: None,
            }
        );
    }

    /// Integrity failure on the incoming side is reported even when the
    /// installed side has no baseline at all -- the check does not require
    /// a comparison partner.
    #[test]
    fn cross_version_integrity_failure_takes_priority_over_missing_installed() {
        let incoming = baseline(0.9, "abc");
        let decision =
            RegressionGate::evaluate_cross_version(None, Some(&incoming), Some("tampered"));
        assert_eq!(
            decision,
            CrossVersionDecision::IntegrityFailure {
                declared_hash: "abc".to_string(),
                actual_hash: Some("tampered".to_string()),
            }
        );
    }

    /// No incoming baseline at all: MissingBaseline, regardless of whether
    /// the installed side has one.
    #[test]
    fn cross_version_missing_baseline_when_incoming_absent() {
        let installed = baseline(0.5, "abc");
        let decision = RegressionGate::evaluate_cross_version(Some(&installed), None, None);
        assert_eq!(
            decision,
            CrossVersionDecision::MissingBaseline {
                installed_present: true,
                incoming_present: false,
            }
        );

        let decision_both_absent = RegressionGate::evaluate_cross_version(None, None, None);
        assert_eq!(
            decision_both_absent,
            CrossVersionDecision::MissingBaseline {
                installed_present: false,
                incoming_present: false,
            }
        );
    }

    /// Incoming baseline present and verified, but no installed baseline to
    /// compare against: MissingBaseline, not Pass or Regression.
    #[test]
    fn cross_version_missing_baseline_when_installed_absent() {
        let incoming = baseline(0.9, "abc");
        let decision = RegressionGate::evaluate_cross_version(None, Some(&incoming), Some("abc"));
        assert_eq!(
            decision,
            CrossVersionDecision::MissingBaseline {
                installed_present: false,
                incoming_present: true,
            }
        );
    }

    /// Non-finite or out-of-range scores on either side fail closed, once
    /// past the integrity and missing-baseline checks.
    #[test]
    fn cross_version_fails_closed_on_invalid_score() {
        let installed_nan = baseline(f32::NAN, "abc");
        let incoming = baseline(0.9, "abc");
        assert_eq!(
            RegressionGate::evaluate_cross_version(
                Some(&installed_nan),
                Some(&incoming),
                Some("abc")
            ),
            CrossVersionDecision::InvalidScore
        );

        let installed = baseline(0.5, "abc");
        let incoming_out_of_range = baseline(1.5, "abc");
        assert_eq!(
            RegressionGate::evaluate_cross_version(
                Some(&installed),
                Some(&incoming_out_of_range),
                Some("abc")
            ),
            CrossVersionDecision::InvalidScore
        );
    }
}
