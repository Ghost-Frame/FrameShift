//! Drift-controlled switching state machine for automate mode.

use crate::policy::Scored;

/// The current state of the automate-mode controller.
#[derive(Debug, Clone, PartialEq)]
pub enum AutomateState {
    /// Automate mode is disabled.
    Off,

    /// Mode is enabled but no persona has been selected yet (or re-evaluation is pending).
    Armed,

    /// A persona is actively in use with recorded confidence.
    Active {
        /// The name of the currently active persona.
        persona: String,
        /// The confidence score at the time of last selection.
        confidence: f32,
    },

    /// The persona was explicitly pinned by the user; auto-switching is suppressed.
    Locked {
        /// The name of the locked persona.
        persona: String,
    },
}

/// Hysteresis parameters controlling when a persona switch is permitted.
#[derive(Debug, Clone)]
pub struct SwitchPolicy {
    /// Minimum confidence required to accept the top candidate as active.
    pub min_confidence: f32,

    /// Minimum score advantage the new candidate must have over the current
    /// active persona before a switch is allowed.
    pub switch_margin: f32,

    /// Number of consecutive `decide` calls the new candidate must be top-ranked
    /// before the switch is actually executed (debounce).
    pub debounce_ticks: u32,
}

impl Default for SwitchPolicy {
    /// Returns the default policy: min_confidence=0.55, switch_margin=0.15, debounce_ticks=2.
    fn default() -> Self {
        SwitchPolicy {
            min_confidence: 0.55,
            switch_margin: 0.15,
            debounce_ticks: 2,
        }
    }
}

/// The outcome of a `decide` call.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Stay with the current persona (or remain unarmed); no change warranted.
    Hold,

    /// Switch to a new persona.
    Switch {
        /// The name of the persona to switch to.
        to: String,
        /// Human-readable rationale for the switch.
        rationale: String,
        /// Confidence score at time of switch.
        confidence: f32,
    },

    /// No candidates passed the confidence threshold (ranked list is empty or all below min).
    NoCandidates,
}

/// Drift-controlled state machine that decides when to switch personas.
///
/// Implements hysteresis: an active persona is not displaced unless the
/// challenger has been consistently ranked higher for `debounce_ticks`
/// consecutive calls AND its score advantage exceeds `switch_margin`.
pub struct SwitchController {
    /// Current automate state.
    state: AutomateState,

    /// Switching hysteresis policy parameters.
    policy: SwitchPolicy,

    /// Number of consecutive ticks the current challenger has been ahead.
    debounce_count: u32,

    /// The persona that is currently being tracked as a challenger (for debounce).
    challenger: Option<String>,
}

impl SwitchController {
    /// Create a new `SwitchController` in the `Off` state with the given policy.
    pub fn new(policy: SwitchPolicy) -> Self {
        SwitchController {
            state: AutomateState::Off,
            policy,
            debounce_count: 0,
            challenger: None,
        }
    }

    /// Transition to `Armed` state, enabling automate mode.
    ///
    /// If currently `Active`, the active persona is retained but the controller
    /// will re-evaluate on the next `decide` call. If `Off`, transitions to `Armed`.
    pub fn arm(&mut self) {
        match &self.state {
            AutomateState::Off | AutomateState::Armed => {
                self.state = AutomateState::Armed;
            }
            AutomateState::Active { .. } => {
                // Retain active persona but signal re-evaluation is welcome.
                self.state = AutomateState::Armed;
            }
            AutomateState::Locked { .. } => {
                // Locking takes priority over arming; no-op.
            }
        }
        self.debounce_count = 0;
        self.challenger = None;
    }

    /// Explicitly lock the current or named persona; auto-switching is suppressed.
    ///
    /// If currently `Active`, locks that persona. If `Armed` or `Off`, does nothing
    /// meaningful (no persona to lock) but records a Locked state with empty name.
    pub fn lock(&mut self) {
        let locked_name = match &self.state {
            AutomateState::Active { persona, .. } => persona.clone(),
            AutomateState::Locked { persona } => persona.clone(),
            _ => String::new(),
        };
        self.state = AutomateState::Locked { persona: locked_name };
        self.debounce_count = 0;
        self.challenger = None;
    }

    /// Unlock, returning to `Armed` state for re-evaluation.
    pub fn unlock(&mut self) {
        self.state = AutomateState::Armed;
        self.debounce_count = 0;
        self.challenger = None;
    }

    /// Return a reference to the current state.
    pub fn state(&self) -> &AutomateState {
        &self.state
    }

    /// Evaluate a fresh ranking and decide whether to switch personas.
    ///
    /// Logic:
    /// - `Locked`: always `Hold` regardless of ranking.
    /// - Empty `ranked` or top confidence < `min_confidence`: `NoCandidates` or `Hold`.
    /// - `Armed` / `Off`: switch immediately to top if confidence passes threshold.
    /// - `Active(p)`: switch only if challenger != p AND score advantage >=
    ///   `switch_margin` AND debounce counter has been saturated.
    ///
    /// Updates internal state and debounce counter on switch.
    pub fn decide(&mut self, ranked: &[Scored]) -> Decision {
        // Locked: always hold, never auto-switch.
        if matches!(self.state, AutomateState::Locked { .. }) {
            return Decision::Hold;
        }

        // No candidates at all.
        if ranked.is_empty() {
            return Decision::NoCandidates;
        }

        let top = &ranked[0];

        // Top confidence below threshold.
        if top.confidence < self.policy.min_confidence {
            // Reset debounce since top didn't qualify.
            self.debounce_count = 0;
            self.challenger = None;
            return Decision::Hold;
        }

        match &self.state.clone() {
            AutomateState::Off | AutomateState::Armed => {
                // Arm/Off: accept top candidate immediately.
                self.state = AutomateState::Active {
                    persona: top.persona.clone(),
                    confidence: top.confidence,
                };
                self.debounce_count = 0;
                self.challenger = None;
                Decision::Switch {
                    to: top.persona.clone(),
                    rationale: top.rationale.clone(),
                    confidence: top.confidence,
                }
            }

            AutomateState::Active { persona: current, .. } => {
                if top.persona == *current {
                    // Same persona at top -- reset challenger tracking, hold.
                    self.debounce_count = 0;
                    self.challenger = None;
                    return Decision::Hold;
                }

                // Find score of the current active persona in ranked list.
                let current_score = ranked
                    .iter()
                    .find(|s| &s.persona == current)
                    .map(|s| s.score)
                    .unwrap_or(0.0);

                let advantage = top.score - current_score;

                if advantage < self.policy.switch_margin {
                    // Advantage too small; not worth switching.
                    self.debounce_count = 0;
                    self.challenger = None;
                    return Decision::Hold;
                }

                // Track debounce for this challenger.
                let same_challenger = self.challenger.as_deref() == Some(top.persona.as_str());
                if same_challenger {
                    self.debounce_count += 1;
                } else {
                    self.challenger = Some(top.persona.clone());
                    self.debounce_count = 1;
                }

                if self.debounce_count >= self.policy.debounce_ticks {
                    // Debounce satisfied -- switch.
                    let new_persona = top.persona.clone();
                    let rationale = top.rationale.clone();
                    let confidence = top.confidence;
                    self.state = AutomateState::Active {
                        persona: new_persona.clone(),
                        confidence,
                    };
                    self.debounce_count = 0;
                    self.challenger = None;
                    Decision::Switch {
                        to: new_persona,
                        rationale,
                        confidence,
                    }
                } else {
                    Decision::Hold
                }
            }

            // Locked handled at top.
            AutomateState::Locked { .. } => Decision::Hold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ScoreComponents;

    /// Build a minimal Scored entry for controller tests.
    fn scored(name: &str, score: f32, confidence: f32) -> Scored {
        Scored {
            persona: name.to_string(),
            score,
            confidence,
            rationale: format!("{name} rationale"),
            components: ScoreComponents {
                language: score,
                lexical: 0.0,
                intent: 0.0,
                capability: 0.0,
            },
        }
    }

    /// A brief weaker competitor must NOT switch an Active persona (debounce + margin).
    #[test]
    fn weaker_competitor_does_not_switch_active() {
        let policy = SwitchPolicy {
            min_confidence: 0.5,
            switch_margin: 0.15,
            debounce_ticks: 2,
        };
        let mut ctrl = SwitchController::new(policy);
        ctrl.arm();

        // Establish active persona with high confidence.
        let ranked_a = vec![scored("alpha", 0.9, 0.85), scored("beta", 0.5, 0.3)];
        let d = ctrl.decide(&ranked_a);
        assert!(matches!(d, Decision::Switch { to, .. } if to == "alpha"));

        // Beta briefly tops the list but advantage is too small.
        let ranked_b = vec![scored("beta", 0.95, 0.8), scored("alpha", 0.88, 0.6)];
        // advantage = 0.95 - 0.88 = 0.07 < switch_margin 0.15 -> Hold
        let d2 = ctrl.decide(&ranked_b);
        assert_eq!(d2, Decision::Hold, "small advantage must not trigger switch");
    }

    /// A sustained clearly-stronger competitor DOES switch after debounce.
    #[test]
    fn sustained_strong_competitor_does_switch() {
        let policy = SwitchPolicy {
            min_confidence: 0.5,
            switch_margin: 0.15,
            debounce_ticks: 2,
        };
        let mut ctrl = SwitchController::new(policy);
        ctrl.arm();

        // Establish alpha as active.
        let ranked_a = vec![scored("alpha", 0.7, 0.65), scored("beta", 0.3, 0.2)];
        ctrl.decide(&ranked_a);
        assert!(matches!(ctrl.state(), AutomateState::Active { persona, .. } if persona == "alpha"));

        // Beta clearly stronger: advantage 0.9 - 0.5 = 0.4 > 0.15.
        let ranked_b = vec![scored("beta", 0.9, 0.85), scored("alpha", 0.5, 0.4)];

        // First tick -- debounce_count becomes 1, still Hold.
        let d1 = ctrl.decide(&ranked_b);
        assert_eq!(d1, Decision::Hold, "first tick should still hold");

        // Second tick -- debounce saturated, switch.
        let d2 = ctrl.decide(&ranked_b);
        assert!(matches!(d2, Decision::Switch { to, .. } if to == "beta"), "second tick should switch");
    }

    /// Locked state never auto-switches regardless of ranking.
    #[test]
    fn locked_never_switches() {
        let policy = SwitchPolicy::default();
        let mut ctrl = SwitchController::new(policy);
        ctrl.arm();

        // Establish active.
        let ranked_a = vec![scored("alpha", 0.9, 0.85)];
        ctrl.decide(&ranked_a);

        ctrl.lock();
        assert!(matches!(ctrl.state(), AutomateState::Locked { .. }));

        // Even a perfect candidate doesn't switch.
        let ranked_b = vec![scored("beta", 1.0, 1.0), scored("alpha", 0.1, 0.1)];
        let d = ctrl.decide(&ranked_b);
        assert_eq!(d, Decision::Hold, "locked must never switch");
        assert!(matches!(ctrl.state(), AutomateState::Locked { .. }));
    }

    /// Low-confidence top candidate yields Hold.
    #[test]
    fn low_confidence_top_yields_hold() {
        let policy = SwitchPolicy {
            min_confidence: 0.55,
            switch_margin: 0.15,
            debounce_ticks: 2,
        };
        let mut ctrl = SwitchController::new(policy);
        ctrl.arm();

        // Top candidate has confidence below threshold.
        let ranked = vec![scored("alpha", 0.4, 0.3)];
        let d = ctrl.decide(&ranked);
        assert_eq!(d, Decision::Hold, "low confidence must yield Hold");
    }

    /// arm() while Active transitions to Armed (re-evaluation welcome).
    #[test]
    fn arm_while_active_rearms() {
        let policy = SwitchPolicy::default();
        let mut ctrl = SwitchController::new(policy);
        ctrl.arm();
        let ranked = vec![scored("alpha", 0.9, 0.85)];
        ctrl.decide(&ranked);
        assert!(matches!(ctrl.state(), AutomateState::Active { .. }));

        ctrl.arm();
        assert_eq!(*ctrl.state(), AutomateState::Armed);
    }

    /// unlock() returns to Armed state.
    #[test]
    fn unlock_returns_to_armed() {
        let policy = SwitchPolicy::default();
        let mut ctrl = SwitchController::new(policy);
        ctrl.arm();
        let ranked = vec![scored("alpha", 0.9, 0.85)];
        ctrl.decide(&ranked);
        ctrl.lock();
        ctrl.unlock();
        assert_eq!(*ctrl.state(), AutomateState::Armed);
    }
}
