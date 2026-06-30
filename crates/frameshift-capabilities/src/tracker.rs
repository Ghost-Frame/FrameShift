use std::collections::BTreeSet;

use crate::report::UsageReport;

/// Records which capabilities were actually invoked during a session and diffs
/// them against the persona's declared manifest to produce a [`UsageReport`].
#[derive(Debug, Clone, Default)]
pub struct UsageTracker {
    declared: BTreeSet<String>,
    used: BTreeSet<String>,
}

impl UsageTracker {
    /// Construct a tracker seeded with the declared capability set.
    pub fn new<I, S>(declared: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            declared: declared.into_iter().map(Into::into).collect(),
            used: BTreeSet::new(),
        }
    }

    /// Record that `capability` was invoked. Idempotent: repeat calls collapse.
    pub fn record(&mut self, capability: &str) {
        self.used.insert(capability.to_string());
    }

    /// Snapshot the declared and used sets into a [`UsageReport`].
    pub fn report(&self) -> UsageReport {
        UsageReport::new(self.declared.clone(), self.used.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_reports_declared_but_unused() {
        let mut tracker = UsageTracker::new(["Read", "Edit", "Bash"]);
        tracker.record("Read");
        tracker.record("Read"); // idempotent

        let report = tracker.report();
        assert_eq!(
            report.declared,
            ["Bash", "Edit", "Read"]
                .into_iter()
                .map(String::from)
                .collect()
        );
        assert_eq!(
            report.used,
            ["Read"].into_iter().map(String::from).collect()
        );
        let unused: Vec<&str> = report
            .unused_capabilities()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(unused, vec!["Bash", "Edit"]);
    }

    #[test]
    fn tracker_reports_undeclared_invocations() {
        let mut tracker = UsageTracker::new(["Read"]);
        tracker.record("Read");
        tracker.record("Bash");

        let report = tracker.report();
        let undeclared: Vec<String> = report.undeclared_invocations().into_iter().collect();
        assert_eq!(undeclared, vec!["Bash".to_string()]);
    }
}
