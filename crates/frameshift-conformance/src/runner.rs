//! Shared path-free execution of typed conformance bundles through pluggable runners.

use crate::error::ConformanceError;
use crate::{score_test, ScorerKind, TestBundle};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Abstracts the model adapter that turns a prompt into a response.
///
/// The runtime supplies a real impl (HTTP call to Anthropic/OpenAI/etc.);
/// tests use [`MockRunner`].
#[async_trait]
pub trait Runner: Send + Sync {
    /// Produce one response for a public conformance prompt.
    async fn run(&self, prompt: &str) -> Result<String, ConformanceError>;
}

/// Always returns the same canned response. Used by tests and for offline
/// development of the harness itself.
pub struct MockRunner {
    /// Response returned for every prompt.
    pub canned_response: String,
}

/// Construction helpers for the deterministic offline runner.
impl MockRunner {
    /// Create an offline runner that returns `canned_response` for every prompt.
    pub fn new(canned_response: impl Into<String>) -> Self {
        Self {
            canned_response: canned_response.into(),
        }
    }
}

/// Execute prompts without network access by returning one canned response.
#[async_trait]
impl Runner for MockRunner {
    /// Return the configured response without inspecting the prompt.
    async fn run(&self, _prompt: &str) -> Result<String, ConformanceError> {
        Ok(self.canned_response.clone())
    }
}

/// Path-free score for one declared conformance test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConformanceTestResult {
    /// Stable test identifier from the authoritative bundle.
    pub id: String,
    /// Built-in scoring strategy applied to the response.
    pub scorer: ScorerKind,
    /// Score constrained by the selected scorer to `0.0..=1.0`.
    pub score: f32,
}

/// Path-free aggregate returned after every declared test executes exactly once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConformanceRunReport {
    /// Average score across the authoritative bundle test set.
    pub score: f32,
    /// Per-test scores in bundle declaration order.
    pub tests: Vec<ConformanceTestResult>,
}

/// Execute every declared test once and discard raw responses after scoring.
pub async fn run_bundle(
    bundle: &TestBundle,
    runner: &dyn Runner,
) -> Result<ConformanceRunReport, ConformanceError> {
    if let Some(test) = bundle
        .tests
        .iter()
        .find(|test| test.scorer == ScorerKind::Caller)
    {
        return Err(ConformanceError::UnsupportedCallerScorer(test.id.clone()));
    }

    let mut tests = Vec::with_capacity(bundle.tests.len());
    let mut total = 0.0;
    for test in &bundle.tests {
        let response = runner.run(&test.prompt).await?;
        let score = score_test(test, &response).0;
        total += score;
        tests.push(ConformanceTestResult {
            id: test.id.clone(),
            scorer: test.scorer,
            score,
        });
    }
    let score = if tests.is_empty() {
        0.0
    } else {
        total / tests.len() as f32
    };
    Ok(ConformanceRunReport { score, tests })
}

#[cfg(test)]
/// Tests for offline runners and the shared bundle executor.
mod tests {
    use super::*;
    use crate::{ExpectedBehavior, TestCase};

    /// The offline runner returns its configured response exactly.
    #[tokio::test]
    async fn mock_runner_returns_canned_response() {
        let runner = MockRunner::new("hello world");
        let response = runner.run("anything").await.expect("runner");
        assert_eq!(response, "hello world");
    }

    /// Shared execution preserves bundle order and excludes raw responses.
    #[tokio::test]
    async fn bundle_execution_returns_path_free_scores() {
        let bundle = TestBundle {
            name: "runner-test".to_string(),
            version: "1.0.0".to_string(),
            tests: vec![TestCase {
                id: "contains-greeting".to_string(),
                prompt: "Return a greeting.".to_string(),
                expected: ExpectedBehavior::Contains {
                    value: "hello".to_string(),
                },
                scorer: ScorerKind::Substring,
            }],
        };

        let report = run_bundle(&bundle, &MockRunner::new("hello world"))
            .await
            .expect("bundle execution");
        assert_eq!(report.score, 1.0);
        assert_eq!(
            report.tests,
            vec![ConformanceTestResult {
                id: "contains-greeting".to_string(),
                scorer: ScorerKind::Substring,
                score: 1.0,
            }]
        );
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("hello world"));
    }

    /// Caller-scored tests fail before any runner invocation can occur.
    #[tokio::test]
    async fn bundle_execution_rejects_missing_caller_scorer() {
        let bundle = TestBundle {
            name: "runner-test".to_string(),
            version: "1.0.0".to_string(),
            tests: vec![TestCase {
                id: "judged".to_string(),
                prompt: "Return anything.".to_string(),
                expected: ExpectedBehavior::Custom {
                    id: "judge".to_string(),
                },
                scorer: ScorerKind::Caller,
            }],
        };

        let error = run_bundle(&bundle, &MockRunner::new("unused"))
            .await
            .expect_err("caller scorer must be explicit");
        assert!(matches!(
            error,
            ConformanceError::UnsupportedCallerScorer(id) if id == "judged"
        ));
    }
}
