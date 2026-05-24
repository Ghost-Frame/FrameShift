//! Implementation of the `frameshift verify` subcommand.
//!
//! Loads a conformance bundle from a persona's source directory (or a
//! directly-specified bundle path), runs each test case through a
//! [`MockRunner`] with a canned response, scores the results, and prints
//! a summary table.  Returns an error if the overall score falls below the
//! configured threshold.

use std::path::PathBuf;

use clap::Args;
use frameshift_client::Client;
use frameshift_conformance::{
    bundle_score, load_from_dir, score_test, MockRunner, Runner, TestCase,
};

use crate::util::{persona_source_dir, CliError};

/// Arguments for the `verify` subcommand.
///
/// Exactly one of `--persona` or `--bundle` must be provided.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Name of the installed persona to verify.
    #[arg(long)]
    pub persona: Option<String>,

    /// Path to a conformance bundle directory.
    #[arg(long)]
    pub bundle: Option<PathBuf>,

    /// Canned response for all test prompts (non-interactive mode).
    #[arg(long, default_value = "")]
    pub canned_response: String,

    /// Minimum passing score (0.0 to 1.0).
    #[arg(long, default_value = "0.5")]
    pub threshold: f32,
}

/// Execute the `verify` subcommand.
///
/// Resolves the bundle directory from `--persona` or `--bundle`, loads the
/// bundle, runs each test case through a [`MockRunner`], prints a results
/// table, and returns an error if the overall score is below the threshold.
pub fn run_verify(args: VerifyArgs) -> Result<(), CliError> {
    // Validate that exactly one of --persona or --bundle is specified.
    let bundle_dir = match (&args.persona, &args.bundle) {
        (Some(_), Some(_)) => {
            return Err(CliError::Growth(
                "specify either --persona or --bundle, not both".to_string(),
            ));
        }
        (None, None) => {
            return Err(CliError::Growth(
                "specify either --persona or --bundle".to_string(),
            ));
        }
        (Some(name), None) => {
            // Resolve the persona's conformance bundle subdirectory.
            let client = Client::with_default_data_root()?;
            let source_dir = persona_source_dir(&client, name)?;
            source_dir.join("conformance")
        }
        (None, Some(path)) => path.clone(),
    };

    // Load the bundle from the directory.
    let bundle = load_from_dir(&bundle_dir).map_err(|e| CliError::Conformance(e.to_string()))?;

    // Build the mock runner once and reuse it for every test case.
    let runner = MockRunner::new(args.canned_response.clone());

    // Run each test case, collecting (TestCase, response) pairs.
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| CliError::Growth(format!("failed to create runtime: {e}")))?;

    let results: Vec<(TestCase, String)> = bundle
        .tests
        .iter()
        .map(|test| {
            let response = rt
                .block_on(runner.run(&test.prompt))
                .map_err(|e| CliError::Growth(format!("runner error: {e}")))?;
            Ok((test.clone(), response))
        })
        .collect::<Result<_, CliError>>()?;

    // Print the results table.
    println!("{:<20} {:<12} {:<8} result", "id", "scorer", "score");
    println!("{}", "-".repeat(55));
    for (test, response) in &results {
        let score = score_test(test, response);
        let pass = if score.0 >= args.threshold {
            "pass"
        } else {
            "FAIL"
        };
        println!(
            "{:<20} {:<12} {:<8.3} {}",
            test.id,
            format!("{:?}", test.scorer),
            score.0,
            pass
        );
    }
    println!("{}", "-".repeat(55));

    // Compute and print the overall score.
    let overall = bundle_score(&bundle, &results);
    println!(
        "overall score: {:.3} (threshold: {:.3})",
        overall.0, args.threshold
    );

    if overall.0 < args.threshold {
        return Err(CliError::Growth(format!(
            "score {:.3} is below threshold {:.3}",
            overall.0, args.threshold
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Write a minimal bundle.toml to a temp directory and return the dir path.
    fn write_bundle(dir: &std::path::Path, expected_value: &str) {
        let toml = format!(
            r#"name = "test"
version = "0.1.0"

[[tests]]
id = "t1"
prompt = "say hello"
scorer = "substring"

[tests.expected]
kind = "contains"
value = "{expected_value}"
"#
        );
        fs::write(dir.join("bundle.toml"), toml).expect("write bundle.toml");
    }

    /// Neither --persona nor --bundle specified returns an error.
    #[test]
    fn verify_no_args_returns_error() {
        let args = VerifyArgs {
            persona: None,
            bundle: None,
            canned_response: String::new(),
            threshold: 0.5,
        };
        let result = run_verify(args);
        assert!(result.is_err(), "expected error when no args provided");
    }

    /// Both --persona and --bundle specified returns an error.
    #[test]
    fn verify_both_args_returns_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let args = VerifyArgs {
            persona: Some("test".to_string()),
            bundle: Some(tmp.path().to_path_buf()),
            canned_response: String::new(),
            threshold: 0.5,
        };
        let result = run_verify(args);
        assert!(result.is_err(), "expected error when both args provided");
    }

    /// Canned response "hello world" contains "hello" -- score should be 1.0.
    #[test]
    fn verify_bundle_with_matching_response() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_bundle(tmp.path(), "hello");

        let args = VerifyArgs {
            persona: None,
            bundle: Some(tmp.path().to_path_buf()),
            canned_response: "hello world".to_string(),
            threshold: 0.5,
        };
        let result = run_verify(args);
        assert!(
            result.is_ok(),
            "expected Ok for matching response: {result:?}"
        );
    }

    /// Canned response "goodbye" does not contain "hello" -- score should be 0.0.
    #[test]
    fn verify_bundle_with_nonmatching_response() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_bundle(tmp.path(), "hello");

        let args = VerifyArgs {
            persona: None,
            bundle: Some(tmp.path().to_path_buf()),
            canned_response: "goodbye".to_string(),
            threshold: 0.5,
        };
        let result = run_verify(args);
        // Score 0.0 < 0.5 threshold, so expect Err.
        assert!(result.is_err(), "expected Err for non-matching response");
    }

    /// Score 1.0 >= threshold 0.5 -- should return Ok.
    #[test]
    fn verify_threshold_pass() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_bundle(tmp.path(), "hello");

        let args = VerifyArgs {
            persona: None,
            bundle: Some(tmp.path().to_path_buf()),
            canned_response: "hello world".to_string(),
            threshold: 0.5,
        };
        assert!(
            run_verify(args).is_ok(),
            "score 1.0 should pass threshold 0.5"
        );
    }

    /// Score 0.0 < threshold 0.5 -- should return Err.
    #[test]
    fn verify_threshold_fail() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_bundle(tmp.path(), "hello");

        let args = VerifyArgs {
            persona: None,
            bundle: Some(tmp.path().to_path_buf()),
            canned_response: "goodbye".to_string(),
            threshold: 0.5,
        };
        assert!(
            run_verify(args).is_err(),
            "score 0.0 should fail threshold 0.5"
        );
    }
}
