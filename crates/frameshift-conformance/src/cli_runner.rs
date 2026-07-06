//! Subscription-backed conformance runner that drives the `agy` Gemini CLI in
//! an isolated workspace. Behind the `cli-runner` feature.

use crate::error::ConformanceError;

/// Build the `agy` argument vector for a single headless call.
///
/// The persona is applied via the isolated HOME's `GEMINI.md`, so only the
/// test prompt and model are passed on the command line.
pub(crate) fn assemble_args(model: &str, prompt: &str) -> Vec<String> {
    vec![
        "-p".to_string(),
        prompt.to_string(),
        "--model".to_string(),
        model.to_string(),
    ]
}

/// Turn a finished `agy` invocation into a scoreable response or a typed error.
///
/// Non-zero exit or empty (whitespace-only) stdout are failures. On success the
/// trimmed stdout is returned.
pub(crate) fn classify_output(
    success: bool,
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> Result<String, ConformanceError> {
    if !success {
        let tail: String = stderr.chars().rev().take(400).collect::<String>().chars().rev().collect();
        return Err(ConformanceError::Runner(format!(
            "agy exited with {code:?}: {tail}"
        )));
    }
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(ConformanceError::Runner(
            "agy produced empty output".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_args_orders_flags() {
        let args = assemble_args("Gemini 3.1 Pro (High)", "hello?");
        assert_eq!(
            args,
            vec!["-p", "hello?", "--model", "Gemini 3.1 Pro (High)"]
        );
    }

    #[test]
    fn classify_output_trims_success() {
        let r = classify_output(true, Some(0), "  Axum 0.8\n", "").expect("ok");
        assert_eq!(r, "Axum 0.8");
    }

    #[test]
    fn classify_output_rejects_empty() {
        let e = classify_output(true, Some(0), "   \n", "");
        assert!(matches!(e, Err(ConformanceError::Runner(_))));
    }

    #[test]
    fn classify_output_rejects_nonzero() {
        let e = classify_output(false, Some(1), "", "boom");
        match e {
            Err(ConformanceError::Runner(m)) => assert!(m.contains("boom")),
            other => panic!("expected Runner error, got {other:?}"),
        }
    }
}
