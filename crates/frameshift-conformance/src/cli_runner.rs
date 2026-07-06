//! Subscription-backed conformance runner that drives the `agy` Gemini CLI in
//! an isolated workspace. Behind the `cli-runner` feature.

use crate::error::ConformanceError;
use std::path::Path;
use tempfile::TempDir;

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
        let tail: String = stderr
            .chars()
            .rev()
            .take(400)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
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

/// Build an isolated HOME whose `.gemini` mirrors `gemini_src` (auth intact)
/// but whose global context is exactly `persona`.
///
/// Copies `gemini_src` with `cp -a` into `<home>/.gemini` (preserving symlinks
/// and the `0600` creds mode), truncates the global appendix, removes the
/// `hooks` symlink, and writes `persona` as `.gemini/GEMINI.md`. The returned
/// `TempDir` owns the directory and deletes it on drop.
pub(crate) fn prepare_isolated_home(
    gemini_src: &Path,
    persona: &str,
) -> Result<TempDir, ConformanceError> {
    let home =
        tempfile::tempdir().map_err(|e| ConformanceError::Runner(format!("tempdir: {e}")))?;
    let dst = home.path().join(".gemini");

    // Recursive, permission- and symlink-preserving copy. `cp -a src dst`
    // creates dst as a copy of src when dst does not exist.
    let status = std::process::Command::new("cp")
        .arg("-a")
        .arg(gemini_src)
        .arg(&dst)
        .status()
        .map_err(|e| ConformanceError::Runner(format!("cp spawn: {e}")))?;
    if !status.success() {
        return Err(ConformanceError::Runner(format!(
            "cp -a failed with {status:?}"
        )));
    }

    // Global context becomes exactly the persona under test.
    std::fs::write(dst.join("GEMINI.md"), persona)
        .map_err(|e| ConformanceError::Runner(format!("write GEMINI.md: {e}")))?;

    // Neutralize the appendix if present.
    let appendix = dst.join("GEMINI-appendix.md");
    if appendix.exists() {
        std::fs::write(&appendix, b"")
            .map_err(|e| ConformanceError::Runner(format!("blank appendix: {e}")))?;
    }

    // Remove the hooks symlink so hook-injected context cannot leak in.
    let hooks = dst.join("hooks");
    if hooks.symlink_metadata().is_ok() {
        std::fs::remove_file(&hooks)
            .map_err(|e| ConformanceError::Runner(format!("remove hooks: {e}")))?;
    }

    Ok(home)
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

    #[test]
    fn isolated_home_bakes_persona_and_neutralizes_context() {
        use std::fs;
        // Build a fake ~/.gemini fixture: GIR global context + appendix + a hooks
        // symlink target + a stand-in creds file.
        let src = tempfile::tempdir().expect("src");
        fs::write(src.path().join("GEMINI.md"), "GIR TACOS").expect("w1");
        fs::write(src.path().join("GEMINI-appendix.md"), "more gir").expect("w2");
        fs::write(src.path().join("oauth_creds.json"), "{\"t\":1}").expect("w3");
        let target = src.path().join("hooks-target");
        fs::create_dir(&target).expect("mkdir");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, src.path().join("hooks")).expect("symlink");

        let home = prepare_isolated_home(src.path(), "PERSONA UNDER TEST").expect("prepare");
        let dst = home.path().join(".gemini");

        assert_eq!(
            fs::read_to_string(dst.join("GEMINI.md")).expect("read gemini"),
            "PERSONA UNDER TEST"
        );
        assert_eq!(
            fs::read_to_string(dst.join("GEMINI-appendix.md")).expect("read appendix"),
            ""
        );
        assert!(!dst.join("hooks").exists(), "hooks must be removed");
        assert!(dst.join("oauth_creds.json").exists(), "creds must survive");
    }
}
