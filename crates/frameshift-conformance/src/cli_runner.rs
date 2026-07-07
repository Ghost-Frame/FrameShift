//! Subscription-backed conformance runner that drives the `agy` Gemini CLI in
//! an isolated workspace. Behind the `cli-runner` feature.

use crate::error::ConformanceError;
use crate::runner::Runner;
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
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
///
/// On failure the returned error may include a trailing slice of the process
/// stderr for diagnostics; treat `ConformanceError::Runner` as potentially
/// sensitive at call sites that log it.
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

/// Files copied from the source `.gemini` into the isolated HOME: an allowlist
/// of the credential and state files `agy` needs to authenticate and run
/// headlessly. Everything else in the source directory -- the global
/// `GEMINI.md`, hook registrations in `settings.json`, MCP config, extensions,
/// skills, and session history -- is deliberately NOT copied, so no ambient
/// context can contaminate a conformance run.
const GEMINI_AUTH_FILES: &[&str] = &[
    "oauth_creds.json",
    "google_accounts.json",
    "installation_id",
    "projects.json",
    "state.json",
    "trustedFolders.json",
];

/// Build an isolated HOME whose `.gemini` contains only the allowlisted auth
/// files plus the persona-under-test as the sole global `GEMINI.md`.
///
/// Auth files are copied with `std::fs::copy` (kernel-level; their contents are
/// never read into this process) which preserves their permission bits, so a
/// `0600` credential stays `0600`. The returned `TempDir` owns the directory
/// (created `0700` on Unix) and deletes it on drop.
pub(crate) fn prepare_isolated_home(
    gemini_src: &Path,
    persona: &str,
) -> Result<TempDir, ConformanceError> {
    #[cfg(unix)]
    let home = {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .map_err(|e| ConformanceError::Runner(format!("tempdir: {e}")))?
    };
    #[cfg(not(unix))]
    let home =
        tempfile::tempdir().map_err(|e| ConformanceError::Runner(format!("tempdir: {e}")))?;

    let dst = home.path().join(".gemini");
    std::fs::create_dir(&dst)
        .map_err(|e| ConformanceError::Runner(format!("create .gemini: {e}")))?;

    // Copy only the allowlisted auth/state files that exist in the source.
    for name in GEMINI_AUTH_FILES {
        let src_file = gemini_src.join(name);
        if src_file.exists() {
            std::fs::copy(&src_file, dst.join(name))
                .map_err(|e| ConformanceError::Runner(format!("copy {name}: {e}")))?;
        }
    }

    // The persona under test becomes the ONLY global context.
    std::fs::write(dst.join("GEMINI.md"), persona)
        .map_err(|e| ConformanceError::Runner(format!("write GEMINI.md: {e}")))?;

    Ok(home)
}

/// Default per-call ceiling for an `agy` invocation.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);

/// Conformance runner that drives the `agy` Gemini CLI with the persona applied
/// as the isolated HOME's global context. Persona-scoped: build one per persona
/// and reuse it across that bundle's test cases.
/// Not safe for concurrent `run` calls on one instance: they share a single
/// isolated HOME, so drive a given runner sequentially.
pub struct CliRunner {
    /// Isolated HOME whose `.gemini/GEMINI.md` is the persona under test.
    iso_home: TempDir,
    /// Model name passed to `agy --model`.
    model: String,
    /// Program to invoke (`agy` in production; a stub in tests).
    program: String,
    /// Per-call timeout.
    timeout: Duration,
}

/// Construction helpers for [`CliRunner`].
impl CliRunner {
    /// Build a runner for `persona`, copying auth from the real `~/.gemini`.
    ///
    /// Errors if `$HOME` is unset or the isolated HOME cannot be prepared.
    /// Blocks the calling thread while copying auth files; do not call from an
    /// async task without `tokio::task::spawn_blocking`.
    pub fn new(persona: &str, model: impl Into<String>) -> Result<Self, ConformanceError> {
        let home = std::env::var("HOME")
            .map_err(|_| ConformanceError::Runner("HOME is not set".to_string()))?;
        let gemini_dir = PathBuf::from(home).join(".gemini");
        Self::with_program_and_gemini_dir(persona, model, "agy".to_string(), gemini_dir)
    }

    /// Test seam: build a runner with an explicit program and source gemini dir.
    /// Blocks the calling thread while copying auth files; do not call from an
    /// async task without `tokio::task::spawn_blocking`.
    pub fn with_program_and_gemini_dir(
        persona: &str,
        model: impl Into<String>,
        program: String,
        gemini_dir: PathBuf,
    ) -> Result<Self, ConformanceError> {
        let iso_home = prepare_isolated_home(&gemini_dir, persona)?;
        Ok(Self {
            iso_home,
            model: model.into(),
            program,
            timeout: DEFAULT_TIMEOUT,
        })
    }
}

#[async_trait]
/// Runs each conformance prompt through `agy` with the persona applied as the
/// isolated HOME's global context.
impl Runner for CliRunner {
    /// Invoke `agy` once for `prompt` and return its trimmed stdout.
    ///
    /// Fails with [`ConformanceError::Runner`] on timeout, spawn/IO error,
    /// non-zero exit status, or empty output.
    async fn run(&self, prompt: &str) -> Result<String, ConformanceError> {
        let args = assemble_args(&self.model, prompt);
        let fut = tokio::process::Command::new(&self.program)
            .args(&args)
            .current_dir(self.iso_home.path())
            .env("HOME", self.iso_home.path())
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output();

        let output = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| ConformanceError::Runner("agy timed out".to_string()))?
            .map_err(|e| ConformanceError::Runner(format!("agy spawn: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        classify_output(
            output.status.success(),
            output.status.code(),
            &stdout,
            &stderr,
        )
    }
}

/// Unit and integration tests for the `cli-runner` module.
#[cfg(test)]
mod tests {
    use super::*;

    /// `assemble_args` places `-p <prompt>` before `--model <model>` in that order.
    #[test]
    fn assemble_args_orders_flags() {
        let args = assemble_args("Gemini 3.1 Pro (High)", "hello?");
        assert_eq!(
            args,
            vec!["-p", "hello?", "--model", "Gemini 3.1 Pro (High)"]
        );
    }

    /// A successful exit with non-empty stdout returns the trimmed output.
    #[test]
    fn classify_output_trims_success() {
        let r = classify_output(true, Some(0), "  Axum 0.8\n", "").expect("ok");
        assert_eq!(r, "Axum 0.8");
    }

    /// A successful exit with whitespace-only stdout is treated as a failure.
    #[test]
    fn classify_output_rejects_empty() {
        let e = classify_output(true, Some(0), "   \n", "");
        assert!(matches!(e, Err(ConformanceError::Runner(_))));
    }

    /// A non-zero exit is a failure whose error message includes the stderr tail.
    #[test]
    fn classify_output_rejects_nonzero() {
        let e = classify_output(false, Some(1), "", "boom");
        match e {
            Err(ConformanceError::Runner(m)) => assert!(m.contains("boom")),
            other => panic!("expected Runner error, got {other:?}"),
        }
    }

    /// Only the allowlisted auth files are copied; the persona is the sole
    /// global context; ambient-context channels (settings.json hooks,
    /// extensions, hooks symlink) are excluded.
    #[test]
    #[cfg(unix)]
    fn isolated_home_allowlists_auth_and_excludes_context() {
        use std::fs;
        let src = tempfile::tempdir().expect("src");
        fs::write(src.path().join("oauth_creds.json"), "{\"t\":1}").expect("creds");
        fs::write(src.path().join("installation_id"), "id123").expect("id");
        fs::write(src.path().join("GEMINI.md"), "GIR TACOS").expect("gir");
        fs::write(src.path().join("settings.json"), "{\"hooks\":{}}").expect("settings");
        fs::create_dir(src.path().join("extensions")).expect("ext");
        std::os::unix::fs::symlink(src.path().join("nonexistent"), src.path().join("hooks"))
            .expect("hooks symlink");

        let home = prepare_isolated_home(src.path(), "PERSONA UNDER TEST").expect("prepare");
        let dst = home.path().join(".gemini");

        assert_eq!(
            fs::read_to_string(dst.join("oauth_creds.json")).expect("creds"),
            "{\"t\":1}"
        );
        assert_eq!(
            fs::read_to_string(dst.join("installation_id")).expect("id"),
            "id123"
        );
        assert_eq!(
            fs::read_to_string(dst.join("GEMINI.md")).expect("gemini"),
            "PERSONA UNDER TEST"
        );
        assert!(
            !dst.join("settings.json").exists(),
            "settings.json (carries hooks) must not be copied"
        );
        assert!(
            !dst.join("extensions").exists(),
            "extensions must not be copied"
        );
        assert!(!dst.join("hooks").exists(), "hooks must not be copied");
    }

    /// A source with no `GEMINI.md` (fresh gemini-cli install) still yields a
    /// persona-only global context.
    #[test]
    #[cfg(unix)]
    fn isolated_home_writes_persona_when_source_has_none() {
        use std::fs;
        let src = tempfile::tempdir().expect("src");
        fs::write(src.path().join("oauth_creds.json"), "{}").expect("creds");
        let home = prepare_isolated_home(src.path(), "P").expect("prepare");
        assert_eq!(
            fs::read_to_string(home.path().join(".gemini").join("GEMINI.md")).expect("gemini"),
            "P"
        );
    }

    /// `CliRunner::run` spawns the configured stub program and returns its
    /// trimmed stdout.
    #[tokio::test]
    async fn cli_runner_invokes_program_and_returns_stdout() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        // Fake ~/.gemini so prepare_isolated_home succeeds.
        let gem = tempfile::tempdir().expect("gem");
        fs::write(gem.path().join("GEMINI.md"), "x").expect("w");

        // Stub "agy": a script that ignores its args and prints a canned line.
        let bindir = tempfile::tempdir().expect("bin");
        let stub = bindir.path().join("agy-stub");
        fs::write(&stub, "#!/bin/sh\necho 'Axum 0.8 is the answer'\n").expect("stub");
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("chmod");

        let runner = CliRunner::with_program_and_gemini_dir(
            "PERSONA",
            "Gemini 3.1 Pro (High)",
            stub.to_string_lossy().to_string(),
            gem.path().to_path_buf(),
        )
        .expect("build runner");

        let out = runner.run("which web framework?").await.expect("run");
        assert!(out.contains("Axum 0.8"), "got: {out}");
    }

    /// Real end-to-end check against `agy`. Run manually:
    /// `cargo test -p frameshift-conformance --features cli-runner real_agy -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn real_agy_rust_persona_scores_axum() {
        let persona = std::fs::read_to_string(format!(
            "{}/.local/share/frameshift/personas-private/rust/AGENTS.md",
            std::env::var("HOME").unwrap()
        ))
        .expect("read rust persona");
        let runner = CliRunner::new(&persona, "Gemini 3.1 Pro (High)").expect("runner");
        let out = runner
            .run("Which web framework should I build this HTTP service on?")
            .await
            .expect("run");
        println!("RESPONSE:\n{out}");
        let re = regex::Regex::new("(?i)axum").unwrap();
        assert!(re.is_match(&out), "expected axum in response, got: {out}");
        assert!(!out.to_lowercase().contains("taco"), "GIR bleed detected");
    }
}
