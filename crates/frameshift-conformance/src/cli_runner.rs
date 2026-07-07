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

/// Write `contents` to `path` as a plain file, first removing any symlink at
/// `path`. `cp -a` preserves symlinks, and a bare `fs::write` would follow one
/// and clobber a file outside the sandbox; removing it first prevents that.
fn write_plain(path: &Path, contents: &[u8]) -> Result<(), ConformanceError> {
    if let Ok(meta) = path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            std::fs::remove_file(path)
                .map_err(|e| ConformanceError::Runner(format!("unlink {path:?}: {e}")))?;
        }
    }
    std::fs::write(path, contents)
        .map_err(|e| ConformanceError::Runner(format!("write {path:?}: {e}")))
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
    // Isolated HOME with 0700 perms so the copied credential files are not
    // exposed in a world-readable directory.
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

    // Global context becomes exactly the persona under test (symlink-safe).
    write_plain(&dst.join("GEMINI.md"), persona.as_bytes())?;

    // Neutralize the global appendix if present (symlink-safe).
    let appendix = dst.join("GEMINI-appendix.md");
    if appendix.symlink_metadata().is_ok() {
        write_plain(&appendix, b"")?;
    }

    // Remove the hooks symlink so hook-injected context cannot leak in.
    let hooks = dst.join("hooks");
    if hooks.symlink_metadata().is_ok() {
        std::fs::remove_file(&hooks)
            .map_err(|e| ConformanceError::Runner(format!("remove hooks: {e}")))?;
    }

    Ok(home)
}

/// Default per-call ceiling for an `agy` invocation.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);

/// Conformance runner that drives the `agy` Gemini CLI with the persona applied
/// as the isolated HOME's global context. Persona-scoped: build one per persona
/// and reuse it across that bundle's test cases.
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

impl CliRunner {
    /// Build a runner for `persona`, copying auth from the real `~/.gemini`.
    ///
    /// Errors if `$HOME` is unset or the isolated HOME cannot be prepared.
    pub fn new(persona: &str, model: impl Into<String>) -> Result<Self, ConformanceError> {
        let home = std::env::var("HOME")
            .map_err(|_| ConformanceError::Runner("HOME is not set".to_string()))?;
        let gemini_dir = PathBuf::from(home).join(".gemini");
        Self::with_program_and_gemini_dir(persona, model, "agy".to_string(), gemini_dir)
    }

    /// Test seam: build a runner with an explicit program and source gemini dir.
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
impl Runner for CliRunner {
    async fn run(&self, prompt: &str) -> Result<String, ConformanceError> {
        let args = assemble_args(&self.model, prompt);
        let fut = tokio::process::Command::new(&self.program)
            .args(&args)
            .current_dir(self.iso_home.path())
            .env("HOME", self.iso_home.path())
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

    /// A symlinked source GEMINI.md must not be written through: the external
    /// target stays intact and the isolated copy is a plain file.
    #[test]
    #[cfg(unix)]
    fn isolated_home_does_not_write_through_symlinked_gemini_md() {
        use std::fs;
        let ext = tempfile::tempdir().expect("ext");
        let real = ext.path().join("real_gemini.md");
        fs::write(&real, "EXTERNAL CONTENT").expect("write real");

        let src = tempfile::tempdir().expect("src");
        std::os::unix::fs::symlink(&real, src.path().join("GEMINI.md")).expect("symlink");

        let home = prepare_isolated_home(src.path(), "PERSONA").expect("prepare");
        let dst_gemini = home.path().join(".gemini").join("GEMINI.md");

        assert_eq!(
            fs::read_to_string(&dst_gemini).expect("read dst"),
            "PERSONA"
        );
        assert!(!dst_gemini
            .symlink_metadata()
            .expect("meta")
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_to_string(&real).expect("read real"),
            "EXTERNAL CONTENT"
        );
    }

    /// A dangling `hooks` symlink is removed without error.
    #[test]
    #[cfg(unix)]
    fn isolated_home_handles_dangling_hooks_symlink() {
        use std::fs;
        let src = tempfile::tempdir().expect("src");
        fs::write(src.path().join("GEMINI.md"), "g").expect("w");
        std::os::unix::fs::symlink(src.path().join("nonexistent"), src.path().join("hooks"))
            .expect("symlink");

        let home = prepare_isolated_home(src.path(), "P").expect("prepare");
        assert!(!home.path().join(".gemini").join("hooks").exists());
    }

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
