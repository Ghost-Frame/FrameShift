//! Per-persona materialization resilience.
//!
//! One unrenderable pack in the lockfile must not brick every other persona:
//! `sync`/`install` isolate per-persona failures into `SyncReport::failures` /
//! `InstallReport::materialize_failures`, and `activate` fails with a typed
//! error only when the *requested* persona is the one that failed. Legacy
//! local packs carrying the `local-unsigned` author_pubkey sentinel must keep
//! installing and rendering under the strict manifest parser.
use frameshift_client::{
    Client, ClientError, ClientOptions, InstallRequest, InstallSource, PersonaSpec,
};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Write a pack directory from `(relative path, contents)` pairs.
fn write_pack(root: &Path, files: &[(&str, &str)]) {
    for (rel, contents) in files {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create pack subdir");
        }
        fs::write(&path, contents).expect("write pack file");
    }
}

/// Minimal healthy pack manifest for `name` with a well-formed hex pubkey.
fn manifest_toml(name: &str) -> String {
    format!(
        "schema_version = 1\nname = \"{name}\"\nauthor_handle = \"alice\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"0.1.0\"\n"
    )
}

/// Install the pack at `pack_root` under `name` into `project_root`.
fn install(
    client: &Client,
    project_root: &Path,
    pack_root: PathBuf,
    name: &str,
) -> frameshift_client::InstallReport {
    client
        .install(InstallRequest {
            project_root: project_root.to_path_buf(),
            spec: PersonaSpec {
                name: name.to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(pack_root),
        })
        .unwrap_or_else(|e| panic!("install {name}: {e}"))
}

/// Shared fixture: a project with healthy `alpha` and `beta` installed, then
/// `beta`'s cached copy vandalized so it can no longer render (mirrors the
/// live content-less stub packs from the broken-seeder era).
fn project_with_broken_beta(temp: &TempDir) -> (Client, PathBuf) {
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    let client = Client::new(ClientOptions {
        data_root,
        config_root: None,
        vault: None,
    });

    let alpha_root = temp.path().join("alpha-pack");
    write_pack(
        &alpha_root,
        &[
            ("pack.toml", &manifest_toml("alpha")),
            ("AGENTS.md", "# alpha\n"),
        ],
    );
    install(&client, &project_root, alpha_root, "alpha");

    let beta_root = temp.path().join("beta-pack");
    write_pack(
        &beta_root,
        &[
            ("pack.toml", &manifest_toml("beta")),
            ("AGENTS.md", "# beta\n"),
        ],
    );
    let beta_report = install(&client, &project_root, beta_root, "beta");

    // Strip the markdown out of beta's cache entry: the cached pack is now a
    // pack.toml-only stub, exactly the on-disk shape that bricked `use` live.
    fs::remove_file(beta_report.cache_path.join("AGENTS.md")).expect("vandalize beta cache");

    (client, project_root)
}

#[test]
fn sync_isolates_unrenderable_persona() {
    let temp = TempDir::new().expect("tempdir");
    let (client, project_root) = project_with_broken_beta(&temp);

    let report = client.sync(&project_root).expect("sync must not abort");

    // Both personas are still locked...
    assert!(report.personas.iter().any(|p| p == "alpha"));
    assert!(report.personas.iter().any(|p| p == "beta"));
    // ...but only beta failed, and the failure names it.
    assert_eq!(report.failures.len(), 1, "failures: {:?}", report.failures);
    assert_eq!(report.failures[0].persona, "beta");
    assert!(!report.failures[0].error.is_empty());

    // Alpha rendered fine.
    let project_id = client.project_id(&project_root).expect("project id");
    let personas_dir = temp
        .path()
        .join("data-root/projects")
        .join(&project_id)
        .join("personas");
    assert!(
        personas_dir
            .join("alpha/rendered/claude/CLAUDE.md")
            .is_file(),
        "alpha must render despite beta's failure"
    );
    // Beta's partial dir was cleaned up, not left half-materialized.
    assert!(
        !personas_dir.join("beta").exists(),
        "failed persona dir must be removed"
    );
}

#[test]
fn activate_persona_that_failed_materialize_errors_typed() {
    let temp = TempDir::new().expect("tempdir");
    let (client, project_root) = project_with_broken_beta(&temp);

    let err = client
        .activate(&project_root, "beta")
        .expect_err("activating a persona that failed materialize must error");
    match err {
        ClientError::PersonaMaterializeFailed { persona, .. } => assert_eq!(persona, "beta"),
        other => panic!("expected PersonaMaterializeFailed, got: {other:?}"),
    }

    // The healthy persona still activates.
    client
        .activate(&project_root, "alpha")
        .expect("alpha must activate despite beta's failure");
}

#[test]
fn install_reports_unrelated_materialize_failure_as_warning() {
    let temp = TempDir::new().expect("tempdir");
    let (client, project_root) = project_with_broken_beta(&temp);

    // Installing a third persona must succeed and surface beta's failure
    // instead of aborting the install.
    let gamma_root = temp.path().join("gamma-pack");
    write_pack(
        &gamma_root,
        &[
            ("pack.toml", &manifest_toml("gamma")),
            ("AGENTS.md", "# gamma\n"),
        ],
    );
    let report = install(&client, &project_root, gamma_root, "gamma");

    assert_eq!(report.materialize_failures.len(), 1);
    assert_eq!(report.materialize_failures[0].persona, "beta");
}

#[test]
fn legacy_local_unsigned_pack_installs_and_renders() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    let client = Client::new(ClientOptions {
        data_root,
        config_root: None,
        vault: None,
    });

    // The exact manifest shape every pre-hardening local install wrote.
    let pack_root = temp.path().join("legacy-pack");
    write_pack(
        &pack_root,
        &[
            (
                "pack.toml",
                "schema_version = 1\nname = \"legacy\"\nauthor_handle = \"local\"\nauthor_pubkey = \"local-unsigned\"\nversion = \"0.1.0\"\n",
            ),
            ("AGENTS.md", "# legacy\n"),
        ],
    );
    install(&client, &project_root, pack_root, "legacy");

    let report = client.sync(&project_root).expect("sync");
    assert!(
        report.failures.is_empty(),
        "failures: {:?}",
        report.failures
    );

    let project_id = client.project_id(&project_root).expect("project id");
    let rendered = temp
        .path()
        .join("data-root/projects")
        .join(&project_id)
        .join("personas/legacy/rendered/claude/CLAUDE.md");
    assert_eq!(fs::read_to_string(rendered).expect("render"), "# legacy\n");
}
