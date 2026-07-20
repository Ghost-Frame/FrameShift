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

/// One unrenderable persona degrades to a reported failure while every other
/// persona still materializes, and the broken persona's half-built dir is
/// removed rather than left corrupt.
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

/// Activating the persona that failed materialization yields the typed
/// `PersonaMaterializeFailed` error; activating a healthy persona still works.
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

/// Installing a healthy persona while another locked persona is broken
/// succeeds and carries the unrelated failure on the report as a warning.
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

/// A persona whose cache entry disappears AFTER a successful materialization
/// keeps its last-known-good content: the failure occurs before any mutation,
/// so sync reports it without destroying the still-usable rendered output.
#[test]
fn missing_cache_entry_preserves_last_good_materialization() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");
    let client = Client::new(ClientOptions {
        data_root,
        config_root: None,
        vault: None,
    });

    let beta_root = temp.path().join("beta-pack");
    write_pack(
        &beta_root,
        &[
            ("pack.toml", &manifest_toml("beta")),
            ("AGENTS.md", "# beta\n"),
        ],
    );
    let report = install(&client, &project_root, beta_root, "beta");

    // Simulate cache rot: the whole content-addressed entry vanishes while
    // the lockfile still references it.
    fs::remove_dir_all(&report.cache_path).expect("remove cache entry");

    let sync = client.sync(&project_root).expect("sync must not abort");
    assert_eq!(sync.failures.len(), 1);
    assert_eq!(sync.failures[0].persona, "beta");
    assert!(
        sync.failures[0].error.contains("cache entry"),
        "failure must be the missing cache entry, got: {}",
        sync.failures[0].error
    );

    // The previously materialized content survives as last-known-good.
    let project_id = client.project_id(&project_root).expect("project id");
    let rendered = temp
        .path()
        .join("data-root/projects")
        .join(&project_id)
        .join("personas/beta/rendered/claude/CLAUDE.md");
    assert_eq!(
        fs::read_to_string(rendered).expect("last-known-good render must survive"),
        "# beta\n"
    );
}

/// The persona BEING installed failing to materialize re-raises its own typed
/// error even when other healthy personas coexist in the project, and leaves
/// the healthy personas' materialized state intact.
#[test]
fn install_of_failing_persona_errors_typed_with_others_healthy() {
    let temp = TempDir::new().expect("tempdir");
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

    // A pack declaring a composition base that is not installed fails its own
    // materialization with the typed Compose error. Typed source is required
    // for the composer path to engage.
    let child_root = temp.path().join("child-pack");
    write_pack(
        &child_root,
        &[
            (
                "pack.toml",
                "schema_version = 1\nname = \"child\"\nauthor_handle = \"alice\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"0.1.0\"\nextends = \"missing-base@0.1.0\"\n",
            ),
            ("AGENTS.md", "# child\n"),
        ],
    );
    frameshift_source::PersonaSource::new(frameshift_source::Persona::new("child"))
        .write_to_dir(&child_root)
        .expect("write typed child source");
    let err = client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "child".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(child_root),
        })
        .expect_err("install of composing pack without its base must fail");
    assert!(
        matches!(err, ClientError::Compose(_)),
        "own-persona failure must re-raise the ORIGINAL typed error, got: {err:?}"
    );

    // Alpha's materialized state is untouched by the failed install.
    let project_id = client.project_id(&project_root).expect("project id");
    let alpha_rendered = temp
        .path()
        .join("data-root/projects")
        .join(&project_id)
        .join("personas/alpha/rendered/claude/CLAUDE.md");
    assert!(alpha_rendered.is_file(), "healthy persona must survive");
}

/// Every locked persona failing at once still returns Ok: all failures are
/// reported, nothing renders, and nothing panics.
#[test]
fn sync_reports_all_personas_failing() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");
    let client = Client::new(ClientOptions {
        data_root,
        config_root: None,
        vault: None,
    });

    // Install two healthy personas, then vandalize BOTH cache entries.
    for name in ["alpha", "beta"] {
        let pack_root = temp.path().join(format!("{name}-pack"));
        write_pack(
            &pack_root,
            &[
                ("pack.toml", &manifest_toml(name)),
                ("AGENTS.md", "# pack\n"),
            ],
        );
        let report = install(&client, &project_root, pack_root, name);
        fs::remove_file(report.cache_path.join("AGENTS.md")).expect("vandalize cache");
    }

    let report = client.sync(&project_root).expect("sync must still be Ok");
    assert_eq!(report.personas.len(), 2);
    assert_eq!(report.failures.len(), 2, "failures: {:?}", report.failures);
    let mut failed: Vec<&str> = report.failures.iter().map(|f| f.persona.as_str()).collect();
    failed.sort_unstable();
    assert_eq!(failed, vec!["alpha", "beta"]);
}

/// `active_persona_state` distinguishes a healthy active persona from one
/// whose materialization failed after activation (marker still set, dir
/// cleaned), without requiring a re-sync.
#[test]
fn active_persona_state_reports_materialization() {
    use frameshift_client::ActivePersonaState;

    let temp = TempDir::new().expect("tempdir");
    let (client, project_root) = project_with_broken_beta(&temp);

    // No marker yet.
    assert!(matches!(
        client.active_persona_state(&project_root).expect("state"),
        ActivePersonaState::None
    ));

    // Healthy persona activates and reads back as materialized.
    client.activate(&project_root, "alpha").expect("activate");
    assert!(matches!(
        client.active_persona_state(&project_root).expect("state"),
        ActivePersonaState::Materialized(ref name) if name == "alpha"
    ));

    // Re-point the marker at beta by hand (activation would refuse), then
    // sync so beta's broken cache cleans its materialized dir: the marker
    // survives (beta is still locked) but the content is gone.
    let project_id = client.project_id(&project_root).expect("project id");
    fs::write(
        temp.path()
            .join("data-root/projects")
            .join(&project_id)
            .join("active"),
        "beta",
    )
    .expect("write marker");
    client.sync(&project_root).expect("sync");
    assert!(matches!(
        client.active_persona_state(&project_root).expect("state"),
        ActivePersonaState::Unmaterialized(ref name) if name == "beta"
    ));
}

/// The exact pack.toml shape written by pre-hardening local installs
/// (author_pubkey = "local-unsigned") still installs and renders.
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
