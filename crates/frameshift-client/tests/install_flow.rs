use frameshift_client::{Client, ClientOptions, InstallRequest, InstallSource, PersonaSpec};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn install_activate_and_sync_materialize_central_state() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    let pack_root = temp.path().join("cryptographic-pack");

    fs::create_dir_all(&project_root).expect("create project");
    write_pack(
        &pack_root,
        &[
            (
                "pack.toml",
                r#"
schema_version = 1
name = "cryptographic"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.3.1"
"#,
            ),
            ("AGENTS.md", "# cryptographic\n"),
            ("notes/README.md", "nested\n"),
        ],
    );

    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
    });

    let report = client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "cryptographic".to_string(),
                version: "0.3.1".to_string(),
            },
            source: InstallSource::LocalPath(pack_root.clone()),
        })
        .expect("install");

    assert_eq!(report.persona.name, "cryptographic");
    // Project root must remain pristine -- no legacy frameshift.toml/lock.
    assert!(
        !project_root.join("frameshift.toml").exists(),
        "frameshift.toml must not be written to the project root"
    );
    assert!(
        !project_root.join("frameshift.lock").exists(),
        "frameshift.lock must not be written to the project root"
    );

    let project_entries = list_relative_files(&project_root);
    let expected: BTreeSet<String> = BTreeSet::new();
    assert_eq!(
        project_entries, expected,
        "project root must contain zero files after install"
    );

    let project_id = client.project_id(&project_root).expect("project id");
    let central_project_dir = data_root.join("projects").join(&project_id);
    assert!(
        central_project_dir.join("lock.toml").is_file(),
        "central lock.toml must exist"
    );
    let persona_root = central_project_dir.join("personas").join("cryptographic");
    assert!(persona_root.join("source/AGENTS.md").is_file());
    assert!(persona_root.join("source/notes/README.md").is_file());
    assert_eq!(
        fs::read_to_string(persona_root.join("rendered/claude/CLAUDE.md")).expect("claude render"),
        "# cryptographic\n"
    );
    assert_eq!(
        fs::read_to_string(persona_root.join("rendered/codex/AGENTS.md")).expect("codex render"),
        "# cryptographic\n"
    );
    // Growth is a single local-only file per persona now.
    assert!(persona_root.join("growth.md").is_file());
    assert!(!persona_root.join("growth").exists());
    assert!(!persona_root.join("entities.toml").exists());
    assert!(report.cache_path.is_dir());

    client
        .activate(&project_root, "cryptographic")
        .expect("activate");
    assert_eq!(
        fs::read_to_string(central_project_dir.join("active")).expect("active file"),
        "cryptographic"
    );

    let sync_one = client.sync(&project_root).expect("sync one");
    let sync_two = client.sync(&project_root).expect("sync two");
    assert_eq!(sync_one, sync_two);

    // Sync must not have leaked anything into the project root either.
    let post_sync_entries = list_relative_files(&project_root);
    assert_eq!(post_sync_entries, BTreeSet::new());
}

#[test]
fn migrates_legacy_project_files() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    let legacy_config_content = "schema_version = 1\n";
    let legacy_lock_content = "schema_version = 1\n";
    fs::write(project_root.join("frameshift.toml"), legacy_config_content)
        .expect("write legacy config");
    fs::write(project_root.join("frameshift.lock"), legacy_lock_content)
        .expect("write legacy lock");

    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
    });

    // project_paths() triggers the migration shim.
    let paths = client.project_paths(&project_root).expect("paths");

    assert!(
        !project_root.join("frameshift.toml").exists(),
        "legacy frameshift.toml must be removed"
    );
    assert!(
        !project_root.join("frameshift.lock").exists(),
        "legacy frameshift.lock must be removed"
    );

    let migrated_config = fs::read_to_string(&paths.config_path).expect("read central config");
    assert_eq!(migrated_config, legacy_config_content);
    let migrated_lock = fs::read_to_string(&paths.lock_path).expect("read central lock");
    assert_eq!(migrated_lock, legacy_lock_content);
}

#[test]
fn gc_removes_unreferenced_cache_entries() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    let pack_root = temp.path().join("cryptographic-pack");

    fs::create_dir_all(&project_root).expect("create project");
    write_pack(
        &pack_root,
        &[
            (
                "pack.toml",
                r#"
schema_version = 1
name = "cryptographic"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.3.1"
"#,
            ),
            ("AGENTS.md", "# cryptographic\n"),
        ],
    );

    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
    });
    let report = client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "cryptographic".to_string(),
                version: "0.3.1".to_string(),
            },
            source: InstallSource::LocalPath(pack_root),
        })
        .expect("install");

    let stale_hash = "deadbeef";
    let stale_dir = data_root.join("cache").join(stale_hash);
    fs::create_dir_all(&stale_dir).expect("stale dir");
    fs::write(stale_dir.join("pack.toml"), "stale").expect("stale manifest");

    let gc_report = client.gc().expect("gc");
    assert!(gc_report.removed_hashes.contains(&stale_hash.to_string()));
    assert!(!gc_report.removed_hashes.contains(&report.persona.hash));
    assert!(!stale_dir.exists());
    assert!(report.cache_path.exists());
}

fn write_pack(root: &Path, files: &[(&str, &str)]) {
    for (relative, content) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, content).expect("write pack file");
    }
}

fn list_relative_files(root: &Path) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    collect_relative_files(root, root, &mut files);
    files
}

fn collect_relative_files(root: &Path, current: &Path, files: &mut BTreeSet<String>) {
    let mut entries = fs::read_dir(current)
        .expect("read dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect entries");
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().expect("file type");
        if file_type.is_dir() {
            collect_relative_files(root, &path, files);
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("strip prefix")
                .to_string_lossy()
                .to_string();
            files.insert(relative);
        }
    }
}
