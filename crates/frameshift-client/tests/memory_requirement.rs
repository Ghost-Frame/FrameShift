//! Activation-time enforcement of the pack manifest's memory requirement.

use frameshift_client::{
    Client, ClientError, ClientOptions, InstallRequest, InstallSource, PersonaSpec,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Write a minimal pack directory with the given `memory_required` level.
fn write_pack(root: &Path, name: &str, memory_required: &str) {
    fs::create_dir_all(root).expect("create pack root");
    fs::write(
        root.join("pack.toml"),
        format!(
            r#"
schema_version = 1
name = "{name}"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"

[capability_manifest]
memory_required = "{memory_required}"
"#
        ),
    )
    .expect("write pack.toml");
    fs::write(root.join("AGENTS.md"), format!("# {name}\n")).expect("write AGENTS.md");
}

/// Install `name` from a local pack dir into a fresh client + project.
fn install(client: &Client, project_root: &Path, pack_root: &Path, name: &str) {
    client
        .install(InstallRequest {
            project_root: project_root.to_path_buf(),
            spec: PersonaSpec {
                name: name.to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(pack_root.to_path_buf()),
        })
        .expect("install");
}

/// Declare a `[memory]` adapter in the project's central config.toml.
fn declare_memory(client: &Client, data_root: &Path, project_root: &Path) {
    let project_id = client.project_id(project_root).expect("project id");
    let project_dir = data_root.join("projects").join(project_id);
    fs::create_dir_all(&project_dir).expect("create project dir");
    fs::write(
        project_dir.join("config.toml"),
        "schema_version = 1\n\n[memory]\nadapter = \"http\"\nendpoint = \"http://127.0.0.1:4200\"\n",
    )
    .expect("write config.toml");
}

/// A hard memory requirement with no declared adapter refuses to activate.
#[test]
fn hard_requirement_without_adapter_blocks_activation() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    let pack_root = temp.path().join("pack");
    fs::create_dir_all(&project_root).expect("create project");
    write_pack(&pack_root, "archivist", "hard");

    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
        vault: None,
    });
    install(&client, &project_root, &pack_root, "archivist");

    let err = client
        .activate(&project_root, "archivist")
        .expect_err("hard requirement without adapter must refuse activation");
    assert!(
        matches!(err, ClientError::MemoryRequirementUnmet { ref persona, .. } if persona == "archivist"),
        "unexpected error: {err}"
    );
    assert!(
        !data_root
            .join("projects")
            .join(client.project_id(&project_root).unwrap())
            .join("active")
            .exists(),
        "active marker must not be written on refused activation"
    );
}

/// A hard memory requirement activates once the project declares an adapter.
#[test]
fn hard_requirement_with_adapter_activates() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    let pack_root = temp.path().join("pack");
    fs::create_dir_all(&project_root).expect("create project");
    write_pack(&pack_root, "archivist", "hard");

    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
        vault: None,
    });
    install(&client, &project_root, &pack_root, "archivist");
    declare_memory(&client, &data_root, &project_root);

    client
        .activate(&project_root, "archivist")
        .expect("hard requirement with declared adapter must activate");
}

/// A soft requirement activates without an adapter but reports soft_unmet.
#[test]
fn soft_requirement_activates_and_reports_unmet() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    let pack_root = temp.path().join("pack");
    fs::create_dir_all(&project_root).expect("create project");
    write_pack(&pack_root, "coach", "soft");

    let client = Client::new(ClientOptions {
        data_root,
        config_root: None,
        vault: None,
    });
    install(&client, &project_root, &pack_root, "coach");

    client
        .activate(&project_root, "coach")
        .expect("soft requirement must not block activation");
    let status = client
        .memory_requirement_status(&project_root, "coach")
        .expect("status");
    assert!(status.soft_unmet(), "soft requirement should report unmet");
    assert!(!status.hard_unmet());
}

/// A pack with no capability manifest reports no requirement and activates.
#[test]
fn absent_manifest_section_means_no_requirement() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    let pack_root = temp.path().join("pack");
    fs::create_dir_all(&project_root).expect("create project");
    fs::create_dir_all(&pack_root).expect("create pack root");
    fs::write(
        pack_root.join("pack.toml"),
        r#"
schema_version = 1
name = "plain"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
"#,
    )
    .expect("write pack.toml");
    fs::write(pack_root.join("AGENTS.md"), "# plain\n").expect("write AGENTS.md");

    let client = Client::new(ClientOptions {
        data_root,
        config_root: None,
        vault: None,
    });
    install(&client, &project_root, &pack_root, "plain");

    client.activate(&project_root, "plain").expect("activate");
    let status = client
        .memory_requirement_status(&project_root, "plain")
        .expect("status");
    assert_eq!(
        status.requirement,
        frameshift_pack::MemoryRequirement::None,
        "absent capability_manifest must mean no requirement"
    );
}
