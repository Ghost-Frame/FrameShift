//! Integration tests for render-time persona composition (`extends`/`mixin`).
//!
//! These exercise the hook wired into `materialize_project_state`: a pack
//! that declares `extends`/`mixin` and ships typed source (`persona.toml`)
//! is composed with its resolved bases before markdown rendering.

use frameshift_client::{
    Client, ClientError, ClientOptions, InstallRequest, InstallSource, PersonaSpec,
};
use frameshift_compose::ComposeError;
use frameshift_source::{Layer, Persona, PersonaSource, Rule, RuleSet};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Writes `pack.toml` (and any extra plain files) into `dir`.
fn write_pack_manifest(dir: &Path, manifest_toml: &str, extra_files: &[(&str, &str)]) {
    fs::create_dir_all(dir).expect("create pack dir");
    fs::write(dir.join("pack.toml"), manifest_toml).expect("write pack.toml");
    for (relative, content) in extra_files {
        let path = dir.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, content).expect("write extra file");
    }
}

/// Builds a minimal `PersonaSource` with a single L1 rule carrying `rule_text`.
fn source_with_l1_rule(name: &str, rule_id: &str, rule_text: &str) -> PersonaSource {
    let mut src = PersonaSource::new(Persona::new(name));
    src.rules = RuleSet {
        rules: vec![Rule {
            id: rule_id.to_string(),
            layer: Layer::L1,
            text: rule_text.to_string(),
            reasoning: None,
            override_inherited: false,
        }],
    };
    src
}

/// Installing a child pack that `extends` an already-installed base composes
/// the base's rules into the child's rendered output.
#[test]
fn install_composes_extends_base() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
    });

    // Base pack: typed source with one L1 rule, no composition of its own.
    let base_dir = temp.path().join("base-pack");
    write_pack_manifest(
        &base_dir,
        r#"
schema_version = 1
name = "base"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
"#,
        // Base does not itself declare extends/mixin, so it takes the unchanged
        // markdown render path, which requires a renderable markdown source.
        &[("AGENTS.md", "# base\n")],
    );
    source_with_l1_rule("base", "base-rule", "Base rule text.")
        .write_to_dir(&base_dir)
        .expect("write base source");

    client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "base".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(base_dir),
        })
        .expect("install base");

    // Child pack: extends "base@0.1.0", ships its own distinct L1 rule.
    let child_dir = temp.path().join("child-pack");
    write_pack_manifest(
        &child_dir,
        r#"
schema_version = 1
name = "child"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
extends = "base@0.1.0"
"#,
        &[],
    );
    source_with_l1_rule("child", "child-rule", "Child rule text.")
        .write_to_dir(&child_dir)
        .expect("write child source");

    client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "child".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(child_dir),
        })
        .expect("install child");

    let project_id = client.project_id(&project_root).expect("project id");
    let rendered = data_root
        .join("projects")
        .join(&project_id)
        .join("personas/child/rendered/claude/CLAUDE.md");
    let content = fs::read_to_string(&rendered).expect("read rendered claude output");

    assert!(
        content.contains("Base rule text."),
        "composed output must inherit the base's rule; got:\n{content}"
    );
    assert!(
        content.contains("Child rule text."),
        "composed output must keep the child's own rule; got:\n{content}"
    );
}

/// Installing a pack that declares `extends` for a base that was never
/// installed must hard-fail with `ClientError::Compose(ComposeError::Unresolved)`.
#[test]
fn install_fails_when_extends_missing() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
    });

    let child_dir = temp.path().join("child-pack");
    write_pack_manifest(
        &child_dir,
        r#"
schema_version = 1
name = "child"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
extends = "base@0.1.0"
"#,
        &[],
    );
    source_with_l1_rule("child", "child-rule", "Child rule text.")
        .write_to_dir(&child_dir)
        .expect("write child source");

    let err = client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "child".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(child_dir),
        })
        .expect_err("install must fail when base is not installed");

    let ClientError::Compose(inner) = &err else {
        panic!("expected ClientError::Compose, got {err}");
    };
    assert!(
        matches!(**inner, ComposeError::Unresolved { .. }),
        "expected ComposeError::Unresolved, got {err}"
    );
}

/// A mixin that redeclares an L1 rule already owned by the base must hard-fail
/// with `ComposeError::L1Override`, per the SD6 protection in `frameshift-compose`.
#[test]
fn mixin_l1_override_fails_install() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
    });

    // Base pack owns L1 rule "no-panic".
    let base_dir = temp.path().join("base-pack");
    write_pack_manifest(
        &base_dir,
        r#"
schema_version = 1
name = "base"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
"#,
        // Base does not itself declare extends/mixin, so it takes the unchanged
        // markdown render path, which requires a renderable markdown source.
        &[("AGENTS.md", "# base\n")],
    );
    source_with_l1_rule("base", "no-panic", "Never panic.")
        .write_to_dir(&base_dir)
        .expect("write base source");

    client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "base".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(base_dir),
        })
        .expect("install base");

    // Mixin pack also redeclares "no-panic" as L1 -- must be rejected.
    let mixin_dir = temp.path().join("mixin-pack");
    write_pack_manifest(
        &mixin_dir,
        r#"
schema_version = 1
name = "strictmixin"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
"#,
        // Mixin does not itself declare extends/mixin, so it also takes the
        // unchanged markdown render path.
        &[("AGENTS.md", "# strictmixin\n")],
    );
    source_with_l1_rule("strictmixin", "no-panic", "Never panic (mixin).")
        .write_to_dir(&mixin_dir)
        .expect("write mixin source");

    client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "strictmixin".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(mixin_dir),
        })
        .expect("install mixin");

    // Child pack extends base and mixes in strictmixin -- L1 collision.
    let child_dir = temp.path().join("child-pack");
    write_pack_manifest(
        &child_dir,
        r#"
schema_version = 1
name = "child"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
extends = "base@0.1.0"
mixin = ["strictmixin@0.1.0"]
"#,
        &[],
    );
    PersonaSource::new(Persona::new("child"))
        .write_to_dir(&child_dir)
        .expect("write child source");

    let err = client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "child".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(child_dir),
        })
        .expect_err("install must fail on L1 override by mixin");

    let ClientError::Compose(inner) = &err else {
        panic!("expected ClientError::Compose, got {err}");
    };
    assert!(
        matches!(&**inner, ComposeError::L1Override { rule_id, .. } if rule_id.as_str() == "no-panic"),
        "expected ClientError::Compose(ComposeError::L1Override), got {err}"
    );
}
