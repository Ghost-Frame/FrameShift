//! Integration tests for render-time persona composition (`extends`/`mixin`).
//!
//! These exercise the hook wired into `materialize_project_state`: a pack
//! that declares `extends`/`mixin` and ships split or inline typed source is
//! composed with its resolved bases before markdown rendering.

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

/// Writes a runtime-complete pack whose typed source is inline in `pack.toml`.
fn write_inline_pack(dir: &Path, name: &str, composition: &str, rule_id: &str, rule_text: &str) {
    let manifest = format!(
        r#"schema_version = 1
name = "{name}"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
{composition}
[voice]
tone = "precise"

[[voice.questions]]
text = "Which layer owns this truth?"

[[rule]]
id = "{rule_id}"
layer = "L1"
text = "{rule_text}"
"#
    );
    write_pack_manifest(dir, &manifest, &[]);
}

/// Installing standalone typed source renders target-specific Markdown even
/// when the pack carries no pre-rendered Markdown and declares no composition.
#[test]
fn install_renders_standalone_typed_source_without_markdown() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
        vault: None,
    });
    let pack_dir = temp.path().join("typed-pack");
    write_pack_manifest(
        &pack_dir,
        r#"
schema_version = 1
name = "typed"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
"#,
        &[],
    );
    source_with_l1_rule("typed", "authority", "The server owns consequential state.")
        .write_to_dir(&pack_dir)
        .expect("write typed source");

    client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "typed".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(pack_dir),
        })
        .expect("install standalone typed source");

    let project_id = client.project_id(&project_root).expect("project id");
    for (target, filename) in [
        ("claude", "CLAUDE.md"),
        ("codex", "AGENTS.md"),
        ("gemini", "GEMINI.md"),
        ("generic", "AGENTS.md"),
    ] {
        let rendered = data_root
            .join("projects")
            .join(&project_id)
            .join("personas/typed/rendered")
            .join(target)
            .join(filename);
        let content = fs::read_to_string(rendered).expect("read typed render");
        assert!(content.contains("The server owns consequential state."));
    }
}

/// Installing one inline `pack.toml` renders every target without auxiliary
/// source files and preserves the pack as the sole materialized source file.
#[test]
fn install_renders_inline_pack_source_without_markdown() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");
    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
        vault: None,
    });
    let pack_dir = temp.path().join("inline-pack");
    write_inline_pack(
        &pack_dir,
        "inline",
        "",
        "authority",
        "The server owns consequential state.",
    );

    client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "inline".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(pack_dir),
        })
        .expect("install inline source");

    let project_id = client.project_id(&project_root).expect("project id");
    let persona_root = data_root
        .join("projects")
        .join(&project_id)
        .join("personas/inline");
    let source_entries = fs::read_dir(persona_root.join("source"))
        .expect("read materialized source")
        .map(|entry| entry.expect("source entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(source_entries, vec!["pack.toml"]);

    for (target, filename) in [
        ("claude", "CLAUDE.md"),
        ("codex", "AGENTS.md"),
        ("gemini", "GEMINI.md"),
        ("generic", "AGENTS.md"),
    ] {
        let content = fs::read_to_string(persona_root.join("rendered").join(target).join(filename))
            .expect("read inline render");
        assert!(content.contains("The server owns consequential state."));
        assert!(content.contains("Which layer owns this truth?"));
    }
}

/// Installing a malformed declared inline source fails instead of falling
/// through to Markdown discovery.
#[test]
fn install_rejects_malformed_inline_pack_source() {
    let temp = TempDir::new().expect("tempdir");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");
    let client = Client::new(ClientOptions {
        data_root: temp.path().join("data-root"),
        config_root: None,
        vault: None,
    });
    let pack_dir = temp.path().join("broken-inline-pack");
    write_pack_manifest(
        &pack_dir,
        r#"schema_version = 1
name = "broken-inline"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
voice = "not-a-table"
"#,
        &[],
    );

    let error = client
        .install(InstallRequest {
            project_root,
            spec: PersonaSpec {
                name: "broken-inline".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(pack_dir),
        })
        .expect_err("malformed inline source must fail");

    assert!(
        matches!(error, ClientError::Compose(_)),
        "expected typed-source failure, got {error}"
    );
}

/// Inline pack composition resolves an inline base from the content cache.
#[test]
fn install_composes_inline_pack_base() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");
    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
        vault: None,
    });

    let base_dir = temp.path().join("inline-base");
    write_inline_pack(&base_dir, "inline-base", "", "base-rule", "Base truth.");
    client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "inline-base".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(base_dir),
        })
        .expect("install inline base");

    let child_dir = temp.path().join("inline-child");
    write_inline_pack(
        &child_dir,
        "inline-child",
        "extends = \"inline-base@0.1.0\"\n",
        "child-rule",
        "Child truth.",
    );
    client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "inline-child".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(child_dir),
        })
        .expect("install inline child");

    let project_id = client.project_id(&project_root).expect("project id");
    let rendered = data_root
        .join("projects")
        .join(project_id)
        .join("personas/inline-child/rendered/codex/AGENTS.md");
    let content = fs::read_to_string(rendered).expect("read composed inline output");
    assert!(content.contains("Base truth."));
    assert!(content.contains("Child truth."));
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
        vault: None,
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
        &[],
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

/// Installing a child pack that `extends` a base which itself `extends` a
/// grandparent must hard-fail instead of silently dropping the grandparent's
/// rules. The composer only resolves one level (child -> base), so composing
/// anyway would produce a child persona whose effective ruleset is missing
/// everything the grandparent contributed to the base -- most dangerous when
/// that dropped layer carries inherited L1 safety rules.
#[test]
fn install_fails_when_base_itself_declares_extends() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
        vault: None,
    });

    // Grandparent pack: typed source with one L1 rule, no composition of its own.
    let grandparent_dir = temp.path().join("grandparent-pack");
    write_pack_manifest(
        &grandparent_dir,
        r#"
schema_version = 1
name = "grandparent"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
"#,
        &[],
    );
    source_with_l1_rule("grandparent", "grandparent-rule", "Grandparent rule text.")
        .write_to_dir(&grandparent_dir)
        .expect("write grandparent source");

    client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "grandparent".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(grandparent_dir),
        })
        .expect("install grandparent");

    // Base pack: one supported level of composition, extends grandparent.
    let base_dir = temp.path().join("base-pack");
    write_pack_manifest(
        &base_dir,
        r#"
schema_version = 1
name = "base"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
extends = "grandparent@0.1.0"
"#,
        &[],
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
        .expect("install base (one level of composition is supported)");

    // Child pack: extends "base@0.1.0", which itself extends grandparent --
    // this second level must be rejected rather than silently dropped.
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
        .expect_err("install must fail closed when base itself declares extends");

    match &err {
        ClientError::UnsupportedMultiLevelComposition { persona, base, .. } => {
            assert_eq!(persona, "child");
            assert_eq!(base, "base");
        }
        other => panic!("expected ClientError::UnsupportedMultiLevelComposition, got {other}"),
    }
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
        vault: None,
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
        vault: None,
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
        &[],
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
        &[],
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
