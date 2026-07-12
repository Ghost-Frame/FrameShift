//! Integration tests for `{{token}}` substitution at render time -- the
//! `pack.template.toml` + [`frameshift_client::VaultProvider`] pipeline
//! wired into `Client::materialize_persona_rendered_outputs` /
//! `materialize_rendered_outputs`.
//!
//! The load-bearing invariant under test: a pack that ships no
//! `pack.template.toml` renders byte-identically to how it did before this
//! feature existed, regardless of whether a vault provider is configured.

use frameshift_client::{
    Client, ClientError, ClientOptions, InstallRequest, InstallSource, PersonaSpec, VaultData,
    VaultProvider,
};
use frameshift_vault::{Auth, Identity, Preferences, RuntimeMode};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
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

/// Builds a minimal, schema-valid [`VaultData`] whose `variables` map is
/// `vars`. The identity/auth/preferences sections are placeholders -- these
/// tests only exercise the `variables` map that `{{token}}` substitution
/// reads from.
fn vault_with_variables(vars: &[(&str, &str)]) -> VaultData {
    VaultData {
        schema_version: 1,
        identity: Identity {
            keypair_pub: "age1test".to_owned(),
            handle: "tester".to_owned(),
        },
        auth: Auth {
            methods: vec!["passphrase".to_owned()],
            unlock: "passphrase".to_owned(),
        },
        preferences: Preferences {
            runtime_mode: RuntimeMode::Rendered,
            publish_intent: "no".to_owned(),
            recovery: "own-backup".to_owned(),
        },
        memory: None,
        variables: vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        overlays: BTreeMap::new(),
    }
}

/// A [`VaultProvider`] that always returns a clone of `data`, ignoring the
/// requested path -- sufficient for tests with a single vault.
fn fixed_vault_provider(data: VaultData) -> Arc<dyn VaultProvider> {
    Arc::new(
        move |_path: &Path| -> Result<VaultData, frameshift_client::VaultError> {
            Ok(data.clone())
        },
    )
}

/// A minimal, schema-valid `pack.toml` shared by every test in this file
/// (name/version are overwritten per test via string formatting where needed).
const PACK_TOML: &str = r#"
schema_version = 1
name = "templated"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
"#;

/// A pack that ships `pack.template.toml` declaring a required token, paired
/// with a vault that supplies it, substitutes the token into every render
/// target's output file.
#[test]
fn templated_pack_substitutes_required_token_in_every_target() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    let vault = vault_with_variables(&[("greeting_name", "Ada")]);
    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
        vault: Some(fixed_vault_provider(vault)),
    });

    let pack_dir = temp.path().join("templated-pack");
    write_pack_manifest(
        &pack_dir,
        PACK_TOML,
        &[
            ("AGENTS.md", "Hello {{greeting_name}}!\n"),
            (
                "pack.template.toml",
                r#"
[tokens]
greeting_name = { type = "string", required = true, description = "Who to greet" }
"#,
            ),
        ],
    );

    client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "templated".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(pack_dir),
        })
        .expect("install");

    let project_id = client.project_id(&project_root).expect("project id");
    let rendered_root = data_root
        .join("projects")
        .join(&project_id)
        .join("personas/templated/rendered");

    for (target_dir, filename) in [
        ("claude", "CLAUDE.md"),
        ("codex", "AGENTS.md"),
        ("gemini", "GEMINI.md"),
        ("generic", "AGENTS.md"),
    ] {
        let content = fs::read_to_string(rendered_root.join(target_dir).join(filename))
            .unwrap_or_else(|e| panic!("read {target_dir}/{filename}: {e}"));
        assert!(
            content.contains("Hello Ada!"),
            "{target_dir}/{filename} must have the token substituted; got:\n{content}"
        );
        assert!(
            !content.contains("{{greeting_name}}"),
            "{target_dir}/{filename} must not leave the placeholder unsubstituted"
        );
    }
}

/// Required tokens with no vault value fail install with
/// `ClientError::MissingRequiredTokens` naming every missing token (not just
/// the first), and never produce a `rendered/` directory for the persona.
#[test]
fn missing_required_tokens_fail_install_cleanly_and_name_every_token() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    // Vault exists but supplies neither required token.
    let vault = vault_with_variables(&[]);
    let client = Client::new(ClientOptions {
        data_root: data_root.clone(),
        config_root: None,
        vault: Some(fixed_vault_provider(vault)),
    });

    let pack_dir = temp.path().join("templated-pack");
    write_pack_manifest(
        &pack_dir,
        PACK_TOML,
        &[
            (
                "AGENTS.md",
                "Hello {{greeting_name}}, key is {{api_key}}!\n",
            ),
            (
                "pack.template.toml",
                r#"
[tokens]
greeting_name = { type = "string", required = true, description = "Who to greet" }
api_key = { type = "string", required = true, description = "API key" }
"#,
            ),
        ],
    );

    let err = client
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "templated".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(pack_dir),
        })
        .expect_err("install must fail when required tokens are missing");

    let ClientError::MissingRequiredTokens { tokens, .. } = &err else {
        panic!("expected ClientError::MissingRequiredTokens, got {err}");
    };
    assert_eq!(
        tokens,
        &vec!["api_key".to_string(), "greeting_name".to_string()],
        "every missing required token must be named, not just the first"
    );

    let project_id = client.project_id(&project_root).expect("project id");
    let rendered_dir = data_root
        .join("projects")
        .join(&project_id)
        .join("personas/templated/rendered");
    assert!(
        !rendered_dir.exists(),
        "a failed install must not leave a partial rendered/ directory"
    );
}

/// A pack that ships no `pack.template.toml` renders byte-identically
/// whether or not a vault provider is configured on the `Client` -- the
/// load-bearing regression invariant: every pack that predates this feature
/// must behave exactly as it did before.
#[test]
fn pack_without_manifest_renders_byte_identically_regardless_of_vault() {
    let temp = TempDir::new().expect("tempdir");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    /// Same shape as `PACK_TOML` but named to match this test's install spec.
    const PLAIN_PACK_TOML: &str = r#"
schema_version = 1
name = "plain"
author_handle = "alice"
author_pubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
version = "0.1.0"
"#;

    let pack_dir = temp.path().join("plain-pack");
    write_pack_manifest(
        &pack_dir,
        PLAIN_PACK_TOML,
        &[(
            "AGENTS.md",
            "Hello {{not_a_declared_token}}, this pack has no manifest.\n",
        )],
    );

    // Render with no vault provider at all.
    let data_root_no_vault = temp.path().join("data-root-no-vault");
    let client_no_vault = Client::new(ClientOptions {
        data_root: data_root_no_vault.clone(),
        config_root: None,
        vault: None,
    });
    client_no_vault
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "plain".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(pack_dir.clone()),
        })
        .expect("install without a vault provider configured");

    // Render again with a vault provider present and populated -- but the
    // pack still ships no pack.template.toml, so the provider must never
    // even be consulted, and the token marker must survive untouched.
    let data_root_with_vault = temp.path().join("data-root-with-vault");
    let vault = vault_with_variables(&[("not_a_declared_token", "should never be used")]);
    let client_with_vault = Client::new(ClientOptions {
        data_root: data_root_with_vault.clone(),
        config_root: None,
        vault: Some(fixed_vault_provider(vault)),
    });
    client_with_vault
        .install(InstallRequest {
            project_root: project_root.clone(),
            spec: PersonaSpec {
                name: "plain".to_string(),
                version: "0.1.0".to_string(),
            },
            source: InstallSource::LocalPath(pack_dir),
        })
        .expect("install with a vault provider configured");

    let project_id = client_no_vault
        .project_id(&project_root)
        .expect("project id");
    let rendered_path = |root: &Path| {
        root.join("projects")
            .join(&project_id)
            .join("personas/plain/rendered/claude/CLAUDE.md")
    };

    let no_vault_content =
        fs::read_to_string(rendered_path(&data_root_no_vault)).expect("read no-vault render");
    let with_vault_content =
        fs::read_to_string(rendered_path(&data_root_with_vault)).expect("read with-vault render");

    assert_eq!(
        no_vault_content, with_vault_content,
        "rendering must be byte-identical regardless of vault provider presence"
    );
    assert!(
        no_vault_content.contains("{{not_a_declared_token}}"),
        "an unmanifested pack's {{{{token}}}} markers are left untouched, exactly as before \
         this feature existed"
    );
}
