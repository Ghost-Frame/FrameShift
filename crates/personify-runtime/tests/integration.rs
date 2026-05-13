//! Integration tests for personify-runtime.
//!
//! Uses an in-test [`MemVaultBackend`] (sync, in-memory) to exercise
//! [`Runtime::load`], [`Runtime::render`], and all documented error paths.

use std::collections::BTreeMap;
use std::sync::Mutex;

use personify_runtime::{CapabilityManifest, Runtime, RuntimeConfig, RuntimeError, TemplateSource};
use personify_vault::{
    Auth, Identity, Preferences, RuntimeMode, VaultBackend, VaultData, VaultError,
};

use personify_memory::MemoryRequirement;

// ---------------------------------------------------------------------------
// MemVaultBackend -- in-test vault backend
// ---------------------------------------------------------------------------

/// Minimal in-memory vault backend for testing.
///
/// Wraps a `Mutex<Option<VaultData>>`. `open` returns the stored value (or
/// `BackendUnavailable` if none was loaded). `save` and `exists` are provided
/// for completeness but are not exercised by the runtime.
struct MemVaultBackend {
    /// The stored vault, if any.
    data: Mutex<Option<VaultData>>,
}

impl MemVaultBackend {
    /// Create a backend pre-loaded with `data`.
    fn with(data: VaultData) -> Self {
        Self {
            data: Mutex::new(Some(data)),
        }
    }
}

impl VaultBackend for MemVaultBackend {
    fn open(&self) -> Result<VaultData, VaultError> {
        self.data
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| VaultError::BackendUnavailable("empty".into()))
    }

    fn save(&self, data: &VaultData) -> Result<(), VaultError> {
        *self.data.lock().unwrap() = Some(data.clone());
        Ok(())
    }

    fn exists(&self) -> Result<bool, VaultError> {
        Ok(self.data.lock().unwrap().is_some())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal valid [`VaultData`] with the supplied key-value variables.
fn make_vault(variables: BTreeMap<String, String>) -> VaultData {
    VaultData {
        schema_version: 1,
        identity: Identity {
            keypair_pub: "age1testpubkey000000000000000000000000000000000000000000000000".into(),
            handle: "test-user".into(),
        },
        auth: Auth {
            methods: vec!["password".into()],
            unlock: "password".into(),
        },
        preferences: Preferences {
            runtime_mode: RuntimeMode::Rendered,
            publish_intent: "no".into(),
            recovery: "own-backup".into(),
        },
        memory: None,
        variables,
        overlays: BTreeMap::new(),
    }
}

/// Inline template source with two tokens and one section.
///
/// Token `name` is required; token `greeting` is optional.
const TEMPLATE_BODY: &str = "\
{{greeting}}, {{name}}!\n\
<!-- section:intro -->\n\
Default intro.\n\
<!-- /section -->\n\
";

const TEMPLATE_MANIFEST: &str = r#"
[tokens]
name = { type = "string", required = true, description = "The principal's name." }
greeting = { type = "string", required = false, description = "Optional greeting word." }

[sections]
intro = { description = "Introductory paragraph.", overridable = true }
"#;

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

/// A fully-configured Runtime renders the expected string.
#[test]
fn runtime_renders_correctly() {
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Alice".into());
    vars.insert("greeting".into(), "Hello".into());

    let vault = make_vault(vars);
    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: TEMPLATE_BODY.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let runtime = Runtime::load(config).expect("load must succeed");
    let output = runtime.render();
    assert!(output.contains("Hello, Alice!"), "rendered: {output}");
    assert!(output.contains("Default intro."), "rendered: {output}");
}

/// Optional token absent from vault leaves the placeholder in the output.
#[test]
fn optional_token_absent_leaves_placeholder() {
    // Only supply the required token; leave `greeting` absent.
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Bob".into());

    let vault = make_vault(vars);
    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: TEMPLATE_BODY.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let runtime = Runtime::load(config).expect("load must succeed");
    let output = runtime.render();
    // The template renderer leaves unresolved optional tokens as {{greeting}}.
    assert!(
        output.contains("{{greeting}},") || output.contains("{{greeting}} ,"),
        "optional token should remain unresolved: {output}"
    );
    assert!(output.contains("Bob!"), "rendered: {output}");
}

/// Vault overlay replaces the section's default content in the rendered output.
#[test]
fn vault_overlay_replaces_section_content() {
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Carol".into());
    vars.insert("greeting".into(), "Hi".into());

    let mut vault = make_vault(vars);
    // Key matches the section ID.
    vault
        .overlays
        .insert("intro".into(), "Custom intro for Carol.\n".into());

    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: TEMPLATE_BODY.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let runtime = Runtime::load(config).expect("load must succeed");
    let output = runtime.render();
    assert!(
        output.contains("Custom intro for Carol."),
        "rendered: {output}"
    );
    assert!(
        !output.contains("Default intro."),
        "default should be replaced: {output}"
    );
}

/// `Runtime::vault()` returns the vault that was loaded.
#[test]
fn runtime_vault_accessor() {
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Dave".into());
    let vault = make_vault(vars);

    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: TEMPLATE_BODY.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let runtime = Runtime::load(config).expect("load must succeed");
    assert_eq!(runtime.vault().identity.handle, "test-user");
}

/// `Runtime::template_manifest()` returns the parsed manifest.
#[test]
fn runtime_template_manifest_accessor() {
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Eve".into());
    let vault = make_vault(vars);

    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: TEMPLATE_BODY.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let runtime = Runtime::load(config).expect("load must succeed");
    let manifest = runtime.template_manifest();
    assert!(manifest.tokens.contains_key("name"));
    assert!(manifest.sections.contains_key("intro"));
}

/// `Runtime::memory()` returns `None` when no adapter was configured.
#[test]
fn runtime_memory_none_when_not_configured() {
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Frank".into());
    let vault = make_vault(vars);

    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: TEMPLATE_BODY.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let runtime = Runtime::load(config).expect("load must succeed");
    assert!(runtime.memory().is_none());
}

// ---------------------------------------------------------------------------
// Error-path tests
// ---------------------------------------------------------------------------

/// A required token absent from vault produces `MissingRequiredToken`.
#[test]
fn missing_required_token_returns_error() {
    // Supply no variables; `name` is required.
    let vault = make_vault(BTreeMap::new());

    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: TEMPLATE_BODY.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let err = Runtime::load(config).expect_err("must fail: required token missing");
    assert!(
        matches!(err, RuntimeError::MissingRequiredToken(ref t) if t == "name"),
        "unexpected error: {err}"
    );
}

/// Template referencing a token not in the manifest produces `UndeclaredToken`.
#[test]
fn undeclared_token_returns_error() {
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Grace".into());
    let vault = make_vault(vars);

    // Template references {{unknown_token}} which is absent from the manifest.
    let bad_template = "{{name}} {{unknown_token}}\n";
    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: bad_template.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let err = Runtime::load(config).expect_err("must fail: undeclared token");
    assert!(
        matches!(err, RuntimeError::UndeclaredToken(ref t) if t == "unknown_token"),
        "unexpected error: {err}"
    );
}

/// Template referencing a section not in the manifest produces `UndeclaredSection`.
#[test]
fn undeclared_section_returns_error() {
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Hank".into());
    let vault = make_vault(vars);

    // Template has a section `ghost` not declared in the manifest.
    let bad_template = "\
{{name}}\n\
<!-- section:ghost -->\n\
Default.\n\
<!-- /section -->\n\
";
    // Use a manifest that has `name` declared but no `ghost` section.
    let manifest = r#"
[tokens]
name = { type = "string", required = true, description = "Name." }
"#;
    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: bad_template.into(),
            manifest: manifest.into(),
        },
        memory_adapter: None,
    };

    let err = Runtime::load(config).expect_err("must fail: undeclared section");
    assert!(
        matches!(err, RuntimeError::UndeclaredSection(ref s) if s == "ghost"),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------------------
// check_memory_capability tests
// ---------------------------------------------------------------------------

/// Hard memory requirement with no adapter returns `MemoryUnconfigured`.
#[test]
fn check_memory_capability_hard_no_adapter() {
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Iris".into());
    let vault = make_vault(vars);

    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: TEMPLATE_BODY.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let runtime = Runtime::load(config).expect("load must succeed");

    let capability = CapabilityManifest {
        memory_required: Some(MemoryRequirement::Hard),
        memory_required_ops: vec![],
    };

    let err = runtime
        .check_memory_capability(&capability)
        .expect_err("must fail: memory unconfigured");
    assert!(
        matches!(err, RuntimeError::MemoryUnconfigured),
        "unexpected error: {err}"
    );
}

/// Soft memory requirement with no adapter returns `Ok`.
#[test]
fn check_memory_capability_soft_no_adapter_ok() {
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Jack".into());
    let vault = make_vault(vars);

    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: TEMPLATE_BODY.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let runtime = Runtime::load(config).expect("load must succeed");

    let capability = CapabilityManifest {
        memory_required: Some(MemoryRequirement::Soft),
        memory_required_ops: vec![],
    };

    runtime
        .check_memory_capability(&capability)
        .expect("soft requirement with no adapter should be Ok");
}

/// No memory requirement at all returns `Ok`.
#[test]
fn check_memory_capability_none_ok() {
    let mut vars = BTreeMap::new();
    vars.insert("name".into(), "Kim".into());
    let vault = make_vault(vars);

    let config = RuntimeConfig {
        vault_backend: Box::new(MemVaultBackend::with(vault)),
        template_source: TemplateSource::Inline {
            content: TEMPLATE_BODY.into(),
            manifest: TEMPLATE_MANIFEST.into(),
        },
        memory_adapter: None,
    };

    let runtime = Runtime::load(config).expect("load must succeed");

    let capability = CapabilityManifest::default();
    runtime
        .check_memory_capability(&capability)
        .expect("no requirement should always be Ok");
}
