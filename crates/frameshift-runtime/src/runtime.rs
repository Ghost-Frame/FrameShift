//! Core [`Runtime`] type and its construction via [`RuntimeConfig`].

use std::collections::BTreeMap;
use std::sync::Arc;

use frameshift_memory::{MemoryAdapter, MemoryRequirement};
use frameshift_template::{Template, TemplateManifest};
use frameshift_vault::{VaultBackend, VaultData};

use crate::capability::CapabilityManifest;
use crate::error::RuntimeError;
use crate::source::TemplateSource;

// ---------------------------------------------------------------------------
// RuntimeConfig
// ---------------------------------------------------------------------------

/// Configuration required to construct a [`Runtime`].
///
/// Callers assemble a `RuntimeConfig` -- providing a vault backend, template
/// source, and optionally a memory adapter -- then hand it to [`Runtime::load`].
pub struct RuntimeConfig {
    /// The vault backend from which [`VaultData`] will be loaded.
    ///
    /// Must be `Send + Sync` so it can be used across thread boundaries.
    pub vault_backend: Box<dyn VaultBackend + Send + Sync>,

    /// How to obtain the template body and companion manifest.
    pub template_source: TemplateSource,

    /// Optional memory adapter for use by agent shims after the runtime is
    /// constructed. The runtime itself does not call any adapter methods
    /// during `load` or `render`.
    pub memory_adapter: Option<Arc<dyn MemoryAdapter>>,
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

/// An orchestrated persona runtime, ready to render a prompt string.
///
/// Constructed via [`Runtime::load`], which performs all validation up front
/// so that [`Runtime::render`] is always infallible.
///
/// # Invariants
///
/// After `load` succeeds:
/// - Every token referenced by the template is declared in the manifest.
/// - Every section referenced by the template is declared in the manifest.
/// - Every `required = true` token in the manifest has a value in the vault.
///
/// These invariants mean that `render` will always produce a fully-substituted
/// string (no dangling `{{token}}` markers for required tokens).
///
/// `Debug` is implemented manually because `Arc<dyn MemoryAdapter>` does not
/// require the trait object to implement `Debug`.
pub struct Runtime {
    /// The decrypted, validated vault contents.
    vault: VaultData,

    /// The parsed template, ready for rendering.
    template: Template,

    /// The parsed companion manifest describing declared tokens and sections.
    manifest: TemplateManifest,

    /// Optional memory adapter held for use by agent shims.
    memory: Option<Arc<dyn MemoryAdapter>>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("vault", &self.vault)
            .field("manifest", &self.manifest)
            .field("memory_configured", &self.memory.is_some())
            .finish_non_exhaustive()
    }
}

impl Runtime {
    /// Load and validate a [`Runtime`] from the supplied [`RuntimeConfig`].
    ///
    /// # Steps
    ///
    /// 1. Open the vault via `config.vault_backend.open()`.
    /// 2. Load the template body and manifest (from inline strings or disk).
    /// 3. Parse both with [`Template::parse`] and [`TemplateManifest::from_toml`].
    /// 4. Validate that every token used in the template is declared in the manifest.
    /// 5. Validate that every section used in the template is declared in the manifest.
    /// 6. Validate that every `required = true` token has a value in the vault.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Vault`] when the vault backend fails,
    /// [`RuntimeError::Template`] when parsing fails,
    /// [`RuntimeError::UndeclaredToken`] / [`RuntimeError::UndeclaredSection`]
    /// when the template references names not in the manifest, and
    /// [`RuntimeError::MissingRequiredToken`] when a required vault variable is absent.
    pub fn load(config: RuntimeConfig) -> Result<Self, RuntimeError> {
        // Step 1: open vault.
        let vault = config.vault_backend.open()?;

        // Step 2 + 3: load and parse template source.
        let (template, manifest) = load_template(config.template_source)?;

        // Step 4: every token name in the template must be declared in the manifest.
        for token_name in template.tokens() {
            if !manifest.tokens.contains_key(token_name) {
                return Err(RuntimeError::UndeclaredToken(token_name.to_owned()));
            }
        }

        // Step 5: every section ID in the template must be declared in the manifest.
        for section_id in template.sections() {
            if !manifest.sections.contains_key(section_id) {
                return Err(RuntimeError::UndeclaredSection(section_id.to_owned()));
            }
        }

        // Step 6: every required token must have a value in the vault.
        for (name, decl) in &manifest.tokens {
            if decl.required && !vault.variables.contains_key(name) {
                return Err(RuntimeError::MissingRequiredToken(name.clone()));
            }
        }

        Ok(Self {
            vault,
            template,
            manifest,
            memory: config.memory_adapter,
        })
    }

    /// Render the persona template to a fully-substituted string.
    ///
    /// Vault variables are used as token substitution values, and vault overlays
    /// are used as section overlay values. Both maps are passed through
    /// directly; the template's own renderer handles missing keys gracefully
    /// (missing optional tokens are left as `{{name}}` in the output, missing
    /// overlay sections use their default content).
    ///
    /// This method is infallible: all validation was performed in [`Runtime::load`].
    pub fn render(&self) -> String {
        // Clone the BTreeMap references out so we can call render with &BTreeMap.
        // vault.variables() returns &BTreeMap<String, String> so no allocation needed.
        let variables: &BTreeMap<String, String> = self.vault.variables();
        let overlays: &BTreeMap<String, String> = self.vault.overlays();
        self.template.render(variables, overlays)
    }

    /// Return a reference to the loaded vault data.
    pub fn vault(&self) -> &VaultData {
        &self.vault
    }

    /// Return a reference to the parsed template manifest.
    pub fn template_manifest(&self) -> &TemplateManifest {
        &self.manifest
    }

    /// Return a reference to the optional memory adapter, if one was configured.
    pub fn memory(&self) -> Option<&Arc<dyn MemoryAdapter>> {
        self.memory.as_ref()
    }

    /// Check whether the configured memory adapter satisfies `capability`.
    ///
    /// Returns `Ok(())` unless `capability.memory_required` is
    /// [`MemoryRequirement::Hard`] and no memory adapter was configured, in
    /// which case [`RuntimeError::MemoryUnconfigured`] is returned.
    ///
    /// Soft requirements and absent requirements always return `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::MemoryUnconfigured`] when a hard memory
    /// requirement is declared but no adapter is present.
    pub fn check_memory_capability(
        &self,
        capability: &CapabilityManifest,
    ) -> Result<(), RuntimeError> {
        if capability.memory_required == Some(MemoryRequirement::Hard) && self.memory.is_none() {
            return Err(RuntimeError::MemoryUnconfigured);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Load the template body and manifest TOML from a [`TemplateSource`], then
/// parse both.  Returns `(Template, TemplateManifest)` on success.
fn load_template(source: TemplateSource) -> Result<(Template, TemplateManifest), RuntimeError> {
    let (template_text, manifest_text) = match source {
        TemplateSource::Inline { content, manifest } => (content, manifest),
        TemplateSource::File {
            template_path,
            manifest_path,
        } => {
            let template_text =
                std::fs::read_to_string(&template_path).map_err(|source| RuntimeError::Io {
                    path: template_path.clone(),
                    source,
                })?;
            let manifest_text =
                std::fs::read_to_string(&manifest_path).map_err(|source| RuntimeError::Io {
                    path: manifest_path.clone(),
                    source,
                })?;
            (template_text, manifest_text)
        }
    };

    let template = Template::parse(&template_text)?;
    let manifest = TemplateManifest::from_toml(&manifest_text)?;
    Ok((template, manifest))
}
