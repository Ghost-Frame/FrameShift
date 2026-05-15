//! Template manifest parsing for `pack.template.toml`.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::TemplateError;

// ── Public types ──────────────────────────────────────────────────────────────

/// A parsed `pack.template.toml` manifest describing a template's overridable
/// sections and required token declarations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TemplateManifest {
    /// Declared sections, keyed by section ID.
    #[serde(default)]
    pub sections: BTreeMap<String, SectionDecl>,

    /// Declared tokens, keyed by token name.
    #[serde(default)]
    pub tokens: BTreeMap<String, TokenDecl>,
}

impl TemplateManifest {
    /// Parse a `pack.template.toml` manifest from its TOML source text.
    ///
    /// # Errors
    ///
    /// Returns [`TemplateError::ManifestParse`] when the TOML is malformed or
    /// does not match the expected schema.
    pub fn from_toml(source: &str) -> Result<Self, TemplateError> {
        let manifest: Self = toml::from_str(source)?;
        Ok(manifest)
    }
}

/// Declaration of a single overridable section in a template.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SectionDecl {
    /// Human-readable description of what this section controls.
    pub description: String,

    /// Whether this section may be overridden by a persona pack.
    pub overridable: bool,
}

/// Declaration of a single token placeholder in a template.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TokenDecl {
    /// The type of the token value. Currently always `"string"`.
    #[serde(rename = "type")]
    pub token_type: String,

    /// Whether a value for this token must be supplied at render time.
    pub required: bool,

    /// Human-readable description of this token's purpose.
    pub description: String,
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
[sections]
identity_prelude = { description = "How the agent addresses the principal", overridable = true }
behavioral_mandates = { description = "Core behavioral rules", overridable = true }
tool_preferences = { description = "Tool usage preferences", overridable = false }

[tokens]
principal_name = { type = "string", required = true, description = "Name of the principal user" }
principal_address = { type = "string", required = true, description = "How the agent addresses the principal" }
memory_endpoint = { type = "string", required = false, description = "Memory server URL" }
"#;

    #[test]
    fn manifest_round_trip() {
        let manifest = TemplateManifest::from_toml(SAMPLE_TOML).unwrap();

        // Sections
        assert_eq!(manifest.sections.len(), 3);
        let ip = manifest.sections.get("identity_prelude").unwrap();
        assert_eq!(ip.description, "How the agent addresses the principal");
        assert!(ip.overridable);

        let tp = manifest.sections.get("tool_preferences").unwrap();
        assert!(!tp.overridable);

        // Tokens
        assert_eq!(manifest.tokens.len(), 3);
        let pn = manifest.tokens.get("principal_name").unwrap();
        assert_eq!(pn.token_type, "string");
        assert!(pn.required);

        let me = manifest.tokens.get("memory_endpoint").unwrap();
        assert!(!me.required);
    }

    #[test]
    fn empty_manifest_is_valid() {
        let manifest = TemplateManifest::from_toml("").unwrap();
        assert!(manifest.sections.is_empty());
        assert!(manifest.tokens.is_empty());
    }

    #[test]
    fn invalid_toml_returns_error() {
        let err = TemplateManifest::from_toml("not = [valid toml").unwrap_err();
        assert!(matches!(err, crate::error::TemplateError::ManifestParse(_)));
    }
}
