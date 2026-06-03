use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackManifest {
    pub schema_version: u32,
    pub name: String,
    pub author_handle: String,
    pub author_pubkey: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_manifest: Option<CapabilityManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires: Option<Requires>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_required: Option<BTreeMap<String, TokenSpec>>,
    /// Persona this pack extends (composition base). Format: "<name>@<semver-req>".
    /// Resolution happens at install time; missing base is a hard error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    /// Mixin packs composed on top of (extends -> self). Same format as `extends`.
    /// Resolution order: extends -> mixins[0] -> mixins[1] -> ... -> self.
    /// Conflicts between layers require explicit `override` declarations in the source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mixin: Vec<String>,
    /// Conformance baseline: minimum score the pack version asserts on its own test bundle.
    /// The runtime conformance runner (M4) gates upgrades on this; if a newer version
    /// scores below baseline on the OLD bundle, the upgrade is blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformance_baseline: Option<ConformanceBaseline>,
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct ConformanceBaseline {
    /// Floor score (0.0..1.0) the pack claims on its bundled tests at publish time.
    pub score: f32,
    /// Hash of the test bundle this score was measured against (sha256 hex).
    /// Lets the runtime detect if the bundle changed underneath the baseline.
    pub bundle_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityManifest {
    #[serde(default)]
    pub required_tools: Vec<String>,
    #[serde(default)]
    pub network_egress: bool,
    #[serde(default)]
    pub env_vars_read: Vec<String>,
    #[serde(default)]
    pub filesystem_scope: FilesystemScope,
    #[serde(default)]
    pub memory_required: MemoryRequirement,
    #[serde(default)]
    pub memory_required_ops: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemScope {
    None,
    #[default]
    ProjectOnly,
    Home,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MemoryRequirement {
    #[default]
    None,
    Soft,
    Hard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Requires {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_min_version: Option<String>,
    #[serde(default)]
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenSpec {
    #[serde(rename = "type")]
    pub token_type: String,
    pub prompt: String,
    #[serde(default)]
    pub optional: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_full_manifest() {
        let toml_str = r#"
schema_version = 1
name = "zenpilot"
author_handle = "alice"
author_pubkey = "age1test..."
version = "1.2.0"
description = "A thoughtful architectural review persona"
tags = ["architecture", "review"]
parent_hash = "sha256:abc123"
license = "CC-BY-SA-4.0"

[capability_manifest]
required_tools = ["Read", "Edit", "Bash"]
network_egress = false
env_vars_read = ["HOME", "USER"]
filesystem_scope = "project-only"
memory_required = "none"
memory_required_ops = []

[requires]
template_min_version = "2.0"
targets = ["assistant", "coder"]

[tokens_required.principal_address]
type = "string"
prompt = "How should the agent address you?"

[tokens_required.favorite_motto]
type = "string"
prompt = "A short motto for the agent's voice"
optional = true
"#;
        let manifest: PackManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.name, "zenpilot");
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.author_handle, "alice");
        assert_eq!(
            manifest.description,
            Some("A thoughtful architectural review persona".to_string())
        );
        assert_eq!(
            manifest.tags,
            vec!["architecture".to_string(), "review".to_string()]
        );
        assert_eq!(manifest.parent_hash, Some("sha256:abc123".to_string()));

        let cap = manifest.capability_manifest.unwrap();
        assert_eq!(cap.required_tools, vec!["Read", "Edit", "Bash"]);
        assert!(!cap.network_egress);
        assert_eq!(cap.filesystem_scope, FilesystemScope::ProjectOnly);
        assert_eq!(cap.memory_required, MemoryRequirement::None);

        let req = manifest.requires.unwrap();
        assert_eq!(req.targets, vec!["assistant", "coder"]);

        let tokens = manifest.tokens_required.unwrap();
        assert_eq!(tokens.len(), 2);
        assert!(tokens["favorite_motto"].optional);
        assert!(!tokens["principal_address"].optional);
    }

    #[test]
    fn deserialize_minimal_manifest() {
        let toml_str = r#"
schema_version = 1
name = "minimal"
author_handle = "test"
author_pubkey = "age1minimal..."
version = "0.1.0"
"#;
        let manifest: PackManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.name, "minimal");
        assert!(manifest.capability_manifest.is_none());
        assert!(manifest.requires.is_none());
        assert!(manifest.tokens_required.is_none());
        assert!(manifest.parent_hash.is_none());
        assert!(manifest.description.is_none());
        assert!(manifest.tags.is_empty());
    }

    #[test]
    fn manifest_roundtrip_with_extends_and_mixin() {
        let original = PackManifest {
            schema_version: 1,
            name: "child".to_string(),
            author_handle: "alice".to_string(),
            author_pubkey: "age1test...".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Child persona".to_string()),
            tags: vec!["child".to_string(), "mixin".to_string()],
            parent_hash: None,
            license: None,
            capability_manifest: None,
            requires: None,
            tokens_required: None,
            extends: Some("base@^1.0".to_string()),
            mixin: vec!["addon-a@~0.2".to_string(), "addon-b@1.0.0".to_string()],
            conformance_baseline: Some(ConformanceBaseline {
                score: 0.85,
                bundle_hash: "deadbeef".to_string(),
            }),
        };

        let serialized = toml::to_string(&original).unwrap();
        let parsed: PackManifest = toml::from_str(&serialized).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn manifest_omits_empty_optional_fields() {
        let minimal = PackManifest {
            schema_version: 1,
            name: "minimal".to_string(),
            author_handle: "t".to_string(),
            author_pubkey: "k".to_string(),
            version: "0.1.0".to_string(),
            description: None,
            tags: Vec::new(),
            parent_hash: None,
            license: None,
            capability_manifest: None,
            requires: None,
            tokens_required: None,
            extends: None,
            mixin: Vec::new(),
            conformance_baseline: None,
        };

        let serialized = toml::to_string(&minimal).unwrap();
        assert!(!serialized.contains("extends"));
        assert!(!serialized.contains("mixin"));
        assert!(!serialized.contains("conformance_baseline"));
        assert!(!serialized.contains("description"));
        assert!(!serialized.contains("tags"));
    }
}
