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
    pub parent_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_manifest: Option<CapabilityManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires: Option<Requires>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_required: Option<BTreeMap<String, TokenSpec>>,
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
    }
}
