//! Filters runtime tools against capabilities declared by a persona pack.

use std::collections::BTreeSet;

use frameshift_pack::CapabilityManifest;
use serde::{Deserialize, Serialize};

/// A tool advertised by a runtime (Claude Code, MCP server, etc.) with the set of
/// capability names it requires the persona to have declared in order to be exposed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tool {
    /// Runtime-advertised tool name.
    pub name: String,
    /// Capabilities that must all be declared before the tool is exposed.
    pub required_capabilities: Vec<String>,
}

/// Filters runtime-advertised tool lists down to those whose required capabilities
/// are all present in the persona's declared manifest.
#[derive(Debug, Clone)]
pub struct CapabilityFilter {
    /// Canonical capability names declared by the active persona.
    declared: BTreeSet<String>,
}

/// Construction, inspection, and filtering operations for capability policy.
impl CapabilityFilter {
    /// Build a filter from a pack capability manifest.
    ///
    /// For now we treat `required_tools` as the canonical declared-capability set
    /// (each tool name doubles as a capability key). Additional dimensions
    /// (`network_egress`, `filesystem_scope`, etc.) are tracked separately by the
    /// caller and are out of scope for the basic tool-list filter.
    pub fn from_manifest(manifest: &CapabilityManifest) -> Self {
        let declared = manifest.required_tools.iter().cloned().collect();
        Self { declared }
    }

    /// Build a filter directly from an explicit declared-capability set. Useful for
    /// tests and for callers that compose capabilities from multiple sources.
    pub fn from_declared<I, S>(declared: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            declared: declared.into_iter().map(Into::into).collect(),
        }
    }

    /// The declared capability set this filter enforces against.
    pub fn declared(&self) -> &BTreeSet<String> {
        &self.declared
    }

    /// Return `true` if every required capability of `tool` is declared.
    pub fn allows(&self, tool: &Tool) -> bool {
        tool.required_capabilities
            .iter()
            .all(|cap| self.declared.contains(cap))
    }

    /// Drop any tool whose required capabilities are not all declared.
    pub fn filter_tool_list(&self, tools: &[Tool]) -> Vec<Tool> {
        tools.iter().filter(|t| self.allows(t)).cloned().collect()
    }
}

#[cfg(test)]
/// Regression tests for restrictive capability filtering and deserialization.
mod tests {
    use super::*;

    /// Tools requiring any undeclared capability are excluded.
    #[test]
    fn filter_drops_tools_requiring_undeclared_capabilities() {
        let filter = CapabilityFilter::from_declared(["Read", "Edit"]);
        let tools = vec![
            Tool {
                name: "Read".to_string(),
                required_capabilities: vec!["Read".to_string()],
            },
            Tool {
                name: "Bash".to_string(),
                required_capabilities: vec!["Bash".to_string()],
            },
            Tool {
                name: "Edit".to_string(),
                required_capabilities: vec!["Read".to_string(), "Edit".to_string()],
            },
        ];
        let allowed = filter.filter_tool_list(&tools);
        let names: Vec<&str> = allowed.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["Read", "Edit"]);
    }

    /// Explicitly unrestricted tools remain usable with an empty declaration set.
    #[test]
    fn tool_with_no_required_capabilities_is_always_allowed() {
        let filter = CapabilityFilter::from_declared::<[&str; 0], _>([]);
        let tool = Tool {
            name: "Noop".to_string(),
            required_capabilities: vec![],
        };
        assert!(filter.allows(&tool));
    }

    /// Missing capability metadata is rejected instead of becoming unrestricted.
    #[test]
    fn tool_deserialization_requires_capability_metadata() {
        let error = serde_json::from_str::<Tool>(r#"{"name":"Bash"}"#).unwrap_err();
        assert!(error.to_string().contains("required_capabilities"));
    }
}
