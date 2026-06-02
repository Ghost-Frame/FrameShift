use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default)]
    pub telemetry_opt_in: bool,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            project_id: None,
            telemetry_opt_in: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lockfile {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default, rename = "persona")]
    pub personas: Vec<LockedPersona>,
}

impl Default for Lockfile {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            personas: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedPersona {
    pub name: String,
    pub version: String,
    pub author_handle: String,
    pub author_pubkey: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaSpec {
    pub name: String,
    pub version: String,
}

impl std::str::FromStr for PersonaSpec {
    type Err = crate::ClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((name, version)) = s.split_once('@') else {
            return Err(crate::ClientError::InvalidPersonaSpec(s.to_string()));
        };

        if name.is_empty() || version.is_empty() {
            return Err(crate::ClientError::InvalidPersonaSpec(s.to_string()));
        }

        Ok(Self {
            name: name.to_string(),
            version: version.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallSource {
    LocalPath(PathBuf),
    Registry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRequest {
    pub project_root: PathBuf,
    pub spec: PersonaSpec,
    pub source: InstallSource,
}

/// Options for constructing a Frameshift `Client`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOptions {
    /// Root of the Frameshift data directory (e.g. ~/.local/share/frameshift).
    pub data_root: PathBuf,
    /// Root of the XDG config directory (e.g. ~/.config).
    /// When set, the engine looks for `frameshift/infrastructure.md`
    /// under this path and composes it into rendered output.
    pub config_root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPaths {
    pub project_root: PathBuf,
    pub project_id: String,
    /// Central-store config path: `$XDG_DATA_HOME/frameshift/projects/<id>/config.toml`.
    pub config_path: PathBuf,
    /// Central-store lock path: `$XDG_DATA_HOME/frameshift/projects/<id>/lock.toml`.
    /// This is the canonical lock location -- nothing is written to the project root.
    pub lock_path: PathBuf,
    pub cache_dir: PathBuf,
    pub project_state_dir: PathBuf,
    pub active_path: PathBuf,
    pub personas_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub project_id: String,
    pub persona: LockedPersona,
    pub cache_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub project_id: String,
    pub personas: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    pub removed_hashes: Vec<String>,
}

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}
