use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Whether the user has opted in to sharing anonymous persona-selection
    /// telemetry. Privacy-first: defaults to `false`, so telemetry is only ever
    /// sent when the user explicitly enables it (and an endpoint is configured).
    #[serde(default)]
    pub telemetry_opt_in: bool,
    /// Optional memory-adapter declaration for this project. Personas whose
    /// pack manifest sets `memory_required = "hard"` refuse to activate unless
    /// this is present; `"soft"` personas surface a warning without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryConfig>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            project_id: None,
            telemetry_opt_in: false,
            memory: None,
        }
    }
}

/// The memory-requirement posture of a persona within a project, combining
/// the pack manifest's declared requirement with whether the project declares
/// a memory adapter. Consumed by activation surfaces to refuse or warn.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryRequirementStatus {
    /// Requirement declared by the persona's pack manifest.
    pub requirement: frameshift_pack::MemoryRequirement,
    /// Whether the project declares a `[memory]` adapter in config.toml.
    pub memory_declared: bool,
}

impl MemoryRequirementStatus {
    /// A hard requirement with no declared adapter: activation must refuse.
    pub fn hard_unmet(&self) -> bool {
        self.requirement == frameshift_pack::MemoryRequirement::Hard && !self.memory_declared
    }

    /// A soft requirement with no declared adapter: callers should warn.
    pub fn soft_unmet(&self) -> bool {
        self.requirement == frameshift_pack::MemoryRequirement::Soft && !self.memory_declared
    }
}

/// A declared memory adapter for a project.
///
/// The sync client only records and validates the declaration; live
/// connectivity checks belong to the async surfaces (daemon, server) that
/// actually construct a `MemoryAdapter`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryConfig {
    /// Adapter kind, e.g. `"http"` or `"sqlite"`.
    pub adapter: String,
    /// Endpoint URL for HTTP-backed adapters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Database path for local file-backed adapters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
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

impl PersonaSpec {
    /// Parse a loosely-specified persona spec: either a bare name (`"foo"`)
    /// or a `name@version` pair (`"foo@1.0.0"`).
    ///
    /// Unlike [`PersonaSpec::from_str`] (the strict `FromStr` impl, pinned by
    /// `rejects_invalid_persona_specs` and unchanged here), a bare name with
    /// no `@` is accepted and returned with `None` for the version, so the
    /// caller can resolve it to the registry's latest published version.
    ///
    /// Returns `Err(ClientError::InvalidPersonaSpec)` for an empty string, an
    /// empty name (`"@version"`), or an empty version after `@`
    /// (`"name@"`).
    pub fn parse_loose(s: &str) -> Result<(String, Option<String>), crate::ClientError> {
        match s.split_once('@') {
            None => {
                if s.is_empty() {
                    Err(crate::ClientError::InvalidPersonaSpec(s.to_string()))
                } else {
                    Ok((s.to_string(), None))
                }
            }
            Some((name, version)) => {
                if name.is_empty() || version.is_empty() {
                    Err(crate::ClientError::InvalidPersonaSpec(s.to_string()))
                } else {
                    Ok((name.to_string(), Some(version.to_string())))
                }
            }
        }
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
///
/// `Debug`/`PartialEq`/`Eq` are implemented manually (rather than derived)
/// because `vault` holds a trait object: [`crate::VaultProvider`]
/// implementations are not generally `Debug` or comparable by value. See
/// the manual impls below for exactly what each derives to.
#[derive(Clone)]
pub struct ClientOptions {
    /// Root of the Frameshift data directory (e.g. ~/.local/share/frameshift).
    pub data_root: PathBuf,
    /// Root of the XDG config directory (e.g. ~/.config).
    /// When set, the engine looks for `frameshift/infrastructure.md`
    /// under this path and composes it into rendered output.
    pub config_root: Option<PathBuf>,
    /// Optional supplier of decrypted vault data, used to substitute
    /// `{{token}}` placeholders when materializing a templated pack (one
    /// that ships `pack.template.toml`). `None` means templated packs fail
    /// render with [`crate::ClientError::MissingRequiredTokens`] rather than
    /// silently leaving `{{token}}` placeholders unsubstituted.
    ///
    /// # Never-prompts contract
    ///
    /// The client library itself never prompts for a vault passphrase.
    /// Implementations of [`crate::VaultProvider`] passed here MUST NOT
    /// block on interactive input (stdin reads, TTY prompts, etc.); any
    /// interactive passphrase prompting belongs in the caller (e.g. the
    /// `frameshift` CLI's `make_client`), performed before the passphrase is
    /// captured into the provider closure/impl.
    pub vault: Option<Arc<dyn crate::VaultProvider>>,
}

impl std::fmt::Debug for ClientOptions {
    /// Prints whether a vault provider is configured, without attempting to
    /// format the trait object itself (arbitrary `VaultProvider` impls are
    /// not required to be `Debug`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("data_root", &self.data_root)
            .field("config_root", &self.config_root)
            .field("vault_configured", &self.vault.is_some())
            .finish()
    }
}

impl PartialEq for ClientOptions {
    /// Compares `data_root`/`config_root` structurally and `vault` by
    /// `Arc` pointer identity (`Arc::ptr_eq`) -- trait objects have no
    /// general notion of value equality, but pointer identity is still a
    /// well-defined equivalence relation, so this remains a lawful `Eq`.
    fn eq(&self, other: &Self) -> bool {
        self.data_root == other.data_root
            && self.config_root == other.config_root
            && match (&self.vault, &other.vault) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}

impl Eq for ClientOptions {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPaths {
    pub project_root: PathBuf,
    pub project_id: String,
    /// Central-store config path: `$XDG_DATA_HOME/frameshift/projects/<id>/config.toml`.
    pub config_path: PathBuf,
    /// Central-store lock path: `$XDG_DATA_HOME/frameshift/projects/<id>/lock.toml`.
    /// This is the canonical lock location -- nothing is written to the project root.
    pub lock_path: PathBuf,
    /// Central-store vault path: `$XDG_DATA_HOME/frameshift/projects/<id>/vault.age`.
    /// Sibling of `config_path`. Holds this project's `{{token}}` values for
    /// templated packs, age-encrypted via `frameshift-vault-local`. Nothing
    /// is written to the project root.
    pub vault_path: PathBuf,
    pub cache_dir: PathBuf,
    pub project_state_dir: PathBuf,
    pub active_path: PathBuf,
    pub personas_dir: PathBuf,
}

/// Outcome of [`crate::Client::install`].
///
/// `conformance_upgrade` is additive: it carries a best-effort, warn-only
/// comparison of the incoming pack's shipped conformance baseline against
/// the previously-installed version's baseline (see
/// `frameshift_conformance::RegressionGate::evaluate_cross_version`).
/// No derive of `Eq` here (unlike the other report types) because
/// `CrossVersionDecision` carries `f32` score deltas, which are not `Eq`.
#[derive(Debug, Clone, PartialEq)]
pub struct InstallReport {
    pub project_id: String,
    pub persona: LockedPersona,
    pub cache_path: PathBuf,
    /// Cross-version conformance-baseline comparison against the version
    /// previously installed for this project, when there was one. `None`
    /// for a fresh install (no prior version) or when the comparison could
    /// not be attempted for any reason -- this field is advisory only and
    /// never blocks or fails the install. See [`crate::Client::install`].
    pub conformance_upgrade: Option<frameshift_conformance::CrossVersionDecision>,
    /// Per-persona materialization failures of OTHER locked personas hit while
    /// re-materializing project state for this install. The persona being
    /// installed failing is a hard error, never an entry here. Advisory:
    /// callers should surface these as warnings.
    pub materialize_failures: Vec<MaterializeFailure>,
}

/// A single persona that could not be materialized from the cache during
/// project-state materialization (unrenderable pack, missing cache entry,
/// unparsable manifest). Carried on [`SyncReport`]/[`InstallReport`] so one
/// rotten pack degrades to a warning instead of bricking every persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializeFailure {
    /// Name of the locked persona that failed.
    pub persona: String,
    /// Human-readable cause, rendered from the underlying [`crate::ClientError`].
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub project_id: String,
    pub personas: Vec<String>,
    /// Locked personas that failed to materialize this sync (advisory; the
    /// healthy personas listed in `personas` still rendered).
    pub failures: Vec<MaterializeFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    pub removed_hashes: Vec<String>,
}

/// Result of [`crate::Client::active_persona_state`]: the active marker
/// cross-checked against whether the persona's content is actually on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivePersonaState {
    /// No active marker (or an empty one).
    None,
    /// The marker names a persona whose `source/pack.toml` is materialized.
    Materialized(String),
    /// The marker names a persona whose materialized content is absent --
    /// typically because its last sync failed and the half-built directory
    /// was cleaned. Reading its source or rendered output will fail; the
    /// actionable remedies are a re-sync or a reinstall.
    Unmaterialized(String),
}

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    /// parse_loose accepts a bare name and returns `None` for the version.
    #[test]
    fn parse_loose_accepts_bare_name() {
        let (name, version) = PersonaSpec::parse_loose("cryptographic").unwrap();
        assert_eq!(name, "cryptographic");
        assert_eq!(version, None);
    }

    /// parse_loose accepts a `name@version` pair.
    #[test]
    fn parse_loose_accepts_versioned_spec() {
        let (name, version) = PersonaSpec::parse_loose("cryptographic@1.2.3").unwrap();
        assert_eq!(name, "cryptographic");
        assert_eq!(version, Some("1.2.3".to_string()));
    }

    /// parse_loose rejects an empty name before `@`.
    #[test]
    fn parse_loose_rejects_empty_name() {
        assert!(PersonaSpec::parse_loose("@1.0.0").is_err());
    }

    /// parse_loose rejects an empty version after `@`.
    #[test]
    fn parse_loose_rejects_empty_version() {
        assert!(PersonaSpec::parse_loose("cryptographic@").is_err());
    }

    /// parse_loose rejects an empty string.
    #[test]
    fn parse_loose_rejects_empty_string() {
        assert!(PersonaSpec::parse_loose("").is_err());
    }
}
