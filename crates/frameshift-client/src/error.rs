use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("failed to read or write {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse TOML from {path}: {source}")]
    TomlDeserialize {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("failed to serialize TOML: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("central project config at {0} is corrupted or unreadable")]
    CorruptedCentralConfig(PathBuf),

    #[error("invalid persona spec {0:?}; expected <name>@<version>")]
    InvalidPersonaSpec(String),

    #[error("project path is not valid UTF-8: {0}")]
    NonUtf8Path(PathBuf),

    #[error("invalid explicit project_id {0:?}; path separators are not allowed")]
    InvalidProjectId(String),

    #[error(
        "pack manifest did not match requested spec: expected {expected_name}@{expected_version}, got {actual_name}@{actual_version}"
    )]
    ManifestMismatch {
        expected_name: String,
        expected_version: String,
        actual_name: String,
        actual_version: String,
    },

    #[error("registry fetch failed: {0}")]
    RegistryFetch(String),

    #[error("telemetry error: {0}")]
    Telemetry(String),

    #[error("cache entry {hash} is missing at {path}")]
    MissingCacheEntry { hash: String, path: PathBuf },

    #[error("no renderable markdown entry found in pack at {0}")]
    MissingRenderSource(PathBuf),

    #[error("persona {0:?} is not present in frameshift.lock")]
    PersonaNotInstalled(String),

    #[error("author_pubkey is not a supported ed25519 public key encoding: {0}")]
    InvalidAuthorPublicKey(String),

    #[error("pack signature verification failed")]
    SignatureVerification,

    #[error(transparent)]
    Pack(#[from] frameshift_pack::PackError),

    /// The rendered output file for the requested persona and target does not exist.
    #[error("rendered persona '{persona}' for target '{target}' not found at {path}")]
    RenderedPersonaNotFound {
        /// The persona name.
        persona: String,
        /// The render target (e.g. "claude", "codex").
        target: String,
        /// The expected path that was missing.
        path: std::path::PathBuf,
    },

    /// The requested render target is not a known target.
    #[error("unknown render target '{0}'; known targets: claude, codex, gemini, generic")]
    UnknownRenderTarget(String),
}
