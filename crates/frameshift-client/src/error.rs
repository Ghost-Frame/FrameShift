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

    /// Kept for backwards compatibility with existing match arms. No longer returned
    /// by the registry install path -- use `RegistryHttp` / `ContentHashMismatch` instead.
    #[error("registry installs are not yet implemented; use --from-path for M0")]
    RegistryInstallNotImplemented,

    /// An HTTP request to the registry failed (network error or non-2xx status).
    #[error("registry HTTP request to {url} failed: {detail}")]
    RegistryHttp {
        /// The URL that was requested.
        url: String,
        /// Human-readable description of the failure (status code, network error, etc.).
        detail: String,
    },

    /// The registry returned a non-2xx status to a signed request (publish or register).
    /// Carries the status code so callers can give targeted advice (e.g. 401 -> register first).
    #[error("registry request to {url} rejected with HTTP {status}: {message}")]
    RegistryRejected {
        /// The URL that was requested.
        url: String,
        /// The HTTP status code returned by the server.
        status: u16,
        /// The server's response body (or a short description) for context.
        message: String,
    },

    /// The managed author signing key on disk is malformed (wrong length or unreadable).
    #[error("author signing key at {path} is invalid: {detail}")]
    InvalidSigningKey {
        /// Path to the signing key file.
        path: PathBuf,
        /// Description of why the key could not be loaded.
        detail: String,
    },

    /// Failed to serialize a JSON request body for a registry call.
    #[error("failed to serialize request JSON: {0}")]
    JsonSerialize(String),

    /// The SHA-256 hash of the downloaded archive did not match the registry record.
    #[error("content hash mismatch for {pack}: expected {expected}, got {actual}")]
    ContentHashMismatch {
        /// The pack name/version being installed (for error context).
        pack: String,
        /// The hex hash advertised by the registry.
        expected: String,
        /// The hex hash of the bytes that were actually downloaded.
        actual: String,
    },

    /// The registry returned a version record with no signature but one is required for verification.
    #[error("registry returned no signature for pack {pack}")]
    RegistrySignatureMissing {
        /// The pack name/version that had no signature.
        pack: String,
    },

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
