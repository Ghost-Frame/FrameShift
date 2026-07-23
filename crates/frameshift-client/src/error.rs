use std::path::PathBuf;

/// Every failure the client library can surface to callers (CLI, daemon,
/// MCP server, desktop app). Variants carry enough context to render an
/// actionable message without any additional lookup.
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

    /// A persona name (from a lockfile, pack manifest, or caller) is not safe to
    /// use as a single path component -- it contained a separator, `..`, a
    /// leading `.`, a control character, or was empty.
    #[error("invalid persona name {name:?}: {reason}")]
    InvalidPersonaName {
        /// The rejected name.
        name: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    #[error(
        "pack manifest did not match requested spec: expected {expected_name}@{expected_version}, got {actual_name}@{actual_version}"
    )]
    ManifestMismatch {
        expected_name: String,
        expected_version: String,
        actual_name: String,
        actual_version: String,
    },

    /// A mutable local source changed between initial verification and cache publication.
    #[error("local pack changed during install: expected hash {expected}, got {actual}")]
    LocalPackChanged {
        /// Canonical hash computed before copying the source.
        expected: String,
        /// Canonical hash computed from the private cache snapshot.
        actual: String,
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

    /// The metadata-only publisher-key inventory failed schema or integrity validation.
    #[error("publisher key inventory at {path} is invalid: {detail}")]
    InvalidPublisherKeyInventory {
        /// Path to the rejected inventory.
        path: PathBuf,
        /// Description of the violated inventory invariant.
        detail: String,
    },

    /// No publisher key matched the requested local identifier.
    #[error("publisher key {key_id:?} was not found")]
    PublisherKeyNotFound {
        /// Requested stable local key identifier.
        key_id: String,
    },

    /// Publisher private material was missing, malformed, or mismatched.
    #[error("publisher key {key_id:?} secret is unavailable: {detail}")]
    PublisherKeySecret {
        /// Stable local identifier of the affected key.
        key_id: String,
        /// Sanitized failure detail that never contains the private seed.
        detail: String,
    },

    /// The native credential store failed and no encrypted fallback was supplied.
    #[error(
        "native publisher key storage is unavailable: {detail}; provide an encrypted fallback passphrase"
    )]
    PublisherKeychainUnavailable {
        /// Sanitized platform credential-store failure.
        detail: String,
    },

    /// An age-backed publisher key cannot be opened without its passphrase.
    #[error("publisher key {key_id:?} requires the encrypted fallback passphrase")]
    PublisherKeyPassphraseRequired {
        /// Stable local identifier of the encrypted key.
        key_id: String,
    },

    /// Recovery-package encryption, decryption, or validation failed.
    #[error("publisher key recovery operation at {path} failed: {detail}")]
    PublisherKeyRecovery {
        /// Recovery-package or encrypted-seed path involved in the failure.
        path: PathBuf,
        /// Sanitized failure detail that never contains a passphrase or seed.
        detail: String,
    },

    /// A publisher-key label was empty or exceeded the supported bound.
    #[error("publisher key label must contain 1 to {max_chars} characters")]
    InvalidPublisherKeyLabel {
        /// Maximum accepted Unicode scalar count.
        max_chars: usize,
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

    /// A registry presented a different key for an author that was previously trusted.
    #[error(
        "registry author key changed for {author} at {registry}: expected {expected}, got {actual}"
    )]
    RegistryAuthorKeyChanged {
        /// Registry base URL whose trust namespace contained the pin.
        registry: String,
        /// Author handle whose key continuity check failed.
        author: String,
        /// Previously trusted Ed25519 key as lowercase hex.
        expected: String,
        /// Newly presented Ed25519 key as lowercase hex.
        actual: String,
    },

    #[error("cache entry {hash} is missing at {path}")]
    MissingCacheEntry { hash: String, path: PathBuf },

    #[error("no renderable markdown entry found in pack at {0}")]
    MissingRenderSource(PathBuf),

    #[error("persona {0:?} is not present in frameshift.lock")]
    PersonaNotInstalled(String),

    #[error("persona {persona:?} is installed but failed to materialize: {cause}")]
    PersonaMaterializeFailed { persona: String, cause: String },

    #[error(
        "pack {name:?} declares author_pubkey = \"local-unsigned\"; publishing requires a real \
         Ed25519 author key (set author_pubkey to your signing key's 64-char hex)"
    )]
    PublishLocalUnsigned { name: String },

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

    /// Persona composition (extends/mixin resolution and merge) failed. Per the
    /// pack manifest contract, a missing base or an L1 override is a hard error.
    ///
    /// Boxed to keep `ClientError` small: `ComposeError` is large enough that
    /// inlining it here trips `clippy::result_large_err` on every function that
    /// returns `Result<_, ClientError>`.
    #[error("persona composition failed: {0}")]
    Compose(#[source] Box<frameshift_compose::ComposeError>),

    /// The registry has a record for `name` but it has no published version
    /// yet (`latest_version` is `None`), so there is nothing to resolve a
    /// bare (version-less) install spec to.
    #[error("pack {0:?} exists in the registry but has no published version")]
    NoPublishedVersion(String),

    /// An install-over-existing was refused because the incoming pack's shipped
    /// conformance baseline failed integrity verification: the bundle hash the
    /// baseline declares does not match the hash of the conformance bundle the
    /// pack actually ships, so its conformance evidence cannot be trusted.
    #[error(
        "refusing to install persona {persona:?}: its shipped conformance baseline failed \
         integrity verification (declared bundle hash {declared_hash}, actual {actual_hash}); \
         the pack's conformance evidence may have been tampered with. Set \
         FRAMESHIFT_ALLOW_CONFORMANCE_INTEGRITY_FAILURE=1 to install anyway"
    )]
    ConformanceIntegrityFailure {
        /// The persona whose upgrade was refused.
        persona: String,
        /// The bundle hash the shipped baseline declares.
        declared_hash: String,
        /// The hash of the conformance bundle the pack actually ships, or
        /// `"missing"` when the pack ships no bundle at all.
        actual_hash: String,
    },

    /// The persona's pack manifest declares `memory_required = "hard"` but the
    /// project declares no `[memory]` adapter in its config.toml.
    #[error(
        "persona {persona:?} requires a memory adapter (memory_required = \"hard\") but this \
         project declares none; add a [memory] table to {config_path}"
    )]
    MemoryRequirementUnmet {
        /// The persona that refused to activate.
        persona: String,
        /// The central project config.toml that would declare the adapter.
        config_path: PathBuf,
    },

    /// A templated pack (one shipping a `pack.template.toml` manifest, see
    /// `frameshift_template::TemplateManifest`) declares one or more
    /// `required = true` tokens that have no value available. This fires in
    /// three situations that all boil down to "no usable value exists":
    /// no [`crate::VaultProvider`] was configured on the `Client`, the
    /// project's vault file does not exist yet, or the vault exists but is
    /// missing one or more of the required values. Every missing token is
    /// named, not just the first, so a single failure gives the complete
    /// remediation list. This check runs before any render output is
    /// written, so a failure here never leaves a persona's `rendered/`
    /// directory partially updated.
    #[error(
        "persona {persona:?} requires vault token(s) {tokens:?} but they have no value in the \
         vault at {vault_path}; run `frameshift vault init` (if the vault does not exist yet) \
         then `frameshift vault set <key>` for each listed token"
    )]
    MissingRequiredTokens {
        /// The persona whose template render was blocked.
        persona: String,
        /// The project's vault file path (see `ProjectPaths::vault_path`).
        vault_path: PathBuf,
        /// Every required token name with no value, in sorted (`BTreeMap`) order.
        tokens: Vec<String>,
    },

    /// A configured [`crate::VaultProvider`] failed to open the project
    /// vault for a reason other than "the file does not exist" -- a wrong
    /// passphrase, corrupt ciphertext, or an unsupported schema version, for
    /// example. Wraps the underlying `VaultError` unchanged so the real
    /// cause reaches the caller instead of a generic message.
    /// The error is boxed to keep `ClientError` small; an inline
    /// `VaultError` trips `clippy::result_large_err` on every function that
    /// returns `Result<_, ClientError>` (same treatment as `Compose`).
    #[error("failed to open vault at {vault_path}: {source}")]
    VaultOpen {
        /// The vault file path that failed to open.
        vault_path: PathBuf,
        /// The underlying vault-backend error.
        #[source]
        source: Box<frameshift_vault::VaultError>,
    },

    /// A templated pack's `pack.template.toml` manifest, or its rendered
    /// markdown once vault values are substituted in, failed to parse as a
    /// `frameshift_template` document. `context` names what was being
    /// parsed (the manifest path, or the persona/target being rendered) so
    /// the error is actionable without a second lookup.
    /// The error is boxed to keep `ClientError` small, mirroring `Compose`
    /// and `VaultOpen`.
    #[error("template parse error ({context}): {source}")]
    Template {
        /// Human-readable description of what was being parsed.
        context: String,
        /// The underlying template parse error.
        #[source]
        source: Box<frameshift_template::TemplateError>,
    },
}

/// Box the composition error so `ClientError` stays small while `?` on a bare
/// `ComposeError` still converts transparently.
impl From<frameshift_compose::ComposeError> for ClientError {
    /// Wrap a `ComposeError` into the boxed `Compose` variant.
    fn from(err: frameshift_compose::ComposeError) -> Self {
        ClientError::Compose(Box::new(err))
    }
}
