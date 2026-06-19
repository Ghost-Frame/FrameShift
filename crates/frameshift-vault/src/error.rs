//! Error types for vault operations.

use std::path::PathBuf;

/// All errors that vault operations can produce.
///
/// Callers should match on variants to distinguish recoverable conditions
/// (e.g., [`VaultError::SchemaVersionUnsupported`]) from I/O failures.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// An I/O error occurred while reading or writing the vault file at `path`.
    #[error("vault I/O error at {path}: {source}")]
    Io {
        /// The path that was being accessed when the error occurred.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The vault TOML could not be deserialized.
    #[error("vault parse error: {0}")]
    Parse(#[from] toml::de::Error),

    /// The vault data could not be serialized to TOML.
    #[error("vault serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),

    /// The requested backend is unavailable or misconfigured.
    ///
    /// The inner string provides a human-readable reason.
    #[error("vault backend unavailable: {0}")]
    BackendUnavailable(String),

    /// A vault field failed a semantic validation rule (e.g. a disallowed
    /// endpoint scheme, an over-cap map, or a dangling vault reference).
    #[error("invalid vault configuration: {0}")]
    InvalidConfig(String),

    /// The vault file declares a `schema_version` higher than this library supports.
    #[error(
        "unsupported vault schema version {found}; this library supports up to {max_supported}"
    )]
    SchemaVersionUnsupported {
        /// The schema version found in the vault file.
        found: u32,
        /// The highest schema version this library can handle.
        max_supported: u32,
    },

    /// A required identity field is empty.
    #[error("identity field {field} must not be empty")]
    MissingIdentityField {
        /// The name of the empty field.
        field: &'static str,
    },

    /// A cryptographic operation (encrypt/decrypt) failed.
    #[error("vault crypto error: {0}")]
    Crypto(#[source] Box<dyn std::error::Error + Send + Sync>),
}
