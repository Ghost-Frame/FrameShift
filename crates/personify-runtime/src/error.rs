//! Error types for the personify-runtime crate.

use std::path::PathBuf;

use personify_template::TemplateError;
use personify_vault::VaultError;

/// All errors that can occur during [`crate::Runtime::load`] or capability checks.
///
/// Rendering is infallible once a [`crate::Runtime`] has been constructed
/// successfully; these errors only surface at load time or during
/// [`crate::Runtime::check_memory_capability`].
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// A vault operation failed.
    #[error("vault: {0}")]
    Vault(#[from] VaultError),

    /// Template parsing or manifest parsing failed.
    #[error("template: {0}")]
    Template(#[from] TemplateError),

    /// A token that is declared `required = true` in the manifest has no
    /// corresponding value in the vault's `variables` map.
    #[error("required token has no value in vault: {0}")]
    MissingRequiredToken(String),

    /// The template body references a token name that is not declared in the
    /// manifest's `[tokens]` table.
    #[error("template references token not declared in manifest: {0}")]
    UndeclaredToken(String),

    /// The template body references a section ID that is not declared in the
    /// manifest's `[sections]` table.
    #[error("template references section not declared in manifest: {0}")]
    UndeclaredSection(String),

    /// A capability manifest requires `Hard` memory but no adapter was configured.
    #[error("memory adapter required but not configured")]
    MemoryUnconfigured,

    /// An I/O error occurred while reading a template or manifest file from disk.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// The path that was being read when the error occurred.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}
