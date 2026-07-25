//! Errors produced while loading, canonicalizing, signing, and verifying packs.

use std::path::PathBuf;

/// Failures at the deterministic pack trust boundary.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    /// Required pack manifest is absent.
    #[error("missing pack.toml manifest")]
    MissingManifest,

    /// A filesystem operation failed at one exact path.
    #[error("failed to read {path}: {source}")]
    Io {
        /// Path being accessed.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },

    /// TOML did not match the public manifest schema.
    #[error("failed to parse pack.toml: {0}")]
    ManifestParse(#[from] toml::de::Error),

    /// Fork permission or provenance violates the public manifest contract.
    #[error("invalid fork contract: {0}")]
    ForkContract(#[from] crate::manifest::ForkContractError),

    /// Canonical pack bytes exceed the total size limit.
    #[error("pack exceeds total size limit: {size} bytes > {limit} bytes")]
    TotalSizeExceeded {
        /// Observed canonical byte count.
        size: u64,
        /// Maximum accepted canonical byte count.
        limit: u64,
    },

    /// Canonical pack file count exceeds the entry limit.
    #[error("pack exceeds file count limit: {count} files > {limit} files")]
    FileCountExceeded {
        /// Observed file count.
        count: usize,
        /// Maximum accepted file count.
        limit: usize,
    },

    /// One public file exceeds the per-file size limit.
    #[error("file {path} exceeds size limit: {size} bytes > {limit} bytes")]
    FileSizeExceeded {
        /// Canonical public path.
        path: String,
        /// Observed byte count.
        size: u64,
        /// Maximum accepted byte count.
        limit: u64,
    },

    /// A public path cannot be represented as UTF-8.
    #[error("path is not valid UTF-8: {0:?}")]
    NonUtf8Path(PathBuf),

    /// Two filesystem paths normalize to the same canonical path.
    #[error("duplicate canonical path after normalization: {0}")]
    DuplicatePath(String),

    /// Ed25519 signature does not verify against the selected key.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Ed25519 signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(#[from] ed25519_dalek::SignatureError),

    /// Verification was requested for an unsigned pack.
    #[error("pack has no signature")]
    NoSignature,

    /// signature.sig is present on disk but has the wrong byte length.
    ///
    /// Ed25519 signatures must be exactly 64 bytes. A file of any other length
    /// is not silently treated as unsigned -- callers should inspect and repair it.
    #[error("signature.sig is present but malformed: expected 64 bytes, found {found}")]
    MalformedSignature {
        /// Actual byte length of the file that was read.
        found: usize,
    },
}
