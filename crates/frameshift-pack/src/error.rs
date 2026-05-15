use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("missing pack.toml manifest")]
    MissingManifest,

    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse pack.toml: {0}")]
    ManifestParse(#[from] toml::de::Error),

    #[error("pack exceeds total size limit: {size} bytes > {limit} bytes")]
    TotalSizeExceeded { size: u64, limit: u64 },

    #[error("pack exceeds file count limit: {count} files > {limit} files")]
    FileCountExceeded { count: usize, limit: usize },

    #[error("file {path} exceeds size limit: {size} bytes > {limit} bytes")]
    FileSizeExceeded { path: String, size: u64, limit: u64 },

    #[error("path is not valid UTF-8: {0:?}")]
    NonUtf8Path(PathBuf),

    #[error("duplicate canonical path after normalization: {0}")]
    DuplicatePath(String),

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("signing failed: {0}")]
    SigningFailed(#[from] ed25519_dalek::SignatureError),

    #[error("pack has no signature")]
    NoSignature,
}
