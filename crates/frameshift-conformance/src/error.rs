//! Typed failures produced while loading, executing, or scoring conformance bundles.

use std::path::PathBuf;

/// Failures that prevent one conformance bundle from producing a trustworthy score.
#[derive(Debug, thiserror::Error)]
pub enum ConformanceError {
    /// The selected directory does not contain the required bundle manifest.
    #[error("missing bundle.toml in {0}")]
    MissingBundle(PathBuf),

    /// A bundle file could not be read.
    #[error("failed to read {path}: {source}")]
    Io {
        /// Path that could not be read.
        path: PathBuf,
        /// Underlying filesystem failure.
        source: std::io::Error,
    },

    /// The bundle manifest is not valid typed TOML.
    #[error("failed to parse bundle.toml: {0}")]
    BundleParse(#[from] toml::de::Error),

    /// The typed bundle could not be rendered deterministically.
    #[error("failed to serialize bundle: {0}")]
    BundleSerialize(#[from] toml::ser::Error),

    /// The selected runner could not produce a scoreable response.
    #[error("runner failure: {0}")]
    Runner(String),

    /// A caller-scored test was supplied without a caller scoring implementation.
    #[error("test {0:?} requires a caller-provided scorer")]
    UnsupportedCallerScorer(String),
}
