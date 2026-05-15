//! [`TemplateSource`] -- describes where to load template content from.

use std::path::PathBuf;

/// Describes how the template body and companion manifest are supplied to the
/// runtime.
///
/// Use [`TemplateSource::Inline`] for programmatic construction (tests, agent
/// shims) and [`TemplateSource::File`] when both files live on disk.
#[derive(Debug)]
pub enum TemplateSource {
    /// Both the template body and its manifest TOML are supplied as owned
    /// strings.
    ///
    /// The `content` field is the raw template text (may contain `{{token}}`
    /// and `<!-- section:id -->` markers). The `manifest` field is a TOML
    /// string conforming to the `pack.template.toml` schema.
    Inline {
        /// Raw template text.
        content: String,
        /// Manifest TOML source.
        manifest: String,
    },

    /// Both the template body and its manifest are read from the filesystem.
    ///
    /// - `template_path` should point to the `.md` or `.txt` template file.
    /// - `manifest_path` should point to the `pack.template.toml` file.
    File {
        /// Filesystem path to the template body file.
        template_path: PathBuf,
        /// Filesystem path to the manifest TOML file.
        manifest_path: PathBuf,
    },
}
