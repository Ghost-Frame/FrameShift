//! Error types for the frameshift-template crate.

use thiserror::Error;

/// All errors that can occur during template parsing.
///
/// Parsing is fallible when the template is structurally invalid. Rendering
/// is infallible -- missing tokens or overlays are handled gracefully.
#[derive(Debug, Error)]
pub enum TemplateError {
    /// A `<!-- section:ID -->` marker was opened but never closed.
    #[error("unclosed section '{id}' opened at line {line}")]
    UnclosedSection {
        /// The ID of the section that was not closed.
        id: String,
        /// 1-based line number where the opening marker was found.
        line: usize,
    },

    /// A `<!-- section:INNER -->` marker appeared while already inside another section.
    #[error("nested section '{inner}' inside '{outer}' at line {line}")]
    NestedSection {
        /// The ID of the already-open outer section.
        outer: String,
        /// The ID of the attempted inner section.
        inner: String,
        /// 1-based line number of the inner opening marker.
        line: usize,
    },

    /// A `<!-- /section -->` marker appeared with no corresponding opening marker.
    #[error("unmatched section close marker at line {line}")]
    UnmatchedClose {
        /// 1-based line number of the unmatched close marker.
        line: usize,
    },

    /// A token placeholder `{{}}` contained no name after whitespace trimming.
    #[error("empty token name at line {line}")]
    EmptyTokenName {
        /// 1-based line number where the empty token was found.
        line: usize,
    },

    /// A token placeholder contained a name that does not match `[a-zA-Z_][a-zA-Z0-9_]*`.
    #[error("invalid token name '{name}' at line {line}")]
    InvalidTokenName {
        /// The invalid name found between the braces.
        name: String,
        /// 1-based line number where the invalid token was found.
        line: usize,
    },

    /// The `pack.template.toml` manifest could not be deserialized.
    #[error("manifest parse error: {0}")]
    ManifestParse(#[from] toml::de::Error),
}
