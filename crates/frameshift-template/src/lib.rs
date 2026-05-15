//! Template parser and renderer for Personify persona files.
//!
//! This crate provides two main capabilities:
//!
//! 1. **Token placeholders** -- `{{name}}` markers replaced at render time with
//!    caller-supplied values.
//! 2. **Section overlays** -- `<!-- section:id --> ... <!-- /section -->` blocks
//!    whose default content can be replaced by persona pack overlays.
//!
//! # Quick start
//!
//! ```rust
//! use std::collections::BTreeMap;
//! use frameshift_template::Template;
//!
//! let tmpl = Template::parse("Hello {{name}}!\n").unwrap();
//! let mut vars = BTreeMap::new();
//! vars.insert("name".to_owned(), "World".to_owned());
//! let rendered = tmpl.render(&vars, &BTreeMap::new());
//! assert_eq!(rendered, "Hello World!\n");
//! ```

mod error;
mod manifest;
mod parse;
mod render;

// ── Public re-exports ─────────────────────────────────────────────────────────

pub use error::TemplateError;
pub use manifest::{SectionDecl, TemplateManifest, TokenDecl};
pub use parse::Template;
