//! # personify-runtime
//!
//! Orchestration layer for the Personify persona marketplace platform.
//!
//! This crate ties the vault, template, and memory layers together into a
//! single [`Runtime`] value that can load a persona from its constituent
//! parts and render the final prompt string.
//!
//! ## Responsibilities
//!
//! 1. Load [`VaultData`] via a [`VaultBackend`] implementation.
//! 2. Parse the template body and its companion manifest.
//! 3. Validate that every token and section referenced in the template is
//!    declared in the manifest, and that every required token has a value
//!    in the vault.
//! 4. Hold an optional [`MemoryAdapter`] for use by agent shims.
//!
//! All validation happens in [`Runtime::load`] so that [`Runtime::render`]
//! is infallible and returns a plain [`String`].
//!
//! ## Example
//!
//! ```rust,ignore
//! use personify_runtime::{Runtime, RuntimeConfig, TemplateSource};
//!
//! let config = RuntimeConfig {
//!     vault_backend: Box::new(my_backend),
//!     template_source: TemplateSource::Inline {
//!         content: "Hello {{name}}!\n".into(),
//!         manifest: r#"[tokens]\nname = { type = "string", required = true, description = "The name." }"#.into(),
//!     },
//!     memory_adapter: None,
//! };
//! let runtime = Runtime::load(config).unwrap();
//! let rendered = runtime.render();
//! ```

mod capability;
mod error;
mod runtime;
mod source;

pub use capability::CapabilityManifest;
pub use error::RuntimeError;
pub use runtime::{Runtime, RuntimeConfig};
pub use source::TemplateSource;
