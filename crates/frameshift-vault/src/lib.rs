//! # frameshift-vault
//!
//! Vault trait and canonical TOML schema for the frameshift persona marketplace.
//!
//! The vault is the owner's personal, encrypted store of identity, auth
//! configuration, preference flags, optional memory-backend config, arbitrary
//! key/value variables, and overlay prose blocks.
//!
//! ## Crate layout
//!
//! | Module | Contents |
//! |---|---|
//! | [`schema`] | [`VaultData`] and all sub-types (TOML schema types) |
//! | [`backend`] | [`VaultBackend`] trait (storage abstraction) |
//! | [`error`] | [`VaultError`] enum |
//! | [`validate`] | Post-deserialization semantic validation |
//!
//! ## Quick start
//!
//! ```rust
//! use frameshift_vault::{VaultData, VaultBackend, VaultError};
//!
//! /// A trivial in-memory backend for illustration purposes.
//! struct MemBackend(std::sync::Mutex<Option<VaultData>>);
//!
//! impl VaultBackend for MemBackend {
//!     fn open(&self) -> Result<VaultData, VaultError> {
//!         self.0
//!             .lock()
//!             .unwrap()
//!             .clone()
//!             .ok_or_else(|| VaultError::BackendUnavailable("empty".into()))
//!     }
//!     fn save(&self, data: &VaultData) -> Result<(), VaultError> {
//!         *self.0.lock().unwrap() = Some(data.clone());
//!         Ok(())
//!     }
//!     fn exists(&self) -> Result<bool, VaultError> {
//!         Ok(self.0.lock().unwrap().is_some())
//!     }
//! }
//! ```

pub mod backend;
pub mod error;
pub mod schema;
pub mod validate;

pub use backend::VaultBackend;
pub use error::VaultError;
pub use schema::{
    Auth, Identity, MemoryConfig, Preferences, RuntimeMode, VaultData, MAX_SUPPORTED_SCHEMA_VERSION,
};
pub use validate::validate;
