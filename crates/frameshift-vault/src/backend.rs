//! The [`VaultBackend`] trait -- the storage abstraction for vault data.
//!
//! Concrete implementations (filesystem TOML, encrypted age file, remote HTTP
//! store, etc.) live in separate crates.  This module only defines the
//! contract that all backends must satisfy.

use crate::{VaultData, VaultError};

/// A storage backend that can persist and retrieve a [`VaultData`] document.
///
/// The trait is intentionally minimal: it moves the entire document as a unit.
/// Higher-level operations (reading individual variables, patching overlays)
/// are methods on [`VaultData`] itself rather than on the backend.
///
/// # Implementors
///
/// Implementors are responsible for serializing [`VaultData`] to their chosen
/// format (TOML, encrypted binary, remote API, etc.) and for returning typed
/// [`VaultError`] variants that allow callers to distinguish I/O failures,
/// parse errors, and configuration problems.
pub trait VaultBackend {
    /// Opens the vault and returns its full contents as a [`VaultData`].
    ///
    /// The returned value is a snapshot; callers who need to persist mutations
    /// must call [`VaultBackend::save`] afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Io`] if the underlying storage cannot be read,
    /// [`VaultError::Parse`] if the stored bytes are not valid TOML or do not
    /// match the schema, and [`VaultError::SchemaVersionUnsupported`] if the
    /// stored schema version exceeds [`crate::MAX_SUPPORTED_SCHEMA_VERSION`].
    fn open(&self) -> Result<VaultData, VaultError>;

    /// Persists `data` to the backend, overwriting any previously stored vault.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Io`] if the write fails, or
    /// [`VaultError::Serialize`] if `data` cannot be converted to the
    /// backend's on-disk format.
    fn save(&self, data: &VaultData) -> Result<(), VaultError>;

    /// Returns `true` if a vault already exists in this backend.
    ///
    /// This is useful for bootstrap logic: callers can check whether a vault
    /// needs to be created before calling [`VaultBackend::open`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Io`] if the existence check itself encounters an
    /// I/O error, or [`VaultError::BackendUnavailable`] if the backend cannot
    /// be reached at all.
    fn exists(&self) -> Result<bool, VaultError>;
}
