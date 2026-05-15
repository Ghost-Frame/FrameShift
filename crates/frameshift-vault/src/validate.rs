//! Schema validation for [`VaultData`] documents.
//!
//! Validation runs after deserialization and before the data is handed to
//! callers.  It catches semantic errors that TOML parsing alone cannot catch,
//! such as an unsupported schema version.

use crate::{VaultData, VaultError, MAX_SUPPORTED_SCHEMA_VERSION};

/// Validates a [`VaultData`] document against the schema constraints.
///
/// Enforces:
/// - `schema_version <= MAX_SUPPORTED_SCHEMA_VERSION`
/// - `identity.keypair_pub` is non-empty
/// - `identity.handle` is non-empty
///
/// # Errors
///
/// Returns [`VaultError::SchemaVersionUnsupported`] when the vault's
/// `schema_version` exceeds [`MAX_SUPPORTED_SCHEMA_VERSION`].
///
/// Returns [`VaultError::MissingIdentityField`] when a required identity
/// field is empty.
pub fn validate(data: &VaultData) -> Result<(), VaultError> {
    if data.schema_version > MAX_SUPPORTED_SCHEMA_VERSION {
        return Err(VaultError::SchemaVersionUnsupported {
            found: data.schema_version,
            max_supported: MAX_SUPPORTED_SCHEMA_VERSION,
        });
    }
    if data.identity.keypair_pub.is_empty() {
        return Err(VaultError::MissingIdentityField {
            field: "keypair_pub",
        });
    }
    if data.identity.handle.is_empty() {
        return Err(VaultError::MissingIdentityField { field: "handle" });
    }
    Ok(())
}
