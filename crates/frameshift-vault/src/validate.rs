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

    // Memory backend: gate the endpoint scheme (a `file://` or other scheme
    // would let a backend that follows the URL read local files / hit cloud
    // metadata), and ensure the named credential reference actually exists.
    if let Some(memory) = &data.memory {
        let scheme = memory.endpoint.scheme();
        if scheme != "https" && scheme != "http" {
            return Err(VaultError::InvalidConfig(format!(
                "memory endpoint scheme {scheme:?} is not allowed; use http or https"
            )));
        }
        if !data.variables.contains_key(&memory.auth_value_vault_ref) {
            return Err(VaultError::InvalidConfig(format!(
                "memory.auth_value_vault_ref {:?} is not present in variables",
                memory.auth_value_vault_ref
            )));
        }
    }

    // Bound the secret-bearing maps so a hostile or oversized vault file cannot
    // exhaust memory or smuggle an unbounded prompt overlay into agent context.
    const MAX_ENTRIES: usize = 256;
    const MAX_VALUE_BYTES: usize = 64 * 1024;
    for (label, map) in [("variables", &data.variables), ("overlays", &data.overlays)] {
        if map.len() > MAX_ENTRIES {
            return Err(VaultError::InvalidConfig(format!(
                "{label} has {} entries; maximum is {MAX_ENTRIES}",
                map.len()
            )));
        }
        for (key, value) in map {
            if value.len() > MAX_VALUE_BYTES {
                return Err(VaultError::InvalidConfig(format!(
                    "{label}[{key:?}] is {} bytes; maximum is {MAX_VALUE_BYTES}",
                    value.len()
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{Auth, Identity, MemoryConfig, Preferences, RuntimeMode, VaultData};
    use std::collections::BTreeMap;

    /// Build a minimal valid vault for mutation in tests.
    fn base() -> VaultData {
        VaultData {
            schema_version: 1,
            identity: Identity {
                keypair_pub: "age1test".to_owned(),
                handle: "tester".to_owned(),
            },
            auth: Auth {
                methods: vec!["passphrase".to_owned()],
                unlock: "passphrase".to_owned(),
            },
            preferences: Preferences {
                runtime_mode: RuntimeMode::Wrapped,
                publish_intent: "no".to_owned(),
                recovery: "own-backup".to_owned(),
            },
            memory: None,
            variables: BTreeMap::new(),
            overlays: BTreeMap::new(),
        }
    }

    /// The redacting Debug prints variable KEYS but never their secret values.
    #[test]
    fn debug_redacts_secret_values() {
        let mut v = base();
        v.set_variable("api_key".to_owned(), "super-secret-token".to_owned());
        v.set_overlay("agent.slot".to_owned(), "hidden prose".to_owned());
        let rendered = format!("{v:?}");
        assert!(rendered.contains("api_key"), "key names are shown");
        assert!(
            !rendered.contains("super-secret-token"),
            "secret value must not appear: {rendered}"
        );
        assert!(
            !rendered.contains("hidden prose"),
            "overlay value must not appear"
        );
    }

    /// A non-http(s) memory endpoint is rejected.
    #[test]
    fn rejects_non_http_endpoint() {
        let mut v = base();
        v.set_variable("memory_api_key".to_owned(), "k".to_owned());
        v.memory = Some(MemoryConfig {
            backend: "http".to_owned(),
            endpoint: "file:///etc/passwd".parse().unwrap(),
            auth_method: "api-key".to_owned(),
            auth_value_vault_ref: "memory_api_key".to_owned(),
        });
        assert!(
            super::validate(&v).is_err(),
            "file:// endpoint must be rejected"
        );
    }

    /// An over-cap overlay value is rejected.
    #[test]
    fn rejects_oversized_overlay() {
        let mut v = base();
        v.set_overlay("agent.slot".to_owned(), "x".repeat(64 * 1024 + 1));
        assert!(
            super::validate(&v).is_err(),
            "oversized overlay must be rejected"
        );
    }
}
