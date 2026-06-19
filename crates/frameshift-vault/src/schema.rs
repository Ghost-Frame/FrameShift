//! Canonical schema types for the frameshift vault TOML format.
//!
//! The decrypted vault is a TOML document.  This module provides strongly-typed
//! Rust representations of every section.  Use [`VaultData`] as the top-level
//! entry point for serialization and deserialization.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use url::Url;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The highest `schema_version` value this library is able to read and write.
///
/// Vault files whose `schema_version` exceeds this constant will be rejected
/// with [`crate::VaultError::SchemaVersionUnsupported`].
pub const MAX_SUPPORTED_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Top-level document
// ---------------------------------------------------------------------------

/// The complete, decrypted contents of a frameshift vault.
///
/// Serializes to / deserializes from the canonical vault TOML format.
/// Construct with [`Default`] for an empty vault at schema version 1, or
/// deserialize from a TOML string produced by a vault backend.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultData {
    /// Schema version of the vault file.  Must be `<= MAX_SUPPORTED_SCHEMA_VERSION`.
    pub schema_version: u32,

    /// Identity section -- public key and human-readable handle.
    pub identity: Identity,

    /// Authentication section -- allowed methods and preferred unlock method.
    pub auth: Auth,

    /// User preference section -- runtime mode, publish intent, recovery.
    pub preferences: Preferences,

    /// Optional memory backend configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryConfig>,

    /// Arbitrary key/value variables stored in the vault.
    ///
    /// Values are plain strings.  Sensitive values (API keys, tokens, etc.)
    /// should be treated as secrets by callers; the schema layer does not
    /// enforce secrecy so that the map remains uniformly typed and easy to
    /// iterate.
    #[serde(default)]
    pub variables: BTreeMap<String, String>,

    /// Named overlay blocks keyed by `"agent.slot"` identifiers.
    ///
    /// Overlay values are prose strings injected into agent prompts.
    #[serde(default)]
    pub overlays: BTreeMap<String, String>,
}

/// Redacting `Debug`: the `variables` and `overlays` maps hold plaintext
/// secrets (API keys, tokens) and prose injected into prompts. This impl prints
/// their KEY names but never their values, so `{:?}` / `tracing::debug!(?vault)`
/// / panic messages cannot leak vault secrets to logs or crash dumps. Every
/// other field is non-secret and printed normally.
impl fmt::Debug for VaultData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultData")
            .field("schema_version", &self.schema_version)
            .field("identity", &self.identity)
            .field("auth", &self.auth)
            .field("preferences", &self.preferences)
            .field("memory", &self.memory)
            .field("variables", &RedactedValues(&self.variables))
            .field("overlays", &RedactedValues(&self.overlays))
            .finish()
    }
}

/// `Debug` helper that renders a map as its key set with every value redacted.
struct RedactedValues<'a>(&'a BTreeMap<String, String>);

impl fmt::Debug for RedactedValues<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|k| (k, "<redacted>")))
            .finish()
    }
}

impl VaultData {
    /// Returns the value of the variable named `key`, or `None` if absent.
    pub fn get_variable(&self, key: &str) -> Option<&str> {
        self.variables.get(key).map(String::as_str)
    }

    /// Inserts or replaces the variable named `key` with `value`.
    pub fn set_variable(&mut self, key: String, value: String) {
        self.variables.insert(key, value);
    }

    /// Removes the variable named `key` and returns its former value,
    /// or `None` if the key was not present.
    pub fn remove_variable(&mut self, key: &str) -> Option<String> {
        self.variables.remove(key)
    }

    /// Returns the overlay string for `key`, or `None` if absent.
    pub fn get_overlay(&self, key: &str) -> Option<&str> {
        self.overlays.get(key).map(String::as_str)
    }

    /// Inserts or replaces the overlay named `key` with `value`.
    pub fn set_overlay(&mut self, key: String, value: String) {
        self.overlays.insert(key, value);
    }

    /// Removes the overlay named `key` and returns its former value,
    /// or `None` if the key was not present.
    pub fn remove_overlay(&mut self, key: &str) -> Option<String> {
        self.overlays.remove(key)
    }

    /// Returns a shared reference to the full variables map.
    pub fn variables(&self) -> &BTreeMap<String, String> {
        &self.variables
    }

    /// Returns a shared reference to the full overlays map.
    pub fn overlays(&self) -> &BTreeMap<String, String> {
        &self.overlays
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// The identity section of a vault.
///
/// Holds the user's public key (in age format) and their human-readable handle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    /// The user's age public key, e.g. `"age1..."`.
    pub keypair_pub: String,

    /// The user's handle / display name, e.g. `"alice"`.
    pub handle: String,
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// The authentication section of a vault.
///
/// Describes which authentication methods are available and which one is used
/// to unlock the vault on open.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Auth {
    /// Ordered list of supported authentication methods,
    /// e.g. `["piv-yubikey", "github-oauth"]`.
    pub methods: Vec<String>,

    /// The authentication method used to unlock the vault,
    /// e.g. `"piv-yubikey"`.
    pub unlock: String,
}

// ---------------------------------------------------------------------------
// Preferences
// ---------------------------------------------------------------------------

/// The preferences section of a vault.
///
/// Controls runtime behaviour, publication intent, and recovery strategy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Preferences {
    /// How the vault owner's persona should be applied at runtime.
    pub runtime_mode: RuntimeMode,

    /// Whether the owner intends to publish their persona.
    /// Free-form string (`"yes"` / `"no"` / etc.).
    pub publish_intent: String,

    /// Chosen recovery strategy, e.g. `"own-backup"`.
    pub recovery: String,
}

// ---------------------------------------------------------------------------
// RuntimeMode enum
// ---------------------------------------------------------------------------

/// The runtime mode that controls how a persona is applied.
///
/// Serializes to and from lowercase TOML strings:
/// `"wrapped"`, `"rendered"`, or `"both"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeMode {
    /// The persona is applied as a system-prompt wrapper around the base model.
    Wrapped,

    /// The persona is fully rendered into the prompt before the model sees it.
    Rendered,

    /// Both wrapped and rendered modes are active simultaneously.
    Both,
}

// ---------------------------------------------------------------------------
// MemoryConfig
// ---------------------------------------------------------------------------

/// Optional configuration for an external memory backend.
///
/// When present the vault owner has configured a remote memory store.
/// The `auth_value_vault_ref` field names the [`VaultData::variables`] key
/// whose value holds the actual secret used to authenticate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// The memory backend type, e.g. `"http"`.
    pub backend: String,

    /// The URL of the memory backend endpoint.
    pub endpoint: Url,

    /// Authentication method used against the memory backend,
    /// e.g. `"api-key"`.
    pub auth_method: String,

    /// The key in [`VaultData::variables`] that holds the auth credential.
    ///
    /// For example, `"memory_api_key"` means the auth value is found at
    /// `variables["memory_api_key"]`.
    pub auth_value_vault_ref: String,
}
