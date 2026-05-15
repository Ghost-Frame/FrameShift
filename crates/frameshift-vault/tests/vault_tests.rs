//! Integration tests for frameshift-vault schema, methods, and validation.

use frameshift_vault::{
    validate, Auth, Identity, MemoryConfig, Preferences, RuntimeMode, VaultData, VaultError,
    MAX_SUPPORTED_SCHEMA_VERSION,
};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal valid [`VaultData`] (no memory, no variables, no overlays).
fn minimal_vault() -> VaultData {
    VaultData {
        schema_version: 1,
        identity: Identity {
            keypair_pub: "age1testpubkey000000000000000000000000000000000000000000000000".into(),
            handle: "alice".into(),
        },
        auth: Auth {
            methods: vec!["piv-yubikey".into()],
            unlock: "piv-yubikey".into(),
        },
        preferences: Preferences {
            runtime_mode: RuntimeMode::Wrapped,
            publish_intent: "yes".into(),
            recovery: "own-backup".into(),
        },
        memory: None,
        variables: BTreeMap::new(),
        overlays: BTreeMap::new(),
    }
}

const MINIMAL_TOML: &str = r#"
schema_version = 1

[identity]
keypair_pub = "age1testpubkey000000000000000000000000000000000000000000000000"
handle = "alice"

[auth]
methods = ["piv-yubikey"]
unlock = "piv-yubikey"

[preferences]
runtime_mode = "wrapped"
publish_intent = "yes"
recovery = "own-backup"
"#;

const FULL_TOML: &str = r#"
schema_version = 1

[identity]
keypair_pub = "age1testpubkey000000000000000000000000000000000000000000000000"
handle = "alice"

[auth]
methods = ["piv-yubikey", "github-oauth"]
unlock = "piv-yubikey"

[preferences]
runtime_mode = "both"
publish_intent = "yes"
recovery = "own-backup"

[memory]
backend = "http"
endpoint = "https://memory.example.com"
auth_method = "api-key"
auth_value_vault_ref = "memory_api_key"

[variables]
principal_name = "Alice"
memory_api_key = "s3cr3t"

[overlays]
"persona.identity_prelude" = "Full prose block here."
"global.behavioral_mandates" = "Be excellent."
"#;

// ---------------------------------------------------------------------------
// Deserialization tests
// ---------------------------------------------------------------------------

#[test]
fn deserialize_minimal_vault() {
    let data: VaultData = toml::from_str(MINIMAL_TOML).expect("minimal TOML should parse");
    assert_eq!(data.schema_version, 1);
    assert_eq!(data.identity.handle, "alice");
    assert_eq!(data.auth.methods, vec!["piv-yubikey"]);
    assert_eq!(data.preferences.runtime_mode, RuntimeMode::Wrapped);
    assert!(data.memory.is_none());
    assert!(data.variables.is_empty());
    assert!(data.overlays.is_empty());
}

#[test]
fn deserialize_full_vault() {
    let data: VaultData = toml::from_str(FULL_TOML).expect("full TOML should parse");
    assert_eq!(data.schema_version, 1);
    assert_eq!(data.auth.methods.len(), 2);
    assert_eq!(data.preferences.runtime_mode, RuntimeMode::Both);

    let mem = data
        .memory
        .as_ref()
        .expect("memory section should be present");
    assert_eq!(mem.backend, "http");
    assert_eq!(mem.endpoint.as_str(), "https://memory.example.com/");
    assert_eq!(mem.auth_method, "api-key");
    assert_eq!(mem.auth_value_vault_ref, "memory_api_key");

    assert_eq!(
        data.variables.get("principal_name"),
        Some(&"Alice".to_string())
    );
    assert_eq!(
        data.variables.get("memory_api_key"),
        Some(&"s3cr3t".to_string())
    );

    assert_eq!(
        data.overlays.get("persona.identity_prelude"),
        Some(&"Full prose block here.".to_string())
    );
}

// ---------------------------------------------------------------------------
// Round-trip test
// ---------------------------------------------------------------------------

#[test]
fn round_trip_serialize_deserialize() {
    let original: VaultData = toml::from_str(FULL_TOML).expect("parse should succeed");
    let serialized = toml::to_string(&original).expect("serialize should succeed");
    let restored: VaultData = toml::from_str(&serialized).expect("re-parse should succeed");
    assert_eq!(original, restored);
}

#[test]
fn round_trip_minimal_preserves_empty_maps() {
    let original = minimal_vault();
    let serialized = toml::to_string(&original).expect("serialize should succeed");
    let restored: VaultData = toml::from_str(&serialized).expect("re-parse should succeed");
    assert!(restored.variables.is_empty());
    assert!(restored.overlays.is_empty());
}

// ---------------------------------------------------------------------------
// VaultData method tests
// ---------------------------------------------------------------------------

#[test]
fn get_set_remove_variable() {
    let mut data = minimal_vault();

    assert!(data.get_variable("foo").is_none());

    data.set_variable("foo".into(), "bar".into());
    assert_eq!(data.get_variable("foo"), Some("bar"));

    let removed = data.remove_variable("foo");
    assert_eq!(removed, Some("bar".to_string()));
    assert!(data.get_variable("foo").is_none());
}

#[test]
fn remove_nonexistent_variable_returns_none() {
    let mut data = minimal_vault();
    let result = data.remove_variable("does_not_exist");
    assert!(result.is_none());
}

#[test]
fn get_set_remove_overlay() {
    let mut data = minimal_vault();

    assert!(data.get_overlay("persona.identity_prelude").is_none());

    data.set_overlay("persona.identity_prelude".into(), "Prose block.".into());
    assert_eq!(
        data.get_overlay("persona.identity_prelude"),
        Some("Prose block.")
    );

    let removed = data.remove_overlay("persona.identity_prelude");
    assert_eq!(removed, Some("Prose block.".to_string()));
    assert!(data.get_overlay("persona.identity_prelude").is_none());
}

#[test]
fn remove_nonexistent_overlay_returns_none() {
    let mut data = minimal_vault();
    assert!(data.remove_overlay("no.such.overlay").is_none());
}

#[test]
fn variables_and_overlays_accessors_return_correct_maps() {
    let mut data = minimal_vault();
    data.set_variable("k".into(), "v".into());
    data.set_overlay("a.b".into(), "text".into());

    assert_eq!(data.variables().len(), 1);
    assert_eq!(data.overlays().len(), 1);
    assert_eq!(data.variables().get("k").map(String::as_str), Some("v"));
    assert_eq!(data.overlays().get("a.b").map(String::as_str), Some("text"));
}

// ---------------------------------------------------------------------------
// Validation tests
// ---------------------------------------------------------------------------

#[test]
fn validate_supported_schema_version_passes() {
    let data = minimal_vault();
    assert!(validate(&data).is_ok());
}

#[test]
fn validate_rejects_unsupported_schema_version() {
    let mut data = minimal_vault();
    data.schema_version = MAX_SUPPORTED_SCHEMA_VERSION + 1;
    match validate(&data) {
        Err(VaultError::SchemaVersionUnsupported {
            found,
            max_supported,
        }) => {
            assert_eq!(found, MAX_SUPPORTED_SCHEMA_VERSION + 1);
            assert_eq!(max_supported, MAX_SUPPORTED_SCHEMA_VERSION);
        }
        other => panic!("expected SchemaVersionUnsupported, got {other:?}"),
    }
}

#[test]
fn validate_schema_version_zero_passes() {
    let mut data = minimal_vault();
    data.schema_version = 0;
    assert!(validate(&data).is_ok(), "version 0 should be accepted");
}

// ---------------------------------------------------------------------------
// RuntimeMode serialization tests
// ---------------------------------------------------------------------------

#[test]
fn runtime_mode_serializes_as_lowercase() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Wrapper {
        mode: RuntimeMode,
    }

    let w = Wrapper {
        mode: RuntimeMode::Wrapped,
    };
    let s = toml::to_string(&w).expect("serialize");
    assert!(s.contains(r#"mode = "wrapped""#), "got: {s}");

    let w = Wrapper {
        mode: RuntimeMode::Rendered,
    };
    let s = toml::to_string(&w).expect("serialize");
    assert!(s.contains(r#"mode = "rendered""#), "got: {s}");

    let w = Wrapper {
        mode: RuntimeMode::Both,
    };
    let s = toml::to_string(&w).expect("serialize");
    assert!(s.contains(r#"mode = "both""#), "got: {s}");
}

#[test]
fn runtime_mode_deserializes_from_lowercase() {
    let wrapped: RuntimeMode = toml::from_str(r#"mode = "wrapped""#)
        .map(|t: toml::Value| {
            t.get("mode")
                .and_then(|v| v.as_str())
                .map(|s| toml::from_str::<toml::Value>(&format!(r#"mode = "{s}""#)).unwrap())
                .unwrap()
        })
        .ok()
        .and_then(|_| {
            // Simpler: deserialize directly via a wrapper struct
            #[derive(serde::Deserialize)]
            struct W {
                mode: RuntimeMode,
            }
            toml::from_str::<W>(r#"mode = "wrapped""#)
                .ok()
                .map(|w| w.mode)
        })
        .expect("should deserialize");

    assert_eq!(wrapped, RuntimeMode::Wrapped);
}

#[test]
fn overlay_key_with_dots_round_trips() {
    let mut data = minimal_vault();
    let key = "persona.identity_prelude";
    data.set_overlay(key.into(), "Prose.".into());

    let serialized = toml::to_string(&data).expect("serialize");
    let restored: VaultData = toml::from_str(&serialized).expect("re-parse");

    assert_eq!(restored.get_overlay(key), Some("Prose."));
}

// ---------------------------------------------------------------------------
// Memory section optional test
// ---------------------------------------------------------------------------

#[test]
fn missing_memory_section_deserializes_as_none() {
    let data: VaultData = toml::from_str(MINIMAL_TOML).expect("parse");
    assert!(data.memory.is_none());
}

#[test]
fn memory_section_present_deserializes_correctly() {
    let data: VaultData = toml::from_str(FULL_TOML).expect("parse");
    let mem = data.memory.expect("memory section should be Some");
    assert_eq!(mem.auth_value_vault_ref, "memory_api_key");
}

// ---------------------------------------------------------------------------
// MemoryConfig type check
// ---------------------------------------------------------------------------

#[test]
fn memory_config_endpoint_is_url() {
    let mem = MemoryConfig {
        backend: "http".into(),
        endpoint: "https://memory.example.com".parse().expect("valid URL"),
        auth_method: "api-key".into(),
        auth_value_vault_ref: "memory_api_key".into(),
    };
    assert_eq!(mem.endpoint.scheme(), "https");
    assert_eq!(mem.endpoint.host_str(), Some("memory.example.com"));
}

// ---------------------------------------------------------------------------
// Identity validation tests
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_empty_keypair_pub() {
    let mut data = minimal_vault();
    data.identity.keypair_pub = String::new();
    match validate(&data) {
        Err(VaultError::MissingIdentityField { field }) => {
            assert_eq!(field, "keypair_pub");
        }
        other => panic!("expected MissingIdentityField, got {other:?}"),
    }
}

#[test]
fn validate_rejects_empty_handle() {
    let mut data = minimal_vault();
    data.identity.handle = String::new();
    match validate(&data) {
        Err(VaultError::MissingIdentityField { field }) => {
            assert_eq!(field, "handle");
        }
        other => panic!("expected MissingIdentityField, got {other:?}"),
    }
}
