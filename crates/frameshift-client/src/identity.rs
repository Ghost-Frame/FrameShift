//! Versioned local publisher-key inventory and secret storage.
//!
//! The inventory contains labels, public keys, local state, and secret-backend
//! locators only. Active private Ed25519 seeds live in the platform credential
//! store or in a dedicated age-encrypted file when no usable native store
//! exists. A migrated plaintext legacy seed is retained only as an owner-only
//! quarantine artifact under the repository's pre-erasure recovery policy.

use std::collections::HashSet;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use age::secrecy::SecretString as AgeSecretString;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::ClientError;

/// Current on-disk publisher-key inventory schema version.
const INVENTORY_SCHEMA_VERSION: u32 = 1;
/// Current encrypted recovery-package schema version.
const RECOVERY_SCHEMA_VERSION: u32 = 1;
/// Native credential-store service namespace.
const KEYRING_SERVICE: &str = "org.frameshift.publisher-keys";
/// Relative path of the metadata-only inventory.
const INVENTORY_REL: &str = "identity/publisher-keys.json";
/// Relative path of the cross-process inventory mutation lock.
const INVENTORY_LOCK_REL: &str = "identity/publisher-keys.lock";
/// Relative directory containing age-encrypted fallback secrets.
const ENCRYPTED_KEYS_REL: &str = "identity/publisher-key-secrets";
/// Relative path of the pre-inventory raw signing seed.
const LEGACY_SIGNING_KEY_REL: &str = "identity/ed25519-signing-key.bin";
/// Maximum accepted inventory or recovery plaintext size.
const MAX_IDENTITY_DOCUMENT_BYTES: u64 = 1024 * 1024;
/// Maximum user-visible publisher-key label length.
const MAX_KEY_LABEL_CHARS: usize = 100;

/// Local lifecycle state for one publisher key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalPublisherKeyState {
    /// The key may be selected for new signatures.
    Active,
    /// Revocation was requested and must be reconciled with the registry.
    RevocationPending,
    /// The key was revoked remotely and remains as local historical metadata.
    Revoked,
}

/// Secret-storage backend used by one local publisher key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherSecretBackend {
    /// The private seed is stored in the platform credential store.
    Keychain,
    /// The private seed is stored in a dedicated age-encrypted file.
    AgeFile,
}

/// Non-secret metadata for one local publisher signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherKeyMetadata {
    /// Stable identifier derived from the public key.
    pub id: String,
    /// User-visible device or purpose label.
    pub label: String,
    /// Base64url-no-pad Ed25519 public key.
    pub public_key: String,
    /// Local lifecycle state.
    pub state: LocalPublisherKeyState,
    /// Secret-storage backend locator.
    pub secret_backend: PublisherSecretBackend,
    /// Unix timestamp when this metadata record was created.
    pub created_at: u64,
}

/// Versioned metadata-only publisher-key inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherKeyInventory {
    /// On-disk schema version.
    pub schema_version: u32,
    /// Key selected for new signatures, or `None` when no local active key remains.
    pub active_key_id: Option<String>,
    /// Local publisher keys in stable creation order.
    pub keys: Vec<PublisherKeyMetadata>,
}

/// Result of initializing or reconciling the publisher-key inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherKeyInitialization {
    /// Reconciled metadata-only inventory.
    pub inventory: PublisherKeyInventory,
    /// Whether a pre-inventory seed was adopted during this call.
    pub migrated_legacy_seed: bool,
    /// Owner-only quarantine path retained under the pre-erasure recovery policy.
    pub legacy_quarantine_path: Option<PathBuf>,
}

/// Local manager for publisher-key metadata and secret material.
#[derive(Debug, Clone)]
pub struct PublisherKeyStore {
    /// Frameshift central data root.
    data_root: PathBuf,
}

/// Held cross-process publisher-key inventory mutation lock.
struct PublisherKeyLock {
    /// Open lock file whose lifetime owns the advisory lock.
    file: fs::File,
}

/// Release the advisory inventory lock when the guard leaves scope.
impl Drop for PublisherKeyLock {
    /// Unlock the file, with close-on-drop as the final fallback.
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// Minimal credential-store boundary used by production and deterministic tests.
trait CredentialStore {
    /// Persist `seed` under the stable key identifier and verify it can be read back.
    fn put(&self, key_id: &str, seed: &[u8; 32]) -> Result<(), String>;
    /// Load the seed stored under the stable key identifier.
    fn get(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, String>;
}

/// Production adapter for the operating system credential store.
struct SystemCredentialStore;

/// Native credential-store implementation.
impl CredentialStore for SystemCredentialStore {
    /// Store and read back one binary seed without rendering it as text.
    fn put(&self, key_id: &str, seed: &[u8; 32]) -> Result<(), String> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, key_id)
            .map_err(|error| format!("credential entry unavailable: {error}"))?;
        entry
            .set_secret(seed)
            .map_err(|error| format!("credential write failed: {error}"))?;
        let stored = Zeroizing::new(
            entry
                .get_secret()
                .map_err(|error| format!("credential read-back failed: {error}"))?,
        );
        if stored.as_slice() != seed {
            return Err("credential read-back did not match the stored seed".to_string());
        }
        Ok(())
    }

    /// Load one binary seed from the native credential store.
    fn get(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, key_id)
            .map_err(|error| format!("credential entry unavailable: {error}"))?;
        entry
            .get_secret()
            .map(Zeroizing::new)
            .map_err(|error| format!("credential read failed: {error}"))
    }
}

/// Plaintext payload protected inside an encrypted recovery package.
#[derive(Serialize, Deserialize)]
struct RecoveryPackage {
    /// Recovery-package schema version.
    schema_version: u32,
    /// Stable local key identifier.
    key_id: String,
    /// User-visible label at export time.
    label: String,
    /// Base64url-no-pad public key used to verify the secret after decryption.
    public_key: String,
    /// Base64url-no-pad private Ed25519 seed.
    seed: String,
}

/// Wipe the encoded private seed when a recovery payload leaves scope.
impl Drop for RecoveryPackage {
    /// Zero the only secret field in the otherwise public package metadata.
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Publisher-key store operations.
impl PublisherKeyStore {
    /// Create a publisher-key store rooted at the Frameshift data directory.
    pub fn new(data_root: impl Into<PathBuf>) -> Self {
        Self {
            data_root: data_root.into(),
        }
    }

    /// Return the path of the metadata-only inventory.
    pub fn inventory_path(&self) -> PathBuf {
        self.data_root.join(INVENTORY_REL)
    }

    /// Return the path of the pre-inventory raw seed.
    pub fn legacy_signing_key_path(&self) -> PathBuf {
        self.data_root.join(LEGACY_SIGNING_KEY_REL)
    }

    /// Load and validate the inventory without accessing private material.
    pub fn load_inventory(&self) -> Result<Option<PublisherKeyInventory>, ClientError> {
        load_inventory_file(&self.inventory_path())
    }

    /// Initialize the inventory, adopting the legacy seed or creating a first key.
    ///
    /// Native credential storage is attempted first. `fallback_passphrase` is
    /// used only when the native store is unusable.
    pub fn initialize(
        &self,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<PublisherKeyInitialization, ClientError> {
        let _lock = self.acquire_lock()?;
        self.initialize_with_store_unlocked(&SystemCredentialStore, fallback_passphrase)
    }

    /// Create a new publisher key with the supplied label.
    ///
    /// The first key becomes selected automatically. Later keys remain
    /// unselected until [`Self::select_key`] is called.
    pub fn create_key(
        &self,
        label: &str,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<PublisherKeyMetadata, ClientError> {
        let _lock = self.acquire_lock()?;
        self.create_key_with_store_unlocked(label, &SystemCredentialStore, fallback_passphrase)
    }

    /// Load the selected signing key after verifying it matches inventory metadata.
    pub fn load_selected_key(
        &self,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<SigningKey, ClientError> {
        let _lock = self.acquire_lock()?;
        let initialization =
            self.initialize_with_store_unlocked(&SystemCredentialStore, fallback_passphrase)?;
        let active_id = initialization
            .inventory
            .active_key_id
            .as_deref()
            .ok_or_else(|| ClientError::PublisherKeyNotFound {
                key_id: "active".to_string(),
            })?;
        let metadata = initialization
            .inventory
            .keys
            .iter()
            .find(|key| key.id == active_id)
            .ok_or_else(|| ClientError::PublisherKeyNotFound {
                key_id: active_id.to_string(),
            })?;
        self.load_key_with_store(metadata, &SystemCredentialStore, fallback_passphrase)
    }

    /// Load one active signing key by stable identifier.
    pub fn load_key(
        &self,
        key_id: &str,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<SigningKey, ClientError> {
        self.load_active_key(key_id, fallback_passphrase)
            .map(|(_, key)| key)
    }

    /// Atomically snapshot active metadata and load its matching signing key.
    pub fn load_active_key(
        &self,
        key_id: &str,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<(PublisherKeyMetadata, SigningKey), ClientError> {
        let _lock = self.acquire_lock()?;
        let inventory = self.require_inventory()?;
        let metadata = find_key(&inventory, key_id)?.clone();
        if metadata.state != LocalPublisherKeyState::Active {
            return Err(ClientError::PublisherKeySecret {
                key_id: key_id.to_string(),
                detail: "non-active keys cannot be loaded for signing".to_string(),
            });
        }
        let key =
            self.load_key_with_store(&metadata, &SystemCredentialStore, fallback_passphrase)?;
        Ok((metadata, key))
    }

    /// Select an active local key for future signatures.
    pub fn select_key(&self, key_id: &str) -> Result<PublisherKeyMetadata, ClientError> {
        let _lock = self.acquire_lock()?;
        let mut inventory = self.require_inventory()?;
        let metadata = find_key(&inventory, key_id)?.clone();
        if metadata.state != LocalPublisherKeyState::Active {
            return Err(ClientError::PublisherKeySecret {
                key_id: key_id.to_string(),
                detail: "non-active keys cannot be selected".to_string(),
            });
        }
        inventory.active_key_id = Some(metadata.id.clone());
        save_inventory_file(&self.inventory_path(), &inventory)?;
        Ok(metadata)
    }

    /// Replace a key's user-visible label.
    pub fn label_key(
        &self,
        key_id: &str,
        label: &str,
    ) -> Result<PublisherKeyMetadata, ClientError> {
        let _lock = self.acquire_lock()?;
        let label = validate_label(label)?;
        let mut inventory = self.require_inventory()?;
        let metadata = inventory
            .keys
            .iter_mut()
            .find(|key| key.id == key_id)
            .ok_or_else(|| ClientError::PublisherKeyNotFound {
                key_id: key_id.to_string(),
            })?;
        metadata.label = label;
        let updated = metadata.clone();
        save_inventory_file(&self.inventory_path(), &inventory)?;
        Ok(updated)
    }

    /// Disable a local key before requesting irreversible remote revocation.
    pub fn mark_revocation_pending(
        &self,
        key_id: &str,
    ) -> Result<PublisherKeyMetadata, ClientError> {
        let _lock = self.acquire_lock()?;
        let mut inventory = self.require_inventory()?;
        let metadata = inventory
            .keys
            .iter_mut()
            .find(|key| key.id == key_id)
            .ok_or_else(|| ClientError::PublisherKeyNotFound {
                key_id: key_id.to_string(),
            })?;
        if metadata.state == LocalPublisherKeyState::Revoked {
            return Err(ClientError::PublisherKeySecret {
                key_id: key_id.to_string(),
                detail: "revoked keys cannot begin revocation again".to_string(),
            });
        }
        metadata.state = LocalPublisherKeyState::RevocationPending;
        let updated = metadata.clone();
        if inventory.active_key_id.as_deref() == Some(key_id) {
            inventory.active_key_id = inventory
                .keys
                .iter()
                .find(|key| key.state == LocalPublisherKeyState::Active)
                .map(|key| key.id.clone());
        }
        save_inventory_file(&self.inventory_path(), &inventory)?;
        Ok(updated)
    }

    /// Restore a pending key after the registry definitively rejects revocation.
    pub fn cancel_revocation(&self, key_id: &str) -> Result<PublisherKeyMetadata, ClientError> {
        let _lock = self.acquire_lock()?;
        let mut inventory = self.require_inventory()?;
        let metadata = inventory
            .keys
            .iter_mut()
            .find(|key| key.id == key_id)
            .ok_or_else(|| ClientError::PublisherKeyNotFound {
                key_id: key_id.to_string(),
            })?;
        match metadata.state {
            LocalPublisherKeyState::Active => {}
            LocalPublisherKeyState::RevocationPending => {
                metadata.state = LocalPublisherKeyState::Active;
            }
            LocalPublisherKeyState::Revoked => {
                return Err(ClientError::PublisherKeySecret {
                    key_id: key_id.to_string(),
                    detail: "completed revocation cannot be cancelled".to_string(),
                });
            }
        }
        let updated = metadata.clone();
        if inventory.active_key_id.is_none() {
            inventory.active_key_id = Some(key_id.to_string());
        }
        save_inventory_file(&self.inventory_path(), &inventory)?;
        Ok(updated)
    }

    /// Mark a local key revoked after the registry confirms revocation.
    pub fn mark_revoked(&self, key_id: &str) -> Result<PublisherKeyMetadata, ClientError> {
        let _lock = self.acquire_lock()?;
        let mut inventory = self.require_inventory()?;
        let metadata = inventory
            .keys
            .iter_mut()
            .find(|key| key.id == key_id)
            .ok_or_else(|| ClientError::PublisherKeyNotFound {
                key_id: key_id.to_string(),
            })?;
        metadata.state = LocalPublisherKeyState::Revoked;
        let updated = metadata.clone();
        if inventory.active_key_id.as_deref() == Some(key_id) {
            inventory.active_key_id = inventory
                .keys
                .iter()
                .find(|key| key.state == LocalPublisherKeyState::Active)
                .map(|key| key.id.clone());
        }
        save_inventory_file(&self.inventory_path(), &inventory)?;
        Ok(updated)
    }

    /// Export one key to an explicitly named age-encrypted recovery package.
    pub fn export_recovery(
        &self,
        key_id: &str,
        output_path: &Path,
        storage_passphrase: Option<&SecretString>,
        recovery_passphrase: &SecretString,
    ) -> Result<(), ClientError> {
        self.export_recovery_with_store(
            key_id,
            output_path,
            storage_passphrase,
            recovery_passphrase,
            &SystemCredentialStore,
        )
    }

    /// Export one key through an injectable credential store.
    fn export_recovery_with_store(
        &self,
        key_id: &str,
        output_path: &Path,
        storage_passphrase: Option<&SecretString>,
        recovery_passphrase: &SecretString,
        credential_store: &dyn CredentialStore,
    ) -> Result<(), ClientError> {
        let _lock = self.acquire_lock()?;
        validate_nonempty_passphrase(recovery_passphrase, output_path)?;
        let inventory = self.require_inventory()?;
        let metadata = find_key(&inventory, key_id)?;
        let signing_key =
            self.load_key_with_store(metadata, credential_store, storage_passphrase)?;
        let package = RecoveryPackage {
            schema_version: RECOVERY_SCHEMA_VERSION,
            key_id: metadata.id.clone(),
            label: metadata.label.clone(),
            public_key: metadata.public_key.clone(),
            seed: URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        };
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&package)
                .map_err(|error| ClientError::JsonSerialize(error.to_string()))?,
        );
        write_age_file_new(output_path, &plaintext, recovery_passphrase)
    }

    /// Import and select a key from an age-encrypted recovery package.
    pub fn import_recovery(
        &self,
        input_path: &Path,
        recovery_passphrase: &SecretString,
        fallback_passphrase: Option<&SecretString>,
        label_override: Option<&str>,
    ) -> Result<PublisherKeyMetadata, ClientError> {
        self.import_recovery_with_store(
            input_path,
            recovery_passphrase,
            fallback_passphrase,
            label_override,
            &SystemCredentialStore,
        )
    }

    /// Import one recovery package through an injectable credential store.
    fn import_recovery_with_store(
        &self,
        input_path: &Path,
        recovery_passphrase: &SecretString,
        fallback_passphrase: Option<&SecretString>,
        label_override: Option<&str>,
        credential_store: &dyn CredentialStore,
    ) -> Result<PublisherKeyMetadata, ClientError> {
        let _lock = self.acquire_lock()?;
        self.import_recovery_with_store_unlocked(
            input_path,
            recovery_passphrase,
            fallback_passphrase,
            label_override,
            credential_store,
        )
    }

    /// Import one recovery package while the inventory lock is held.
    fn import_recovery_with_store_unlocked(
        &self,
        input_path: &Path,
        recovery_passphrase: &SecretString,
        fallback_passphrase: Option<&SecretString>,
        label_override: Option<&str>,
        credential_store: &dyn CredentialStore,
    ) -> Result<PublisherKeyMetadata, ClientError> {
        validate_nonempty_passphrase(recovery_passphrase, input_path)?;
        let plaintext = read_age_file(input_path, recovery_passphrase)?;
        let package: RecoveryPackage = serde_json::from_slice(&plaintext).map_err(|error| {
            ClientError::PublisherKeyRecovery {
                path: input_path.to_path_buf(),
                detail: format!("invalid recovery package: {error}"),
            }
        })?;
        if package.schema_version != RECOVERY_SCHEMA_VERSION {
            return Err(ClientError::PublisherKeyRecovery {
                path: input_path.to_path_buf(),
                detail: format!("unsupported schema version {}", package.schema_version),
            });
        }
        let seed = decode_seed(&package.seed, input_path)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = public_key_b64(&signing_key);
        let key_id = key_id_for(&signing_key);
        if public_key != package.public_key || key_id != package.key_id {
            return Err(ClientError::PublisherKeyRecovery {
                path: input_path.to_path_buf(),
                detail: "recovery seed does not match its public metadata".to_string(),
            });
        }
        let label = validate_label(label_override.unwrap_or(&package.label))?;
        self.import_seed_with_store(
            &seed,
            &key_id,
            &public_key,
            &label,
            credential_store,
            fallback_passphrase,
        )
    }

    /// Require an initialized metadata inventory.
    fn require_inventory(&self) -> Result<PublisherKeyInventory, ClientError> {
        self.load_inventory()?
            .ok_or_else(|| ClientError::PublisherKeyNotFound {
                key_id: "inventory".to_string(),
            })
    }

    /// Initialize using an injectable credential-store implementation.
    fn initialize_with_store(
        &self,
        credential_store: &dyn CredentialStore,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<PublisherKeyInitialization, ClientError> {
        let _lock = self.acquire_lock()?;
        self.initialize_with_store_unlocked(credential_store, fallback_passphrase)
    }

    /// Initialize while the inventory mutation lock is already held.
    fn initialize_with_store_unlocked(
        &self,
        credential_store: &dyn CredentialStore,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<PublisherKeyInitialization, ClientError> {
        let legacy_path = self.legacy_signing_key_path();
        if let Some(inventory) = self.load_inventory()? {
            let quarantine = self.reconcile_legacy_file(
                &inventory,
                credential_store,
                fallback_passphrase,
                &legacy_path,
            )?;
            return Ok(PublisherKeyInitialization {
                inventory,
                migrated_legacy_seed: quarantine.is_some(),
                legacy_quarantine_path: quarantine,
            });
        }

        let (signing_key, migrated_legacy_seed) = match fs::symlink_metadata(&legacy_path) {
            Ok(_) => (load_legacy_signing_key(&legacy_path)?, true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (SigningKey::generate(&mut OsRng), false)
            }
            Err(source) => {
                return Err(ClientError::Io {
                    path: legacy_path,
                    source,
                });
            }
        };
        let metadata = self.store_new_signing_key(
            &signing_key,
            "primary",
            credential_store,
            fallback_passphrase,
        )?;
        let inventory = PublisherKeyInventory {
            schema_version: INVENTORY_SCHEMA_VERSION,
            active_key_id: Some(metadata.id.clone()),
            keys: vec![metadata],
        };
        save_inventory_file(&self.inventory_path(), &inventory)?;
        let legacy_quarantine_path = if migrated_legacy_seed {
            Some(quarantine_legacy_seed(&legacy_path)?)
        } else {
            None
        };
        Ok(PublisherKeyInitialization {
            inventory,
            migrated_legacy_seed,
            legacy_quarantine_path,
        })
    }

    /// Create a key using an injectable credential store.
    fn create_key_with_store(
        &self,
        label: &str,
        credential_store: &dyn CredentialStore,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<PublisherKeyMetadata, ClientError> {
        let _lock = self.acquire_lock()?;
        self.create_key_with_store_unlocked(label, credential_store, fallback_passphrase)
    }

    /// Create a key while the inventory mutation lock is already held.
    fn create_key_with_store_unlocked(
        &self,
        label: &str,
        credential_store: &dyn CredentialStore,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<PublisherKeyMetadata, ClientError> {
        let label = validate_label(label)?;
        let mut inventory = match self.load_inventory()? {
            Some(inventory) => inventory,
            None => match fs::symlink_metadata(self.legacy_signing_key_path()) {
                Ok(_) => {
                    self.initialize_with_store_unlocked(credential_store, fallback_passphrase)?
                        .inventory
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    PublisherKeyInventory {
                        schema_version: INVENTORY_SCHEMA_VERSION,
                        active_key_id: None,
                        keys: Vec::new(),
                    }
                }
                Err(source) => {
                    return Err(ClientError::Io {
                        path: self.legacy_signing_key_path(),
                        source,
                    });
                }
            },
        };
        let signing_key = SigningKey::generate(&mut OsRng);
        let metadata = self.store_new_signing_key(
            &signing_key,
            &label,
            credential_store,
            fallback_passphrase,
        )?;
        if inventory.keys.iter().any(|key| key.id == metadata.id) {
            return Err(ClientError::InvalidPublisherKeyInventory {
                path: self.inventory_path(),
                detail: format!("duplicate generated key id {}", metadata.id),
            });
        }
        if inventory.active_key_id.is_none() {
            inventory.active_key_id = Some(metadata.id.clone());
        }
        inventory.keys.push(metadata.clone());
        save_inventory_file(&self.inventory_path(), &inventory)?;
        Ok(metadata)
    }

    /// Store imported seed bytes and add or refresh their metadata record.
    fn import_seed_with_store(
        &self,
        seed: &[u8; 32],
        key_id: &str,
        public_key: &str,
        label: &str,
        credential_store: &dyn CredentialStore,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<PublisherKeyMetadata, ClientError> {
        let signing_key = SigningKey::from_bytes(seed);
        if key_id_for(&signing_key) != key_id || public_key_b64(&signing_key) != public_key {
            return Err(ClientError::PublisherKeySecret {
                key_id: key_id.to_string(),
                detail: "imported seed does not match its public metadata".to_string(),
            });
        }
        let mut inventory = self.load_inventory()?.unwrap_or(PublisherKeyInventory {
            schema_version: INVENTORY_SCHEMA_VERSION,
            active_key_id: None,
            keys: Vec::new(),
        });
        if let Some(existing) = inventory
            .keys
            .iter()
            .find(|entry| entry.public_key == public_key)
        {
            if existing.state != LocalPublisherKeyState::Active {
                return Err(ClientError::PublisherKeySecret {
                    key_id: existing.id.clone(),
                    detail:
                        "recovery cannot reactivate a key pending revocation or already revoked"
                            .to_string(),
                });
            }
        }
        let backend = self.store_seed(key_id, seed, credential_store, fallback_passphrase)?;
        let metadata = PublisherKeyMetadata {
            id: key_id.to_string(),
            label: label.to_string(),
            public_key: public_key.to_string(),
            state: LocalPublisherKeyState::Active,
            secret_backend: backend,
            created_at: unix_now(),
        };
        if let Some(existing) = inventory
            .keys
            .iter_mut()
            .find(|entry| entry.public_key == public_key)
        {
            existing.label = metadata.label.clone();
            existing.secret_backend = backend;
            inventory.active_key_id = Some(existing.id.clone());
            let imported = existing.clone();
            save_inventory_file(&self.inventory_path(), &inventory)?;
            return Ok(imported);
        }
        inventory.active_key_id = Some(metadata.id.clone());
        inventory.keys.push(metadata.clone());
        save_inventory_file(&self.inventory_path(), &inventory)?;
        Ok(metadata)
    }

    /// Persist one signing key and return its metadata record.
    fn store_new_signing_key(
        &self,
        signing_key: &SigningKey,
        label: &str,
        credential_store: &dyn CredentialStore,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<PublisherKeyMetadata, ClientError> {
        let key_id = key_id_for(signing_key);
        let seed = Zeroizing::new(signing_key.to_bytes());
        let secret_backend =
            self.store_seed(&key_id, &seed, credential_store, fallback_passphrase)?;
        Ok(PublisherKeyMetadata {
            id: key_id,
            label: validate_label(label)?,
            public_key: public_key_b64(signing_key),
            state: LocalPublisherKeyState::Active,
            secret_backend,
            created_at: unix_now(),
        })
    }

    /// Store one seed in the native credential store or encrypted fallback.
    fn store_seed(
        &self,
        key_id: &str,
        seed: &[u8; 32],
        credential_store: &dyn CredentialStore,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<PublisherSecretBackend, ClientError> {
        match credential_store.put(key_id, seed) {
            Ok(()) => Ok(PublisherSecretBackend::Keychain),
            Err(native_error) => {
                let passphrase = fallback_passphrase.ok_or_else(|| {
                    ClientError::PublisherKeychainUnavailable {
                        detail: native_error.clone(),
                    }
                })?;
                let path = self.encrypted_key_path(key_id);
                validate_nonempty_passphrase(passphrase, &path)?;
                store_age_seed(&path, seed, passphrase)?;
                Ok(PublisherSecretBackend::AgeFile)
            }
        }
    }

    /// Load and validate one signing key through an injectable credential store.
    fn load_key_with_store(
        &self,
        metadata: &PublisherKeyMetadata,
        credential_store: &dyn CredentialStore,
        fallback_passphrase: Option<&SecretString>,
    ) -> Result<SigningKey, ClientError> {
        let seed_bytes = match metadata.secret_backend {
            PublisherSecretBackend::Keychain => {
                credential_store.get(&metadata.id).map_err(|detail| {
                    ClientError::PublisherKeySecret {
                        key_id: metadata.id.clone(),
                        detail,
                    }
                })?
            }
            PublisherSecretBackend::AgeFile => {
                let path = self.encrypted_key_path(&metadata.id);
                let passphrase = fallback_passphrase.ok_or_else(|| {
                    ClientError::PublisherKeyPassphraseRequired {
                        key_id: metadata.id.clone(),
                    }
                })?;
                read_age_file(&path, passphrase)?
            }
        };
        if seed_bytes.len() != 32 {
            return Err(ClientError::PublisherKeySecret {
                key_id: metadata.id.clone(),
                detail: format!("expected 32-byte seed, found {} bytes", seed_bytes.len()),
            });
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        seed.copy_from_slice(&seed_bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        if public_key_b64(&signing_key) != metadata.public_key
            || key_id_for(&signing_key) != metadata.id
        {
            return Err(ClientError::PublisherKeySecret {
                key_id: metadata.id.clone(),
                detail: "private seed does not match inventory public metadata".to_string(),
            });
        }
        Ok(signing_key)
    }

    /// Reconcile a leftover legacy seed after a completed inventory write.
    fn reconcile_legacy_file(
        &self,
        inventory: &PublisherKeyInventory,
        credential_store: &dyn CredentialStore,
        fallback_passphrase: Option<&SecretString>,
        legacy_path: &Path,
    ) -> Result<Option<PathBuf>, ClientError> {
        match fs::symlink_metadata(legacy_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ClientError::Io {
                    path: legacy_path.to_path_buf(),
                    source,
                });
            }
            Ok(_) => {}
        }
        let legacy_key = load_legacy_signing_key(legacy_path)?;
        let public_key = public_key_b64(&legacy_key);
        let metadata = inventory
            .keys
            .iter()
            .find(|key| key.public_key == public_key)
            .ok_or_else(|| ClientError::InvalidPublisherKeyInventory {
                path: self.inventory_path(),
                detail: "legacy seed public key is absent from the inventory".to_string(),
            })?;
        let secured = self.load_key_with_store(metadata, credential_store, fallback_passphrase)?;
        if secured.to_bytes() != legacy_key.to_bytes() {
            return Err(ClientError::PublisherKeySecret {
                key_id: metadata.id.clone(),
                detail: "secured seed differs from the legacy seed".to_string(),
            });
        }
        quarantine_legacy_seed(legacy_path).map(Some)
    }

    /// Derive the fixed age fallback path for one validated key identifier.
    fn encrypted_key_path(&self, key_id: &str) -> PathBuf {
        self.data_root
            .join(ENCRYPTED_KEYS_REL)
            .join(format!("{key_id}.age"))
    }

    /// Acquire the cross-process lock that serializes inventory mutations.
    fn acquire_lock(&self) -> Result<PublisherKeyLock, ClientError> {
        acquire_identity_lock(&self.data_root.join(INVENTORY_LOCK_REL))
    }
}

/// Return the base64url-no-pad public key for a signing key.
pub fn public_key_b64(key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
}

/// Return the lowercase-hex public key for a signing key.
pub fn public_key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

/// Find one metadata record by stable identifier.
fn find_key<'a>(
    inventory: &'a PublisherKeyInventory,
    key_id: &str,
) -> Result<&'a PublisherKeyMetadata, ClientError> {
    inventory
        .keys
        .iter()
        .find(|key| key.id == key_id)
        .ok_or_else(|| ClientError::PublisherKeyNotFound {
            key_id: key_id.to_string(),
        })
}

/// Load and validate a metadata-only inventory file.
fn load_inventory_file(path: &Path) -> Result<Option<PublisherKeyInventory>, ClientError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ClientError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.file_type().is_file() {
        return Err(ClientError::InvalidPublisherKeyInventory {
            path: path.to_path_buf(),
            detail: "inventory path is not a regular file".to_string(),
        });
    }
    let bytes = read_regular_file_bounded(path, MAX_IDENTITY_DOCUMENT_BYTES)?;
    let inventory: PublisherKeyInventory = serde_json::from_slice(&bytes).map_err(|error| {
        ClientError::InvalidPublisherKeyInventory {
            path: path.to_path_buf(),
            detail: error.to_string(),
        }
    })?;
    validate_inventory(path, &inventory)?;
    Ok(Some(inventory))
}

/// Validate all inventory invariants before any secret lookup.
fn validate_inventory(path: &Path, inventory: &PublisherKeyInventory) -> Result<(), ClientError> {
    if inventory.schema_version != INVENTORY_SCHEMA_VERSION {
        return Err(ClientError::InvalidPublisherKeyInventory {
            path: path.to_path_buf(),
            detail: format!("unsupported schema version {}", inventory.schema_version),
        });
    }
    let mut ids = HashSet::new();
    let mut public_keys = HashSet::new();
    for key in &inventory.keys {
        validate_label(&key.label).map_err(|error| ClientError::InvalidPublisherKeyInventory {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
        let public_bytes = URL_SAFE_NO_PAD.decode(&key.public_key).map_err(|_| {
            ClientError::InvalidPublisherKeyInventory {
                path: path.to_path_buf(),
                detail: format!("key {} has invalid public-key encoding", key.id),
            }
        })?;
        let public_array: [u8; 32] = public_bytes.as_slice().try_into().map_err(|_| {
            ClientError::InvalidPublisherKeyInventory {
                path: path.to_path_buf(),
                detail: format!("key {} public key is not 32 bytes", key.id),
            }
        })?;
        if stable_key_id(&public_array) != key.id {
            return Err(ClientError::InvalidPublisherKeyInventory {
                path: path.to_path_buf(),
                detail: format!("key {} identifier does not match its public key", key.id),
            });
        }
        if !ids.insert(key.id.clone()) || !public_keys.insert(key.public_key.clone()) {
            return Err(ClientError::InvalidPublisherKeyInventory {
                path: path.to_path_buf(),
                detail: "inventory contains duplicate keys".to_string(),
            });
        }
    }
    if let Some(active_id) = inventory.active_key_id.as_deref() {
        let active = inventory
            .keys
            .iter()
            .find(|key| key.id == active_id)
            .ok_or_else(|| ClientError::InvalidPublisherKeyInventory {
                path: path.to_path_buf(),
                detail: "active key identifier is absent from the inventory".to_string(),
            })?;
        if active.state != LocalPublisherKeyState::Active {
            return Err(ClientError::InvalidPublisherKeyInventory {
                path: path.to_path_buf(),
                detail: "active key identifier points to a non-active key".to_string(),
            });
        }
    }
    Ok(())
}

/// Persist validated inventory metadata with private permissions and atomic replacement.
fn save_inventory_file(path: &Path, inventory: &PublisherKeyInventory) -> Result<(), ClientError> {
    validate_inventory(path, inventory)?;
    ensure_regular_or_missing(path, "inventory")?;
    let bytes = serde_json::to_vec_pretty(inventory)
        .map_err(|error| ClientError::JsonSerialize(error.to_string()))?;
    write_private_file_atomic(path, &bytes, true)
}

/// Store a private seed in an age-encrypted file and verify decryption.
fn store_age_seed(
    path: &Path,
    seed: &[u8; 32],
    passphrase: &SecretString,
) -> Result<(), ClientError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(ClientError::PublisherKeyRecovery {
                    path: path.to_path_buf(),
                    detail: "encrypted seed path is not a regular file".to_string(),
                });
            }
            let existing = read_age_file(path, passphrase)?;
            if existing.as_slice() == seed {
                return Ok(());
            }
            return Err(ClientError::PublisherKeyRecovery {
                path: path.to_path_buf(),
                detail: "encrypted seed path already contains different material".to_string(),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ClientError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    write_age_file_new(path, seed, passphrase)?;
    let stored = read_age_file(path, passphrase)?;
    if stored.as_slice() != seed {
        return Err(ClientError::PublisherKeyRecovery {
            path: path.to_path_buf(),
            detail: "encrypted seed read-back mismatch".to_string(),
        });
    }
    Ok(())
}

/// Write a new age passphrase-encrypted file without replacing an existing path.
fn write_age_file_new(
    path: &Path,
    plaintext: &[u8],
    passphrase: &SecretString,
) -> Result<(), ClientError> {
    ensure_regular_or_missing(path, "encrypted identity file")?;
    if path.exists() {
        return Err(ClientError::PublisherKeyRecovery {
            path: path.to_path_buf(),
            detail: "destination already exists".to_string(),
        });
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| ClientError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| ClientError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    set_private_permissions(temporary.as_file(), parent)?;
    let encryptor = age::Encryptor::with_user_passphrase(AgeSecretString::new(
        passphrase.expose_secret().to_owned(),
    ));
    {
        let mut writer = encryptor
            .wrap_output(temporary.as_file_mut())
            .map_err(|error| ClientError::PublisherKeyRecovery {
                path: path.to_path_buf(),
                detail: format!("encryption setup failed: {error}"),
            })?;
        writer
            .write_all(plaintext)
            .map_err(|source| ClientError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        writer
            .finish()
            .map_err(|error| ClientError::PublisherKeyRecovery {
                path: path.to_path_buf(),
                detail: format!("encryption finalization failed: {error}"),
            })?;
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| ClientError::Io {
            path: path.to_path_buf(),
            source: error.error,
        })?;
    sync_parent_directory(parent);
    Ok(())
}

/// Read an age passphrase-encrypted file into a zeroizing bounded buffer.
fn read_age_file(
    path: &Path,
    passphrase: &SecretString,
) -> Result<Zeroizing<Vec<u8>>, ClientError> {
    let file = open_regular_file_nofollow(path)?;
    let decryptor = age::Decryptor::new(std::io::BufReader::new(file)).map_err(|error| {
        ClientError::PublisherKeyRecovery {
            path: path.to_path_buf(),
            detail: format!("invalid age ciphertext: {error}"),
        }
    })?;
    let age_passphrase = AgeSecretString::new(passphrase.expose_secret().to_owned());
    let mut reader =
        match decryptor {
            age::Decryptor::Passphrase(decryptor) => decryptor
                .decrypt(&age_passphrase, None)
                .map_err(|error| ClientError::PublisherKeyRecovery {
                    path: path.to_path_buf(),
                    detail: format!("decryption failed: {error}"),
                })?,
            _ => {
                return Err(ClientError::PublisherKeyRecovery {
                    path: path.to_path_buf(),
                    detail: "identity file is not passphrase encrypted".to_string(),
                });
            }
        };
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(MAX_IDENTITY_DOCUMENT_BYTES + 1)
        .read_to_end(&mut plaintext)
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if plaintext.len() as u64 > MAX_IDENTITY_DOCUMENT_BYTES {
        return Err(ClientError::PublisherKeyRecovery {
            path: path.to_path_buf(),
            detail: "decrypted identity document exceeds the size limit".to_string(),
        });
    }
    Ok(plaintext)
}

/// Load the pre-inventory raw 32-byte signing seed without following symlinks.
fn load_legacy_signing_key(path: &Path) -> Result<SigningKey, ClientError> {
    let mut file = open_regular_file_nofollow(path)?;
    set_private_permissions(&file, path)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(33));
    std::io::Read::by_ref(&mut file)
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() != 32 {
        return Err(ClientError::InvalidSigningKey {
            path: path.to_path_buf(),
            detail: format!("expected 32-byte seed, found {} bytes", bytes.len()),
        });
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

/// Rename a verified legacy seed to a unique quarantine path without deleting it.
fn quarantine_legacy_seed(path: &Path) -> Result<PathBuf, ClientError> {
    let mut nonce = [0_u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ed25519-signing-key.bin");
    let quarantine = path.with_file_name(format!(
        "{file_name}.QUARANTINE-{}-{}",
        unix_now(),
        hex::encode(nonce)
    ));
    if fs::symlink_metadata(&quarantine).is_ok() {
        return Err(ClientError::InvalidSigningKey {
            path: quarantine,
            detail: "generated quarantine path already exists".to_string(),
        });
    }
    fs::rename(path, &quarantine).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if path.exists() || !quarantine.is_file() {
        return Err(ClientError::InvalidSigningKey {
            path: quarantine,
            detail: "legacy seed quarantine verification failed".to_string(),
        });
    }
    Ok(quarantine)
}

/// Open and exclusively lock the publisher-key inventory lock file.
fn acquire_identity_lock(path: &Path) -> Result<PublisherKeyLock, ClientError> {
    ensure_regular_or_missing(path, "inventory lock")?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| ClientError::Io {
        path: parent.to_path_buf(),
        source,
    })?;

    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClientError::InvalidPublisherKeyInventory {
            path: path.to_path_buf(),
            detail: "inventory lock path is not a regular file".to_string(),
        });
    }
    #[cfg(windows)]
    if metadata_is_windows_reparse_point(&metadata) {
        return Err(ClientError::InvalidPublisherKeyInventory {
            path: path.to_path_buf(),
            detail: "inventory lock path is a reparse point".to_string(),
        });
    }
    set_private_permissions(&file, path)?;
    fs2::FileExt::lock_exclusive(&file).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(PublisherKeyLock { file })
}

/// Open a regular file for reading without following a final-component symlink.
fn open_regular_file_nofollow(path: &Path) -> Result<fs::File, ClientError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClientError::InvalidSigningKey {
            path: path.to_path_buf(),
            detail: "secret path is not a regular file".to_string(),
        });
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClientError::InvalidSigningKey {
            path: path.to_path_buf(),
            detail: "secret path changed to a non-regular file while opening".to_string(),
        });
    }
    #[cfg(windows)]
    if metadata_is_windows_reparse_point(&metadata) {
        return Err(ClientError::InvalidSigningKey {
            path: path.to_path_buf(),
            detail: "secret path is a reparse point".to_string(),
        });
    }
    Ok(file)
}

#[cfg(windows)]
/// Return whether handle metadata identifies any Windows reparse point.
fn metadata_is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Read a bounded regular file without following a final-component symlink.
fn read_regular_file_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, ClientError> {
    let file = open_regular_file_nofollow(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(ClientError::InvalidPublisherKeyInventory {
            path: path.to_path_buf(),
            detail: "identity document exceeds the size limit".to_string(),
        });
    }
    Ok(bytes)
}

/// Atomically write a private file, optionally replacing an existing regular file.
fn write_private_file_atomic(path: &Path, bytes: &[u8], replace: bool) -> Result<(), ClientError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| ClientError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| ClientError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    set_private_permissions(temporary.as_file(), parent)?;
    temporary
        .write_all(bytes)
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if replace {
        temporary.persist(path)
    } else {
        temporary.persist_noclobber(path)
    }
    .map_err(|error| ClientError::Io {
        path: path.to_path_buf(),
        source: error.error,
    })?;
    sync_parent_directory(parent);
    Ok(())
}

/// Apply owner-only permissions to a private file on Unix.
fn set_private_permissions(file: &fs::File, path: &Path) -> Result<(), ClientError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| ClientError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }
    #[cfg(not(unix))]
    let _ = (file, path);
    Ok(())
}

/// Best-effort fsync of a parent directory after an atomic rename.
fn sync_parent_directory(parent: &Path) {
    #[cfg(unix)]
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    #[cfg(not(unix))]
    let _ = parent;
}

/// Reject an existing path unless it is a regular file.
fn ensure_regular_or_missing(path: &Path, kind: &str) -> Result<(), ClientError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(ClientError::InvalidPublisherKeyInventory {
            path: path.to_path_buf(),
            detail: format!("{kind} path is not a regular file"),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ClientError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Validate and normalize a user-visible key label.
fn validate_label(label: &str) -> Result<String, ClientError> {
    let trimmed = label.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_KEY_LABEL_CHARS {
        return Err(ClientError::InvalidPublisherKeyLabel {
            max_chars: MAX_KEY_LABEL_CHARS,
        });
    }
    Ok(trimmed.to_string())
}

/// Reject an empty fallback or recovery passphrase.
fn validate_nonempty_passphrase(passphrase: &SecretString, path: &Path) -> Result<(), ClientError> {
    if passphrase.expose_secret().is_empty() {
        return Err(ClientError::PublisherKeyRecovery {
            path: path.to_path_buf(),
            detail: "passphrase must not be empty".to_string(),
        });
    }
    Ok(())
}

/// Decode an exact 32-byte seed from recovery-package base64.
fn decode_seed(encoded: &str, path: &Path) -> Result<Zeroizing<[u8; 32]>, ClientError> {
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        ClientError::PublisherKeyRecovery {
            path: path.to_path_buf(),
            detail: "recovery seed encoding is invalid".to_string(),
        }
    })?);
    if decoded.len() != 32 {
        return Err(ClientError::PublisherKeyRecovery {
            path: path.to_path_buf(),
            detail: format!(
                "expected a 32-byte recovery seed, found {} bytes",
                decoded.len()
            ),
        });
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&decoded);
    Ok(seed)
}

/// Return the stable local identifier for a signing key.
fn key_id_for(key: &SigningKey) -> String {
    stable_key_id(&key.verifying_key().to_bytes())
}

/// Derive a stable public identifier from raw Ed25519 public-key bytes.
fn stable_key_id(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("pk_{}", hex::encode(&digest[..16]))
}

/// Return the current Unix timestamp in seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
/// Publisher-key inventory and encrypted-secret regression tests.
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Barrier, Mutex};

    use ed25519_dalek::{Signer as _, Verifier as _};

    use super::*;

    /// Deterministic in-memory credential store with optional forced failure.
    #[derive(Default)]
    struct FakeCredentialStore {
        /// Stored secret bytes keyed by local identifier.
        secrets: Mutex<HashMap<String, Vec<u8>>>,
        /// Error returned by every operation when configured.
        failure: Option<String>,
    }

    /// Fake credential-store constructors and inspection helpers.
    impl FakeCredentialStore {
        /// Create a store that rejects every operation.
        fn unavailable() -> Self {
            Self {
                secrets: Mutex::new(HashMap::new()),
                failure: Some("native store unavailable".to_string()),
            }
        }
    }

    /// In-memory credential-store implementation.
    impl CredentialStore for FakeCredentialStore {
        /// Persist one seed unless failure was configured.
        fn put(&self, key_id: &str, seed: &[u8; 32]) -> Result<(), String> {
            if let Some(failure) = &self.failure {
                return Err(failure.clone());
            }
            self.secrets
                .lock()
                .unwrap()
                .insert(key_id.to_string(), seed.to_vec());
            Ok(())
        }

        /// Load one seed unless failure was configured.
        fn get(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, String> {
            if let Some(failure) = &self.failure {
                return Err(failure.clone());
            }
            self.secrets
                .lock()
                .unwrap()
                .get(key_id)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| "credential missing".to_string())
        }
    }

    /// Existing raw seed migrates byte-for-byte through the encrypted fallback.
    #[test]
    fn legacy_seed_migrates_without_identity_change() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PublisherKeyStore::new(temp.path());
        let legacy_path = store.legacy_signing_key_path();
        fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        let original = [7_u8; 32];
        fs::write(&legacy_path, original).unwrap();
        let passphrase = SecretString::new("fallback test passphrase".to_string());
        let credentials = FakeCredentialStore::unavailable();

        let initialized = store
            .initialize_with_store(&credentials, Some(&passphrase))
            .unwrap();
        assert!(initialized.migrated_legacy_seed);
        assert!(!legacy_path.exists());
        let quarantine = initialized.legacy_quarantine_path.unwrap();
        assert_eq!(fs::read(quarantine).unwrap(), original);

        let metadata = &initialized.inventory.keys[0];
        assert_eq!(metadata.secret_backend, PublisherSecretBackend::AgeFile);
        let migrated = store
            .load_key_with_store(metadata, &credentials, Some(&passphrase))
            .unwrap();
        assert_eq!(migrated.to_bytes(), original);
        assert_eq!(
            metadata.public_key,
            public_key_b64(&SigningKey::from_bytes(&original))
        );
        let message = b"frameshift legacy migration proof";
        migrated
            .verifying_key()
            .verify(message, &migrated.sign(message))
            .unwrap();
    }

    /// Reconciliation is idempotent once the legacy file is quarantined.
    #[test]
    fn repeated_initialization_keeps_the_same_key() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PublisherKeyStore::new(temp.path());
        let legacy_path = store.legacy_signing_key_path();
        fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        fs::write(&legacy_path, [9_u8; 32]).unwrap();
        let credentials = FakeCredentialStore::default();

        let first = store.initialize_with_store(&credentials, None).unwrap();
        let second = store.initialize_with_store(&credentials, None).unwrap();
        assert_eq!(first.inventory, second.inventory);
        assert!(first.migrated_legacy_seed);
        assert!(!second.migrated_legacy_seed);
    }

    /// Multiple keys retain distinct secrets and explicit selected-key state.
    #[test]
    fn multiple_keys_can_be_created_and_selected() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PublisherKeyStore::new(temp.path());
        let credentials = FakeCredentialStore::default();

        let first = store
            .create_key_with_store("laptop", &credentials, None)
            .unwrap();
        let second = store
            .create_key_with_store("desktop", &credentials, None)
            .unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(
            store.load_inventory().unwrap().unwrap().active_key_id,
            Some(first.id.clone())
        );

        store.select_key(&second.id).unwrap();
        assert_eq!(
            store.load_inventory().unwrap().unwrap().active_key_id,
            Some(second.id)
        );
    }

    /// Starting revocation durably disables the key and selects another active key.
    #[test]
    fn pending_revocation_cannot_remain_selected() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PublisherKeyStore::new(temp.path());
        let credentials = FakeCredentialStore::default();
        let first = store
            .create_key_with_store("laptop", &credentials, None)
            .unwrap();
        let second = store
            .create_key_with_store("desktop", &credentials, None)
            .unwrap();

        let pending = store.mark_revocation_pending(&first.id).unwrap();
        let inventory = store.load_inventory().unwrap().unwrap();
        assert_eq!(pending.state, LocalPublisherKeyState::RevocationPending);
        assert_eq!(inventory.active_key_id, Some(second.id));
        assert!(store.select_key(&first.id).is_err());
    }

    /// Cancelling a rejected sole-key revocation restores signing selection.
    #[test]
    fn cancelled_sole_key_revocation_restores_selection() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PublisherKeyStore::new(temp.path());
        let credentials = FakeCredentialStore::default();
        let key = store
            .create_key_with_store("only device", &credentials, None)
            .unwrap();

        store.mark_revocation_pending(&key.id).unwrap();
        assert_eq!(store.load_inventory().unwrap().unwrap().active_key_id, None);
        let restored = store.cancel_revocation(&key.id).unwrap();

        assert_eq!(restored.state, LocalPublisherKeyState::Active);
        assert_eq!(
            store.load_inventory().unwrap().unwrap().active_key_id,
            Some(key.id)
        );
    }

    /// Concurrent creators serialize their inventory updates without losing a key.
    #[test]
    fn concurrent_key_creation_preserves_both_records() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PublisherKeyStore::new(temp.path());
        let credentials = Arc::new(FakeCredentialStore::default());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();

        for label in ["laptop", "desktop"] {
            let worker_store = store.clone();
            let worker_credentials = Arc::clone(&credentials);
            let worker_barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                worker_barrier.wait();
                worker_store
                    .create_key_with_store(label, worker_credentials.as_ref(), None)
                    .unwrap()
            }));
        }
        barrier.wait();
        let created: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();

        let inventory = store.load_inventory().unwrap().unwrap();
        assert_eq!(inventory.keys.len(), 2);
        assert!(created
            .iter()
            .all(|metadata| inventory.keys.iter().any(|key| key.id == metadata.id)));
    }

    /// Recovery packages reject the wrong passphrase and preserve key identity.
    #[test]
    fn recovery_package_round_trip_preserves_seed() {
        let source_temp = tempfile::TempDir::new().unwrap();
        let source = PublisherKeyStore::new(source_temp.path());
        let source_credentials = FakeCredentialStore::default();
        let metadata = source
            .create_key_with_store("source", &source_credentials, None)
            .unwrap();
        let original = source
            .load_key_with_store(&metadata, &source_credentials, None)
            .unwrap();
        let package_path = source_temp.path().join("publisher-recovery.age");
        let recovery_passphrase = SecretString::new("recovery test passphrase".to_string());
        source
            .export_recovery_with_store(
                &metadata.id,
                &package_path,
                None,
                &recovery_passphrase,
                &source_credentials,
            )
            .unwrap();

        let wrong = SecretString::new("wrong passphrase".to_string());
        let target_temp = tempfile::TempDir::new().unwrap();
        let target = PublisherKeyStore::new(target_temp.path());
        let target_credentials = FakeCredentialStore::default();
        assert!(target
            .import_recovery_with_store(&package_path, &wrong, None, None, &target_credentials)
            .is_err());

        let imported = target
            .import_recovery_with_store(
                &package_path,
                &recovery_passphrase,
                None,
                Some("restored device"),
                &target_credentials,
            )
            .unwrap();
        let restored = target
            .load_key_with_store(&imported, &target_credentials, None)
            .unwrap();
        assert_eq!(imported.id, metadata.id);
        assert_eq!(imported.public_key, metadata.public_key);
        assert_eq!(imported.label, "restored device");
        assert_eq!(restored.to_bytes(), original.to_bytes());
    }

    /// Import cannot reverse a locally recorded revocation for the same public key.
    #[test]
    fn recovery_import_does_not_reactivate_revoked_key() {
        let source_temp = tempfile::TempDir::new().unwrap();
        let source = PublisherKeyStore::new(source_temp.path());
        let source_credentials = FakeCredentialStore::default();
        let metadata = source
            .create_key_with_store("source", &source_credentials, None)
            .unwrap();
        let package_path = source_temp.path().join("publisher-recovery.age");
        let recovery_passphrase = SecretString::new("recovery test passphrase".to_string());
        source
            .export_recovery_with_store(
                &metadata.id,
                &package_path,
                None,
                &recovery_passphrase,
                &source_credentials,
            )
            .unwrap();

        let target_temp = tempfile::TempDir::new().unwrap();
        let target = PublisherKeyStore::new(target_temp.path());
        let target_credentials = FakeCredentialStore::default();
        target
            .import_recovery_with_store(
                &package_path,
                &recovery_passphrase,
                None,
                None,
                &target_credentials,
            )
            .unwrap();
        target.mark_revoked(&metadata.id).unwrap();

        let error = target
            .import_recovery_with_store(
                &package_path,
                &recovery_passphrase,
                None,
                None,
                &target_credentials,
            )
            .unwrap_err();
        assert!(error.to_string().contains("cannot reactivate"));
        let inventory = target.load_inventory().unwrap().unwrap();
        assert_eq!(inventory.active_key_id, None);
        assert_eq!(inventory.keys[0].state, LocalPublisherKeyState::Revoked);
    }

    /// Inventory validation rejects a public-key identifier mismatch.
    #[test]
    fn inventory_rejects_tampered_key_identifier() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("publisher-keys.json");
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let inventory = PublisherKeyInventory {
            schema_version: INVENTORY_SCHEMA_VERSION,
            active_key_id: Some("pk_wrong".to_string()),
            keys: vec![PublisherKeyMetadata {
                id: "pk_wrong".to_string(),
                label: "tampered".to_string(),
                public_key: public_key_b64(&signing_key),
                state: LocalPublisherKeyState::Active,
                secret_backend: PublisherSecretBackend::Keychain,
                created_at: 1,
            }],
        };
        fs::write(&path, serde_json::to_vec(&inventory).unwrap()).unwrap();
        assert!(load_inventory_file(&path).is_err());
    }
}
