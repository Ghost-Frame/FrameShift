//! # frameshift-vault-local
//!
//! A [`VaultBackend`] implementation that stores vault data in a single
//! age-encrypted file on the local filesystem.
//!
//! ## Encryption
//!
//! v1 supports scrypt passphrase recipients only.  The public surface is
//! designed so that future variants (FIDO2, TPM, PIV plugin) can be added as
//! new [`Recipients`] variants without breaking changes.
//!
//! ## Atomic writes
//!
//! [`LocalAgeBackend::save`] always writes to a sibling temporary file and
//! renames it into place.  A crash mid-write leaves the original vault intact.

use std::{
    fs,
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};

use frameshift_vault::{VaultBackend, VaultData, VaultError};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Recipients
// ---------------------------------------------------------------------------

/// The recipient configuration used to encrypt and decrypt a vault file.
///
/// Each variant represents a distinct key management strategy.  The enum is
/// `#[non_exhaustive]` so that future variants (FIDO2, TPM, PIV plugin
/// recipients) can be added without requiring a version bump.
#[derive(Clone)]
#[non_exhaustive]
pub enum Recipients {
    /// Scrypt-based passphrase encryption -- the age default for human-provided
    /// passphrases.  Anyone who knows the passphrase can open the vault.
    Passphrase(SecretString),
}

// ---------------------------------------------------------------------------
// LocalAgeBackend
// ---------------------------------------------------------------------------

/// A [`VaultBackend`] that persists vault data as a single age-encrypted file.
///
/// Construct with [`LocalAgeBackend::new`], then use the [`VaultBackend`] trait
/// methods to read and write vault contents.
pub struct LocalAgeBackend {
    /// The filesystem path of the vault file.
    path: PathBuf,
    /// The recipient configuration used for encryption and decryption.
    recipients: Recipients,
}

impl LocalAgeBackend {
    /// Creates a new backend that will store the vault at `path`, encrypted
    /// using `recipients`.
    ///
    /// This call is infallible; it does not touch the filesystem.
    pub fn new(path: PathBuf, recipients: Recipients) -> Self {
        Self { path, recipients }
    }

    /// Returns the filesystem path of the vault file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ---------------------------------------------------------------------------
// VaultBackend impl
// ---------------------------------------------------------------------------

impl VaultBackend for LocalAgeBackend {
    /// Opens the vault file, decrypts it, deserializes the TOML contents, and
    /// returns the result as a [`VaultData`].
    ///
    /// # Errors
    ///
    /// - [`VaultError::Io`] when the file cannot be opened (including
    ///   `NotFound`).
    /// - [`VaultError::Crypto`] when decryption fails (wrong passphrase,
    ///   corrupt ciphertext, etc.).
    /// - [`VaultError::Parse`] when the decrypted bytes are not valid TOML or
    ///   do not match the schema.
    fn open(&self) -> Result<VaultData, VaultError> {
        // Open the file first so a NotFound produces VaultError::Io.
        let file = fs::File::open(&self.path).map_err(|source| VaultError::Io {
            path: self.path.clone(),
            source,
        })?;

        // Decrypt into an in-memory buffer.  The plaintext lives in a
        // Zeroizing<String> so it is wiped on drop -- vault contents include
        // identity material that should not survive to swap.
        let plaintext =
            decrypt_age(BufReader::new(file), &self.recipients).map_err(VaultError::Crypto)?;

        // Deserialize TOML from the protected buffer.
        let data: VaultData = toml::from_str(plaintext.as_str())?;
        Ok(data)
    }

    /// Serializes `data` to TOML, encrypts it, and atomically replaces the
    /// vault file.
    ///
    /// Parent directories are created if they do not exist.
    ///
    /// # Errors
    ///
    /// - [`VaultError::Io`] for filesystem errors (directory creation, temp
    ///   file, rename).
    /// - [`VaultError::Serialize`] if `data` cannot be converted to TOML.
    /// - [`VaultError::Crypto`] if encryption fails.
    fn save(&self, data: &VaultData) -> Result<(), VaultError> {
        // Serialize to TOML first so we fail fast before touching the fs.
        // The serialized bytes contain vault plaintext and are wrapped in
        // Zeroizing so they are wiped from memory on drop.
        let toml_bytes: Zeroizing<Vec<u8>> =
            Zeroizing::new(toml::to_string_pretty(data)?.into_bytes());

        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|source| VaultError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        // Determine the parent directory for the temp file (must be on the
        // same filesystem as the target to allow an atomic rename).
        let parent_dir = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        // Write encrypted content to a named temp file in the same directory.
        let tmp =
            tempfile::NamedTempFile::new_in(&parent_dir).map_err(|source| VaultError::Io {
                path: parent_dir.clone(),
                source,
            })?;

        // Encrypt into the temp file.  tempfile::NamedTempFile already creates
        // the file with 0o600 on Unix, so there is no window with default
        // permissions.
        {
            let mut tmp_file = tmp.as_file();
            encrypt_age(&toml_bytes, &mut tmp_file, &self.recipients)
                .map_err(VaultError::Crypto)?;
            tmp_file.flush().map_err(|source| VaultError::Io {
                path: parent_dir.clone(),
                source,
            })?;
        }

        // Set permissions on Unix as defense in depth (tempfile already does
        // this, but explicit is better than implicit for security-sensitive
        // paths).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            tmp.as_file()
                .set_permissions(perms)
                .map_err(|source| VaultError::Io {
                    path: parent_dir.clone(),
                    source,
                })?;
        }

        // Durability: fsync the file contents to disk before renaming so a
        // crash between rename and the writeback cannot leave a zero-length
        // vault on certain filesystems.
        tmp.as_file().sync_all().map_err(|source| VaultError::Io {
            path: parent_dir.clone(),
            source,
        })?;

        // Atomically rename temp file over the target path.
        tmp.persist(&self.path).map_err(|e| VaultError::Io {
            path: self.path.clone(),
            source: e.error,
        })?;

        // Durability: fsync the parent directory so the rename is itself
        // durable on crash.  Best-effort on Windows (no directory fsync).
        #[cfg(unix)]
        {
            if let Ok(dir) = fs::File::open(&parent_dir) {
                let _ = dir.sync_all();
            }
        }

        Ok(())
    }

    /// Returns `true` if the vault file exists at [`LocalAgeBackend::path`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Io`] if the filesystem check itself fails (e.g.,
    /// permission denied accessing the parent directory).  A missing file
    /// returns `Ok(false)`, not an error.
    fn exists(&self) -> Result<bool, VaultError> {
        match fs::metadata(&self.path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(VaultError::Io {
                path: self.path.clone(),
                source,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Encrypts `plaintext` into `writer` using the provided [`Recipients`].
///
/// Returns a boxed error on failure so the caller can wrap it in
/// [`VaultError::Crypto`].
fn encrypt_age<W: Write>(
    plaintext: &[u8],
    writer: &mut W,
    recipients: &Recipients,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match recipients {
        Recipients::Passphrase(passphrase) => {
            let encryptor = age::Encryptor::with_user_passphrase(
                // Reconstruct a SecretString so we pass the correct type to age.
                age::secrecy::SecretString::new(passphrase.expose_secret().to_owned()),
            );
            let mut age_writer = encryptor.wrap_output(writer)?;
            age_writer.write_all(plaintext)?;
            age_writer.finish()?;
            Ok(())
        }
    }
}

/// Decrypts the age-encrypted stream in `reader` using the provided
/// [`Recipients`].
///
/// Returns the plaintext as a UTF-8 string.  Returns a boxed error on any
/// failure so the caller can wrap it in [`VaultError::Crypto`].
fn decrypt_age<R: Read>(
    reader: R,
    recipients: &Recipients,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error + Send + Sync>> {
    let decryptor = age::Decryptor::new(reader)?;
    match (decryptor, recipients) {
        (age::Decryptor::Passphrase(d), Recipients::Passphrase(passphrase)) => {
            // Plaintext is wrapped in Zeroizing so it is wiped on drop.
            let mut plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
            let mut decrypted_reader = d.decrypt(
                &age::secrecy::SecretString::new(passphrase.expose_secret().to_owned()),
                None,
            )?;
            decrypted_reader.read_to_end(&mut plaintext)?;
            // String::from_utf8 takes ownership of the Vec.  We zero the bytes
            // via the Zeroizing<Vec<u8>> first, then construct the String from
            // a copy that lives in a Zeroizing<String>.
            let text = std::str::from_utf8(&plaintext)?.to_owned();
            Ok(Zeroizing::new(text))
        }
        // The file was encrypted with a different recipient type than what we
        // have configured -- treat it as a crypto error.
        (_, _) => {
            Err("recipient type mismatch: vault was not encrypted with the expected method".into())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use frameshift_vault::{Auth, Identity, Preferences, RuntimeMode, VaultData};
    use std::collections::BTreeMap;

    /// Constructs a minimal valid [`VaultData`] for use in tests.
    fn sample_vault() -> VaultData {
        VaultData {
            schema_version: 1,
            identity: Identity {
                keypair_pub: "age1test000".to_owned(),
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

    /// Builds a passphrase-based [`Recipients`] for tests.
    fn test_recipients(pass: &str) -> Recipients {
        Recipients::Passphrase(SecretString::new(pass.to_owned()))
    }

    /// Roundtrip: save then open recovers the same [`VaultData`].
    #[test]
    fn roundtrip_save_and_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.age");
        let backend = LocalAgeBackend::new(path, test_recipients("hunter2"));

        let original = sample_vault();
        backend.save(&original).unwrap();
        let recovered = backend.open().unwrap();
        assert_eq!(original, recovered);
    }

    /// Wrong passphrase on open returns [`VaultError::Crypto`].
    #[test]
    fn wrong_passphrase_returns_crypto_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.age");

        // Save with one passphrase.
        let save_backend = LocalAgeBackend::new(path.clone(), test_recipients("correct_horse"));
        save_backend.save(&sample_vault()).unwrap();

        // Open with a different passphrase.
        let open_backend = LocalAgeBackend::new(path, test_recipients("battery_staple"));
        let err = open_backend.open().unwrap_err();
        assert!(
            matches!(err, VaultError::Crypto(_)),
            "expected Crypto, got {err:?}"
        );
    }

    /// Missing vault file on open returns [`VaultError::Io`] with
    /// `kind() == NotFound`.
    #[test]
    fn missing_file_returns_io_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.age");
        let backend = LocalAgeBackend::new(path.clone(), test_recipients("pass"));

        let err = backend.open().unwrap_err();
        match err {
            VaultError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }

    /// [`VaultBackend::exists`] returns `false` before save and `true` after.
    #[test]
    fn exists_reports_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.age");
        let backend = LocalAgeBackend::new(path, test_recipients("abc"));

        assert!(!backend.exists().unwrap());
        backend.save(&sample_vault()).unwrap();
        assert!(backend.exists().unwrap());
    }

    /// Atomic-save: a save that cannot complete (parent dir is read-only) does
    /// not corrupt a previously written vault.
    ///
    /// This test is skipped on non-Unix targets where chmod is not available.
    #[test]
    #[cfg(unix)]
    fn atomic_save_does_not_corrupt_existing_vault() {
        use std::os::unix::fs::PermissionsExt;

        let outer_dir = tempfile::tempdir().unwrap();
        let vault_dir = outer_dir.path().join("vaultdir");
        fs::create_dir_all(&vault_dir).unwrap();

        let path = vault_dir.join("vault.age");
        let backend = LocalAgeBackend::new(path.clone(), test_recipients("safe_pass"));

        // Write a known-good vault first.
        let original = sample_vault();
        backend.save(&original).unwrap();

        // Make the vault directory read-only so the temp file cannot be created.
        fs::set_permissions(&vault_dir, fs::Permissions::from_mode(0o555)).unwrap();

        // Attempt a save -- it must fail.
        let mut modified = original.clone();
        modified.identity.handle = "corrupted".to_owned();
        let save_result = backend.save(&modified);

        // Restore permissions so tempdir cleanup works.
        fs::set_permissions(&vault_dir, fs::Permissions::from_mode(0o755)).unwrap();

        // The save must have failed.
        assert!(
            save_result.is_err(),
            "expected save to fail on read-only directory"
        );

        // The original vault must still be intact.
        let recovered = backend.open().unwrap();
        assert_eq!(
            recovered.identity.handle, "tester",
            "original vault must be intact after failed save"
        );
    }
}
