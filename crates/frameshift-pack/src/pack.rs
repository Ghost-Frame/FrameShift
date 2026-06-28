use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::path::{Path, PathBuf};

use crate::canonical::{collect_entries, hash_entries, PackEntry};
use crate::error::PackError;
use crate::manifest::PackManifest;

/// A loaded pack: its directory contents, canonical hash, and optional signature.
pub struct Pack {
    dir: PathBuf,
    #[allow(dead_code)]
    entries: Vec<PackEntry>,
    hash: [u8; 32],
    manifest: PackManifest,
    signature: Option<Signature>,
}

impl Pack {
    /// Load a pack from a directory on disk.
    pub fn from_dir(dir: &Path) -> Result<Self, PackError> {
        let entries = collect_entries(dir)?;
        let hash = hash_entries(&entries);

        let manifest_entry = entries
            .iter()
            .find(|e| e.canonical_path == "pack.toml")
            .expect("collect_entries guarantees pack.toml exists");
        let manifest_str =
            std::str::from_utf8(&manifest_entry.content).map_err(|_| PackError::MissingManifest)?;
        let manifest: PackManifest = toml::from_str(manifest_str)?;

        let signature = load_signature(dir)?;

        Ok(Self {
            dir: dir.to_path_buf(),
            entries,
            hash,
            manifest,
            signature,
        })
    }

    /// The deterministic canonical SHA-256 hash of this pack's contents.
    pub fn canonical_hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The canonical hash formatted as a hex string.
    pub fn canonical_hash_hex(&self) -> String {
        hex_encode(&self.hash)
    }

    /// The parsed pack manifest.
    pub fn manifest(&self) -> &PackManifest {
        &self.manifest
    }

    /// The directory this pack was loaded from.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Sign this pack's canonical hash with the given key. Writes signature.sig to the pack dir.
    pub fn sign(&mut self, key: &SigningKey) -> Result<Signature, PackError> {
        let sig = key.sign(&self.hash);
        let sig_path = self.dir.join("signature.sig");
        std::fs::write(&sig_path, sig.to_bytes()).map_err(|e| PackError::Io {
            path: sig_path,
            source: e,
        })?;
        self.signature = Some(sig);
        Ok(sig)
    }

    /// Verify this pack's signature against the given public key.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), PackError> {
        let sig = self.signature.ok_or(PackError::NoSignature)?;
        key.verify(&self.hash, &sig)
            .map_err(|_| PackError::SignatureInvalid)
    }

    /// Whether this pack has a signature loaded.
    pub fn has_signature(&self) -> bool {
        self.signature.is_some()
    }
}

/// Try to load signature.sig from a pack directory.
///
/// Returns `Ok(None)` when the file is absent (unsigned pack is valid).
/// Returns `Err(PackError::MalformedSignature)` when the file exists but is
/// not exactly 64 bytes -- a present-but-wrong-length file is never silently
/// treated as unsigned, because that would mask a corrupted or truncated sig.
/// Returns `Err(PackError::Io)` on any other I/O failure reading the file.
fn load_signature(dir: &Path) -> Result<Option<Signature>, PackError> {
    let sig_path = dir.join("signature.sig");
    let bytes = match std::fs::read(&sig_path) {
        Ok(b) => b,
        // File absent: pack is simply unsigned.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // Any other I/O error (permissions, device error, etc.) is hard.
        Err(e) => {
            return Err(PackError::Io {
                path: sig_path,
                source: e,
            })
        }
    };
    // File present: must be exactly 64 bytes; wrong length is an explicit error.
    let found = bytes.len();
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| PackError::MalformedSignature { found })?;
    Ok(Some(Signature::from_bytes(&arr)))
}

/// Encode a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use tempfile::TempDir;

    const MANIFEST: &[u8] = b"schema_version = 1\nname = \"test\"\nauthor_handle = \"t\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"0.1.0\"\n";

    fn write_pack(dir: &Path, files: &[(&str, &[u8])]) {
        for (path, content) in files {
            let full = dir.join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&full, content).unwrap();
        }
    }

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::from_bytes(&[1u8; 32]);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    #[test]
    fn load_and_hash() {
        let tmp = TempDir::new().unwrap();
        write_pack(tmp.path(), &[("pack.toml", MANIFEST), ("README.md", b"hi")]);

        let pack = Pack::from_dir(tmp.path()).unwrap();
        assert_eq!(pack.manifest().name, "test");
        assert_eq!(pack.canonical_hash_hex().len(), 64);
        assert!(!pack.has_signature());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let tmp = TempDir::new().unwrap();
        write_pack(tmp.path(), &[("pack.toml", MANIFEST)]);

        let (signing, verifying) = test_keypair();
        let mut pack = Pack::from_dir(tmp.path()).unwrap();
        pack.sign(&signing).unwrap();

        assert!(pack.has_signature());
        assert!(pack.verify(&verifying).is_ok());
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let tmp = TempDir::new().unwrap();
        write_pack(tmp.path(), &[("pack.toml", MANIFEST)]);

        let (signing, _) = test_keypair();
        let wrong_verifying = SigningKey::from_bytes(&[2u8; 32]).verifying_key();

        let mut pack = Pack::from_dir(tmp.path()).unwrap();
        pack.sign(&signing).unwrap();

        assert!(matches!(
            pack.verify(&wrong_verifying),
            Err(PackError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampered_content_fails_verification() {
        let tmp = TempDir::new().unwrap();
        write_pack(
            tmp.path(),
            &[("pack.toml", MANIFEST), ("README.md", b"original")],
        );

        let (signing, verifying) = test_keypair();
        let mut pack = Pack::from_dir(tmp.path()).unwrap();
        pack.sign(&signing).unwrap();

        // Tamper with content after signing
        fs::write(tmp.path().join("README.md"), b"tampered").unwrap();

        // Reload the pack (which re-hashes) and check the old signature
        let tampered = Pack::from_dir(tmp.path()).unwrap();
        assert!(matches!(
            tampered.verify(&verifying),
            Err(PackError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let tmp = TempDir::new().unwrap();
        write_pack(tmp.path(), &[("pack.toml", MANIFEST)]);

        let (signing, verifying) = test_keypair();
        let mut pack = Pack::from_dir(tmp.path()).unwrap();
        pack.sign(&signing).unwrap();

        // Corrupt the signature file
        let sig_path = tmp.path().join("signature.sig");
        let mut sig_bytes = fs::read(&sig_path).unwrap();
        sig_bytes[0] ^= 0xff;
        fs::write(&sig_path, &sig_bytes).unwrap();

        let reloaded = Pack::from_dir(tmp.path()).unwrap();
        assert!(reloaded.verify(&verifying).is_err());
    }

    #[test]
    fn malformed_signature_wrong_length_is_error() {
        // A present-but-truncated signature.sig must produce MalformedSignature,
        // not silently become an unsigned pack.
        let tmp = TempDir::new().unwrap();
        write_pack(tmp.path(), &[("pack.toml", MANIFEST)]);

        let sig_path = tmp.path().join("signature.sig");
        // Write 32 bytes -- half the required 64.
        fs::write(&sig_path, vec![0xffu8; 32]).unwrap();

        // Match rather than `unwrap_err()` so the test does not require `Pack: Debug`.
        let err = match Pack::from_dir(tmp.path()) {
            Ok(_) => panic!("expected MalformedSignature error, got an Ok pack"),
            Err(e) => e,
        };
        assert!(
            matches!(err, PackError::MalformedSignature { found: 32 }),
            "expected MalformedSignature{{found:32}}, got {err:?}"
        );
    }

    #[test]
    fn no_signature_returns_error() {
        let tmp = TempDir::new().unwrap();
        write_pack(tmp.path(), &[("pack.toml", MANIFEST)]);

        let (_, verifying) = test_keypair();
        let pack = Pack::from_dir(tmp.path()).unwrap();
        assert!(matches!(
            pack.verify(&verifying),
            Err(PackError::NoSignature)
        ));
    }

    #[test]
    fn signature_persisted_to_disk() {
        let tmp = TempDir::new().unwrap();
        write_pack(tmp.path(), &[("pack.toml", MANIFEST)]);

        let (signing, verifying) = test_keypair();
        let mut pack = Pack::from_dir(tmp.path()).unwrap();
        pack.sign(&signing).unwrap();

        // Reload from disk -- signature should be found
        let reloaded = Pack::from_dir(tmp.path()).unwrap();
        assert!(reloaded.has_signature());
        assert!(reloaded.verify(&verifying).is_ok());
    }
}
