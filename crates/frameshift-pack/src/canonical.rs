use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use unicode_normalization::UnicodeNormalization;

use crate::error::PackError;

const MAX_TOTAL_SIZE: u64 = 5 * 1024 * 1024;
const MAX_FILE_COUNT: usize = 50;
const MAX_FILE_SIZE: u64 = 1024 * 1024;
const SIGNATURE_FILENAME: &str = "signature.sig";

/// Collect pack entries from a directory, normalize paths, enforce limits, return sorted entries.
pub(crate) fn collect_entries(dir: &Path) -> Result<Vec<PackEntry>, PackError> {
    let mut entries = Vec::new();
    let mut seen_paths = BTreeSet::new();
    collect_recursive(dir, dir, &mut entries, &mut seen_paths)?;

    if entries.is_empty() {
        return Err(PackError::MissingManifest);
    }

    if entries.len() > MAX_FILE_COUNT {
        return Err(PackError::FileCountExceeded {
            count: entries.len(),
            limit: MAX_FILE_COUNT,
        });
    }

    let total_size: u64 = entries.iter().map(|e| e.content.len() as u64).sum();
    if total_size > MAX_TOTAL_SIZE {
        return Err(PackError::TotalSizeExceeded {
            size: total_size,
            limit: MAX_TOTAL_SIZE,
        });
    }

    let has_manifest = entries.iter().any(|e| e.canonical_path == "pack.toml");
    if !has_manifest {
        return Err(PackError::MissingManifest);
    }

    entries.sort_by(|a, b| a.canonical_path.as_bytes().cmp(b.canonical_path.as_bytes()));
    Ok(entries)
}

/// Compute the canonical SHA-256 hash of a pack directory.
///
/// Walks the directory, normalizes paths (NFC unicode, forward slashes),
/// sorts entries in byte-lexicographic order, and hashes each entry as
/// `path\0length\0bytes\0`. The `signature.sig` file is excluded.
pub fn canonical_hash(dir: &Path) -> Result<[u8; 32], PackError> {
    let entries = collect_entries(dir)?;
    Ok(hash_entries(&entries))
}

/// Hash a pre-collected, sorted list of entries.
pub(crate) fn hash_entries(entries: &[PackEntry]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(entry.canonical_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.content.len().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(&entry.content);
        hasher.update(b"\0");
    }
    hasher.finalize().into()
}

/// Recursively walk `current` under `base`, collecting normalized file entries.
fn collect_recursive(
    base: &Path,
    current: &Path,
    entries: &mut Vec<PackEntry>,
    seen: &mut BTreeSet<String>,
) -> Result<(), PackError> {
    let read_dir = std::fs::read_dir(current).map_err(|e| PackError::Io {
        path: current.to_path_buf(),
        source: e,
    })?;

    for dir_entry in read_dir {
        let dir_entry = dir_entry.map_err(|e| PackError::Io {
            path: current.to_path_buf(),
            source: e,
        })?;
        let path = dir_entry.path();
        let file_type = dir_entry.file_type().map_err(|e| PackError::Io {
            path: path.clone(),
            source: e,
        })?;

        if file_type.is_dir() {
            collect_recursive(base, &path, entries, seen)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let rel = path
            .strip_prefix(base)
            .expect("path is under base")
            .to_str()
            .ok_or_else(|| PackError::NonUtf8Path(path.clone()))?;

        let canonical = normalize_path(rel);

        if canonical == SIGNATURE_FILENAME {
            continue;
        }

        if !seen.insert(canonical.clone()) {
            return Err(PackError::DuplicatePath(canonical));
        }

        let content = std::fs::read(&path).map_err(|e| PackError::Io {
            path: path.clone(),
            source: e,
        })?;

        if content.len() as u64 > MAX_FILE_SIZE {
            return Err(PackError::FileSizeExceeded {
                path: canonical,
                size: content.len() as u64,
                limit: MAX_FILE_SIZE,
            });
        }

        entries.push(PackEntry {
            canonical_path: canonical,
            content,
        });
    }

    Ok(())
}

/// Normalize a relative path: NFC unicode normalization, forward slashes, no leading `./`.
fn normalize_path(path: &str) -> String {
    let normalized: String = path.nfc().collect();
    let forward_slashed = normalized.replace('\\', "/");
    forward_slashed
        .strip_prefix("./")
        .unwrap_or(&forward_slashed)
        .to_string()
}

/// A single file entry in a pack: its normalized path and raw content bytes.
#[derive(Debug, Clone)]
pub(crate) struct PackEntry {
    pub canonical_path: String,
    pub content: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_pack(dir: &Path, files: &[(&str, &[u8])]) {
        for (path, content) in files {
            let full = dir.join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&full, content).unwrap();
        }
    }

    #[test]
    fn normalize_backslashes() {
        assert_eq!(normalize_path("overlays\\foo.md"), "overlays/foo.md");
    }

    #[test]
    fn normalize_strips_dot_slash() {
        assert_eq!(normalize_path("./pack.toml"), "pack.toml");
    }

    #[test]
    fn normalize_nfc() {
        // e + combining acute vs precomposed e-acute
        let decomposed = "e\u{0301}";
        let expected = "\u{00e9}";
        assert_eq!(normalize_path(decomposed), expected);
    }

    #[test]
    fn missing_manifest_errors() {
        let tmp = TempDir::new().unwrap();
        write_pack(tmp.path(), &[("README.md", b"hello")]);
        let err = canonical_hash(tmp.path()).unwrap_err();
        assert!(matches!(err, PackError::MissingManifest));
    }

    #[test]
    fn empty_dir_errors() {
        let tmp = TempDir::new().unwrap();
        let err = canonical_hash(tmp.path()).unwrap_err();
        assert!(matches!(err, PackError::MissingManifest));
    }

    #[test]
    fn signature_sig_excluded() {
        let tmp = TempDir::new().unwrap();
        let manifest = b"schema_version = 1\nname = \"test\"\nauthor_handle = \"t\"\nauthor_pubkey = \"k\"\nversion = \"0.1.0\"\n";
        write_pack(
            tmp.path(),
            &[("pack.toml", manifest), ("signature.sig", b"fakesig")],
        );
        let hash_with_sig = canonical_hash(tmp.path()).unwrap();

        let tmp2 = TempDir::new().unwrap();
        write_pack(tmp2.path(), &[("pack.toml", manifest)]);
        let hash_without_sig = canonical_hash(tmp2.path()).unwrap();

        assert_eq!(hash_with_sig, hash_without_sig);
    }

    #[test]
    fn deterministic_regardless_of_file_creation_order() {
        let manifest = b"schema_version = 1\nname = \"test\"\nauthor_handle = \"t\"\nauthor_pubkey = \"k\"\nversion = \"0.1.0\"\n";

        let tmp1 = TempDir::new().unwrap();
        write_pack(
            tmp1.path(),
            &[
                ("pack.toml", manifest),
                ("README.md", b"readme"),
                ("vars.toml", b"x = 1"),
            ],
        );

        let tmp2 = TempDir::new().unwrap();
        write_pack(
            tmp2.path(),
            &[
                ("vars.toml", b"x = 1"),
                ("pack.toml", manifest),
                ("README.md", b"readme"),
            ],
        );

        assert_eq!(
            canonical_hash(tmp1.path()).unwrap(),
            canonical_hash(tmp2.path()).unwrap()
        );
    }

    #[test]
    fn content_sensitivity() {
        let manifest = b"schema_version = 1\nname = \"test\"\nauthor_handle = \"t\"\nauthor_pubkey = \"k\"\nversion = \"0.1.0\"\n";

        let tmp1 = TempDir::new().unwrap();
        write_pack(
            tmp1.path(),
            &[("pack.toml", manifest), ("README.md", b"hello")],
        );

        let tmp2 = TempDir::new().unwrap();
        write_pack(
            tmp2.path(),
            &[("pack.toml", manifest), ("README.md", b"hellx")],
        );

        assert_ne!(
            canonical_hash(tmp1.path()).unwrap(),
            canonical_hash(tmp2.path()).unwrap()
        );
    }

    #[test]
    fn zero_byte_file_hashes_differently_from_absent() {
        let manifest = b"schema_version = 1\nname = \"test\"\nauthor_handle = \"t\"\nauthor_pubkey = \"k\"\nversion = \"0.1.0\"\n";

        let tmp1 = TempDir::new().unwrap();
        write_pack(tmp1.path(), &[("pack.toml", manifest), ("empty.md", b"")]);

        let tmp2 = TempDir::new().unwrap();
        write_pack(tmp2.path(), &[("pack.toml", manifest)]);

        assert_ne!(
            canonical_hash(tmp1.path()).unwrap(),
            canonical_hash(tmp2.path()).unwrap()
        );
    }

    #[test]
    fn nested_overlays() {
        let manifest = b"schema_version = 1\nname = \"test\"\nauthor_handle = \"t\"\nauthor_pubkey = \"k\"\nversion = \"0.1.0\"\n";

        let tmp = TempDir::new().unwrap();
        write_pack(
            tmp.path(),
            &[
                ("pack.toml", manifest),
                ("overlays/persona.identity_prelude.md", b"prelude"),
                ("overlays/global.behavioral_mandates.md", b"mandates"),
            ],
        );

        let hash = canonical_hash(tmp.path()).unwrap();
        // Just confirm it succeeds and is deterministic
        assert_eq!(hash, canonical_hash(tmp.path()).unwrap());
    }

    #[test]
    fn file_size_limit_enforced() {
        let tmp = TempDir::new().unwrap();
        let manifest = b"schema_version = 1\nname = \"test\"\nauthor_handle = \"t\"\nauthor_pubkey = \"k\"\nversion = \"0.1.0\"\n";
        let big = vec![0u8; (MAX_FILE_SIZE + 1) as usize];
        write_pack(tmp.path(), &[("pack.toml", manifest), ("big.bin", &big)]);

        let err = canonical_hash(tmp.path()).unwrap_err();
        assert!(matches!(err, PackError::FileSizeExceeded { .. }));
    }
}

/// Hardcoded test vectors for cross-implementation verification.
#[cfg(test)]
mod test_vectors {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_pack(dir: &Path, files: &[(&str, &[u8])]) {
        for (path, content) in files {
            let full = dir.join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&full, content).unwrap();
        }
    }

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const VECTOR_MANIFEST: &[u8] = b"schema_version = 1\nname = \"test-vector\"\nauthor_handle = \"test\"\nauthor_pubkey = \"age1testkey\"\nversion = \"1.0.0\"\n";
    const VECTOR_README: &[u8] = b"# Test Vector Pack\n\nA test pack for verification.\n";
    const VECTOR_VARS: &[u8] = b"favorite_motto = \"test all the things\"\n";
    const VECTOR_OVERLAY: &[u8] = b"You are a careful guardian of system boundaries.\n";

    #[test]
    fn vector_1_minimal_pack() {
        let tmp = TempDir::new().unwrap();
        write_pack(tmp.path(), &[("pack.toml", VECTOR_MANIFEST)]);
        let hash = canonical_hash(tmp.path()).unwrap();
        assert_eq!(
            hex(&hash),
            "7cb8821acda2de416d752b6a3a6cd46bd32d4b581aa2db8b3fe5700928903b74",
        );
    }

    #[test]
    fn vector_2_with_readme_and_vars() {
        let tmp = TempDir::new().unwrap();
        write_pack(
            tmp.path(),
            &[
                ("pack.toml", VECTOR_MANIFEST),
                ("README.md", VECTOR_README),
                ("vars.toml", VECTOR_VARS),
            ],
        );
        let hash = canonical_hash(tmp.path()).unwrap();
        assert_eq!(
            hex(&hash),
            "12b60e73aa8f38759d24698dff8520963bc6fa0c54259c38d8dbfdc2dd7f3dc1",
        );
    }

    #[test]
    fn vector_3_with_overlays() {
        let tmp = TempDir::new().unwrap();
        write_pack(
            tmp.path(),
            &[
                ("pack.toml", VECTOR_MANIFEST),
                ("README.md", VECTOR_README),
                ("vars.toml", VECTOR_VARS),
                ("overlays/persona.identity_prelude.md", VECTOR_OVERLAY),
            ],
        );
        let hash = canonical_hash(tmp.path()).unwrap();
        assert_eq!(
            hex(&hash),
            "493df759d4604a2c058320f0ba4ef420f0bd3f74dbb91b9a58dfe59f2d233d60",
        );
    }
}
