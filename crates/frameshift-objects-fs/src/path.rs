//! Hash-to-path resolution for the content-addressed filesystem layout.
//!
//! Objects are stored at `{root}/{aa}/{bb}/{hex}` where:
//!
//! - `aa` -- the first byte of the hash, encoded as two lowercase hex digits.
//! - `bb` -- the second byte of the hash, encoded as two lowercase hex digits.
//! - `hex` -- the full 64-character lowercase hex digest (the complete hash).
//!
//! This two-level sharding limits the number of entries per directory to at most
//! 256 for the root, 256 for each first-level shard, and unbounded at the leaf
//! level (bounded in practice by the 256 possible second-byte values combined
//! with the collision resistance of SHA-256).
//!
//! # Invariants
//!
//! - The leaf filename is always exactly 64 lowercase hex characters.
//! - Shard names are always exactly 2 lowercase hex characters.
//! - The path components contain only the characters `[0-9a-f]` and the OS
//!   path separator.

use std::path::{Path, PathBuf};

use frameshift_objects::ObjectHash;

/// Compute the full on-disk path for an object with the given hash.
///
/// The returned path is `{root}/{aa}/{bb}/{hex}` where `aa` and `bb` are the
/// two-hex-digit encodings of the first and second bytes of the hash, and `hex`
/// is the full 64-character lowercase hex digest.
///
/// # Arguments
///
/// - `root` -- the store's root directory (arbitrary depth, need not exist yet).
/// - `hash` -- the 32-byte SHA-256 content-addressing hash of the object.
pub fn object_path(root: &Path, hash: &ObjectHash) -> PathBuf {
    let bytes = hash.as_bytes();
    let aa = format!("{:02x}", bytes[0]);
    let bb = format!("{:02x}", bytes[1]);
    let hex = hash.to_hex();
    root.join(aa).join(bb).join(hex)
}

/// Compute the shard directory path for the first byte of a hash.
///
/// Returns `{root}/{aa}` where `aa` is the two-hex-digit encoding of `first_byte`.
/// Used during prefix-based listing to narrow the walk to a single shard.
pub fn shard_aa(root: &Path, first_byte: u8) -> PathBuf {
    root.join(format!("{:02x}", first_byte))
}

/// Compute the shard directory path for the first two bytes of a hash.
///
/// Returns `{root}/{aa}/{bb}` where `aa` and `bb` are the two-hex-digit
/// encodings of the first and second bytes. Used during prefix-based listing
/// to narrow the walk to a single sub-shard.
pub fn shard_aabb(root: &Path, first_byte: u8, second_byte: u8) -> PathBuf {
    root.join(format!("{:02x}", first_byte))
        .join(format!("{:02x}", second_byte))
}

/// Attempt to parse an [`ObjectHash`] from a filename stem (64-char hex string).
///
/// Returns `None` if the name is not exactly 64 characters or contains
/// non-hex characters. Used when walking the on-disk shard tree to recover
/// hashes from filenames.
pub fn hash_from_filename(name: &str) -> Option<ObjectHash> {
    ObjectHash::from_hex(name).ok()
}

#[cfg(test)]
/// Unit tests for path resolution functions.
mod tests {
    use super::*;
    use std::path::Path;

    /// `object_path` produces the expected `{root}/{aa}/{bb}/{hex}` structure.
    #[test]
    fn object_path_structure() {
        let hash = ObjectHash::of(b"test data");
        let root = Path::new("/store");
        let path = object_path(root, &hash);
        let hex = hash.to_hex();
        let expected = format!("/store/{}/{}/{}", &hex[..2], &hex[2..4], hex);
        assert_eq!(path.to_str().unwrap(), expected);
    }

    /// `shard_aa` produces a two-hex-char directory name in lowercase.
    #[test]
    fn shard_aa_is_two_hex_chars() {
        let root = Path::new("/r");
        let p = shard_aa(root, 0xAB);
        assert_eq!(p.to_str().unwrap(), "/r/ab");
    }

    /// `shard_aabb` produces a two-level path with two-hex-char names.
    #[test]
    fn shard_aabb_is_four_hex_chars() {
        let root = Path::new("/r");
        let p = shard_aabb(root, 0xAB, 0xCD);
        assert_eq!(p.to_str().unwrap(), "/r/ab/cd");
    }

    /// `hash_from_filename` correctly round-trips a known hash.
    #[test]
    fn hash_from_filename_roundtrip() {
        let hash = ObjectHash::of(b"round trip");
        let name = hash.to_hex();
        let recovered = hash_from_filename(&name).unwrap();
        assert_eq!(hash, recovered);
    }

    /// `hash_from_filename` returns `None` for invalid inputs.
    #[test]
    fn hash_from_filename_invalid_returns_none() {
        assert!(hash_from_filename("not-a-hash").is_none());
        assert!(hash_from_filename("").is_none());
    }
}
