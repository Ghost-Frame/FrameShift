/// A 32-byte SHA-256 content-addressing hash for a pack object.
///
/// `ObjectHash` is the canonical identifier used across the frameshift workspace
/// to address pack archives in content-addressed stores. Every layer -- packing,
/// signing, catalog, and object stores -- agrees on this type as the single
/// source of truth for addressing.
///
/// # Invariants
///
/// - Always exactly 32 bytes (SHA-256 output length).
/// - Immutable once constructed; derive-based [`Clone`] and [`Copy`] are intentional.
/// - Implements [`std::fmt::Display`] as lowercase hex for human-readable output
///   and logging.
/// - Implements [`std::fmt::Debug`] with the same hex representation.
///
/// # Construction
///
/// The canonical constructor is [`ObjectHash::from_bytes`], which accepts raw
/// SHA-256 output. Use [`ObjectHash::of`] to hash an arbitrary byte slice in
/// place.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectHash([u8; 32]);

impl ObjectHash {
    /// Construct an [`ObjectHash`] from raw 32-byte SHA-256 output.
    ///
    /// The caller is responsible for ensuring the bytes are a valid SHA-256
    /// digest. No re-hashing is performed.
    #[inline]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compute the SHA-256 hash of the given byte slice and return it as an [`ObjectHash`].
    ///
    /// This is the canonical way to derive the hash for a blob that will be
    /// passed to [`crate::PackStore::put`] or compared against a stored hash.
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        Self(digest)
    }

    /// Return the underlying raw bytes of this hash.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return a lowercase hex-encoded string representation of this hash.
    ///
    /// Equivalent to `format!("{self}")`.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse an [`ObjectHash`] from a 64-character lowercase hex string.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectHashParseError::InvalidLength`] if the string is not
    /// exactly 64 characters, or [`ObjectHashParseError::InvalidHex`] if any
    /// character is not a valid hex digit.
    pub fn from_hex(s: &str) -> Result<Self, ObjectHashParseError> {
        if s.len() != 64 {
            return Err(ObjectHashParseError::InvalidLength(s.len()));
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(chunk[0]).ok_or(ObjectHashParseError::InvalidHex)?;
            let lo = hex_digit(chunk[1]).ok_or(ObjectHashParseError::InvalidHex)?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

/// Decode a single ASCII hex character to its nibble value.
///
/// Returns `None` if the byte is not a valid hex digit.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Errors that can occur when parsing an [`ObjectHash`] from a hex string.
///
/// # Variants
///
/// - [`InvalidLength`](ObjectHashParseError::InvalidLength): the input did not
///   have exactly 64 hex characters.
/// - [`InvalidHex`](ObjectHashParseError::InvalidHex): the input contained a
///   character that is not a valid hex digit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjectHashParseError {
    /// The hex string was not exactly 64 characters (32 bytes * 2 hex digits).
    ///
    /// The contained value is the actual length supplied.
    #[error("object hash must be 64 hex characters, got {0}")]
    InvalidLength(usize),

    /// The hex string contained a character that is not a valid hex digit.
    #[error("object hash contains invalid hex character")]
    InvalidHex,
}

impl std::fmt::Display for ObjectHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::fmt::Debug for ObjectHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ObjectHash({})", self.to_hex())
    }
}

impl AsRef<[u8]> for ObjectHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for ObjectHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<ObjectHash> for [u8; 32] {
    fn from(h: ObjectHash) -> Self {
        h.0
    }
}

impl std::str::FromStr for ObjectHash {
    type Err = ObjectHashParseError;

    /// Parse a 64-character lowercase hex string into an [`ObjectHash`].
    ///
    /// Equivalent to [`ObjectHash::from_hex`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// Serialize the hash as a lowercase hex string.
///
/// JSON / TOML / YAML callers see a 64-character string, not a byte array.
impl serde::Serialize for ObjectHash {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_hex())
    }
}

/// Deserialize the hash from a 64-character lowercase hex string.
///
/// # Errors
///
/// Returns the deserializer's error type if the input is not a string of the
/// correct length or contains non-hex characters.
impl<'de> serde::Deserialize<'de> for ObjectHash {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(de)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_hex() {
        let hash = ObjectHash::of(b"hello world");
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed = ObjectHash::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn from_bytes_round_trip() {
        let bytes = [0xABu8; 32];
        let hash = ObjectHash::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn of_is_sha256() {
        // SHA-256 of empty bytes is a known constant
        let hash = ObjectHash::of(b"");
        assert_eq!(
            hash.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn display_is_lowercase_hex() {
        let hash = ObjectHash::from_bytes([0xFFu8; 32]);
        assert_eq!(
            format!("{hash}"),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn invalid_length_error() {
        let err = ObjectHash::from_hex("abc").unwrap_err();
        assert!(matches!(err, ObjectHashParseError::InvalidLength(3)));
    }

    #[test]
    fn invalid_hex_error() {
        let s = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let err = ObjectHash::from_hex(s).unwrap_err();
        assert!(matches!(err, ObjectHashParseError::InvalidHex));
    }

    #[test]
    fn zero_byte_blob_hash() {
        // Hashing an empty slice produces a stable, non-panicking result
        let h1 = ObjectHash::of(b"");
        let h2 = ObjectHash::of(b"");
        assert_eq!(h1, h2);
    }
}
