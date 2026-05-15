//! Identity types: [`Ed25519PublicKey`].
//!
//! `ObjectHash` is intentionally NOT defined here; it lives in `frameshift-pack`
//! as the workspace canonical content-addressing type, and is re-exported from
//! [`crate`] for ergonomic access.
//!
//! These newtypes enforce encoding conventions at the type boundary so that
//! callers never accidentally pass raw bytes where a typed value is expected.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::fmt;
use std::str::FromStr;

/// An Ed25519 public key, represented as a 32-byte array.
///
/// This newtype is the canonical identifier for authors throughout the catalog.
/// It serializes as a base64url-no-padding string (RFC 4648, section 5) and
/// supports `Display`, `FromStr`, `Debug`, `Hash`, `PartialEq`, `Eq`,
/// `Clone`, and `Copy`.
///
/// # Invariants
///
/// The inner byte array is always exactly 32 bytes. No other structural
/// validation is performed -- callers are responsible for ensuring the bytes
/// represent a valid Ed25519 key before using them for signature verification.
///
/// # Display and Debug
///
/// Both `Display` and `Debug` render the key as base64url without padding.
/// The raw byte array is intentionally hidden to avoid noisy logs and
/// accidental exposure of key material in error messages.
///
/// # Serde
///
/// Serializes to a JSON string (base64url no padding). Deserializes from the
/// same format.
#[derive(Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Ed25519PublicKey(
    /// The raw 32-byte Ed25519 public key.
    ///
    /// Access via `.0` when you need the raw bytes (e.g. for signature
    /// verification with `ed25519-dalek`).
    #[serde(with = "b64_serde")]
    pub [u8; 32],
);

/// Renders the key as a base64url-no-padding string.
impl fmt::Display for Ed25519PublicKey {
    /// Format the key as a base64url string without padding characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

/// Renders the key as a base64url string for debug output (NOT raw bytes).
impl fmt::Debug for Ed25519PublicKey {
    /// Renders the key as a base64url string (NOT raw bytes) to keep logs
    /// readable and avoid security flags in log aggregators.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PublicKey({})", URL_SAFE_NO_PAD.encode(self.0))
    }
}

/// Error returned when a base64url string cannot be decoded as a 32-byte key.
#[derive(Debug, thiserror::Error)]
#[error("invalid Ed25519 public key: {0}")]
pub struct ParseEd25519KeyError(String);

/// Parses an `Ed25519PublicKey` from a base64url-no-padding string.
impl FromStr for Ed25519PublicKey {
    /// The error type returned when parsing fails.
    type Err = ParseEd25519KeyError;

    /// Parse a base64url-no-padding string into an `Ed25519PublicKey`.
    ///
    /// # Errors
    ///
    /// Returns `ParseEd25519KeyError` if the string is not valid base64url or
    /// if the decoded length is not exactly 32 bytes.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| ParseEd25519KeyError(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ParseEd25519KeyError("decoded length is not 32 bytes".to_string()))?;
        Ok(Ed25519PublicKey(arr))
    }
}

/// Serde helper: serialize/deserialize `[u8; 32]` as base64url no padding.
mod b64_serde {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize 32 bytes as a base64url no-padding string.
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Deserialize a base64url no-padding string into 32 bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let encoded = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("decoded length is not 32 bytes"))
    }
}

#[cfg(test)]
/// Unit tests for identity newtypes: Display, FromStr, serde, and Debug behavior.
mod tests {
    use super::*;

    #[test]
    /// Display -> FromStr roundtrip preserves all 32 bytes.
    fn ed25519_pubkey_display_from_str_roundtrip() {
        let raw = [0xab_u8; 32];
        let key = Ed25519PublicKey(raw);
        let displayed = key.to_string();
        let parsed: Ed25519PublicKey = displayed.parse().expect("must parse");
        assert_eq!(parsed.0, raw);
    }

    #[test]
    /// Serde JSON roundtrip preserves equality.
    fn ed25519_pubkey_serde_roundtrip() {
        let key = Ed25519PublicKey([0x7f_u8; 32]);
        let json = serde_json::to_string(&key).expect("serialize");
        let back: Ed25519PublicKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(key, back);
    }

    #[test]
    /// Debug output must be base64url (compact), not the raw byte array.
    fn ed25519_pubkey_debug_is_not_raw_bytes() {
        let key = Ed25519PublicKey([0x01_u8; 32]);
        let debug = format!("{key:?}");
        // Raw byte format would look like "[1, 1, 1, ...]" -- well over 60 chars
        // and contain commas. Base64url is ~43 chars inside Ed25519PublicKey(...).
        assert!(debug.len() < 80, "debug output too long: {debug}");
        assert!(
            !debug.contains(", 1,"),
            "debug contains raw byte array: {debug}"
        );
    }

    #[test]
    /// FromStr rejects a base64 string that decodes to fewer than 32 bytes.
    fn ed25519_pubkey_from_str_rejects_wrong_length() {
        let result: Result<Ed25519PublicKey, _> = "dG9vc2hvcnQ".parse();
        assert!(result.is_err());
    }
}
