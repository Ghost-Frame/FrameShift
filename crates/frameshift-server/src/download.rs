//! HMAC-signed download URL minting and verification.
//!
//! Implements a short-lived bearer-token download flow. The signer mints
//! a token bound to a content hash and an expiry timestamp; the verifier
//! rejects tokens with mismatched HMACs, past expiries, or expiries beyond
//! the configured ceiling.
//!
//! # Token contract
//!
//! `token = HMAC-SHA256(key, hash_bytes || 0x00 || expires_be_bytes) (hex)`
//!
//! - `key` -- 32-byte secret from [`crate::config::ServerConfig::download_key`].
//! - `hash_bytes` -- raw 32-byte SHA-256 from the catalog `content_hash`.
//! - `0x00` -- single null byte field separator between the hash and expiry
//!   so a payload of all-zero hash bytes cannot collide with a non-zero
//!   expiry prefix.
//! - `expires_be_bytes` -- 8-byte big-endian `i64` Unix timestamp.
//!
//! # Why HMAC and not asymmetric signing
//!
//! The same server mints and verifies, so a shared secret is sufficient and
//! cheaper than an Ed25519 signature per request. Author pack signatures
//! (where producer and consumer differ) DO use Ed25519; this token is
//! orthogonal -- it gates the download channel itself.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use frameshift_pack::ObjectHash;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Errors returned by [`verify_download_token`].
///
/// All variants are mapped to `403 Forbidden` by the HTTP layer with a
/// constant-time generic message; the variant itself is only used for
/// structured logging on the server side.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DownloadTokenError {
    /// Token hex string is the wrong length or contains non-hex characters.
    #[error("token format invalid")]
    Format,

    /// HMAC did not match the expected value (constant-time comparison).
    #[error("token signature invalid")]
    Signature,

    /// `expires` is in the past relative to the verifier's clock.
    #[error("token expired")]
    Expired,

    /// `expires` is further in the future than the configured ceiling.
    ///
    /// Defends against a future signer bug that issues long-lived tokens.
    #[error("token expiry beyond max ttl")]
    ExpiryTooFar,
}

/// Compute the HMAC-SHA256 token over `(hash, expires)` and return it as a
/// 64-character lower-case hex string.
///
/// This is the producer side. The caller passes the resulting `token` and
/// `expires` claim back to the verifier as URL query parameters.
///
/// # Parameters
///
/// - `key` -- 32-byte HMAC key.
/// - `hash` -- canonical object hash of the blob being authorised.
/// - `expires` -- Unix timestamp at which this token stops being valid.
///
/// # Returns
///
/// Hex-encoded HMAC-SHA256 digest (64 ASCII characters).
pub fn sign_download_token(key: &[u8; 32], hash: &ObjectHash, expires: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(hash.as_bytes());
    mac.update(&[0u8]);
    mac.update(&expires.to_be_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify a download token against `(hash, expires)` and the configured TTL
/// ceiling.
///
/// Uses [`hmac::Mac::verify_slice`] for constant-time comparison so a timing
/// channel cannot leak which byte of the expected token first diverged.
///
/// # Parameters
///
/// - `key` -- the same 32-byte HMAC key used by [`sign_download_token`].
/// - `hash` -- the content hash from the URL path.
/// - `expires` -- the `expires` claim from the URL query.
/// - `token_hex` -- the `token` claim from the URL query (must be 64 hex chars).
/// - `max_ttl` -- hard cap on how far `expires` may be in the future from `now`.
/// - `now` -- the verifier's current Unix timestamp (injected for test
///   determinism rather than read from the clock here).
///
/// # Errors
///
/// Returns [`DownloadTokenError`] on any failure. The caller maps every
/// variant to the same HTTP status and body so the failure reason is not
/// leaked to the client.
pub fn verify_download_token(
    key: &[u8; 32],
    hash: &ObjectHash,
    expires: i64,
    token_hex: &str,
    max_ttl: Duration,
    now: i64,
) -> Result<(), DownloadTokenError> {
    // Expiry checks first -- cheap, no HMAC computation needed if the claim
    // is already invalid.
    if expires < now {
        return Err(DownloadTokenError::Expired);
    }
    let max_ttl_secs: i64 = max_ttl.as_secs().try_into().unwrap_or(i64::MAX);
    // 60s of slack absorbs clock skew between the signer and verifier without
    // meaningfully extending the bearer-token window.
    if expires > now.saturating_add(max_ttl_secs).saturating_add(60) {
        return Err(DownloadTokenError::ExpiryTooFar);
    }

    // Token must be exactly 64 hex characters; reject early to avoid wasting
    // an HMAC computation on malformed input.
    if token_hex.len() != 64 {
        return Err(DownloadTokenError::Format);
    }
    let token_bytes = hex::decode(token_hex).map_err(|_| DownloadTokenError::Format)?;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(hash.as_bytes());
    mac.update(&[0u8]);
    mac.update(&expires.to_be_bytes());
    mac.verify_slice(&token_bytes)
        .map_err(|_| DownloadTokenError::Signature)
}

/// Current Unix timestamp (seconds since epoch), saturating to 0 if the
/// system clock is set before 1970.
///
/// Wrapper around `SystemTime::now()` that returns the value needed by
/// [`verify_download_token`] and the signer.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a deterministic 32-byte key and a representative object hash for
    /// every test in this module.
    fn fixtures() -> ([u8; 32], ObjectHash) {
        let key = [7u8; 32];
        let hash = ObjectHash::of(b"hello frameshift");
        (key, hash)
    }

    #[test]
    fn roundtrip_valid_token_verifies() {
        let (key, hash) = fixtures();
        let now = 1_700_000_000;
        let expires = now + 300;
        let token = sign_download_token(&key, &hash, expires);
        verify_download_token(&key, &hash, expires, &token, Duration::from_secs(600), now)
            .expect("freshly signed token must verify");
    }

    #[test]
    fn token_with_past_expiry_is_expired() {
        let (key, hash) = fixtures();
        let now = 1_700_000_000;
        let expires = now - 1;
        let token = sign_download_token(&key, &hash, expires);
        let err =
            verify_download_token(&key, &hash, expires, &token, Duration::from_secs(600), now)
                .unwrap_err();
        assert_eq!(err, DownloadTokenError::Expired);
    }

    #[test]
    fn token_with_excessive_expiry_is_rejected() {
        let (key, hash) = fixtures();
        let now = 1_700_000_000;
        let expires = now + 86_400; // 1 day, far beyond 5-min max_ttl
        let token = sign_download_token(&key, &hash, expires);
        let err =
            verify_download_token(&key, &hash, expires, &token, Duration::from_secs(300), now)
                .unwrap_err();
        assert_eq!(err, DownloadTokenError::ExpiryTooFar);
    }

    #[test]
    fn token_for_different_hash_fails_signature() {
        let (key, hash) = fixtures();
        let other = ObjectHash::of(b"a different blob");
        let now = 1_700_000_000;
        let expires = now + 60;
        let token = sign_download_token(&key, &hash, expires);
        let err =
            verify_download_token(&key, &other, expires, &token, Duration::from_secs(600), now)
                .unwrap_err();
        assert_eq!(err, DownloadTokenError::Signature);
    }

    #[test]
    fn token_with_swapped_expiry_fails_signature() {
        let (key, hash) = fixtures();
        let now = 1_700_000_000;
        let expires = now + 60;
        let token = sign_download_token(&key, &hash, expires);
        // Attacker tries to extend the token by bumping `expires` in the URL.
        // The HMAC was bound to the original expiry, so verification fails
        // (rather than the cheaper Expired path).
        let err = verify_download_token(
            &key,
            &hash,
            expires + 1,
            &token,
            Duration::from_secs(600),
            now,
        )
        .unwrap_err();
        assert_eq!(err, DownloadTokenError::Signature);
    }

    #[test]
    fn wrong_key_fails_signature() {
        let (key, hash) = fixtures();
        let other_key = [9u8; 32];
        let now = 1_700_000_000;
        let expires = now + 60;
        let token = sign_download_token(&key, &hash, expires);
        let err = verify_download_token(
            &other_key,
            &hash,
            expires,
            &token,
            Duration::from_secs(600),
            now,
        )
        .unwrap_err();
        assert_eq!(err, DownloadTokenError::Signature);
    }

    #[test]
    fn malformed_token_hex_is_format_error() {
        let (key, hash) = fixtures();
        let now = 1_700_000_000;
        let expires = now + 60;
        let err = verify_download_token(
            &key,
            &hash,
            expires,
            "deadbeef",
            Duration::from_secs(600),
            now,
        )
        .unwrap_err();
        assert_eq!(err, DownloadTokenError::Format);

        let err = verify_download_token(
            &key,
            &hash,
            expires,
            &"z".repeat(64),
            Duration::from_secs(600),
            now,
        )
        .unwrap_err();
        assert_eq!(err, DownloadTokenError::Format);
    }

    #[test]
    fn token_is_deterministic_for_same_inputs() {
        let (key, hash) = fixtures();
        let expires = 1_700_000_300;
        let a = sign_download_token(&key, &hash, expires);
        let b = sign_download_token(&key, &hash, expires);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }
}
