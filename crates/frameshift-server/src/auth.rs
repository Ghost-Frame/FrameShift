//! Ed25519 signed-request authentication for the mutating ("write") endpoints.
//!
//! Every mutating request (`POST /v1/packs`, `POST /v1/authors`,
//! `POST /v1/authors/{handle}/rotate`) must carry an Ed25519 signature that
//! proves the live request was produced by the holder of a specific public
//! key. This replaces the previous `X-Frameshift-Session` stub, which accepted
//! any non-empty value.
//!
//! # Wire format
//!
//! Four request headers carry the credential:
//!
//! | Header | Value |
//! |---|---|
//! | `X-Frameshift-Pubkey` | base64url-no-pad 32-byte Ed25519 public key |
//! | `X-Frameshift-Timestamp` | decimal Unix seconds (signer's clock) |
//! | `X-Frameshift-Nonce` | unique per-request token, base64url charset, 8..=128 chars |
//! | `X-Frameshift-Signature` | base64url-no-pad 64-byte Ed25519 signature |
//!
//! The signature is computed over the [`signing_string`]:
//!
//! ```text
//! frameshift-signed-request/v1\n
//! <METHOD>\n
//! <PATH>\n
//! <hex(sha256(body))>\n
//! <TIMESTAMP>\n
//! <NONCE>
//! ```
//!
//! # Why a domain-separation prefix
//!
//! The first line (`frameshift-signed-request/v1`) is a fixed domain tag. The
//! pack-content signature (stored in [`frameshift_catalog::records::PackVersionRecord`])
//! signs the 32-byte canonical pack hash directly. Because the request signing
//! input always begins with the domain tag, a captured pack signature can never
//! be replayed as a request signature, and vice versa -- the two signature
//! schemes occupy disjoint message spaces.
//!
//! # Replay protection
//!
//! Two independent controls bound replay:
//!
//! 1. **Timestamp skew** -- the request is rejected if its timestamp differs
//!    from server time by more than `max_skew` (config
//!    `SIGNED_REQUEST_MAX_SKEW_SECS`, default 300s).
//! 2. **Nonce cache** -- a verified `(nonce)` is recorded in an in-memory
//!    [`NonceCache`]; a second request reusing that nonce within the retention
//!    window is rejected. Retention is `2 * max_skew`, after which the
//!    timestamp check alone rejects any re-send so the nonce can be forgotten.
//!
//! The nonce cache is **per process**. A multi-instance deployment behind a
//! load balancer would need a shared nonce store (Redis/Postgres) to close the
//! cross-instance replay gap; the timestamp window still bounds it to
//! `2 * max_skew`. This is documented as a known limitation for the
//! single-binary milestone.
//!
//! # Uniform failure
//!
//! Every authentication failure returns the same opaque
//! `401 {"error":"authentication failed"}`. The specific cause (missing header,
//! bad timestamp, replayed nonce, bad signature) is logged at `warn` but never
//! disclosed to the caller, so the endpoint cannot be used as an oracle.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use frameshift_catalog::Ed25519PublicKey;
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// Header carrying the base64url-no-pad 32-byte Ed25519 public key of the signer.
pub const PUBKEY_HEADER: &str = "x-frameshift-pubkey";

/// Header carrying the decimal Unix-seconds timestamp the signer used.
pub const TIMESTAMP_HEADER: &str = "x-frameshift-timestamp";

/// Header carrying the per-request nonce (base64url charset, 8..=128 chars).
pub const NONCE_HEADER: &str = "x-frameshift-nonce";

/// Header carrying the base64url-no-pad 64-byte Ed25519 signature.
pub const SIGNATURE_HEADER: &str = "x-frameshift-signature";

/// Domain-separation prefix prepended to every signed-request message.
///
/// Keeps request signatures in a disjoint message space from pack-content
/// signatures (which sign the raw 32-byte canonical hash).
const SIGNING_DOMAIN: &str = "frameshift-signed-request/v1";

/// Maximum accepted length for any single auth header value.
///
/// Generous enough for a base64url key/signature (43/86 chars) plus slack,
/// but small enough to reject junk before any allocation or parsing work.
const MAX_HEADER_LEN: usize = 256;

/// Minimum nonce length, in characters.
///
/// Eight base64url characters is ~48 bits of entropy, enough that an attacker
/// cannot pre-burn a victim's future nonce by guessing.
const MIN_NONCE_LEN: usize = 8;

/// Maximum nonce length, in characters.
const MAX_NONCE_LEN: usize = 128;

/// The opaque message returned to the client on ANY authentication failure.
///
/// Identical for every cause so the endpoint cannot be used as an oracle.
const AUTH_FAILED: &str = "authentication failed";

/// A request whose Ed25519 signature was verified by the signed-request
/// middleware.
///
/// Inserted into the request extensions by
/// [`crate::middleware::auth::require_signed_request`]. Handlers read it with
/// `axum::Extension<VerifiedSigner>` and use [`Self::pubkey`] as the
/// authenticated caller identity for authorization decisions.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedSigner {
    /// The Ed25519 public key that produced the verified request signature.
    pub pubkey: Ed25519PublicKey,
}

/// Parsed-but-not-yet-verified credential extracted from the request headers.
///
/// Structural validity only: the key/signature/nonce are well-formed, but the
/// signature has not been checked against any message and the timestamp/nonce
/// freshness have not been evaluated. [`verify`] performs those steps.
#[derive(Debug, Clone)]
pub struct SignedRequestParams {
    /// The claimed signer public key (structurally a 32-byte key).
    pub pubkey: Ed25519PublicKey,
    /// The signer-supplied Unix-seconds timestamp.
    pub timestamp: i64,
    /// The per-request nonce string (already charset/length validated).
    pub nonce: String,
    /// The 64-byte Ed25519 signature.
    pub signature: Signature,
}

/// Build the canonical message that the signature must cover.
///
/// `method` is the uppercased HTTP method, `path` is the request URI path
/// (no query string), `body_sha256_hex` is the lowercase hex SHA-256 of the
/// raw request body, `timestamp` is the signer's Unix seconds, and `nonce`
/// is the per-request token.
///
/// The fields are newline-delimited. `method`, the hex digest, and the decimal
/// timestamp cannot contain a newline; `nonce` is restricted to the base64url
/// charset by [`parse_headers`]; `path` is supplied by the router (never
/// attacker-framed beyond the matched route). The leading [`SIGNING_DOMAIN`]
/// line provides cross-protocol domain separation.
pub fn signing_string(
    method: &str,
    path: &str,
    body_sha256_hex: &str,
    timestamp: i64,
    nonce: &str,
) -> String {
    format!("{SIGNING_DOMAIN}\n{method}\n{path}\n{body_sha256_hex}\n{timestamp}\n{nonce}")
}

/// Lowercase hex SHA-256 of `body`.
pub fn body_hash_hex(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    hex::encode(digest)
}

/// Current wall-clock time in Unix seconds.
///
/// Returns `0` if the system clock is somehow before the Unix epoch (which
/// then fails every skew check rather than panicking).
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Extract and structurally validate the four signed-request headers.
///
/// Returns [`AppError::Unauthorized`] (with the opaque [`AUTH_FAILED`] message)
/// if any header is missing, over-length, malformed, or out of the accepted
/// charset. The specific reason is logged at `warn`.
pub fn parse_headers(headers: &HeaderMap) -> Result<SignedRequestParams, AppError> {
    let pubkey_raw = header_str(headers, PUBKEY_HEADER)?;
    let timestamp_raw = header_str(headers, TIMESTAMP_HEADER)?;
    let nonce_raw = header_str(headers, NONCE_HEADER)?;
    let signature_raw = header_str(headers, SIGNATURE_HEADER)?;

    // Public key: base64url-no-pad -> 32 bytes.
    let pubkey = pubkey_raw.parse::<Ed25519PublicKey>().map_err(|e| {
        tracing::warn!(error = %e, "signed request: malformed pubkey header");
        auth_failed()
    })?;

    // Timestamp: decimal i64.
    let timestamp = timestamp_raw.parse::<i64>().map_err(|_| {
        tracing::warn!("signed request: non-integer timestamp header");
        auth_failed()
    })?;

    // Nonce: bounded length + base64url charset.
    if nonce_raw.len() < MIN_NONCE_LEN || nonce_raw.len() > MAX_NONCE_LEN {
        tracing::warn!(len = nonce_raw.len(), "signed request: nonce length out of bounds");
        return Err(auth_failed());
    }
    if !nonce_raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        tracing::warn!("signed request: nonce contains non-base64url characters");
        return Err(auth_failed());
    }

    // Signature: base64url-no-pad -> 64 bytes.
    let sig_bytes = base64_url_decode(signature_raw).map_err(|_| {
        tracing::warn!("signed request: signature not valid base64url");
        auth_failed()
    })?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        tracing::warn!(len = sig_bytes.len(), "signed request: signature not 64 bytes");
        auth_failed()
    })?;
    let signature = Signature::from_bytes(&sig_arr);

    Ok(SignedRequestParams {
        pubkey,
        timestamp,
        nonce: nonce_raw.to_string(),
        signature,
    })
}

/// Verify a parsed signed request against the live message and replay state.
///
/// Order of checks:
/// 1. Timestamp within `±max_skew` of `now` (cheap, no state mutation).
/// 2. Ed25519 signature over [`signing_string`] (no state mutation).
/// 3. Nonce freshness recorded atomically (mutates the cache) -- only AFTER the
///    signature is proven authentic, so an attacker cannot burn nonces without
///    a valid signature.
///
/// On success returns the verified [`Ed25519PublicKey`]. Every failure returns
/// the opaque [`AppError::Unauthorized`].
pub fn verify(
    params: &SignedRequestParams,
    method: &str,
    path: &str,
    body: &[u8],
    now: i64,
    max_skew: Duration,
    nonces: &NonceCache,
) -> Result<Ed25519PublicKey, AppError> {
    // 1. Timestamp skew.
    let skew_secs = max_skew.as_secs() as i64;
    if (now - params.timestamp).abs() > skew_secs {
        tracing::warn!(
            ts = params.timestamp,
            now,
            skew_secs,
            "signed request: timestamp outside allowed skew"
        );
        return Err(auth_failed());
    }

    // 2. Signature over the canonical message.
    let verifying_key = VerifyingKey::from_bytes(&params.pubkey.0).map_err(|e| {
        tracing::warn!(error = %e, "signed request: pubkey is not a valid Ed25519 point");
        auth_failed()
    })?;
    let message = signing_string(
        method,
        path,
        &body_hash_hex(body),
        params.timestamp,
        &params.nonce,
    );
    if verifying_key
        .verify(message.as_bytes(), &params.signature)
        .is_err()
    {
        tracing::warn!(pubkey = %params.pubkey, "signed request: signature verification failed");
        return Err(auth_failed());
    }

    // 3. Replay: burn the nonce only now that the request is proven authentic.
    if !nonces.check_and_record(&params.nonce) {
        tracing::warn!(pubkey = %params.pubkey, "signed request: nonce replay detected");
        return Err(auth_failed());
    }

    Ok(params.pubkey)
}

/// Read a header value as `&str`, enforcing presence and the length cap.
fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, AppError> {
    let value = headers.get(name).ok_or_else(|| {
        tracing::warn!(header = name, "signed request: missing required header");
        auth_failed()
    })?;
    let s = value.to_str().map_err(|_| {
        tracing::warn!(header = name, "signed request: header is not valid ASCII");
        auth_failed()
    })?;
    if s.len() > MAX_HEADER_LEN {
        tracing::warn!(header = name, len = s.len(), "signed request: header too long");
        return Err(auth_failed());
    }
    Ok(s)
}

/// Decode a base64url-no-pad string into bytes.
fn base64_url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(s)
}

/// Construct the single opaque authentication-failure error.
fn auth_failed() -> AppError {
    AppError::Unauthorized(AUTH_FAILED.to_string())
}

/// An in-memory, time-bounded set of recently-seen request nonces.
///
/// Shared via `Arc<NonceCache>` in [`crate::state::AppState`]. Entries expire
/// after [`NonceCache::ttl`] (set to `2 * max_skew` at construction) and are
/// evicted lazily on each [`Self::check_and_record`] call. A hard
/// [`NonceCache::max_entries`] cap fails closed under a flood so the map cannot
/// grow without bound.
pub struct NonceCache {
    /// Guarded map of `nonce -> expiry instant`.
    inner: Mutex<HashMap<String, SystemTime>>,
    /// How long a nonce is remembered after it is first recorded.
    ttl: Duration,
    /// Maximum number of live nonces retained at once.
    max_entries: usize,
}

impl NonceCache {
    /// Default cap on retained nonces.
    ///
    /// At ~64 bytes/entry this bounds the cache to a few MiB. A legitimate
    /// publisher fleet produces far fewer concurrent in-window nonces; the cap
    /// only engages under a deliberate flood, where failing closed (rejecting
    /// new requests) is the safe behavior.
    const DEFAULT_MAX_ENTRIES: usize = 100_000;

    /// Build a cache that remembers each nonce for `ttl`.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            max_entries: Self::DEFAULT_MAX_ENTRIES,
        }
    }

    /// Atomically test-and-set a nonce.
    ///
    /// Returns `true` if the nonce was previously unseen (and is now recorded),
    /// `false` if it is a replay or if the cache is at capacity. Expired
    /// entries are evicted before the check.
    pub fn check_and_record(&self, nonce: &str) -> bool {
        let now = SystemTime::now();
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            // A poisoned lock means a prior panic while holding it. Fail closed.
            Err(_) => return false,
        };
        // Lazy eviction of expired entries.
        map.retain(|_, expiry| *expiry > now);
        if map.contains_key(nonce) {
            return false;
        }
        if map.len() >= self.max_entries {
            // Cache full of still-live nonces -- fail closed rather than grow.
            return false;
        }
        map.insert(nonce.to_string(), now + self.ttl);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Build the four headers for a request signed by `key`.
    fn sign_headers(
        key: &SigningKey,
        method: &str,
        path: &str,
        body: &[u8],
        timestamp: i64,
        nonce: &str,
    ) -> HeaderMap {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let msg = signing_string(method, path, &body_hash_hex(body), timestamp, nonce);
        let sig = key.sign(msg.as_bytes());
        let pubkey = Ed25519PublicKey(key.verifying_key().to_bytes());

        let mut headers = HeaderMap::new();
        headers.insert(PUBKEY_HEADER, pubkey.to_string().parse().unwrap());
        headers.insert(TIMESTAMP_HEADER, timestamp.to_string().parse().unwrap());
        headers.insert(NONCE_HEADER, nonce.parse().unwrap());
        headers.insert(
            SIGNATURE_HEADER,
            URL_SAFE_NO_PAD.encode(sig.to_bytes()).parse().unwrap(),
        );
        headers
    }

    #[test]
    /// A correctly signed request verifies and returns the signer key.
    fn verify_accepts_valid_signature() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let body = b"hello body";
        let now = 1_000_000;
        let headers = sign_headers(&key, "POST", "/v1/packs", body, now, "nonce-aaaa");
        let params = parse_headers(&headers).expect("parse");
        let nonces = NonceCache::new(Duration::from_secs(600));
        let got = verify(
            &params,
            "POST",
            "/v1/packs",
            body,
            now,
            Duration::from_secs(300),
            &nonces,
        )
        .expect("verify");
        assert_eq!(got.0, key.verifying_key().to_bytes());
    }

    #[test]
    /// A tampered body invalidates the signature.
    fn verify_rejects_body_tamper() {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let now = 2_000_000;
        let headers = sign_headers(&key, "POST", "/v1/packs", b"original", now, "nonce-bbbb");
        let params = parse_headers(&headers).expect("parse");
        let nonces = NonceCache::new(Duration::from_secs(600));
        let err = verify(
            &params,
            "POST",
            "/v1/packs",
            b"TAMPERED",
            now,
            Duration::from_secs(300),
            &nonces,
        );
        assert!(matches!(err, Err(AppError::Unauthorized(_))));
    }

    #[test]
    /// Signing one path then verifying against another fails (path is bound).
    fn verify_rejects_path_mismatch() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = 3_000_000;
        let headers = sign_headers(&key, "POST", "/v1/authors", b"x", now, "nonce-cccc");
        let params = parse_headers(&headers).expect("parse");
        let nonces = NonceCache::new(Duration::from_secs(600));
        let err = verify(
            &params,
            "POST",
            "/v1/packs",
            b"x",
            now,
            Duration::from_secs(300),
            &nonces,
        );
        assert!(matches!(err, Err(AppError::Unauthorized(_))));
    }

    #[test]
    /// A timestamp outside the skew window is rejected even with a good signature.
    fn verify_rejects_stale_timestamp() {
        let key = SigningKey::from_bytes(&[6u8; 32]);
        let signed_at = 1_000_000;
        let headers = sign_headers(&key, "POST", "/v1/packs", b"x", signed_at, "nonce-dddd");
        let params = parse_headers(&headers).expect("parse");
        let nonces = NonceCache::new(Duration::from_secs(600));
        // now is 10 minutes after signing; skew window is 5 minutes.
        let err = verify(
            &params,
            "POST",
            "/v1/packs",
            b"x",
            signed_at + 600,
            Duration::from_secs(300),
            &nonces,
        );
        assert!(matches!(err, Err(AppError::Unauthorized(_))));
    }

    #[test]
    /// Replaying the same nonce twice fails the second time.
    fn verify_rejects_nonce_replay() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let now = 5_000_000;
        let headers = sign_headers(&key, "POST", "/v1/packs", b"x", now, "nonce-eeee");
        let params = parse_headers(&headers).expect("parse");
        let nonces = NonceCache::new(Duration::from_secs(600));
        let skew = Duration::from_secs(300);
        // First use succeeds.
        assert!(verify(&params, "POST", "/v1/packs", b"x", now, skew, &nonces).is_ok());
        // Replay with the identical signed request fails.
        let err = verify(&params, "POST", "/v1/packs", b"x", now, skew, &nonces);
        assert!(matches!(err, Err(AppError::Unauthorized(_))));
    }

    #[test]
    /// Missing any required header yields an opaque auth failure.
    fn parse_headers_rejects_missing() {
        let mut headers = HeaderMap::new();
        headers.insert(PUBKEY_HEADER, "abc".parse().unwrap());
        assert!(parse_headers(&headers).is_err());
    }

    #[test]
    /// A nonce shorter than the minimum is rejected at parse time.
    fn parse_headers_rejects_short_nonce() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let headers = sign_headers(&key, "POST", "/v1/packs", b"x", 9_000_000, "short");
        assert!(parse_headers(&headers).is_err());
    }

    #[test]
    /// The nonce cache evicts an entry once its TTL has elapsed, allowing reuse.
    fn nonce_cache_expires_entries() {
        // Zero TTL: every entry is already expired when the next check runs.
        let cache = NonceCache::new(Duration::from_secs(0));
        assert!(cache.check_and_record("n1"));
        // With a zero TTL the prior entry is evicted on the next call, so the
        // same nonce is accepted again.
        assert!(cache.check_and_record("n1"));
    }
}
