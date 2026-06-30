//! Shared Ed25519 signed-request helper for integration tests.
//!
//! Mirrors the wire format verified by `frameshift_server::auth`: a signature
//! over `frameshift-signed-request/v1\n<METHOD>\n<PATH>\n<hex(sha256(body))>\n
//! <TIMESTAMP>\n<NONCE>`, carried in four `X-Frameshift-*` headers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use frameshift_catalog::identity::Ed25519PublicKey;
use sha2::{Digest, Sha256};

/// Domain-separation prefix; MUST match `frameshift_server::auth::SIGNING_DOMAIN`.
const SIGNING_DOMAIN: &str = "frameshift-signed-request/v1";

/// Monotonic source of unique nonces within a single test process.
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// One signed-request header: a static name plus the computed value.
///
/// `allow(dead_code)`: the shared `mocks` module is compiled into every test
/// binary, but only some of them (publish, authors_write) read these fields.
#[allow(dead_code)]
pub struct SignedHeader {
    /// Lowercase header name (e.g. `x-frameshift-pubkey`).
    pub name: &'static str,
    /// Header value.
    pub value: String,
}

/// Build the four signed-request headers for `key` over `(method, path, body)`,
/// using the current wall clock and a fresh process-unique nonce.
#[allow(dead_code)]
pub fn signed_headers(
    key: &SigningKey,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<SignedHeader> {
    signed_headers_at(key, method, path, body, unix_now(), &fresh_nonce())
}

/// Like [`signed_headers`] but with an explicit timestamp and nonce, for
/// skew-window and replay tests.
#[allow(dead_code)]
pub fn signed_headers_at(
    key: &SigningKey,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: i64,
    nonce: &str,
) -> Vec<SignedHeader> {
    let body_hex = hex::encode(Sha256::digest(body));
    let msg = format!("{SIGNING_DOMAIN}\n{method}\n{path}\n{body_hex}\n{timestamp}\n{nonce}");
    let sig = key.sign(msg.as_bytes());
    let pubkey = Ed25519PublicKey(key.verifying_key().to_bytes());
    vec![
        SignedHeader {
            name: "x-frameshift-pubkey",
            value: pubkey.to_string(),
        },
        SignedHeader {
            name: "x-frameshift-timestamp",
            value: timestamp.to_string(),
        },
        SignedHeader {
            name: "x-frameshift-nonce",
            value: nonce.to_string(),
        },
        SignedHeader {
            name: "x-frameshift-signature",
            value: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        },
    ]
}

/// A process-unique nonce string (>= 8 chars, base64url charset).
#[allow(dead_code)]
pub fn fresh_nonce() -> String {
    let n = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("test-nonce-{n:016}")
}

/// Current Unix seconds.
#[allow(dead_code)]
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
