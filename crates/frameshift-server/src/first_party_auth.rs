//! Cryptographic and lifecycle helpers for first-party authentication.

use std::net::IpAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Duration, Utc};
use frameshift_catalog::{
    AccountAuthAuditEventKind, AccountAuthAuditEventRecord, AccountAuthAuditOutcome,
    AccountMfaRecoveryCodeSeed, AccountSessionClientKind, AccountSessionIssuance,
    AccountSessionRecord, EncryptedTotpSecret,
};
use hmac::{Hmac, Mac as _};
use rand_core::{OsRng, RngCore as _};
use secrecy::ExposeSecret as _;
use sha2::{Digest as _, Sha256};
use url::{Host, Url};
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::config::FirstPartyAuthConfig;
use crate::error::AppError;

/// SHA-256 HMAC used for TOTP and deployment-keyed audit tags.
type HmacSha256 = Hmac<Sha256>;

/// Raw byte length of an access token.
const ACCESS_TOKEN_BYTES: usize = 32;
/// Raw random portion of bound one-time tokens.
const BOUND_TOKEN_RANDOM_BYTES: usize = 32;
/// Raw byte length of a bound one-time token.
const BOUND_TOKEN_BYTES: usize = 16 + 1 + BOUND_TOKEN_RANDOM_BYTES;
/// Raw byte length of a native code carrying inherited MFA assurance.
const NATIVE_CODE_TOKEN_BYTES: usize = 16 + 1 + 8 + BOUND_TOKEN_RANDOM_BYTES;
/// Raw byte length of a self-describing refresh token.
const REFRESH_TOKEN_BYTES: usize = 16 + 16 + 8 + 1 + 32;
/// TOTP timestep duration in seconds.
const TOTP_STEP_SECONDS: i64 = 30;
/// Number of decimal digits emitted by a TOTP code.
const TOTP_DIGITS: u32 = 6;
/// Number of recovery codes issued at activation.
pub(crate) const MFA_RECOVERY_CODE_COUNT: usize = 10;

/// Plaintext credentials and digest-only session issuance created together.
pub(crate) struct IssuedSession {
    /// Digest-only session family persisted by the catalog.
    pub(crate) issuance: AccountSessionIssuance,
    /// Random access token returned exactly once.
    pub(crate) access_token: String,
    /// Random refresh token returned exactly once.
    pub(crate) refresh_token: String,
}

/// Validated self-describing refresh token metadata.
pub(crate) struct DecodedRefreshToken {
    /// SHA-256 digest used for the catalog lookup.
    pub(crate) digest: Vec<u8>,
    /// Account identifier authenticated into the token digest.
    pub(crate) account_id: Uuid,
    /// Session-family identifier authenticated into the token digest.
    pub(crate) session_id: Uuid,
    /// Non-extendable session-family expiry authenticated into the token digest.
    pub(crate) absolute_expires_at: DateTime<Utc>,
    /// Client class authenticated into the token digest.
    pub(crate) client_kind: AccountSessionClientKind,
}

/// Validated self-describing one-time token metadata.
pub(crate) struct DecodedBoundToken {
    /// SHA-256 digest used for the catalog lookup.
    pub(crate) digest: Vec<u8>,
    /// Account identifier authenticated into the token digest.
    pub(crate) account_id: Uuid,
    /// Client class authenticated into the token digest.
    pub(crate) client_kind: AccountSessionClientKind,
}

/// Validated self-describing native authorization code metadata.
pub(crate) struct DecodedNativeCode {
    /// SHA-256 digest used for one-time catalog exchange.
    pub(crate) digest: Vec<u8>,
    /// Account identifier authenticated into the code digest.
    pub(crate) account_id: Uuid,
    /// Desktop or CLI class authenticated into the code digest.
    pub(crate) client_kind: AccountSessionClientKind,
    /// Browser MFA assurance inherited by the future native session.
    pub(crate) mfa_verified_at: DateTime<Utc>,
}

/// Deployment-keyed TOTP secret cipher.
pub(crate) struct MfaSecretCipher {
    /// Raw XChaCha20-Poly1305 key cleared when the helper is dropped.
    key: [u8; 32],
    /// Version persisted beside every encrypted secret.
    key_version: i16,
}

/// Secure cleanup for the in-memory MFA encryption key.
impl Drop for MfaSecretCipher {
    /// Clear the raw deployment key before releasing its memory.
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Encryption and decryption operations for TOTP seeds.
impl MfaSecretCipher {
    /// Construct a cipher only from a fully valid enabled configuration.
    pub(crate) fn from_config(config: &FirstPartyAuthConfig) -> Result<Self, AppError> {
        let key = config
            .decoded_mfa_encryption_key()
            .map_err(|_| AppError::Internal("first-party MFA configuration is invalid".into()))?
            .ok_or_else(|| AppError::NotFound("first-party account routes are disabled".into()))?;
        Ok(Self {
            key,
            key_version: config.mfa_key_version,
        })
    }

    /// Encrypt one TOTP seed with account- and authenticator-bound AAD.
    pub(crate) fn encrypt(
        &self,
        account_id: Uuid,
        authenticator_id: Uuid,
        secret: &[u8],
    ) -> Result<EncryptedTotpSecret, AppError> {
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = mfa_aad(account_id, authenticator_id, self.key_version);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| AppError::Internal("MFA secret encryption failed".into()))?;
        Ok(EncryptedTotpSecret {
            ciphertext,
            nonce,
            key_version: self.key_version,
        })
    }

    /// Decrypt one TOTP seed only under its exact owner and authenticator AAD.
    pub(crate) fn decrypt(
        &self,
        account_id: Uuid,
        authenticator_id: Uuid,
        secret: &EncryptedTotpSecret,
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        if secret.key_version != self.key_version {
            return Err(AppError::ServiceUnavailable(
                "MFA encryption key version is unavailable".into(),
            ));
        }
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let aad = mfa_aad(account_id, authenticator_id, secret.key_version);
        cipher
            .decrypt(
                XNonce::from_slice(&secret.nonce),
                Payload {
                    msg: &secret.ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| AppError::Internal("MFA secret decryption failed".into()))
    }
}

/// Generate a random canonical access token and its digest.
pub(crate) fn generate_access_token() -> (String, Vec<u8>) {
    generate_random_token(ACCESS_TOKEN_BYTES)
}

/// Decode one canonical access token and return its digest.
pub(crate) fn decode_access_token(token: &str) -> Result<Vec<u8>, AppError> {
    let raw = decode_canonical_token(token, ACCESS_TOKEN_BYTES)?;
    Ok(Sha256::digest(raw.as_slice()).to_vec())
}

/// Build one new session family and both transport credentials.
pub(crate) fn issue_session(
    config: &FirstPartyAuthConfig,
    account_id: Uuid,
    client_kind: AccountSessionClientKind,
    now: DateTime<Utc>,
    mfa_verified_at: Option<DateTime<Utc>>,
) -> Result<IssuedSession, AppError> {
    let session_id = Uuid::new_v4();
    let (access_token, access_digest) = generate_access_token();
    let absolute_expires_at = add_std_duration(now, config.absolute_ttl, "session absolute TTL")?;
    let (refresh_token, refresh_digest) =
        generate_refresh_token(account_id, session_id, absolute_expires_at, client_kind);
    let idle_ttl = match client_kind {
        AccountSessionClientKind::Browser => config.browser_idle_ttl,
        AccountSessionClientKind::Desktop | AccountSessionClientKind::Cli => config.bearer_idle_ttl,
    };
    let idle_expires_at = std::cmp::min(
        add_std_duration(now, idle_ttl, "session idle TTL")?,
        absolute_expires_at,
    );
    let access_expires_at = std::cmp::min(
        add_std_duration(now, config.access_ttl, "access-token TTL")?,
        absolute_expires_at,
    );
    let refresh_expires_at = std::cmp::min(
        add_std_duration(now, config.refresh_ttl, "refresh-token TTL")?,
        std::cmp::min(idle_expires_at, absolute_expires_at),
    );
    Ok(IssuedSession {
        issuance: AccountSessionIssuance {
            session: AccountSessionRecord {
                id: session_id,
                account_id,
                token_digest: access_digest,
                client_kind,
                created_at: now,
                last_seen_at: now,
                access_expires_at,
                idle_expires_at,
                absolute_expires_at,
                mfa_verified_at,
                revoked_at: None,
            },
            refresh_token_id: Uuid::new_v4(),
            refresh_token_digest: refresh_digest,
            refresh_expires_at,
        },
        access_token,
        refresh_token,
    })
}

/// Generate a refresh token bound to its account and session family.
pub(crate) fn generate_refresh_token(
    account_id: Uuid,
    session_id: Uuid,
    absolute_expires_at: DateTime<Utc>,
    client_kind: AccountSessionClientKind,
) -> (String, Vec<u8>) {
    let mut raw = Zeroizing::new([0_u8; REFRESH_TOKEN_BYTES]);
    raw[..16].copy_from_slice(account_id.as_bytes());
    raw[16..32].copy_from_slice(session_id.as_bytes());
    raw[32..40].copy_from_slice(&absolute_expires_at.timestamp().to_be_bytes());
    raw[40] = encode_client_kind(client_kind);
    OsRng.fill_bytes(&mut raw[41..]);
    (
        URL_SAFE_NO_PAD.encode(raw.as_slice()),
        Sha256::digest(raw.as_slice()).to_vec(),
    )
}

/// Decode a canonical refresh token and recover its authenticated metadata.
pub(crate) fn decode_refresh_token(token: &str) -> Result<DecodedRefreshToken, AppError> {
    let raw = decode_canonical_token(token, REFRESH_TOKEN_BYTES)?;
    let account_id = Uuid::from_slice(&raw[..16])
        .map_err(|_| AppError::Unauthorized("refresh token is invalid or expired".into()))?;
    let session_id = Uuid::from_slice(&raw[16..32])
        .map_err(|_| AppError::Unauthorized("refresh token is invalid or expired".into()))?;
    let timestamp = i64::from_be_bytes(
        raw[32..40]
            .try_into()
            .map_err(|_| AppError::Unauthorized("refresh token is invalid or expired".into()))?,
    );
    let absolute_expires_at = DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| AppError::Unauthorized("refresh token is invalid or expired".into()))?;
    let client_kind = decode_client_kind(raw[40])
        .ok_or_else(|| AppError::Unauthorized("refresh token is invalid or expired".into()))?;
    Ok(DecodedRefreshToken {
        digest: Sha256::digest(raw.as_slice()).to_vec(),
        account_id,
        session_id,
        absolute_expires_at,
        client_kind,
    })
}

/// Generate a one-time token bound to an account and client class.
pub(crate) fn generate_bound_token(
    account_id: Uuid,
    client_kind: AccountSessionClientKind,
) -> (String, Vec<u8>) {
    let mut raw = Zeroizing::new([0_u8; BOUND_TOKEN_BYTES]);
    raw[..16].copy_from_slice(account_id.as_bytes());
    raw[16] = encode_client_kind(client_kind);
    OsRng.fill_bytes(&mut raw[17..]);
    (
        URL_SAFE_NO_PAD.encode(raw.as_slice()),
        Sha256::digest(raw.as_slice()).to_vec(),
    )
}

/// Decode a canonical one-time token and recover its authenticated metadata.
pub(crate) fn decode_bound_token(token: &str) -> Result<DecodedBoundToken, AppError> {
    let raw = decode_canonical_token(token, BOUND_TOKEN_BYTES)?;
    let account_id = Uuid::from_slice(&raw[..16])
        .map_err(|_| AppError::Unauthorized("token is invalid or expired".into()))?;
    let client_kind = decode_client_kind(raw[16])
        .ok_or_else(|| AppError::Unauthorized("token is invalid or expired".into()))?;
    Ok(DecodedBoundToken {
        digest: Sha256::digest(raw.as_slice()).to_vec(),
        account_id,
        client_kind,
    })
}

/// Generate a native authorization code carrying exact inherited MFA assurance.
pub(crate) fn generate_native_code(
    account_id: Uuid,
    client_kind: AccountSessionClientKind,
    mfa_verified_at: DateTime<Utc>,
) -> (String, Vec<u8>, DateTime<Utc>) {
    let timestamp_micros = mfa_verified_at.timestamp_micros();
    let normalized_mfa_verified_at = DateTime::from_timestamp_micros(timestamp_micros)
        .expect("an existing UTC timestamp remains representable at microsecond precision");
    let mut raw = Zeroizing::new([0_u8; NATIVE_CODE_TOKEN_BYTES]);
    raw[..16].copy_from_slice(account_id.as_bytes());
    raw[16] = encode_client_kind(client_kind);
    raw[17..25].copy_from_slice(&timestamp_micros.to_be_bytes());
    OsRng.fill_bytes(&mut raw[25..]);
    (
        URL_SAFE_NO_PAD.encode(raw.as_slice()),
        Sha256::digest(raw.as_slice()).to_vec(),
        normalized_mfa_verified_at,
    )
}

/// Decode one canonical native code and recover its exact assurance binding.
pub(crate) fn decode_native_code(token: &str) -> Result<DecodedNativeCode, AppError> {
    let raw = decode_canonical_token(token, NATIVE_CODE_TOKEN_BYTES)?;
    let account_id = Uuid::from_slice(&raw[..16])
        .map_err(|_| AppError::Unauthorized("authorization code is invalid or expired".into()))?;
    let client_kind = decode_client_kind(raw[16])
        .ok_or_else(|| AppError::Unauthorized("authorization code is invalid or expired".into()))?;
    let timestamp_micros =
        i64::from_be_bytes(raw[17..25].try_into().map_err(|_| {
            AppError::Unauthorized("authorization code is invalid or expired".into())
        })?);
    let mfa_verified_at = DateTime::from_timestamp_micros(timestamp_micros)
        .ok_or_else(|| AppError::Unauthorized("authorization code is invalid or expired".into()))?;
    Ok(DecodedNativeCode {
        digest: Sha256::digest(raw.as_slice()).to_vec(),
        account_id,
        client_kind,
        mfa_verified_at,
    })
}

/// Security-relevant optional bindings carried by one authentication audit event.
#[derive(Default)]
pub(crate) struct AuthAuditContext {
    /// Affected account when known without exposing caller-controlled input.
    pub account_id: Option<Uuid>,
    /// Affected session family when one exists.
    pub session_id: Option<Uuid>,
    /// Client class involved in the authentication transition.
    pub client_kind: Option<AccountSessionClientKind>,
    /// Deployment-keyed canonical identifier digest when available.
    pub identifier_tag: Option<Vec<u8>>,
    /// Bounded static rejection reason that contains no caller input.
    pub reason_code: Option<&'static str>,
}

/// Construct one bounded sanitized authentication audit event.
pub(crate) fn auth_audit_event(
    event_kind: AccountAuthAuditEventKind,
    outcome: AccountAuthAuditOutcome,
    context: AuthAuditContext,
    created_at: DateTime<Utc>,
) -> AccountAuthAuditEventRecord {
    AccountAuthAuditEventRecord {
        id: Uuid::new_v4(),
        event_kind,
        outcome,
        account_id: context.account_id,
        session_id: context.session_id,
        client_kind: context.client_kind,
        identifier_tag: context.identifier_tag,
        network_tag: None,
        reason_code: context.reason_code.map(str::to_string),
        created_at,
    }
}

/// Derive a deployment-keyed identifier tag without storing an email address.
pub(crate) fn identifier_tag(config: &FirstPartyAuthConfig, identifier: &str) -> Vec<u8> {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(
        config.password_pepper.expose_secret().as_bytes(),
    )
    .expect("HMAC accepts keys of every length");
    mac.update(b"frameshift-auth-identifier-v1\0");
    mac.update(identifier.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Generate a random TOTP seed held in zeroizing memory.
pub(crate) fn generate_totp_secret() -> Zeroizing<Vec<u8>> {
    let mut secret = Zeroizing::new(vec![0_u8; 32]);
    OsRng.fill_bytes(secret.as_mut_slice());
    secret
}

/// Verify a six-digit HMAC-SHA256 TOTP within a one-step clock window.
pub(crate) fn verify_totp(secret: &[u8], code: &str, now: DateTime<Utc>) -> Result<i64, AppError> {
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AppError::Unauthorized(
            "MFA proof is invalid or expired".into(),
        ));
    }
    let current = now.timestamp().div_euclid(TOTP_STEP_SECONDS);
    for timestep in [current - 1, current, current + 1] {
        let expected = totp_code(secret, timestep)?;
        if constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            return Ok(timestep);
        }
    }
    Err(AppError::Unauthorized(
        "MFA proof is invalid or expired".into(),
    ))
}

/// Encode a TOTP seed for display in an enrollment URI.
pub(crate) fn base32_no_pad(secret: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((secret.len() * 8).div_ceil(5));
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in secret {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

/// Generate high-entropy recovery codes and digest-only persistence seeds.
pub(crate) fn generate_recovery_codes(
    count: usize,
) -> (Vec<String>, Vec<AccountMfaRecoveryCodeSeed>) {
    let mut plaintext = Vec::with_capacity(count);
    let mut seeds = Vec::with_capacity(count);
    for _ in 0..count {
        let (code, digest) = generate_random_token(18);
        plaintext.push(code);
        seeds.push(AccountMfaRecoveryCodeSeed {
            id: Uuid::new_v4(),
            code_digest: digest,
        });
    }
    (plaintext, seeds)
}

/// Decode and digest one canonical recovery code.
pub(crate) fn decode_recovery_code(code: &str) -> Result<Vec<u8>, AppError> {
    let raw = decode_canonical_token(code, 18)?;
    Ok(Sha256::digest(raw.as_slice()).to_vec())
}

/// Decode an exact canonical S256 PKCE challenge.
pub(crate) fn decode_pkce_challenge(challenge: &str) -> Result<Vec<u8>, AppError> {
    decode_canonical_token(challenge, 32).map(|decoded| decoded.to_vec())
}

/// Hash and validate one RFC 7636 high-entropy PKCE verifier.
pub(crate) fn pkce_challenge_for_verifier(verifier: &str) -> Result<Vec<u8>, AppError> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(AppError::BadRequest("PKCE verifier is invalid".into()));
    }
    Ok(Sha256::digest(verifier.as_bytes()).to_vec())
}

/// Validate and preserve one exact IP-literal loopback redirect URI.
pub(crate) fn canonical_loopback_redirect(raw: &str) -> Result<String, AppError> {
    if raw.len() > 2_048 || raw.chars().any(char::is_control) {
        return Err(AppError::BadRequest("redirect_uri is invalid".into()));
    }
    let parsed =
        Url::parse(raw).map_err(|_| AppError::BadRequest("redirect_uri is invalid".into()))?;
    let loopback = match parsed.host() {
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        Some(Host::Domain(_)) | None => false,
    };
    if parsed.scheme() != "http"
        || !loopback
        || parsed.port().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.as_str() != raw
    {
        return Err(AppError::BadRequest("redirect_uri is invalid".into()));
    }
    Ok(raw.to_string())
}

/// Validate a canonical bounded OAuth state value before reflection.
pub(crate) fn canonical_oauth_state(state: &str) -> Result<String, AppError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(state)
        .map_err(|_| AppError::BadRequest("state is invalid".into()))?;
    if !(16..=64).contains(&decoded.len()) || URL_SAFE_NO_PAD.encode(&decoded) != state {
        return Err(AppError::BadRequest("state is invalid".into()));
    }
    Ok(state.to_string())
}

/// Append an authorization code and reflected state to a validated loopback URI.
pub(crate) fn authorization_redirect(
    redirect_uri: &str,
    code: &str,
    state: &str,
) -> Result<String, AppError> {
    let mut redirect = Url::parse(redirect_uri)
        .map_err(|_| AppError::Internal("validated redirect URI became invalid".into()))?;
    redirect
        .query_pairs_mut()
        .append_pair("code", code)
        .append_pair("state", state);
    Ok(redirect.into())
}

/// Convert one standard duration into a checked UTC timestamp.
pub(crate) fn add_std_duration(
    now: DateTime<Utc>,
    duration: std::time::Duration,
    label: &'static str,
) -> Result<DateTime<Utc>, AppError> {
    let duration = Duration::from_std(duration)
        .map_err(|_| AppError::Internal(format!("{label} is invalid")))?;
    now.checked_add_signed(duration)
        .ok_or_else(|| AppError::Internal(format!("{label} exceeds the timestamp range")))
}

/// Build authenticated additional data for one encrypted TOTP seed.
fn mfa_aad(account_id: Uuid, authenticator_id: Uuid, key_version: i16) -> Vec<u8> {
    format!("frameshift-totp-v1:{account_id}:{authenticator_id}:{key_version}").into_bytes()
}

/// Generate a random canonical token with the requested byte length.
fn generate_random_token(byte_len: usize) -> (String, Vec<u8>) {
    let mut raw = Zeroizing::new(vec![0_u8; byte_len]);
    OsRng.fill_bytes(raw.as_mut_slice());
    (
        URL_SAFE_NO_PAD.encode(raw.as_slice()),
        Sha256::digest(raw.as_slice()).to_vec(),
    )
}

/// Decode canonical unpadded base64url with an exact raw byte length.
fn decode_canonical_token(
    token: &str,
    expected_len: usize,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    if token.len() > 256 || token.chars().any(char::is_whitespace) {
        return Err(AppError::Unauthorized("token is invalid or expired".into()));
    }
    let raw = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| AppError::Unauthorized("token is invalid or expired".into()))?,
    );
    if raw.len() != expected_len || URL_SAFE_NO_PAD.encode(raw.as_slice()) != token {
        return Err(AppError::Unauthorized("token is invalid or expired".into()));
    }
    Ok(raw)
}

/// Encode a client class into a stable one-byte token binding.
fn encode_client_kind(client_kind: AccountSessionClientKind) -> u8 {
    match client_kind {
        AccountSessionClientKind::Browser => 0,
        AccountSessionClientKind::Desktop => 1,
        AccountSessionClientKind::Cli => 2,
    }
}

/// Decode a stable one-byte client-class token binding.
fn decode_client_kind(value: u8) -> Option<AccountSessionClientKind> {
    match value {
        0 => Some(AccountSessionClientKind::Browser),
        1 => Some(AccountSessionClientKind::Desktop),
        2 => Some(AccountSessionClientKind::Cli),
        _ => None,
    }
}

/// Compute one six-digit HMAC-SHA256 TOTP code.
fn totp_code(secret: &[u8], timestep: i64) -> Result<String, AppError> {
    let timestep = u64::try_from(timestep)
        .map_err(|_| AppError::Unauthorized("MFA proof is invalid or expired".into()))?;
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(secret)
        .map_err(|_| AppError::Internal("TOTP key is invalid".into()))?;
    mac.update(&timestep.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(format!("{:06}", value % 10_u32.pow(TOTP_DIGITS)))
}

/// Compare equal-length byte strings without data-dependent early return.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
/// Unit tests for token, redirect, PKCE, and TOTP invariants.
mod tests {
    use super::*;

    /// Access tokens require canonical unpadded base64url encoding.
    #[test]
    fn access_tokens_round_trip_canonically() {
        let (token, digest) = generate_access_token();
        assert_eq!(decode_access_token(&token).unwrap(), digest);
        assert!(decode_access_token(&format!("{token}=")).is_err());
    }

    /// Refresh tokens retain authenticated account and session identifiers.
    #[test]
    fn refresh_tokens_round_trip_bindings() {
        let account_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::hours(1);
        let (token, digest) = generate_refresh_token(
            account_id,
            session_id,
            expires_at,
            AccountSessionClientKind::Cli,
        );
        let decoded = decode_refresh_token(&token).unwrap();
        assert_eq!(decoded.account_id, account_id);
        assert_eq!(decoded.session_id, session_id);
        assert_eq!(
            decoded.absolute_expires_at,
            DateTime::from_timestamp(expires_at.timestamp(), 0).unwrap()
        );
        assert_eq!(decoded.client_kind, AccountSessionClientKind::Cli);
        assert_eq!(decoded.digest, digest);
    }

    /// Redirect validation accepts only exact IP-literal HTTP loopback URIs.
    #[test]
    fn redirect_validation_is_loopback_only() {
        assert!(canonical_loopback_redirect("http://127.0.0.1:49152/callback").is_ok());
        assert!(canonical_loopback_redirect("http://[::1]:49152/callback").is_ok());
        assert!(canonical_loopback_redirect("http://localhost:49152/callback").is_err());
        assert!(canonical_loopback_redirect("https://127.0.0.1:49152/callback").is_err());
        assert!(canonical_loopback_redirect("http://127.0.0.1:49152/callback?x=1").is_err());
    }

    /// PKCE accepts the RFC unreserved verifier alphabet and rejects short inputs.
    #[test]
    fn pkce_verifier_is_bounded() {
        assert!(pkce_challenge_for_verifier(&"a".repeat(43)).is_ok());
        assert!(pkce_challenge_for_verifier(&"a".repeat(42)).is_err());
        assert!(pkce_challenge_for_verifier(&format!("{}!", "a".repeat(42))).is_err());
    }
}
