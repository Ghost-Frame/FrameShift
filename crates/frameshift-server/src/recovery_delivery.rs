//! Encrypted password-recovery delivery and the Resend provider boundary.
//!
//! Reset bearers are encrypted before the catalog transaction persists an
//! outbox row. Only the delivery worker decrypts a claimed payload, and the
//! provider receives a stable outbox UUID as its idempotency key.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Utc};
use frameshift_catalog::{
    CatalogBackend, PasswordRecoveryDeliveryClaimRequest, PasswordRecoveryDeliveryKind,
    PasswordRecoveryDeliveryRecord,
};
use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER, USER_AGENT};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::config::ServerConfig;

/// Resend endpoint used by the production recovery dispatcher.
const RESEND_EMAIL_ENDPOINT: &str = "https://api.resend.com/emails";
/// Bounded provider request timeout, including response-body decoding.
const RESEND_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum provider-directed retry delay accepted from an HTTP header.
const MAX_PROVIDER_RETRY_AFTER: Duration = Duration::from_secs(60 * 60);
/// Domain-separation prefix for recovery delivery associated data.
const RECOVERY_AAD_DOMAIN: &[u8] = b"frameshift-password-recovery-delivery-v1\0";
/// Version tag for an encoded reset-link payload.
const RESET_PAYLOAD_TAG: &[u8; 2] = b"R1";
/// Version tag for an encoded password-change notification.
const PASSWORD_CHANGED_PAYLOAD_TAG: &[u8; 2] = b"C1";
/// Poll interval used by the durable recovery-delivery worker.
const DEFAULT_WORKER_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Lease duration after which another worker may reclaim an abandoned row.
const DEFAULT_WORKER_CLAIM_TTL: Duration = Duration::from_secs(60);
/// Initial delay after one retryable provider failure.
const DEFAULT_WORKER_RETRY_INITIAL: Duration = Duration::from_secs(15);
/// Maximum locally calculated retry delay.
const DEFAULT_WORKER_RETRY_MAX: Duration = Duration::from_secs(60 * 60);
/// Maximum number of provider attempts for one delivery.
const DEFAULT_WORKER_MAX_ATTEMPTS: u32 = 8;
/// Maximum number of rows leased per polling cycle.
const DEFAULT_WORKER_BATCH_SIZE: u32 = 1;

/// Opaque AEAD output persisted in one delivery outbox row.
pub struct EncryptedRecoveryPayload {
    /// XChaCha20-Poly1305 ciphertext including its authentication tag.
    pub ciphertext: Vec<u8>,
    /// Random 192-bit XChaCha nonce.
    pub nonce: [u8; 24],
    /// Positive key version bound into associated data.
    pub key_version: i16,
}

/// In-memory recovery payload borrowed from one zeroizing plaintext buffer.
pub enum RecoveryDeliveryPayload<'a> {
    /// Single-use reset token and the HTTPS page that consumes its fragment.
    Reset {
        /// HTTPS marketplace recovery page without query or fragment.
        reset_url: &'a str,
        /// Canonical random reset bearer.
        token: &'a str,
    },
    /// Notification sent after a password was changed and sessions revoked.
    PasswordChanged,
}

/// Authenticated recovery-delivery cipher using one active deployment key.
pub struct RecoveryDeliveryCipher {
    /// Active 256-bit XChaCha20-Poly1305 key.
    key: [u8; 32],
    /// Positive key version stored beside every ciphertext.
    key_version: i16,
}

/// Secure construction and authenticated payload operations.
impl RecoveryDeliveryCipher {
    /// Build the active cipher when recovery is enabled and valid.
    pub fn from_config(config: &ServerConfig) -> Result<Option<Self>, String> {
        let Some(key) = config.password_recovery_key()? else {
            return Ok(None);
        };
        Ok(Some(Self {
            key,
            key_version: config.first_party_auth.recovery.key_version,
        }))
    }

    /// Encrypt one reset bearer and its configured recovery page.
    pub fn encrypt_reset(
        &self,
        outbox_id: Uuid,
        reset_url: &str,
        token: &str,
    ) -> Result<EncryptedRecoveryPayload, RecoveryCryptoError> {
        let reset_url_len =
            u16::try_from(reset_url.len()).map_err(|_| RecoveryCryptoError::InvalidPlaintext)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            RESET_PAYLOAD_TAG.len() + 2 + reset_url.len() + token.len(),
        ));
        plaintext.extend_from_slice(RESET_PAYLOAD_TAG);
        plaintext.extend_from_slice(&reset_url_len.to_be_bytes());
        plaintext.extend_from_slice(reset_url.as_bytes());
        plaintext.extend_from_slice(token.as_bytes());
        self.encrypt(
            outbox_id,
            PasswordRecoveryDeliveryKind::Reset,
            plaintext.as_slice(),
        )
    }

    /// Encrypt the fixed payload for a password-change notification.
    pub fn encrypt_password_changed(
        &self,
        outbox_id: Uuid,
    ) -> Result<EncryptedRecoveryPayload, RecoveryCryptoError> {
        self.encrypt(
            outbox_id,
            PasswordRecoveryDeliveryKind::PasswordChanged,
            PASSWORD_CHANGED_PAYLOAD_TAG,
        )
    }

    /// Decrypt and authenticate one claimed outbox payload into zeroizing memory.
    pub fn decrypt(
        &self,
        outbox_id: Uuid,
        kind: PasswordRecoveryDeliveryKind,
        key_version: i16,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RecoveryCryptoError> {
        if key_version != self.key_version {
            return Err(RecoveryCryptoError::UnknownKeyVersion);
        }
        let nonce: &[u8; 24] = nonce
            .try_into()
            .map_err(|_| RecoveryCryptoError::InvalidCiphertext)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        let aad = recovery_aad(outbox_id, kind, key_version);
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| RecoveryCryptoError::AuthenticationFailed)
    }

    /// Encrypt one encoded plaintext under random nonce and bound metadata.
    fn encrypt(
        &self,
        outbox_id: Uuid,
        kind: PasswordRecoveryDeliveryKind,
        plaintext: &[u8],
    ) -> Result<EncryptedRecoveryPayload, RecoveryCryptoError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let aad = recovery_aad(outbox_id, kind, self.key_version);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| RecoveryCryptoError::EncryptionFailed)?;
        Ok(EncryptedRecoveryPayload {
            ciphertext,
            nonce: nonce.into(),
            key_version: self.key_version,
        })
    }
}

/// Erase the active delivery key when its cipher leaves memory.
impl Drop for RecoveryDeliveryCipher {
    /// Zeroize the key bytes in place.
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Parse an authenticated plaintext without copying its bearer or URL.
pub fn parse_recovery_delivery_payload(
    plaintext: &[u8],
) -> Result<RecoveryDeliveryPayload<'_>, RecoveryCryptoError> {
    if plaintext == PASSWORD_CHANGED_PAYLOAD_TAG {
        return Ok(RecoveryDeliveryPayload::PasswordChanged);
    }
    if !plaintext.starts_with(RESET_PAYLOAD_TAG) || plaintext.len() < 4 {
        return Err(RecoveryCryptoError::InvalidPlaintext);
    }
    let reset_url_len = usize::from(u16::from_be_bytes([plaintext[2], plaintext[3]]));
    let reset_url_end = 4_usize
        .checked_add(reset_url_len)
        .filter(|end| *end < plaintext.len())
        .ok_or(RecoveryCryptoError::InvalidPlaintext)?;
    let reset_url = std::str::from_utf8(&plaintext[4..reset_url_end])
        .map_err(|_| RecoveryCryptoError::InvalidPlaintext)?;
    let token = std::str::from_utf8(&plaintext[reset_url_end..])
        .map_err(|_| RecoveryCryptoError::InvalidPlaintext)?;
    if token.is_empty() {
        return Err(RecoveryCryptoError::InvalidPlaintext);
    }
    Ok(RecoveryDeliveryPayload::Reset { reset_url, token })
}

/// Sanitized cryptographic failure classifications.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecoveryCryptoError {
    /// Enabled configuration references a key version unavailable to this process.
    #[error("unknown recovery delivery key version")]
    UnknownKeyVersion,
    /// Stored nonce or ciphertext shape is invalid.
    #[error("invalid recovery delivery ciphertext")]
    InvalidCiphertext,
    /// Associated data, nonce, ciphertext, or key failed authentication.
    #[error("recovery delivery authentication failed")]
    AuthenticationFailed,
    /// The authenticated plaintext does not match a supported encoding.
    #[error("invalid recovery delivery plaintext")]
    InvalidPlaintext,
    /// The AEAD primitive rejected encryption.
    #[error("recovery delivery encryption failed")]
    EncryptionFailed,
}

/// Successful provider acknowledgement stored with a completed outbox row.
#[derive(Debug)]
pub struct RecoveryDispatchReceipt {
    /// Provider-assigned message identifier.
    pub provider_message_id: String,
}

/// Sanitized delivery failure used to choose retry or terminal handling.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryDispatchError {
    /// A transport or provider condition that may succeed without payload changes.
    #[error("retryable recovery provider failure: {reason}")]
    Retryable {
        /// Stable non-secret failure category.
        reason: &'static str,
        /// Optional provider-directed delay capped by the adapter.
        retry_after: Option<Duration>,
    },
    /// A request or credential condition that retries cannot repair.
    #[error("permanent recovery provider failure: {reason}")]
    Permanent {
        /// Stable non-secret failure category.
        reason: &'static str,
    },
}

/// Abstract provider boundary injected into the recovery outbox worker.
#[async_trait]
pub trait RecoveryDeliveryDispatcher: Send + Sync {
    /// Deliver one authenticated plaintext using a stable provider idempotency key.
    async fn deliver(
        &self,
        outbox_id: Uuid,
        recipient: &str,
        payload: RecoveryDeliveryPayload<'_>,
    ) -> Result<RecoveryDispatchReceipt, RecoveryDispatchError>;
}

/// Bounded polling, lease, and retry policy for the delivery worker.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryDeliveryWorkerConfig {
    /// Delay between catalog claim attempts.
    pub poll_interval: Duration,
    /// Age after which an abandoned claim may be reclaimed.
    pub claim_ttl: Duration,
    /// Maximum rows acquired in one claim transaction.
    pub batch_size: u32,
    /// Delay used after the first retryable provider failure.
    pub retry_initial: Duration,
    /// Upper bound for locally calculated exponential backoff.
    pub retry_max: Duration,
    /// Maximum number of provider requests for one outbox row.
    pub max_attempts: u32,
}

/// Production defaults for the recovery delivery worker.
impl Default for RecoveryDeliveryWorkerConfig {
    /// Return conservative bounded polling, leasing, and retry settings.
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_WORKER_POLL_INTERVAL,
            claim_ttl: DEFAULT_WORKER_CLAIM_TTL,
            batch_size: DEFAULT_WORKER_BATCH_SIZE,
            retry_initial: DEFAULT_WORKER_RETRY_INITIAL,
            retry_max: DEFAULT_WORKER_RETRY_MAX,
            max_attempts: DEFAULT_WORKER_MAX_ATTEMPTS,
        }
    }
}

/// Validation for caller-supplied worker policy.
impl RecoveryDeliveryWorkerConfig {
    /// Reject zero, over-leased, or internally inconsistent policy values.
    fn validate(self) -> Result<Self, &'static str> {
        if self.poll_interval.is_zero()
            || self.claim_ttl.is_zero()
            || self.batch_size != 1
            || self.retry_initial.is_zero()
            || self.retry_max < self.retry_initial
            || self.max_attempts == 0
        {
            return Err("invalid recovery delivery worker configuration");
        }
        Ok(self)
    }
}

/// Production Resend email dispatcher with redacted credentials.
pub struct ResendRecoveryDispatcher {
    /// Redirect-free bounded HTTP client.
    client: reqwest::Client,
    /// Provider endpoint, overridable only by direct construction in tests.
    endpoint: String,
    /// Dedicated sending credential.
    api_key: SecretString,
    /// Verified FrameShift sender identity.
    from_address: String,
}

/// Construction helpers for the production provider adapter.
impl ResendRecoveryDispatcher {
    /// Build the production dispatcher when recovery configuration is complete.
    pub fn from_config(config: &ServerConfig) -> Result<Option<Self>, String> {
        let configured = match config.password_recovery_key()? {
            Some(mut delivery_key) => {
                delivery_key.zeroize();
                true
            }
            None => false,
        };
        if !configured {
            return Ok(None);
        }
        Self::new(
            RESEND_EMAIL_ENDPOINT.to_string(),
            config.first_party_auth.recovery.provider_api_key.clone(),
            config.first_party_auth.recovery.from_address.clone(),
        )
        .map(Some)
    }

    /// Build a redirect-free dispatcher for an explicit endpoint.
    pub fn new(
        endpoint: String,
        api_key: SecretString,
        from_address: String,
    ) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(RESEND_REQUEST_TIMEOUT)
            .build()
            .map_err(|error| format!("recovery provider client initialization failed: {error}"))?;
        Ok(Self {
            client,
            endpoint,
            api_key,
            from_address,
        })
    }
}

/// Redacted formatting for the concrete provider adapter.
impl std::fmt::Debug for ResendRecoveryDispatcher {
    /// Format non-secret endpoint settings while hiding the provider key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResendRecoveryDispatcher")
            .field("endpoint", &self.endpoint)
            .field("api_key", &"[REDACTED]")
            .field("from_address", &self.from_address)
            .finish_non_exhaustive()
    }
}

/// Borrowed request body accepted by the Resend send-email endpoint.
#[derive(Serialize)]
struct ResendEmailRequest<'a> {
    /// Verified sender identity.
    from: &'a str,
    /// One normalized verified account email.
    to: [&'a str; 1],
    /// Stable message subject.
    subject: &'a str,
    /// Plain-text message body.
    text: &'a str,
    /// Minimal HTML message body.
    html: &'a str,
}

/// Successful Resend response body.
#[derive(Deserialize)]
struct ResendEmailResponse {
    /// Provider-assigned message identifier.
    id: String,
}

/// Resend implementation of the recovery provider boundary.
#[async_trait]
impl RecoveryDeliveryDispatcher for ResendRecoveryDispatcher {
    /// Send one reset or password-change message without logging its body.
    async fn deliver(
        &self,
        outbox_id: Uuid,
        recipient: &str,
        payload: RecoveryDeliveryPayload<'_>,
    ) -> Result<RecoveryDispatchReceipt, RecoveryDispatchError> {
        let (subject, text, html) = render_recovery_email(payload);
        let request = ResendEmailRequest {
            from: &self.from_address,
            to: [recipient],
            subject,
            text: text.as_str(),
            html: html.as_str(),
        };
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(self.api_key.expose_secret())
            .header(
                USER_AGENT,
                concat!("frameshift/", env!("CARGO_PKG_VERSION")),
            )
            .header("Idempotency-Key", outbox_id.to_string())
            .json(&request)
            .send()
            .await
            .map_err(|_| RecoveryDispatchError::Retryable {
                reason: "transport",
                retry_after: None,
            })?;
        let status = response.status();
        let retry_after = retry_after(response.headers());
        if status == reqwest::StatusCode::OK {
            let response = response.json::<ResendEmailResponse>().await.map_err(|_| {
                RecoveryDispatchError::Retryable {
                    reason: "invalid_success_response",
                    retry_after: None,
                }
            })?;
            if response.id.is_empty()
                || response.id.len() > 256
                || response.id.trim() != response.id
                || response.id.chars().any(char::is_control)
            {
                return Err(RecoveryDispatchError::Retryable {
                    reason: "invalid_success_response",
                    retry_after: None,
                });
            }
            return Ok(RecoveryDispatchReceipt {
                provider_message_id: response.id,
            });
        }
        if status == reqwest::StatusCode::REQUEST_TIMEOUT
            || status == reqwest::StatusCode::CONFLICT
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error()
        {
            return Err(RecoveryDispatchError::Retryable {
                reason: "provider_status",
                retry_after,
            });
        }
        Err(RecoveryDispatchError::Permanent {
            reason: "provider_rejected_request",
        })
    }
}

/// Claim, decrypt, deliver, and durably settle recovery outbox rows until stopped.
pub async fn run_recovery_delivery_worker(
    catalog: Arc<dyn CatalogBackend>,
    dispatcher: Arc<dyn RecoveryDeliveryDispatcher>,
    cipher: RecoveryDeliveryCipher,
    config: RecoveryDeliveryWorkerConfig,
    mut stop: watch::Receiver<bool>,
) {
    let config = match config.validate() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "recovery delivery worker configuration rejected");
            return;
        }
    };
    let claim_ttl = match chrono::Duration::from_std(config.claim_ttl) {
        Ok(duration) => duration,
        Err(_) => {
            tracing::error!("recovery delivery worker claim duration is unsupported");
            return;
        }
    };
    let mut interval = tokio::time::interval(config.poll_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if *stop.borrow() {
            return;
        }
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {
                let now = Utc::now();
                let claim_id = Uuid::new_v4();
                let stale_before = now.checked_sub_signed(claim_ttl).unwrap_or(DateTime::<Utc>::MIN_UTC);
                let deliveries = match catalog
                    .claim_password_recovery_deliveries(PasswordRecoveryDeliveryClaimRequest {
                        claim_id,
                        claimed_at: now,
                        stale_before,
                        limit: config.batch_size,
                    })
                    .await
                {
                    Ok(deliveries) => deliveries,
                    Err(_) => {
                        tracing::warn!("recovery delivery claim failed");
                        continue;
                    }
                };

                for delivery in deliveries {
                    process_recovery_delivery(
                        catalog.as_ref(),
                        dispatcher.as_ref(),
                        &cipher,
                        config,
                        claim_id,
                        delivery,
                    )
                    .await;
                }
            }
        }
    }
}

/// Process one claimed row while preserving its catalog claim fence.
async fn process_recovery_delivery(
    catalog: &dyn CatalogBackend,
    dispatcher: &dyn RecoveryDeliveryDispatcher,
    cipher: &RecoveryDeliveryCipher,
    config: RecoveryDeliveryWorkerConfig,
    claim_id: Uuid,
    delivery: PasswordRecoveryDeliveryRecord,
) {
    if delivery.claim_id != Some(claim_id) {
        tracing::warn!(delivery_id = %delivery.id, "recovery delivery returned with an invalid claim fence");
        return;
    }

    let attempt_started_at = Utc::now();
    if attempt_started_at >= delivery.expires_at {
        fail_recovery_delivery(catalog, &delivery, claim_id, attempt_started_at, "expired").await;
        return;
    }
    if delivery.attempt_count > config.max_attempts {
        fail_recovery_delivery(
            catalog,
            &delivery,
            claim_id,
            attempt_started_at,
            "attempt_limit",
        )
        .await;
        return;
    }

    let plaintext = match cipher.decrypt(
        delivery.id,
        delivery.kind,
        delivery.key_version,
        &delivery.nonce,
        &delivery.ciphertext,
    ) {
        Ok(plaintext) => plaintext,
        Err(error) => {
            fail_recovery_delivery(
                catalog,
                &delivery,
                claim_id,
                attempt_started_at,
                recovery_crypto_error_code(&error),
            )
            .await;
            return;
        }
    };
    let payload = match parse_recovery_delivery_payload(&plaintext) {
        Ok(payload) => payload,
        Err(error) => {
            fail_recovery_delivery(
                catalog,
                &delivery,
                claim_id,
                attempt_started_at,
                recovery_crypto_error_code(&error),
            )
            .await;
            return;
        }
    };

    match dispatcher
        .deliver(delivery.id, &delivery.recipient, payload)
        .await
    {
        Ok(receipt) => {
            let sent_at = Utc::now();
            match catalog
                .mark_password_recovery_delivery_sent(
                    delivery.id,
                    claim_id,
                    sent_at,
                    receipt.provider_message_id,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(delivery_id = %delivery.id, "recovery delivery acknowledgement lost its claim fence")
                }
                Err(_) => {
                    tracing::warn!(delivery_id = %delivery.id, "recovery delivery acknowledgement failed")
                }
            }
        }
        Err(RecoveryDispatchError::Permanent { reason }) => {
            fail_recovery_delivery(catalog, &delivery, claim_id, Utc::now(), reason).await;
        }
        Err(RecoveryDispatchError::Retryable {
            reason,
            retry_after,
        }) => {
            settle_retryable_recovery_delivery(
                catalog,
                &delivery,
                claim_id,
                Utc::now(),
                config,
                retry_after,
                reason,
            )
            .await;
        }
    }
}

/// Mark one claimed delivery permanently failed with a bounded static code.
async fn fail_recovery_delivery(
    catalog: &dyn CatalogBackend,
    delivery: &PasswordRecoveryDeliveryRecord,
    claim_id: Uuid,
    failed_at: DateTime<Utc>,
    error_code: &'static str,
) {
    match catalog
        .fail_password_recovery_delivery(delivery.id, claim_id, failed_at, error_code.to_string())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(delivery_id = %delivery.id, "recovery delivery failure lost its claim fence")
        }
        Err(_) => {
            tracing::warn!(delivery_id = %delivery.id, "recovery delivery failure could not be persisted")
        }
    }
}

/// Retry one transient failure unless policy or expiry requires terminal failure.
async fn settle_retryable_recovery_delivery(
    catalog: &dyn CatalogBackend,
    delivery: &PasswordRecoveryDeliveryRecord,
    claim_id: Uuid,
    failed_at: DateTime<Utc>,
    config: RecoveryDeliveryWorkerConfig,
    provider_delay: Option<Duration>,
    error_code: &'static str,
) {
    if delivery.attempt_count >= config.max_attempts {
        fail_recovery_delivery(catalog, delivery, claim_id, failed_at, "attempt_limit").await;
        return;
    }
    let delay = recovery_retry_delay(config, delivery.attempt_count, provider_delay);
    let Ok(delay) = chrono::Duration::from_std(delay) else {
        fail_recovery_delivery(
            catalog,
            delivery,
            claim_id,
            failed_at,
            "invalid_retry_delay",
        )
        .await;
        return;
    };
    let Some(next_attempt_at) = failed_at.checked_add_signed(delay) else {
        fail_recovery_delivery(
            catalog,
            delivery,
            claim_id,
            failed_at,
            "invalid_retry_delay",
        )
        .await;
        return;
    };
    if next_attempt_at >= delivery.expires_at {
        fail_recovery_delivery(catalog, delivery, claim_id, failed_at, "retry_after_expiry").await;
        return;
    }

    match catalog
        .retry_password_recovery_delivery(
            delivery.id,
            claim_id,
            next_attempt_at,
            error_code.to_string(),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(delivery_id = %delivery.id, "recovery delivery retry lost its claim fence")
        }
        Err(_) => {
            tracing::warn!(delivery_id = %delivery.id, "recovery delivery retry could not be persisted")
        }
    }
}

/// Calculate capped exponential backoff while honoring a provider minimum.
fn recovery_retry_delay(
    config: RecoveryDeliveryWorkerConfig,
    attempt_count: u32,
    provider_delay: Option<Duration>,
) -> Duration {
    let exponent = attempt_count.saturating_sub(1).min(16);
    let multiplier = 1_u32 << exponent;
    let local_delay = config
        .retry_initial
        .saturating_mul(multiplier)
        .min(config.retry_max);
    provider_delay
        .map(|delay| local_delay.max(delay.min(MAX_PROVIDER_RETRY_AFTER)))
        .unwrap_or(local_delay)
}

/// Map cryptographic details to non-secret bounded persistence codes.
fn recovery_crypto_error_code(error: &RecoveryCryptoError) -> &'static str {
    match error {
        RecoveryCryptoError::UnknownKeyVersion => "unknown_key_version",
        RecoveryCryptoError::InvalidCiphertext => "invalid_ciphertext",
        RecoveryCryptoError::AuthenticationFailed => "authentication_failed",
        RecoveryCryptoError::InvalidPlaintext => "invalid_plaintext",
        RecoveryCryptoError::EncryptionFailed => "encryption_failed",
    }
}

/// Build stable text and HTML bodies from one authenticated payload.
fn render_recovery_email(
    payload: RecoveryDeliveryPayload<'_>,
) -> (&'static str, Zeroizing<String>, Zeroizing<String>) {
    match payload {
        RecoveryDeliveryPayload::Reset { reset_url, token } => {
            let link = Zeroizing::new(format!("{reset_url}#token={token}"));
            let escaped_link = escape_html(link.as_str());
            (
                "Reset your FrameShift password",
                Zeroizing::new(format!(
                    "A password reset was requested for your FrameShift account. Open this link to choose a new password:\n\n{}\n\nIf you did not request this, you can ignore this email.",
                    link.as_str()
                )),
                Zeroizing::new(format!(
                    "<p>A password reset was requested for your FrameShift account.</p><p><a href=\"{}\">Choose a new password</a></p><p>If you did not request this, you can ignore this email.</p>",
                    escaped_link.as_str()
                )),
            )
        }
        RecoveryDeliveryPayload::PasswordChanged => (
            "Your FrameShift password was changed",
            Zeroizing::new(
                "Your FrameShift password was changed and all existing sessions were signed out. If you did not make this change, contact FrameShift support immediately."
                    .to_string(),
            ),
            Zeroizing::new(
                "<p>Your FrameShift password was changed and all existing sessions were signed out.</p><p>If you did not make this change, contact FrameShift support immediately.</p>"
                    .to_string(),
            ),
        ),
    }
}

/// Escape the five HTML-sensitive characters in one configured reset link.
fn escape_html(value: &str) -> Zeroizing<String> {
    let mut escaped = Zeroizing::new(String::with_capacity(value.len()));
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Parse and cap an integer `Retry-After` delay without reading response bodies.
fn retry_after(headers: &HeaderMap<HeaderValue>) -> Option<Duration> {
    let seconds = headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()?;
    Some(Duration::from_secs(seconds).min(MAX_PROVIDER_RETRY_AFTER))
}

/// Construct unambiguous associated data for one immutable outbox identity.
fn recovery_aad(outbox_id: Uuid, kind: PasswordRecoveryDeliveryKind, key_version: i16) -> Vec<u8> {
    let kind_tag = match kind {
        PasswordRecoveryDeliveryKind::Reset => 1_u8,
        PasswordRecoveryDeliveryKind::PasswordChanged => 2_u8,
    };
    let mut aad = Vec::with_capacity(RECOVERY_AAD_DOMAIN.len() + 16 + 1 + 2);
    aad.extend_from_slice(RECOVERY_AAD_DOMAIN);
    aad.extend_from_slice(outbox_id.as_bytes());
    aad.push(kind_tag);
    aad.extend_from_slice(&key_version.to_be_bytes());
    aad
}

#[cfg(test)]
/// Unit tests for authenticated payloads and provider response handling.
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    /// Build a complete server configuration around one deterministic delivery key.
    fn recovery_config(key: [u8; 32]) -> ServerConfig {
        let mut config = crate::config::test_support::minimal_test_config();
        config.cors_allowed_origins = "https://frameshift.test".to_string();
        config.first_party_auth.password_pepper =
            SecretString::new("test-password-pepper".to_string());
        config.first_party_auth.mfa_encryption_key =
            SecretString::new(URL_SAFE_NO_PAD.encode([17_u8; 32]));
        config.first_party_auth.native_authorization_url =
            "https://frameshift.test/account/".to_string();
        config.first_party_auth.recovery.enabled = true;
        config.first_party_auth.recovery.provider_api_key =
            SecretString::new("re_test_key".to_string());
        config.first_party_auth.recovery.from_address =
            "FrameShift <recovery@frameshift.test>".to_string();
        config.first_party_auth.recovery.reset_url = "https://frameshift.test/recover/".to_string();
        config.first_party_auth.recovery.delivery_key =
            SecretString::new(URL_SAFE_NO_PAD.encode(key));
        config
    }

    #[test]
    /// Ciphertext round-trips only with its exact outbox metadata and key.
    fn recovery_cipher_authenticates_metadata() {
        let config = recovery_config([3_u8; 32]);
        let cipher = RecoveryDeliveryCipher::from_config(&config)
            .unwrap()
            .expect("enabled cipher");
        let outbox_id = Uuid::new_v4();
        let encrypted = cipher
            .encrypt_reset(
                outbox_id,
                "https://frameshift.test/recover/",
                "secret-token",
            )
            .unwrap();
        assert!(!encrypted
            .ciphertext
            .windows("secret-token".len())
            .any(|window| window == b"secret-token"));

        let plaintext = cipher
            .decrypt(
                outbox_id,
                PasswordRecoveryDeliveryKind::Reset,
                encrypted.key_version,
                &encrypted.nonce,
                &encrypted.ciphertext,
            )
            .unwrap();
        let parsed = parse_recovery_delivery_payload(&plaintext).unwrap();
        assert!(matches!(
            parsed,
            RecoveryDeliveryPayload::Reset {
                reset_url: "https://frameshift.test/recover/",
                token: "secret-token"
            }
        ));
        assert!(matches!(
            cipher.decrypt(
                Uuid::new_v4(),
                PasswordRecoveryDeliveryKind::Reset,
                encrypted.key_version,
                &encrypted.nonce,
                &encrypted.ciphertext,
            ),
            Err(RecoveryCryptoError::AuthenticationFailed)
        ));
    }

    #[tokio::test]
    /// Resend dispatch includes a stable idempotency key and both message formats.
    async fn resend_dispatch_uses_outbox_idempotency() {
        let observed = Arc::new(Mutex::new(None::<(HeaderMap, Value)>));
        let server_observed = Arc::clone(&observed);
        let app = Router::new().route(
            "/emails",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                let observed = Arc::clone(&server_observed);
                async move {
                    *observed.lock().unwrap() = Some((headers, body));
                    (StatusCode::OK, Json(json!({"id": "provider-message"})))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/emails", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dispatcher = ResendRecoveryDispatcher::new(
            endpoint,
            SecretString::new("provider-secret".to_string()),
            "FrameShift <recovery@frameshift.test>".to_string(),
        )
        .unwrap();
        let outbox_id = Uuid::new_v4();

        let receipt = dispatcher
            .deliver(
                outbox_id,
                "creator@example.test",
                RecoveryDeliveryPayload::Reset {
                    reset_url: "https://frameshift.test/recover/",
                    token: "secret-token",
                },
            )
            .await
            .unwrap();
        assert_eq!(receipt.provider_message_id, "provider-message");
        let (headers, body) = observed.lock().unwrap().take().unwrap();
        assert_eq!(headers["idempotency-key"], outbox_id.to_string());
        assert_eq!(body["to"][0], "creator@example.test");
        assert!(body["text"]
            .as_str()
            .unwrap()
            .contains("#token=secret-token"));
        assert!(body["html"]
            .as_str()
            .unwrap()
            .contains("#token=secret-token"));
        server.abort();
    }

    #[tokio::test]
    /// Provider throttling returns a capped retryable classification.
    async fn resend_dispatch_honors_retry_after() {
        let app = Router::new().route(
            "/emails",
            post(|| async {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("retry-after", "999999")],
                    Json(json!({"name": "rate_limit_exceeded"})),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/emails", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dispatcher = ResendRecoveryDispatcher::new(
            endpoint,
            SecretString::new("provider-secret".to_string()),
            "recovery@frameshift.test".to_string(),
        )
        .unwrap();

        let error = dispatcher
            .deliver(
                Uuid::new_v4(),
                "creator@example.test",
                RecoveryDeliveryPayload::PasswordChanged,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RecoveryDispatchError::Retryable {
                retry_after: Some(delay),
                ..
            } if delay == MAX_PROVIDER_RETRY_AFTER
        ));
        server.abort();
    }

    #[tokio::test]
    /// Invalid provider identifiers never reach the catalog acknowledgement path.
    async fn resend_dispatch_rejects_invalid_success_identifier() {
        let app = Router::new().route(
            "/emails",
            post(|| async { (StatusCode::OK, Json(json!({"id": ""}))) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/emails", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dispatcher = ResendRecoveryDispatcher::new(
            endpoint,
            SecretString::new("provider-secret".to_string()),
            "recovery@frameshift.test".to_string(),
        )
        .unwrap();

        let error = dispatcher
            .deliver(
                Uuid::new_v4(),
                "creator@example.test",
                RecoveryDeliveryPayload::PasswordChanged,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RecoveryDispatchError::Retryable {
                reason: "invalid_success_response",
                retry_after: None,
            }
        ));
        server.abort();
    }
}
