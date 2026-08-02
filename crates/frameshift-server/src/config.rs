//! Server configuration: [`ServerConfig`], [`LogFormat`], and environment-based
//! parsing via [`figment`].
//!
//! All configuration is read from environment variables at process start.
//! Sensible dev-friendly defaults are provided for every field except
//! `postgres_url`, which defaults to an empty string (production MUST override).
//!
//! # Environment variables
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `BIND_ADDR` | `0.0.0.0:3000` | TCP socket address to listen on |
//! | `POSTGRES_URL` | `""` | Full PostgreSQL connection URL |
//! | `OBJECT_STORE_ROOT` | `/tmp/frameshift-objects` | Root directory for the filesystem object store |
//! | `LOG_LEVEL` | `info` | `tracing` subscriber filter string |
//! | `LOG_FORMAT` | `text` | `json` or `text` |
//! | `MAX_REQUEST_BYTES` | `1048576` (1 MiB) | Maximum allowed request body size |
//! | `MAX_SEARCH_LIMIT` | `200` | Maximum value for `?limit=` on search endpoints |
//! | `SHUTDOWN_GRACE` | `30` | Seconds to wait for in-flight requests during shutdown |
//! | `CORS_ALLOWED_ORIGINS` | `""` | Comma-separated list of allowed CORS origins; empty disables CORS |
//! | `DOWNLOAD_SECRET` | `""` | 64-char hex (32 bytes) HMAC key for signed download URLs; empty disables the download endpoints |
//! | `DOWNLOAD_TOKEN_TTL` | `300` | Default TTL in seconds for newly minted download tokens (5 minutes) |
//! | `DOWNLOAD_MAX_TOKEN_TTL` | `1800` | Hard cap on token TTL accepted by the verifier (30 minutes) |
//! | `DOWNLOAD_RATE_PER_MIN` | `10` | Per-IP rate limit on the mint endpoint (requests/minute); 0 disables |
//! | `ABUSE_RATE_PER_MIN` | `60` | Per-IP limit on signed writes and telemetry (requests/minute); 0 disables |
//! | `ACCOUNT_RATE_PER_MIN` | `120` | Per-account limit on authenticated account routes (requests/minute); 0 disables |
//! | `SIGNER_RATE_PER_MIN` | `60` | Per-signing-key limit on verified signed writes (requests/minute); 0 disables |
//! | `PUBLISHER_RATE_PER_MIN` | `60` | Per-publisher limit on authorized publisher writes (requests/minute); 0 disables |
//! | `METRICS_BEARER_TOKEN` | `""` | Bearer token required by `/metrics`; empty disables the endpoint |
//! | `FRAMESHIFT_PUBLISHER_PUBKEYS` | `""` | Admitted publisher keys; empty disables registration and publishing |
//! | `MAX_VERSIONS_PER_AUTHOR` | `100` | Maximum retained versions per admitted author; 0 disables |
//! | `MAX_BYTES_PER_AUTHOR` | `1073741824` | Maximum retained archive bytes per admitted author; 0 disables |
//! | `OBJECT_STORE_BACKEND` | `fs` | `fs` (filesystem) or `r2` (S3-compatible / Cloudflare R2) |
//! | `R2_ENDPOINT` | `""` | S3 endpoint URL for R2 (required when backend is `r2`) |
//! | `R2_BUCKET` | `""` | Bucket name (required when backend is `r2`) |
//! | `R2_PREFIX` | `objects` | Key prefix for pack blobs inside the bucket |
//! | `R2_REGION` | `auto` | S3 region (R2 always uses `auto`) |
//! | `R2_ACCESS_KEY_ID` | `""` | Access key ID for the bucket |
//! | `R2_SECRET_ACCESS_KEY` | `""` | Secret access key (supplied via a secrets manager in production) |
//! | `QUARANTINE_OBJECT_STORE_BACKEND` | `disabled` | `disabled`, `fs`, or `r2`; enables account-backed submission routes only when explicitly configured |
//! | `QUARANTINE_OBJECT_STORE_ROOT` | `/tmp/frameshift-quarantine` | Root directory for the filesystem quarantine store |
//! | `QUARANTINE_R2_ENDPOINT` | `""` | S3 endpoint URL for the quarantine store |
//! | `QUARANTINE_R2_BUCKET` | `""` | Quarantine bucket name |
//! | `QUARANTINE_R2_PREFIX` | `quarantine` | Key prefix for quarantined archives |
//! | `QUARANTINE_R2_REGION` | `auto` | S3 region for the quarantine store |
//! | `QUARANTINE_R2_ACCESS_KEY_ID` | `""` | Quarantine-store access key ID |
//! | `QUARANTINE_R2_SECRET_ACCESS_KEY` | `""` | Quarantine-store secret access key |
//! | `TRUST_FORWARDED_FOR` | `false` | Trust `X-Forwarded-For` for rate-limit key extraction; set `true` only behind a trusted proxy |
//! | `SIGNED_REQUEST_MAX_SKEW_SECS` | `300` | Max allowed clock skew (seconds) between a signed write request's timestamp and server time; also bounds the replay-nonce retention window |
//! | `FRAMESHIFT_ADMIN_PUBKEYS` | `""` | Deprecated compatibility setting; account-role administrator routes ignore it |
//! | `PUBLISHER_OWNERSHIP_READS` | `true` | Add publisher-preferred ownership metadata to pack read responses; false returns the legacy response shape |
//! | `OIDC_ENABLED` | `false` | Enable OIDC-backed account routes when the remaining OIDC configuration is valid |
//! | `OIDC_ISSUER` | `""` | Exact OIDC issuer URL |
//! | `OIDC_AUDIENCE` | `""` | Required access-token audience |
//! | `OIDC_JWKS_URL` | `""` | Optional explicit JWKS URL; empty uses OIDC discovery |
//! | `OIDC_ALLOWED_ALGORITHMS` | `RS256` | Comma-separated asymmetric JWT algorithms |
//! | `OIDC_JWKS_CACHE_SECS` | `300` | Fresh JWKS cache lifetime |
//! | `OIDC_JWKS_STALE_SECS` | `900` | Additional stale-key window used only during provider outages |
//! | `OIDC_CLOCK_SKEW_SECS` | `30` | Token validation clock skew allowance |
//! | `OIDC_FRESH_AUTH_SECS` | `300` | Maximum `auth_time` age for sensitive key operations |
//! | `INVITE_TURNSTILE_SITE_KEY` | `""` | Public Turnstile site key; empty disables invite intake |
//! | `INVITE_TURNSTILE_SECRET` | `""` | Secret Turnstile verification key |
//! | `INVITE_TURNSTILE_EXPECTED_HOSTNAME` | `""` | Exact hostname accepted from Turnstile |
//! | `INVITE_TURNSTILE_VERIFY_URL` | Cloudflare Siteverify | Turnstile verification endpoint |
//! | `LOCAL_AUTH_PASSWORD_PEPPER` | `""` | Credential-broker password pepper; empty disables first-party auth |
//! | `LOCAL_AUTH_PEPPER_VERSION` | `1` | Positive version stored beside password hashes |
//! | `LOCAL_AUTH_PREVIOUS_PEPPERS` | `""` | Comma-separated `version:secret` entries for peppers rotated out of `LOCAL_AUTH_PASSWORD_PEPPER`; lets credentials hashed under an older pepper version keep verifying instead of being permanently locked out by rotation |
//! | `LOCAL_AUTH_ISSUER` | FrameShift first-party URL | Stable issuer written to local account rows |
//! | `LOCAL_AUTH_COOKIE_NAME` | `__Host-frameshift_session` | Secure browser session cookie name |
//! | `LOCAL_AUTH_INVITE_TTL_SECS` | `604800` | Lifetime of reviewer-issued invitations |
//! | `LOCAL_AUTH_BROWSER_IDLE_SECS` | `604800` | Browser session inactivity lifetime |
//! | `LOCAL_AUTH_BEARER_IDLE_SECS` | `2592000` | Desktop and CLI session inactivity lifetime |
//! | `LOCAL_AUTH_ABSOLUTE_SECS` | `7776000` | Non-extendable lifetime for every local session |
//! | `LOCAL_AUTH_RECOVERY_ENABLED` | `false` | Enable fail-closed first-party password recovery when every remaining recovery setting is valid |
//! | `LOCAL_AUTH_RECOVERY_API_KEY` | `""` | Dedicated Resend sending key supplied by the credential broker |
//! | `LOCAL_AUTH_RECOVERY_FROM` | `""` | Verified FrameShift sender identity used for recovery mail |
//! | `LOCAL_AUTH_RECOVERY_RESET_URL` | `""` | HTTPS marketplace recovery page URL; reset bearers are appended only as URL fragments |
//! | `LOCAL_AUTH_RECOVERY_DELIVERY_KEY` | `""` | Base64url-no-padding encoded 256-bit key used only for delivery-payload AEAD |
//! | `LOCAL_AUTH_RECOVERY_KEY_VERSION` | `1` | Positive key version bound into recovery outbox ciphertext AAD |
//! | `LOCAL_AUTH_RECOVERY_TOKEN_TTL_SECS` | `3600` | Single-use reset-token lifetime, capped at 24 hours |
//! | `LOCAL_AUTH_RECOVERY_COOLDOWN_SECS` | `900` | Minimum interval between reset deliveries for one account |
//!
//! Env var names match the struct field names verbatim (figment maps
//! `download_secret` <-> `DOWNLOAD_SECRET`); shorter aliases would require an
//! explicit remap step which we don't have yet. The deprecated
//! `FRAMESHIFT_ADMIN_PUBKEYS` setting and publisher admission setting retain
//! their historical prefix for configuration compatibility.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use figment::providers::{Env, Serialized};
use figment::Figment;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Maximum lifetime allowed for an emailed password-recovery bearer.
const MAX_RECOVERY_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Maximum accepted Resend API credential size before header construction.
const MAX_RECOVERY_PROVIDER_KEY_BYTES: usize = 512;

/// Log output format.
///
/// Controls whether `tracing-subscriber` emits compact human-readable text or
/// structured JSON lines. JSON is preferred in production; text is more legible
/// during local development.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Structured JSON output, one object per log line.
    Json,
    /// Human-readable compact text output.
    Text,
}

/// OIDC resource-server configuration for account bearer authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Whether authenticated account routes may be mounted.
    pub enabled: bool,
    /// Exact issuer expected in discovery metadata and token claims.
    pub issuer: String,
    /// Audience required in every accepted access token.
    pub audience: String,
    /// Optional operator-pinned JWKS endpoint; empty enables discovery.
    pub jwks_url: String,
    /// Explicit allowlist of accepted asymmetric JWT algorithms.
    pub allowed_algorithms: Vec<String>,
    /// Duration for which fetched JWKS data is considered fresh.
    pub jwks_cache_ttl: Duration,
    /// Additional duration stale keys may be used when refresh fails.
    pub jwks_stale_ttl: Duration,
    /// Allowed clock skew for `exp`, `nbf`, and related time claims.
    pub clock_skew: Duration,
    /// Maximum age of `auth_time` for security-sensitive operations.
    pub fresh_auth_max_age: Duration,
}

/// Constructors for OIDC configuration states.
impl OidcConfig {
    /// Return a fully disabled OIDC configuration for tests and local defaults.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            audience: String::new(),
            jwks_url: String::new(),
            allowed_algorithms: vec!["RS256".to_string()],
            jwks_cache_ttl: Duration::from_secs(300),
            jwks_stale_ttl: Duration::from_secs(900),
            clock_skew: Duration::from_secs(30),
            fresh_auth_max_age: Duration::from_secs(300),
        }
    }
}

/// Anti-bot configuration for the public invite application endpoint.
#[derive(Clone)]
pub struct InviteRequestConfig {
    /// Public Turnstile site key rendered by the marketplace.
    pub turnstile_site_key: String,
    /// Secret Turnstile key used only by the server-side verifier.
    pub turnstile_secret: SecretString,
    /// Exact marketplace hostname expected in successful verification responses.
    pub expected_hostname: String,
    /// Operator-configurable Siteverify URL, primarily for isolated integration tests.
    pub verify_url: String,
}

/// Constructors and readiness checks for invite application configuration.
impl InviteRequestConfig {
    /// Return a disabled configuration that fails closed at the HTTP boundary.
    pub fn disabled() -> Self {
        Self {
            turnstile_site_key: String::new(),
            turnstile_secret: SecretString::new(String::new()),
            expected_hostname: String::new(),
            verify_url: "https://challenges.cloudflare.com/turnstile/v0/siteverify".to_string(),
        }
    }

    /// Return whether every production verification input is configured.
    pub fn enabled(&self) -> bool {
        use secrecy::ExposeSecret as _;

        !self.turnstile_site_key.trim().is_empty()
            && !self.turnstile_secret.expose_secret().trim().is_empty()
            && !self.expected_hostname.trim().is_empty()
            && !self.verify_url.trim().is_empty()
    }
}

/// Redacted formatting for public invite configuration and its secret verifier key.
impl std::fmt::Debug for InviteRequestConfig {
    /// Format non-secret settings while replacing the Turnstile secret with a marker.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteRequestConfig")
            .field("turnstile_site_key", &self.turnstile_site_key)
            .field("turnstile_secret", &"[REDACTED]")
            .field("expected_hostname", &self.expected_hostname)
            .field("verify_url", &self.verify_url)
            .finish()
    }
}

/// Fail-closed password-recovery and delivery configuration.
#[derive(Clone)]
pub struct PasswordRecoveryConfig {
    /// Whether public recovery endpoints and the delivery worker may operate.
    pub enabled: bool,
    /// Dedicated Resend API credential supplied by the credential broker.
    pub provider_api_key: SecretString,
    /// Verified sender identity used for reset and password-change mail.
    pub from_address: String,
    /// HTTPS marketplace page that consumes a reset token from its URL fragment.
    pub reset_url: String,
    /// Base64url-no-padding encoded 256-bit XChaCha20-Poly1305 key.
    pub delivery_key: SecretString,
    /// Positive version bound into encrypted delivery-payload AAD.
    pub key_version: i16,
    /// Exclusive lifetime of a single-use password-reset token.
    pub token_ttl: Duration,
    /// Minimum interval between reset deliveries for one account.
    pub request_cooldown: Duration,
}

/// Constructors and strict validation for password-recovery configuration.
impl PasswordRecoveryConfig {
    /// Return a disabled configuration suitable for tests and deployments without mail.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            provider_api_key: SecretString::new(String::new()),
            from_address: String::new(),
            reset_url: String::new(),
            delivery_key: SecretString::new(String::new()),
            key_version: 1,
            token_ttl: Duration::from_secs(60 * 60),
            request_cooldown: Duration::from_secs(15 * 60),
        }
    }

    /// Validate all enabled settings and decode the active 256-bit delivery key.
    pub fn decoded_delivery_key(&self) -> Result<Option<[u8; 32]>, String> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use secrecy::ExposeSecret as _;

        if !self.enabled {
            return Ok(None);
        }
        let provider_api_key = self.provider_api_key.expose_secret();
        if provider_api_key.trim().is_empty()
            || provider_api_key.trim() != provider_api_key
            || provider_api_key.len() > MAX_RECOVERY_PROVIDER_KEY_BYTES
            || provider_api_key.chars().any(char::is_control)
        {
            return Err(
                "LOCAL_AUTH_RECOVERY_API_KEY must be a bounded canonical credential".into(),
            );
        }
        if self.from_address.trim().is_empty()
            || self.from_address.trim() != self.from_address
            || !self.from_address.contains('@')
            || self.from_address.len() > 320
            || self.from_address.chars().any(char::is_control)
        {
            return Err("LOCAL_AUTH_RECOVERY_FROM must be a bounded sender identity".into());
        }
        let reset_url = url::Url::parse(&self.reset_url)
            .map_err(|error| format!("LOCAL_AUTH_RECOVERY_RESET_URL is invalid: {error}"))?;
        if reset_url.scheme() != "https"
            || reset_url.host_str().is_none()
            || !reset_url.username().is_empty()
            || reset_url.password().is_some()
            || reset_url.query().is_some()
            || reset_url.fragment().is_some()
        {
            return Err(
                "LOCAL_AUTH_RECOVERY_RESET_URL must be an HTTPS URL without credentials, query, or fragment"
                    .into(),
            );
        }
        if self.key_version <= 0 {
            return Err("LOCAL_AUTH_RECOVERY_KEY_VERSION must be positive".into());
        }
        if self.token_ttl.is_zero() || self.token_ttl > MAX_RECOVERY_TOKEN_TTL {
            return Err("LOCAL_AUTH_RECOVERY_TOKEN_TTL_SECS must be between 1 and 86400".into());
        }
        if self.request_cooldown.is_zero() || self.request_cooldown > self.token_ttl {
            return Err(
                "LOCAL_AUTH_RECOVERY_COOLDOWN_SECS must be positive and no greater than the token TTL"
                    .into(),
            );
        }

        let encoded_key = self.delivery_key.expose_secret();
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded_key).map_err(|error| {
            format!("LOCAL_AUTH_RECOVERY_DELIVERY_KEY base64url decode failed: {error}")
        })?);
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != encoded_key.as_str()
        {
            return Err(
                "LOCAL_AUTH_RECOVERY_DELIVERY_KEY must be canonical base64url for exactly 32 bytes"
                    .into(),
            );
        }
        let mut key = [0_u8; 32];
        key.copy_from_slice(decoded.as_slice());
        Ok(Some(key))
    }
}

/// Redacted formatting for password-recovery configuration.
impl std::fmt::Debug for PasswordRecoveryConfig {
    /// Format non-secret recovery settings while replacing both credentials with markers.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordRecoveryConfig")
            .field("enabled", &self.enabled)
            .field("provider_api_key", &"[REDACTED]")
            .field("from_address", &self.from_address)
            .field("reset_url", &self.reset_url)
            .field("delivery_key", &"[REDACTED]")
            .field("key_version", &self.key_version)
            .field("token_ttl", &self.token_ttl)
            .field("request_cooldown", &self.request_cooldown)
            .finish()
    }
}

/// First-party password, invitation, session, and recovery configuration.
#[derive(Clone)]
pub struct FirstPartyAuthConfig {
    /// Deployment pepper supplied by the credential broker.
    pub password_pepper: SecretString,
    /// Positive pepper version stored beside newly created hashes.
    pub pepper_version: i16,
    /// Pepper values rotated out of `password_pepper`, keyed by the
    /// `pepper_version` that was current when they were stamped beside a
    /// stored credential.
    ///
    /// Rotating `LOCAL_AUTH_PASSWORD_PEPPER` (and bumping
    /// `LOCAL_AUTH_PEPPER_VERSION`) without retaining the prior pepper here
    /// would permanently lock out every existing account, because
    /// verification would always run Argon2 with a pepper that never
    /// produced the stored hash. Empty by default, matching prior behavior
    /// exactly when no rotation has occurred.
    pub previous_peppers: HashMap<i16, SecretString>,
    /// Stable issuer written to first-party account rows.
    pub issuer: String,
    /// Secure browser session cookie name.
    pub cookie_name: String,
    /// Lifetime of reviewer-issued invitation tokens.
    pub invite_ttl: Duration,
    /// Sliding inactivity lifetime for browser sessions.
    pub browser_idle_ttl: Duration,
    /// Sliding inactivity lifetime for desktop and CLI bearer sessions.
    pub bearer_idle_ttl: Duration,
    /// Non-extendable maximum session lifetime.
    pub absolute_ttl: Duration,
    /// Optional password-recovery and mail-delivery settings.
    pub recovery: PasswordRecoveryConfig,
}

/// Constructors and readiness checks for first-party account authentication.
impl FirstPartyAuthConfig {
    /// Return a disabled configuration suitable for tests and local development.
    pub fn disabled() -> Self {
        Self {
            password_pepper: SecretString::new(String::new()),
            pepper_version: 1,
            previous_peppers: HashMap::new(),
            issuer: "https://frameshift.syntheos.dev/first-party".to_string(),
            cookie_name: "__Host-frameshift_session".to_string(),
            invite_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            browser_idle_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            bearer_idle_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            absolute_ttl: Duration::from_secs(90 * 24 * 60 * 60),
            recovery: PasswordRecoveryConfig::disabled(),
        }
    }

    /// Return whether the password pepper and all bounded settings are valid.
    pub fn enabled(&self) -> bool {
        use secrecy::ExposeSecret as _;

        !self.password_pepper.expose_secret().is_empty()
            && self.pepper_version > 0
            && !self.issuer.trim().is_empty()
            && self.cookie_name.starts_with("__Host-")
            && !self.cookie_name.contains([';', ' ', '\t', '\r', '\n'])
            && !self.invite_ttl.is_zero()
            && !self.browser_idle_ttl.is_zero()
            && !self.bearer_idle_ttl.is_zero()
            && self.absolute_ttl >= self.browser_idle_ttl
            && self.absolute_ttl >= self.bearer_idle_ttl
    }
}

/// Redacted formatting for first-party authentication configuration.
impl std::fmt::Debug for FirstPartyAuthConfig {
    /// Format non-secret settings while replacing the password pepper with a marker.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirstPartyAuthConfig")
            .field("password_pepper", &"[REDACTED]")
            .field("pepper_version", &self.pepper_version)
            .field(
                "previous_peppers",
                &format!("[REDACTED x{}]", self.previous_peppers.len()),
            )
            .field("issuer", &self.issuer)
            .field("cookie_name", &self.cookie_name)
            .field("invite_ttl", &self.invite_ttl)
            .field("browser_idle_ttl", &self.browser_idle_ttl)
            .field("bearer_idle_ttl", &self.bearer_idle_ttl)
            .field("absolute_ttl", &self.absolute_ttl)
            .field("recovery", &self.recovery)
            .finish()
    }
}

/// Full server configuration resolved from environment variables.
///
/// This struct is the single source of truth for runtime parameters. It is
/// constructed once at startup via [`ServerConfig::from_env`] and then shared
/// read-only across the application as `Arc<ServerConfig>`.
///
/// # Debug redaction
///
/// `postgres_url` is a [`SecretString`] whose raw contents are never emitted
/// by the `Debug` implementation. A manual `impl Debug` on this struct
/// replaces the URL with `"[REDACTED]"`.
#[derive(Clone)]
pub struct ServerConfig {
    /// TCP address the HTTP server will bind to.
    ///
    /// Default: `0.0.0.0:3000`.
    pub bind_addr: SocketAddr,

    /// Full PostgreSQL connection URL (e.g. `postgres://user:pass@host/db`).
    ///
    /// Stored as a [`SecretString`] and never printed in logs or `Debug` output.
    pub postgres_url: SecretString,

    /// Filesystem root for the object store adapter.
    ///
    /// Default: `/tmp/frameshift-objects`.
    pub object_store_root: PathBuf,

    /// `tracing` subscriber filter directive string.
    ///
    /// Accepts the same syntax as `RUST_LOG` (e.g. `info`, `debug,tower=warn`).
    /// Default: `info`.
    pub log_level: String,

    /// Log output format.
    ///
    /// Default: `text`.
    pub log_format: LogFormat,

    /// Maximum number of bytes allowed in a request body.
    ///
    /// Applied globally via [`tower_http::limit::RequestBodyLimitLayer`].
    /// Individual routes may apply a tighter per-route limit.
    /// Default: 1 MiB (1 048 576 bytes).
    pub max_request_bytes: usize,

    /// Maximum value accepted for the `?limit=` query parameter on search
    /// endpoints. Requests with a higher `limit` are clamped to this value and
    /// a `Warning` header is added to the response.
    ///
    /// Default: 200.
    pub max_search_limit: u32,

    /// Duration in-flight requests are allowed to complete after the shutdown
    /// signal is received before the server force-closes.
    ///
    /// Default: 30 seconds.
    pub shutdown_grace: Duration,

    /// Comma-separated list of origins allowed by the CORS preflight layer.
    ///
    /// Empty (the default) disables the CORS layer entirely. Production
    /// deployments set this to the marketplace web origin. Whitespace
    /// around commas is trimmed at parse time by
    /// [`ServerConfig::cors_origins`].
    pub cors_allowed_origins: String,

    /// HMAC key (32 bytes, hex-encoded) for signed download URLs.
    ///
    /// Empty disables the `/dl/...` and `POST /download-url` endpoints
    /// entirely. Production deployments MUST set the `DOWNLOAD_SECRET` env
    /// to a 64-char hex value generated with `openssl rand -hex 32` and
    /// supplied via a secrets manager (never committed to disk in plaintext).
    /// Stored as [`SecretString`] so the bytes never appear in `Debug`.
    pub download_secret: SecretString,

    /// Default TTL for newly minted download tokens.
    ///
    /// Short enough to limit replay if a URL leaks, long enough for slow
    /// clients to start the download. Default: 5 minutes.
    pub download_token_ttl: Duration,

    /// Hard upper bound on token TTL accepted by the verifier.
    ///
    /// Tokens whose `expires` claim is more than this far in the future are
    /// rejected even if the HMAC validates -- this protects against a future
    /// signer bug from issuing arbitrarily long-lived tokens. Default:
    /// 30 minutes.
    pub download_max_token_ttl: Duration,

    /// Per-IP rate limit (requests / minute) on the download-URL mint
    /// endpoint.
    ///
    /// `0` disables rate limiting (escape hatch for local dev or load
    /// tests). The verifier endpoint `/dl/{hash}` is NOT rate-limited --
    /// HMAC validation is the gate there. Default: 10.
    pub download_rate_per_min: u32,

    /// Per-IP rate limit for signed writes and anonymous telemetry.
    ///
    /// This bounds nonce-cache and log-amplification abuse before expensive
    /// authentication or handler work. `0` disables the limit. Default: 60.
    pub abuse_rate_per_min: u32,

    /// Per-account rate limit for authenticated account routes.
    ///
    /// Keyed by the verified durable account ID, so one account rotating
    /// source addresses stays bounded and accounts sharing one address stay
    /// individually bounded. `0` disables the limit. Default: 120.
    pub account_rate_per_min: u32,

    /// Per-signing-key rate limit for verified signed writes.
    ///
    /// Keyed by the Ed25519 key whose request signature already verified, so
    /// forged requests naming a victim key can never spend its budget. `0`
    /// disables the limit. Default: 60.
    pub signer_rate_per_min: u32,

    /// Per-publisher rate limit for authorized publisher-bound writes.
    ///
    /// Keyed by the publisher ID only after active ownership and key
    /// authorization succeed, so unauthorized callers cannot exhaust a
    /// publisher's budget. `0` disables the limit. Default: 60.
    pub publisher_rate_per_min: u32,

    /// Bearer token required to read `/metrics`.
    ///
    /// Empty disables the endpoint with `404`. Stored as [`SecretString`] so
    /// it cannot appear in debug output.
    pub metrics_bearer_token: SecretString,

    /// Base64url Ed25519 keys admitted to register and publish.
    ///
    /// Empty disables both operations. The sentinel `"*"` explicitly opts
    /// into open registration for development deployments.
    pub publisher_pubkeys: Vec<String>,

    /// Maximum retained pack versions per author; `0` disables this limit.
    pub max_versions_per_author: u64,

    /// Maximum retained archive bytes per author; `0` disables this limit.
    pub max_bytes_per_author: u64,

    /// Maximum retained archive bytes across the registry; `0` disables this limit.
    pub max_total_bytes: u64,

    /// Selected object store backend: `"fs"` (default) or `"r2"`.
    ///
    /// `main.rs` reads this to choose between [`frameshift_objects_fs`] and
    /// [`frameshift_objects_r2`]. Both implementations satisfy the
    /// [`frameshift_objects::PackStore`] trait, so handlers don't care
    /// which is wired in.
    pub object_store_backend: String,

    /// R2 endpoint URL (e.g. `https://<acct>.r2.cloudflarestorage.com`).
    ///
    /// Used only when `object_store_backend == "r2"`. Empty otherwise.
    pub r2_endpoint: String,

    /// R2 bucket name. Used only when backend is `r2`.
    pub r2_bucket: String,

    /// Key prefix for pack blobs inside the R2 bucket. Default: `objects`.
    pub r2_prefix: String,

    /// R2 region. Always `"auto"` for Cloudflare R2.
    pub r2_region: String,

    /// R2 access key ID. Used only when backend is `r2`.
    pub r2_access_key_id: String,

    /// R2 secret access key. Stored as [`SecretString`] so the bytes never
    /// appear in `Debug` output. Supplied via a secrets manager in production.
    pub r2_secret_access_key: SecretString,

    /// Quarantine object-store backend: `"disabled"`, `"fs"`, or `"r2"`.
    ///
    /// The default is `"disabled"` so an upgrade never exposes account-backed
    /// publication writes without an explicit isolated-store decision.
    pub quarantine_object_store_backend: String,

    /// Filesystem root used only by the quarantine store.
    pub quarantine_object_store_root: PathBuf,

    /// S3-compatible endpoint used only by the quarantine store.
    pub quarantine_r2_endpoint: String,

    /// S3-compatible bucket used only by the quarantine store.
    pub quarantine_r2_bucket: String,

    /// Object-key prefix used only by the quarantine store.
    pub quarantine_r2_prefix: String,

    /// S3-compatible region used only by the quarantine store.
    pub quarantine_r2_region: String,

    /// Access key ID used only by the quarantine store.
    pub quarantine_r2_access_key_id: String,

    /// Secret access key used only by the quarantine store.
    pub quarantine_r2_secret_access_key: SecretString,

    /// Whether to trust the `X-Forwarded-For` header for rate-limit key extraction.
    ///
    /// Set `true` only when a trusted reverse proxy
    /// rewrites XFF before requests reach this server. When `false` (default),
    /// the raw socket peer IP is used, preventing rate-limit bypass by clients
    /// spoofing the XFF header.
    pub trust_forwarded_for: bool,

    /// Maximum allowed clock skew between a signed write request's timestamp
    /// and the server's wall clock.
    ///
    /// Requests whose `X-Frameshift-Timestamp` is more than this far from
    /// `now` (in either direction) are rejected with `401`. This bounds the
    /// replay window: a captured signed request can only be re-sent for at
    /// most `2 * signed_request_max_skew` before the nonce can be safely
    /// forgotten. Applies to publish and author registration.
    /// Default: 300 seconds (5 minutes).
    pub signed_request_max_skew: Duration,

    /// Deprecated Ed25519 administrator allowlist retained for configuration compatibility.
    ///
    /// Account-role administrator routes do not consult this setting.
    pub admin_pubkeys: Vec<String>,

    /// Whether pack reads resolve additive publisher ownership metadata.
    ///
    /// Set this to `false` for application rollback to the exact legacy
    /// response shape while retaining additive database rows and columns.
    /// Default: `true`.
    pub publisher_ownership_reads: bool,

    /// OIDC resource-server settings for account and publisher routes.
    pub oidc: OidcConfig,

    /// Invite-only account application and anti-bot settings.
    pub invite_requests: InviteRequestConfig,

    /// First-party invitation, password, and revocable-session settings.
    pub first_party_auth: FirstPartyAuthConfig,

    /// Memory backend selector: `"none"` (default), `"http"`, or `"sqlite"`.
    ///
    /// - `"none"` -- no memory adapter; personas that require memory will fail
    ///   to load with a hard capability error.
    /// - `"http"` -- connects to an HTTP memory gateway endpoint.
    /// - `"sqlite"` -- uses a local SQLite FTS5 database.
    pub memory_backend: String,

    /// Base URL for the HTTP memory endpoint (e.g. `http://127.0.0.1:4510`).
    ///
    /// Used only when `memory_backend == "http"`. Ignored otherwise.
    pub memory_http_endpoint: String,

    /// Authentication scheme for the HTTP memory endpoint.
    ///
    /// `"none"` (default) sends no credentials. `"bearer:<token>"` sends an
    /// `Authorization: Bearer <token>` header. Used only when
    /// `memory_backend == "http"`.
    pub memory_http_auth: String,

    /// Per-attempt request timeout for the HTTP memory adapter, in seconds.
    ///
    /// Default: 30 seconds. Used only when `memory_backend == "http"`.
    pub memory_http_timeout_secs: u64,

    /// Path to the SQLite database file for the FTS memory adapter.
    ///
    /// Default: empty string (must be set when `memory_backend == "sqlite"`).
    pub memory_sqlite_path: String,
}

/// Parsing helpers for values stored in [`ServerConfig`].
impl ServerConfig {
    /// Return whether the signer is admitted to register and publish.
    pub fn publisher_allowed(&self, pubkey: &frameshift_catalog::Ed25519PublicKey) -> bool {
        let encoded = pubkey.to_string();
        self.publisher_pubkeys
            .iter()
            .any(|allowed| allowed == "*" || allowed == &encoded)
    }

    /// Iterator over CORS origins parsed from [`Self::cors_allowed_origins`].
    ///
    /// Splits on `,`, trims each entry, and skips empty segments. Yields
    /// borrowed `&str` slices into the underlying field so the caller can
    /// decide whether to validate as a `HeaderValue` or treat as a sentinel.
    pub fn cors_origins(&self) -> impl Iterator<Item = &str> {
        self.cors_allowed_origins
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// Decode [`Self::download_secret`] from hex into the 32-byte HMAC key.
    ///
    /// Returns `Ok(None)` when the secret is empty (download endpoints are
    /// administratively disabled). Returns `Err` when the secret is present
    /// but malformed (not 64 hex chars). The decoded key is wrapped in
    /// [`SecretString`] so it never appears in `Debug` output -- callers
    /// should `expose_secret()` on the result only at the HMAC call site.
    pub fn download_key(&self) -> Result<Option<[u8; 32]>, String> {
        use secrecy::ExposeSecret;
        let raw = self.download_secret.expose_secret().trim();
        if raw.is_empty() {
            return Ok(None);
        }
        let bytes =
            hex::decode(raw).map_err(|e| format!("DOWNLOAD_SECRET hex decode failed: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "DOWNLOAD_SECRET must decode to 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }

    /// Validate enabled recovery against first-party auth and the trusted web origin.
    pub fn password_recovery_key(&self) -> Result<Option<[u8; 32]>, String> {
        let key = self.first_party_auth.recovery.decoded_delivery_key()?;
        if key.is_none() {
            return Ok(None);
        }
        if !self.first_party_auth.enabled() {
            return Err(
                "LOCAL_AUTH_RECOVERY_ENABLED requires valid first-party authentication".into(),
            );
        }
        let reset_url = url::Url::parse(&self.first_party_auth.recovery.reset_url)
            .map_err(|error| format!("LOCAL_AUTH_RECOVERY_RESET_URL is invalid: {error}"))?;
        let reset_origin = reset_url.origin().ascii_serialization();
        if !self
            .cors_origins()
            .any(|configured| configured == reset_origin)
        {
            return Err(
                "LOCAL_AUTH_RECOVERY_RESET_URL origin must appear exactly in CORS_ALLOWED_ORIGINS"
                    .into(),
            );
        }
        Ok(key)
    }
}

/// Manual `Debug` implementation that redacts `postgres_url`.
///
/// All other fields are printed as-is. The raw PostgreSQL credentials are
/// replaced with `"[REDACTED]"` so that accidental debug logging never leaks
/// database credentials.
impl std::fmt::Debug for ServerConfig {
    /// Format configuration values while replacing every credential with a marker.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("bind_addr", &self.bind_addr)
            .field("postgres_url", &"[REDACTED]")
            .field("object_store_root", &self.object_store_root)
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_search_limit", &self.max_search_limit)
            .field("shutdown_grace", &self.shutdown_grace)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("download_secret", &"[REDACTED]")
            .field("download_token_ttl", &self.download_token_ttl)
            .field("download_max_token_ttl", &self.download_max_token_ttl)
            .field("download_rate_per_min", &self.download_rate_per_min)
            .field("abuse_rate_per_min", &self.abuse_rate_per_min)
            .field("account_rate_per_min", &self.account_rate_per_min)
            .field("signer_rate_per_min", &self.signer_rate_per_min)
            .field("publisher_rate_per_min", &self.publisher_rate_per_min)
            .field("metrics_bearer_token", &"[REDACTED]")
            .field(
                "publisher_pubkeys",
                &format!("[{} key(s)]", self.publisher_pubkeys.len()),
            )
            .field("max_versions_per_author", &self.max_versions_per_author)
            .field("max_bytes_per_author", &self.max_bytes_per_author)
            .field("max_total_bytes", &self.max_total_bytes)
            .field("object_store_backend", &self.object_store_backend)
            .field("r2_endpoint", &self.r2_endpoint)
            .field("r2_bucket", &self.r2_bucket)
            .field("r2_prefix", &self.r2_prefix)
            .field("r2_region", &self.r2_region)
            .field("r2_access_key_id", &self.r2_access_key_id)
            .field("r2_secret_access_key", &"[REDACTED]")
            .field(
                "quarantine_object_store_backend",
                &self.quarantine_object_store_backend,
            )
            .field(
                "quarantine_object_store_root",
                &self.quarantine_object_store_root,
            )
            .field("quarantine_r2_endpoint", &self.quarantine_r2_endpoint)
            .field("quarantine_r2_bucket", &self.quarantine_r2_bucket)
            .field("quarantine_r2_prefix", &self.quarantine_r2_prefix)
            .field("quarantine_r2_region", &self.quarantine_r2_region)
            .field(
                "quarantine_r2_access_key_id",
                &self.quarantine_r2_access_key_id,
            )
            .field("quarantine_r2_secret_access_key", &"[REDACTED]")
            .field("trust_forwarded_for", &self.trust_forwarded_for)
            .field("signed_request_max_skew", &self.signed_request_max_skew)
            .field(
                "admin_pubkeys",
                &format!("[{} key(s)]", self.admin_pubkeys.len()),
            )
            .field("publisher_ownership_reads", &self.publisher_ownership_reads)
            .field("oidc", &self.oidc)
            .field("invite_requests", &self.invite_requests)
            .field("first_party_auth", &self.first_party_auth)
            .field("memory_backend", &self.memory_backend)
            .field("memory_http_endpoint", &self.memory_http_endpoint)
            .field("memory_http_auth", &"[REDACTED]")
            .field("memory_http_timeout_secs", &self.memory_http_timeout_secs)
            .field("memory_sqlite_path", &self.memory_sqlite_path)
            .finish()
    }
}

/// Intermediate serde-friendly representation of [`ServerConfig`].
///
/// `figment` deserializes into this type (all plain `String`/`u64` values),
/// after which [`RawConfig::into_server_config`] wraps `postgres_url` in a
/// [`SecretString`] and converts numeric fields.
///
/// This indirection avoids requiring `SecretString: Serialize`, which
/// `secrecy` deliberately does not implement.
#[derive(Debug, Serialize, Deserialize)]
struct RawConfig {
    /// Bind address string, parsed into [`SocketAddr`] by `figment`.
    bind_addr: SocketAddr,

    /// PostgreSQL connection URL as a plain string (wrapped in `SecretString`
    /// during conversion to [`ServerConfig`]).
    postgres_url: String,

    /// Object store root directory path.
    object_store_root: PathBuf,

    /// Log level filter string.
    log_level: String,

    /// Log format tag.
    log_format: LogFormat,

    /// Maximum request body size in bytes.
    max_request_bytes: usize,

    /// Maximum search result limit.
    max_search_limit: u32,

    /// Graceful shutdown duration in seconds.
    shutdown_grace: u64,

    /// Comma-separated CORS allowed origins (raw string).
    cors_allowed_origins: String,

    /// HMAC key for download URLs (hex, 64 chars, optional).
    download_secret: String,

    /// Download token TTL in seconds.
    download_token_ttl: u64,

    /// Max accepted download token TTL in seconds.
    download_max_token_ttl: u64,

    /// Per-IP mint-endpoint rate limit (requests / minute).
    download_rate_per_min: u32,

    /// Per-IP signed-write and telemetry rate limit (requests / minute).
    abuse_rate_per_min: u32,

    /// Per-account authenticated-route rate limit (requests / minute).
    account_rate_per_min: u32,

    /// Per-signing-key verified-write rate limit (requests / minute).
    signer_rate_per_min: u32,

    /// Per-publisher authorized-write rate limit (requests / minute).
    publisher_rate_per_min: u32,

    /// Raw metrics bearer token, wrapped in [`SecretString`] during conversion.
    metrics_bearer_token: String,

    /// Comma-separated publisher admission keys.
    publisher_pubkeys: String,

    /// Maximum retained versions per author.
    max_versions_per_author: u64,

    /// Maximum retained archive bytes per author.
    max_bytes_per_author: u64,

    /// Maximum retained archive bytes across the registry.
    max_total_bytes: u64,

    /// Object store backend selector (`fs` | `r2`).
    object_store_backend: String,
    /// R2 endpoint URL.
    r2_endpoint: String,
    /// R2 bucket name.
    r2_bucket: String,
    /// R2 key prefix.
    r2_prefix: String,
    /// R2 region (`auto`).
    r2_region: String,
    /// R2 access key ID.
    r2_access_key_id: String,
    /// R2 secret access key (raw string, wrapped in `SecretString` on convert).
    r2_secret_access_key: String,

    /// Quarantine object-store backend selector (`disabled` | `fs` | `r2`).
    quarantine_object_store_backend: String,
    /// Filesystem root for quarantined archives.
    quarantine_object_store_root: PathBuf,
    /// S3-compatible quarantine endpoint URL.
    quarantine_r2_endpoint: String,
    /// S3-compatible quarantine bucket name.
    quarantine_r2_bucket: String,
    /// S3-compatible quarantine key prefix.
    quarantine_r2_prefix: String,
    /// S3-compatible quarantine region.
    quarantine_r2_region: String,
    /// S3-compatible quarantine access key ID.
    quarantine_r2_access_key_id: String,
    /// S3-compatible quarantine secret access key.
    quarantine_r2_secret_access_key: String,

    /// Whether to trust XFF for rate limiting (maps to `TRUST_FORWARDED_FOR`).
    trust_forwarded_for: bool,

    /// Max signed-request clock skew in seconds (maps to
    /// `SIGNED_REQUEST_MAX_SKEW_SECS`).
    signed_request_max_skew_secs: u64,

    /// Deprecated raw Ed25519 administrator allowlist compatibility value.
    admin_pubkeys: String,

    /// Whether pack reads add publisher-preferred ownership metadata.
    publisher_ownership_reads: bool,

    /// Whether OIDC-backed account routes are enabled.
    oidc_enabled: bool,
    /// Exact configured OIDC issuer URL.
    oidc_issuer: String,
    /// Required access-token audience.
    oidc_audience: String,
    /// Optional explicit JWKS endpoint.
    oidc_jwks_url: String,
    /// Comma-separated asymmetric JWT algorithm allowlist.
    oidc_allowed_algorithms: String,
    /// Fresh JWKS cache lifetime in seconds.
    oidc_jwks_cache_secs: u64,
    /// Stale-on-outage JWKS lifetime in seconds.
    oidc_jwks_stale_secs: u64,
    /// Token validation clock skew in seconds.
    oidc_clock_skew_secs: u64,
    /// Maximum fresh-auth age in seconds.
    oidc_fresh_auth_secs: u64,

    /// Public Turnstile site key for the invite application.
    invite_turnstile_site_key: String,
    /// Secret Turnstile verification key.
    invite_turnstile_secret: String,
    /// Exact marketplace hostname accepted from Turnstile.
    invite_turnstile_expected_hostname: String,
    /// Turnstile Siteverify endpoint.
    invite_turnstile_verify_url: String,

    /// Credential-broker deployment pepper for first-party passwords.
    local_auth_password_pepper: String,
    /// Positive pepper version stored beside new password hashes.
    local_auth_pepper_version: i16,
    /// Comma-separated `version:secret` entries for peppers rotated out of
    /// `local_auth_password_pepper`.
    local_auth_previous_peppers: String,
    /// Stable issuer written to first-party accounts.
    local_auth_issuer: String,
    /// Secure browser session cookie name.
    local_auth_cookie_name: String,
    /// Reviewer-issued invitation lifetime in seconds.
    local_auth_invite_ttl_secs: u64,
    /// Browser session inactivity lifetime in seconds.
    local_auth_browser_idle_secs: u64,
    /// Desktop and CLI session inactivity lifetime in seconds.
    local_auth_bearer_idle_secs: u64,
    /// Non-extendable session lifetime in seconds.
    local_auth_absolute_secs: u64,
    /// Whether the complete password-recovery subsystem is enabled.
    local_auth_recovery_enabled: bool,
    /// Dedicated Resend API credential for recovery mail.
    local_auth_recovery_api_key: String,
    /// Verified sender identity for recovery mail.
    local_auth_recovery_from: String,
    /// HTTPS marketplace page that consumes reset-token fragments.
    local_auth_recovery_reset_url: String,
    /// Base64url-no-padding encoded 256-bit delivery-encryption key.
    local_auth_recovery_delivery_key: String,
    /// Positive delivery-encryption key version.
    local_auth_recovery_key_version: i16,
    /// Single-use reset-token lifetime in seconds.
    local_auth_recovery_token_ttl_secs: u64,
    /// Minimum interval between reset deliveries for one account.
    local_auth_recovery_cooldown_secs: u64,

    /// Memory backend selector.
    memory_backend: String,
    /// HTTP memory endpoint URL.
    memory_http_endpoint: String,
    /// HTTP memory auth scheme.
    memory_http_auth: String,
    /// HTTP memory timeout in seconds.
    memory_http_timeout_secs: u64,
    /// SQLite memory database path.
    memory_sqlite_path: String,
}

/// Split a comma-separated raw string into a `Vec<String>`, trimming
/// whitespace around each entry and skipping empty segments.
///
/// Mirrors the parsing convention already used by
/// [`ServerConfig::cors_origins`], but eagerly collects into an owned
/// `Vec<String>` instead of returning a lazy iterator, since
/// The deprecated `admin_pubkeys` value still uses this compatibility parser.
fn split_comma_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse `LOCAL_AUTH_PREVIOUS_PEPPERS` into a `pepper_version -> secret` map.
///
/// Each comma-separated entry has the form `version:secret`, where `version`
/// is the positive `i16` [`AccountPasswordCredentialRecord::pepper_version`]
/// (from `frameshift_catalog`) stamped beside credentials hashed while that
/// pepper was current, and `secret` is the exact historical pepper value.
/// Only the first `:` splits each entry, so a secret value may itself
/// contain colons. Malformed entries (no `:`, non-numeric, or non-positive
/// version) are skipped with a `tracing::warn` rather than aborting startup,
/// matching the tolerant convention [`ServerConfig::cors_origins`] already
/// uses for `CORS_ALLOWED_ORIGINS`.
fn parse_previous_peppers(raw: &str) -> HashMap<i16, SecretString> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| match entry.split_once(':') {
            Some((version, secret)) => match version.trim().parse::<i16>() {
                Ok(version) if version > 0 => {
                    Some((version, SecretString::new(secret.to_string())))
                }
                _ => {
                    tracing::warn!(
                        entry = version,
                        "ignoring LOCAL_AUTH_PREVIOUS_PEPPERS entry with an invalid version"
                    );
                    None
                }
            },
            None => {
                tracing::warn!(
                    "ignoring malformed LOCAL_AUTH_PREVIOUS_PEPPERS entry (missing ':')"
                );
                None
            }
        })
        .collect()
}

/// Conversion helpers for the serde-friendly raw configuration.
impl RawConfig {
    /// Convert this raw configuration into a [`ServerConfig`].
    ///
    /// Wraps `postgres_url` in [`SecretString`] and converts `shutdown_grace`
    /// from seconds to [`Duration`].
    fn into_server_config(self) -> ServerConfig {
        ServerConfig {
            bind_addr: self.bind_addr,
            postgres_url: SecretString::new(self.postgres_url),
            object_store_root: self.object_store_root,
            log_level: self.log_level,
            log_format: self.log_format,
            max_request_bytes: self.max_request_bytes,
            max_search_limit: self.max_search_limit,
            shutdown_grace: Duration::from_secs(self.shutdown_grace),
            cors_allowed_origins: self.cors_allowed_origins,
            download_secret: SecretString::new(self.download_secret),
            download_token_ttl: Duration::from_secs(self.download_token_ttl),
            download_max_token_ttl: Duration::from_secs(self.download_max_token_ttl),
            download_rate_per_min: self.download_rate_per_min,
            abuse_rate_per_min: self.abuse_rate_per_min,
            account_rate_per_min: self.account_rate_per_min,
            signer_rate_per_min: self.signer_rate_per_min,
            publisher_rate_per_min: self.publisher_rate_per_min,
            metrics_bearer_token: SecretString::new(self.metrics_bearer_token),
            publisher_pubkeys: split_comma_list(&self.publisher_pubkeys),
            max_versions_per_author: self.max_versions_per_author,
            max_bytes_per_author: self.max_bytes_per_author,
            max_total_bytes: self.max_total_bytes,
            object_store_backend: self.object_store_backend,
            r2_endpoint: self.r2_endpoint,
            r2_bucket: self.r2_bucket,
            r2_prefix: self.r2_prefix,
            r2_region: self.r2_region,
            r2_access_key_id: self.r2_access_key_id,
            r2_secret_access_key: SecretString::new(self.r2_secret_access_key),
            quarantine_object_store_backend: self.quarantine_object_store_backend,
            quarantine_object_store_root: self.quarantine_object_store_root,
            quarantine_r2_endpoint: self.quarantine_r2_endpoint,
            quarantine_r2_bucket: self.quarantine_r2_bucket,
            quarantine_r2_prefix: self.quarantine_r2_prefix,
            quarantine_r2_region: self.quarantine_r2_region,
            quarantine_r2_access_key_id: self.quarantine_r2_access_key_id,
            quarantine_r2_secret_access_key: SecretString::new(
                self.quarantine_r2_secret_access_key,
            ),
            trust_forwarded_for: self.trust_forwarded_for,
            signed_request_max_skew: Duration::from_secs(self.signed_request_max_skew_secs),
            admin_pubkeys: split_comma_list(&self.admin_pubkeys),
            publisher_ownership_reads: self.publisher_ownership_reads,
            oidc: OidcConfig {
                enabled: self.oidc_enabled,
                issuer: self.oidc_issuer,
                audience: self.oidc_audience,
                jwks_url: self.oidc_jwks_url,
                allowed_algorithms: split_comma_list(&self.oidc_allowed_algorithms),
                jwks_cache_ttl: Duration::from_secs(self.oidc_jwks_cache_secs),
                jwks_stale_ttl: Duration::from_secs(self.oidc_jwks_stale_secs),
                clock_skew: Duration::from_secs(self.oidc_clock_skew_secs),
                fresh_auth_max_age: Duration::from_secs(self.oidc_fresh_auth_secs),
            },
            invite_requests: InviteRequestConfig {
                turnstile_site_key: self.invite_turnstile_site_key,
                turnstile_secret: SecretString::new(self.invite_turnstile_secret),
                expected_hostname: self.invite_turnstile_expected_hostname,
                verify_url: self.invite_turnstile_verify_url,
            },
            first_party_auth: FirstPartyAuthConfig {
                password_pepper: SecretString::new(self.local_auth_password_pepper),
                pepper_version: self.local_auth_pepper_version,
                previous_peppers: parse_previous_peppers(&self.local_auth_previous_peppers),
                issuer: self.local_auth_issuer,
                cookie_name: self.local_auth_cookie_name,
                invite_ttl: Duration::from_secs(self.local_auth_invite_ttl_secs),
                browser_idle_ttl: Duration::from_secs(self.local_auth_browser_idle_secs),
                bearer_idle_ttl: Duration::from_secs(self.local_auth_bearer_idle_secs),
                absolute_ttl: Duration::from_secs(self.local_auth_absolute_secs),
                recovery: PasswordRecoveryConfig {
                    enabled: self.local_auth_recovery_enabled,
                    provider_api_key: SecretString::new(self.local_auth_recovery_api_key),
                    from_address: self.local_auth_recovery_from,
                    reset_url: self.local_auth_recovery_reset_url,
                    delivery_key: SecretString::new(self.local_auth_recovery_delivery_key),
                    key_version: self.local_auth_recovery_key_version,
                    token_ttl: Duration::from_secs(self.local_auth_recovery_token_ttl_secs),
                    request_cooldown: Duration::from_secs(self.local_auth_recovery_cooldown_secs),
                },
            },
            memory_backend: self.memory_backend,
            memory_http_endpoint: self.memory_http_endpoint,
            memory_http_auth: self.memory_http_auth,
            memory_http_timeout_secs: self.memory_http_timeout_secs,
            memory_sqlite_path: self.memory_sqlite_path,
        }
    }
}

/// Default values for [`RawConfig`] used when environment variables are absent.
///
/// These values are dev-friendly. Production deployments MUST set `POSTGRES_URL`
/// and SHOULD override `BIND_ADDR`, `LOG_FORMAT`, and `MAX_SEARCH_LIMIT`.
fn default_raw_config() -> RawConfig {
    RawConfig {
        bind_addr: "0.0.0.0:3000".parse().expect("default bind_addr is valid"),
        postgres_url: String::new(),
        object_store_root: PathBuf::from("/tmp/frameshift-objects"),
        log_level: "info".to_string(),
        log_format: LogFormat::Text,
        max_request_bytes: 1_048_576,
        max_search_limit: 200,
        shutdown_grace: 30,
        cors_allowed_origins: String::new(),
        download_secret: String::new(),
        download_token_ttl: 300,
        download_max_token_ttl: 1800,
        download_rate_per_min: 10,
        abuse_rate_per_min: 60,
        account_rate_per_min: 120,
        signer_rate_per_min: 60,
        publisher_rate_per_min: 60,
        metrics_bearer_token: String::new(),
        publisher_pubkeys: String::new(),
        max_versions_per_author: 100,
        max_bytes_per_author: 1024 * 1024 * 1024,
        max_total_bytes: 100 * 1024 * 1024 * 1024,
        object_store_backend: "fs".to_string(),
        r2_endpoint: String::new(),
        r2_bucket: String::new(),
        r2_prefix: "objects".to_string(),
        r2_region: "auto".to_string(),
        r2_access_key_id: String::new(),
        r2_secret_access_key: String::new(),
        quarantine_object_store_backend: "disabled".to_string(),
        quarantine_object_store_root: PathBuf::from("/tmp/frameshift-quarantine"),
        quarantine_r2_endpoint: String::new(),
        quarantine_r2_bucket: String::new(),
        quarantine_r2_prefix: "quarantine".to_string(),
        quarantine_r2_region: "auto".to_string(),
        quarantine_r2_access_key_id: String::new(),
        quarantine_r2_secret_access_key: String::new(),
        trust_forwarded_for: false,
        signed_request_max_skew_secs: 300,
        admin_pubkeys: String::new(),
        publisher_ownership_reads: true,
        oidc_enabled: false,
        oidc_issuer: String::new(),
        oidc_audience: String::new(),
        oidc_jwks_url: String::new(),
        oidc_allowed_algorithms: "RS256".to_string(),
        oidc_jwks_cache_secs: 300,
        oidc_jwks_stale_secs: 900,
        oidc_clock_skew_secs: 30,
        oidc_fresh_auth_secs: 300,
        invite_turnstile_site_key: String::new(),
        invite_turnstile_secret: String::new(),
        invite_turnstile_expected_hostname: String::new(),
        invite_turnstile_verify_url: "https://challenges.cloudflare.com/turnstile/v0/siteverify"
            .to_string(),
        local_auth_password_pepper: String::new(),
        local_auth_pepper_version: 1,
        local_auth_previous_peppers: String::new(),
        local_auth_issuer: "https://frameshift.syntheos.dev/first-party".to_string(),
        local_auth_cookie_name: "__Host-frameshift_session".to_string(),
        local_auth_invite_ttl_secs: 7 * 24 * 60 * 60,
        local_auth_browser_idle_secs: 7 * 24 * 60 * 60,
        local_auth_bearer_idle_secs: 30 * 24 * 60 * 60,
        local_auth_absolute_secs: 90 * 24 * 60 * 60,
        local_auth_recovery_enabled: false,
        local_auth_recovery_api_key: String::new(),
        local_auth_recovery_from: String::new(),
        local_auth_recovery_reset_url: String::new(),
        local_auth_recovery_delivery_key: String::new(),
        local_auth_recovery_key_version: 1,
        local_auth_recovery_token_ttl_secs: 60 * 60,
        local_auth_recovery_cooldown_secs: 15 * 60,
        memory_backend: "none".to_string(),
        memory_http_endpoint: String::new(),
        memory_http_auth: "none".to_string(),
        memory_http_timeout_secs: 30,
        memory_sqlite_path: String::new(),
    }
}

/// Environment-backed construction for [`ServerConfig`].
impl ServerConfig {
    /// Parse [`ServerConfig`] from environment variables, applying defaults where
    /// variables are absent.
    ///
    /// Environment variables are read with no prefix (e.g. `BIND_ADDR` not
    /// `FRAMESHIFT_BIND_ADDR`). See the module-level documentation for the full
    /// mapping. Deprecated `admin_pubkeys` and active `publisher_pubkeys`
    /// retain their historical `FRAMESHIFT_` prefix through a narrow second
    /// environment provider.
    ///
    /// # Errors
    ///
    /// Returns a boxed [`figment::Error`] if any variable cannot be parsed into
    /// its expected type (e.g. `BIND_ADDR` is not a valid socket address, or
    /// `MAX_REQUEST_BYTES` is not a valid integer). The error is boxed to avoid
    /// placing the large `figment::Error` variant on the stack (clippy
    /// `result_large_err`).
    pub fn from_env() -> Result<Self, Box<figment::Error>> {
        let raw: RawConfig = Figment::from(Serialized::defaults(default_raw_config()))
            .merge(Env::raw())
            .merge(Env::prefixed("FRAMESHIFT_").only(&["admin_pubkeys", "publisher_pubkeys"]))
            .extract()
            .map_err(Box::new)?;
        Ok(raw.into_server_config())
    }
}

#[cfg(test)]
/// Test-only helpers for constructing resolved configurations.
pub(crate) mod test_support {
    use super::*;

    /// Return the default resolved configuration for unit tests.
    pub(crate) fn minimal_test_config() -> ServerConfig {
        default_raw_config().into_server_config()
    }
}

#[cfg(test)]
/// Unit tests for configuration parsing and secret redaction.
mod tests {
    use super::*;

    #[test]
    /// Debug output redacts database credentials.
    fn debug_redacts_postgres_url() {
        // Use a unique token in the URL so the assertion below cannot be
        // satisfied by the literal field NAME "download_secret" -- the test
        // is checking that the URL credential value is hidden, not that the
        // word "secret" appears nowhere in the struct's Debug output.
        let pg = "postgres://user:RAW_PG_CREDENTIAL@host/db";
        let cfg = ServerConfig {
            bind_addr: "127.0.0.1:3000".parse().unwrap(),
            postgres_url: SecretString::new(pg.into()),
            object_store_root: PathBuf::from("/tmp"),
            log_level: "info".into(),
            log_format: LogFormat::Text,
            max_request_bytes: 1_048_576,
            max_search_limit: 200,
            shutdown_grace: Duration::from_secs(30),
            cors_allowed_origins: String::new(),
            download_secret: SecretString::new(String::new()),
            download_token_ttl: Duration::from_secs(300),
            download_max_token_ttl: Duration::from_secs(1800),
            download_rate_per_min: 0,
            abuse_rate_per_min: 0,
            account_rate_per_min: 0,
            signer_rate_per_min: 0,
            publisher_rate_per_min: 0,
            metrics_bearer_token: SecretString::new(String::new()),
            publisher_pubkeys: vec!["*".to_string()],
            max_versions_per_author: 0,
            max_bytes_per_author: 0,
            max_total_bytes: 0,
            object_store_backend: "fs".to_string(),
            r2_endpoint: String::new(),
            r2_bucket: String::new(),
            r2_prefix: "objects".to_string(),
            r2_region: "auto".to_string(),
            r2_access_key_id: String::new(),
            r2_secret_access_key: SecretString::new(String::new()),
            quarantine_object_store_backend: "disabled".to_string(),
            quarantine_object_store_root: PathBuf::from("/tmp/frameshift-quarantine-test"),
            quarantine_r2_endpoint: String::new(),
            quarantine_r2_bucket: String::new(),
            quarantine_r2_prefix: "quarantine".to_string(),
            quarantine_r2_region: "auto".to_string(),
            quarantine_r2_access_key_id: String::new(),
            quarantine_r2_secret_access_key: SecretString::new(
                "RAW_QUARANTINE_CREDENTIAL".to_string(),
            ),
            trust_forwarded_for: false,
            signed_request_max_skew: Duration::from_secs(300),
            admin_pubkeys: Vec::new(),
            publisher_ownership_reads: true,
            oidc: OidcConfig::disabled(),
            invite_requests: InviteRequestConfig::disabled(),
            first_party_auth: FirstPartyAuthConfig::disabled(),
            memory_backend: "none".to_string(),
            memory_http_endpoint: String::new(),
            memory_http_auth: "none".to_string(),
            memory_http_timeout_secs: 30,
            memory_sqlite_path: String::new(),
        };
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("RAW_PG_CREDENTIAL"),
            "Debug must not expose postgres_url credential: {debug}"
        );
        assert!(
            !debug.contains("RAW_QUARANTINE_CREDENTIAL"),
            "Debug must not expose quarantine-store credentials: {debug}"
        );
        assert!(debug.contains("[REDACTED]"), "Debug must show [REDACTED]");
    }

    #[test]
    /// Comma-separated CORS origins are trimmed and empty entries are dropped.
    fn cors_origins_splits_and_trims_comma_separated() {
        let cfg = ServerConfig {
            bind_addr: "127.0.0.1:3000".parse().unwrap(),
            postgres_url: SecretString::new("x".into()),
            object_store_root: PathBuf::from("/tmp"),
            log_level: "info".into(),
            log_format: LogFormat::Text,
            max_request_bytes: 1,
            max_search_limit: 1,
            shutdown_grace: Duration::from_secs(1),
            cors_allowed_origins: " https://a.example , ,https://b.example ".into(),
            download_secret: SecretString::new(String::new()),
            download_token_ttl: Duration::from_secs(300),
            download_max_token_ttl: Duration::from_secs(1800),
            download_rate_per_min: 0,
            abuse_rate_per_min: 0,
            account_rate_per_min: 0,
            signer_rate_per_min: 0,
            publisher_rate_per_min: 0,
            metrics_bearer_token: SecretString::new(String::new()),
            publisher_pubkeys: vec!["*".to_string()],
            max_versions_per_author: 0,
            max_bytes_per_author: 0,
            max_total_bytes: 0,
            object_store_backend: "fs".to_string(),
            r2_endpoint: String::new(),
            r2_bucket: String::new(),
            r2_prefix: "objects".to_string(),
            r2_region: "auto".to_string(),
            r2_access_key_id: String::new(),
            r2_secret_access_key: SecretString::new(String::new()),
            quarantine_object_store_backend: "disabled".to_string(),
            quarantine_object_store_root: PathBuf::from("/tmp/frameshift-quarantine-test"),
            quarantine_r2_endpoint: String::new(),
            quarantine_r2_bucket: String::new(),
            quarantine_r2_prefix: "quarantine".to_string(),
            quarantine_r2_region: "auto".to_string(),
            quarantine_r2_access_key_id: String::new(),
            quarantine_r2_secret_access_key: SecretString::new(String::new()),
            trust_forwarded_for: false,
            signed_request_max_skew: Duration::from_secs(300),
            admin_pubkeys: Vec::new(),
            publisher_ownership_reads: true,
            oidc: OidcConfig::disabled(),
            invite_requests: InviteRequestConfig::disabled(),
            first_party_auth: FirstPartyAuthConfig::disabled(),
            memory_backend: "none".to_string(),
            memory_http_endpoint: String::new(),
            memory_http_auth: "none".to_string(),
            memory_http_timeout_secs: 30,
            memory_sqlite_path: String::new(),
        };
        let got: Vec<&str> = cfg.cors_origins().collect();
        assert_eq!(got, vec!["https://a.example", "https://b.example"]);
    }

    #[test]
    /// An empty CORS origin setting yields no configured origins.
    fn cors_origins_empty_yields_no_entries() {
        let cfg = ServerConfig {
            bind_addr: "127.0.0.1:3000".parse().unwrap(),
            postgres_url: SecretString::new("x".into()),
            object_store_root: PathBuf::from("/tmp"),
            log_level: "info".into(),
            log_format: LogFormat::Text,
            max_request_bytes: 1,
            max_search_limit: 1,
            shutdown_grace: Duration::from_secs(1),
            cors_allowed_origins: String::new(),
            download_secret: SecretString::new(String::new()),
            download_token_ttl: Duration::from_secs(300),
            download_max_token_ttl: Duration::from_secs(1800),
            download_rate_per_min: 0,
            abuse_rate_per_min: 0,
            account_rate_per_min: 0,
            signer_rate_per_min: 0,
            publisher_rate_per_min: 0,
            metrics_bearer_token: SecretString::new(String::new()),
            publisher_pubkeys: vec!["*".to_string()],
            max_versions_per_author: 0,
            max_bytes_per_author: 0,
            max_total_bytes: 0,
            object_store_backend: "fs".to_string(),
            r2_endpoint: String::new(),
            r2_bucket: String::new(),
            r2_prefix: "objects".to_string(),
            r2_region: "auto".to_string(),
            r2_access_key_id: String::new(),
            r2_secret_access_key: SecretString::new(String::new()),
            quarantine_object_store_backend: "disabled".to_string(),
            quarantine_object_store_root: PathBuf::from("/tmp/frameshift-quarantine-test"),
            quarantine_r2_endpoint: String::new(),
            quarantine_r2_bucket: String::new(),
            quarantine_r2_prefix: "quarantine".to_string(),
            quarantine_r2_region: "auto".to_string(),
            quarantine_r2_access_key_id: String::new(),
            quarantine_r2_secret_access_key: SecretString::new(String::new()),
            trust_forwarded_for: false,
            signed_request_max_skew: Duration::from_secs(300),
            admin_pubkeys: Vec::new(),
            publisher_ownership_reads: true,
            oidc: OidcConfig::disabled(),
            invite_requests: InviteRequestConfig::disabled(),
            first_party_auth: FirstPartyAuthConfig::disabled(),
            memory_backend: "none".to_string(),
            memory_http_endpoint: String::new(),
            memory_http_auth: "none".to_string(),
            memory_http_timeout_secs: 30,
            memory_sqlite_path: String::new(),
        };
        assert_eq!(cfg.cors_origins().count(), 0);
    }

    #[test]
    /// An empty download secret disables signed download endpoints.
    fn download_key_empty_returns_none() {
        let cfg = make_test_cfg("");
        assert!(matches!(cfg.download_key(), Ok(None)));
    }

    #[test]
    /// A valid 32-byte hex secret decodes without modification.
    fn download_key_valid_hex_returns_bytes() {
        let hex32 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let cfg = make_test_cfg(hex32);
        let key = cfg.download_key().expect("hex valid").expect("not None");
        assert_eq!(key[0], 0x01);
        assert_eq!(key[31], 0xef);
    }

    #[test]
    /// A download secret with the wrong decoded length is rejected.
    fn download_key_wrong_length_errors() {
        let cfg = make_test_cfg("deadbeef"); // 4 bytes, not 32
        assert!(cfg.download_key().is_err());
    }

    #[test]
    /// Non-hex download secret input is rejected.
    fn download_key_invalid_hex_errors() {
        let cfg = make_test_cfg("zz".repeat(32).as_str());
        assert!(cfg.download_key().is_err());
    }

    #[test]
    /// Publisher ownership enrichment defaults on and remains explicitly reversible.
    fn publisher_ownership_reads_default_on_and_can_disable() {
        let raw = default_raw_config();
        assert!(raw.publisher_ownership_reads);

        let mut raw = default_raw_config();
        raw.publisher_ownership_reads = false;
        assert!(!raw.into_server_config().publisher_ownership_reads);
    }

    #[test]
    /// Publication quarantine remains disabled until an operator selects a backend.
    fn publication_quarantine_defaults_disabled() {
        let config = default_raw_config().into_server_config();
        assert_eq!(config.quarantine_object_store_backend, "disabled");
        assert_eq!(
            config.quarantine_object_store_root,
            PathBuf::from("/tmp/frameshift-quarantine")
        );
    }

    #[test]
    /// Password recovery defaults off without requiring provider or encryption secrets.
    fn password_recovery_defaults_disabled() {
        let config = default_raw_config().into_server_config();
        assert!(matches!(config.password_recovery_key(), Ok(None)));
    }

    #[test]
    /// Complete recovery settings decode one canonical key and match the trusted origin.
    fn password_recovery_accepts_complete_configuration() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let mut raw = default_raw_config();
        raw.cors_allowed_origins = "https://frameshift.test".to_string();
        raw.local_auth_password_pepper = "test-password-pepper".to_string();
        raw.local_auth_recovery_enabled = true;
        raw.local_auth_recovery_api_key = "re_test_provider_key".to_string();
        raw.local_auth_recovery_from = "FrameShift <recovery@frameshift.test>".to_string();
        raw.local_auth_recovery_reset_url = "https://frameshift.test/recover/".to_string();
        raw.local_auth_recovery_delivery_key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let config = raw.into_server_config();

        assert_eq!(
            config
                .password_recovery_key()
                .expect("complete recovery configuration")
                .expect("recovery enabled"),
            [7_u8; 32]
        );
    }

    #[test]
    /// Enabled recovery rejects missing secrets, untrusted origins, and excessive token TTLs.
    fn password_recovery_rejects_partial_or_unsafe_configuration() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let mut partial = default_raw_config();
        partial.local_auth_recovery_enabled = true;
        assert!(partial
            .into_server_config()
            .password_recovery_key()
            .is_err());

        let mut unsafe_config = default_raw_config();
        unsafe_config.cors_allowed_origins = "https://other.frameshift.test".to_string();
        unsafe_config.local_auth_password_pepper = "test-password-pepper".to_string();
        unsafe_config.local_auth_recovery_enabled = true;
        unsafe_config.local_auth_recovery_api_key = "re_test_provider_key".to_string();
        unsafe_config.local_auth_recovery_from =
            "FrameShift <recovery@frameshift.test>".to_string();
        unsafe_config.local_auth_recovery_reset_url =
            "https://frameshift.test/recover/".to_string();
        unsafe_config.local_auth_recovery_delivery_key = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        unsafe_config.local_auth_recovery_token_ttl_secs = 24 * 60 * 60 + 1;
        assert!(unsafe_config
            .into_server_config()
            .password_recovery_key()
            .is_err());

        let mut padded_provider_key = default_raw_config();
        padded_provider_key.cors_allowed_origins = "https://frameshift.test".to_string();
        padded_provider_key.local_auth_password_pepper = "test-password-pepper".to_string();
        padded_provider_key.local_auth_recovery_enabled = true;
        padded_provider_key.local_auth_recovery_api_key = " re_test_provider_key".to_string();
        padded_provider_key.local_auth_recovery_from =
            "FrameShift <recovery@frameshift.test>".to_string();
        padded_provider_key.local_auth_recovery_reset_url =
            "https://frameshift.test/recover/".to_string();
        padded_provider_key.local_auth_recovery_delivery_key = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        assert!(padded_provider_key
            .into_server_config()
            .password_recovery_key()
            .is_err());

        let mut padded_delivery_key = default_raw_config();
        padded_delivery_key.cors_allowed_origins = "https://frameshift.test".to_string();
        padded_delivery_key.local_auth_password_pepper = "test-password-pepper".to_string();
        padded_delivery_key.local_auth_recovery_enabled = true;
        padded_delivery_key.local_auth_recovery_api_key = "re_test_provider_key".to_string();
        padded_delivery_key.local_auth_recovery_from =
            "FrameShift <recovery@frameshift.test>".to_string();
        padded_delivery_key.local_auth_recovery_reset_url =
            "https://frameshift.test/recover/".to_string();
        padded_delivery_key.local_auth_recovery_delivery_key =
            format!(" {}", URL_SAFE_NO_PAD.encode([9_u8; 32]));
        assert!(padded_delivery_key
            .into_server_config()
            .password_recovery_key()
            .is_err());
    }

    #[test]
    /// Recovery Debug formatting never exposes provider or delivery-key material.
    fn password_recovery_debug_redacts_secrets() {
        let mut recovery = PasswordRecoveryConfig::disabled();
        recovery.provider_api_key = SecretString::new("RAW_RECOVERY_API_KEY".to_string());
        recovery.delivery_key = SecretString::new("RAW_RECOVERY_DELIVERY_KEY".to_string());
        let debug = format!("{recovery:?}");

        assert!(!debug.contains("RAW_RECOVERY_API_KEY"));
        assert!(!debug.contains("RAW_RECOVERY_DELIVERY_KEY"));
        assert!(debug.contains("[REDACTED]"));
    }

    /// Build a [`ServerConfig`] populated with test-friendly defaults and the
    /// given `download_secret`.
    fn make_test_cfg(secret: &str) -> ServerConfig {
        ServerConfig {
            bind_addr: "127.0.0.1:3000".parse().unwrap(),
            postgres_url: SecretString::new("x".into()),
            object_store_root: PathBuf::from("/tmp"),
            log_level: "info".into(),
            log_format: LogFormat::Text,
            max_request_bytes: 1,
            max_search_limit: 1,
            shutdown_grace: Duration::from_secs(1),
            cors_allowed_origins: String::new(),
            download_secret: SecretString::new(secret.into()),
            download_token_ttl: Duration::from_secs(300),
            download_max_token_ttl: Duration::from_secs(1800),
            download_rate_per_min: 0,
            abuse_rate_per_min: 0,
            account_rate_per_min: 0,
            signer_rate_per_min: 0,
            publisher_rate_per_min: 0,
            metrics_bearer_token: SecretString::new(String::new()),
            publisher_pubkeys: vec!["*".to_string()],
            max_versions_per_author: 0,
            max_bytes_per_author: 0,
            max_total_bytes: 0,
            object_store_backend: "fs".to_string(),
            r2_endpoint: String::new(),
            r2_bucket: String::new(),
            r2_prefix: "objects".to_string(),
            r2_region: "auto".to_string(),
            r2_access_key_id: String::new(),
            r2_secret_access_key: SecretString::new(String::new()),
            quarantine_object_store_backend: "disabled".to_string(),
            quarantine_object_store_root: PathBuf::from("/tmp/frameshift-quarantine-test"),
            quarantine_r2_endpoint: String::new(),
            quarantine_r2_bucket: String::new(),
            quarantine_r2_prefix: "quarantine".to_string(),
            quarantine_r2_region: "auto".to_string(),
            quarantine_r2_access_key_id: String::new(),
            quarantine_r2_secret_access_key: SecretString::new(String::new()),
            trust_forwarded_for: false,
            signed_request_max_skew: Duration::from_secs(300),
            admin_pubkeys: Vec::new(),
            publisher_ownership_reads: true,
            oidc: OidcConfig::disabled(),
            invite_requests: InviteRequestConfig::disabled(),
            first_party_auth: FirstPartyAuthConfig::disabled(),
            memory_backend: "none".to_string(),
            memory_http_endpoint: String::new(),
            memory_http_auth: "none".to_string(),
            memory_http_timeout_secs: 30,
            memory_sqlite_path: String::new(),
        }
    }

    #[test]
    /// Log format variants preserve their serde wire names.
    fn log_format_serde_roundtrip() {
        let j = serde_json::to_string(&LogFormat::Json).unwrap();
        assert_eq!(j, "\"json\"");
        let t = serde_json::to_string(&LogFormat::Text).unwrap();
        assert_eq!(t, "\"text\"");
    }
}
