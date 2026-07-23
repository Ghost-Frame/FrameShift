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
//! | `TRUST_FORWARDED_FOR` | `false` | Trust `X-Forwarded-For` for rate-limit key extraction; set `true` only behind a trusted proxy |
//! | `SIGNED_REQUEST_MAX_SKEW_SECS` | `300` | Max allowed clock skew (seconds) between a signed write request's timestamp and server time; also bounds the replay-nonce retention window |
//! | `FRAMESHIFT_ADMIN_PUBKEYS` | `""` | Comma-separated base64url-no-pad Ed25519 public keys allowed to call `/v1/admin/*` endpoints; empty disables all admin endpoints (404) |
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
//!
//! Env var names match the struct field names verbatim (figment maps
//! `download_secret` <-> `DOWNLOAD_SECRET`); shorter aliases would require an
//! explicit remap step which we don't have yet. `FRAMESHIFT_ADMIN_PUBKEYS` is
//! the one deliberate exception: it carries the `FRAMESHIFT_` prefix so it
//! cannot be confused with an unrelated `ADMIN_PUBKEYS` variable that some
//! other tool in the deployment environment might already own.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use figment::providers::{Env, Serialized};
use figment::Figment;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

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
    /// Publish endpoints in a later milestone will override this per-route.
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

    /// Base64url-no-pad Ed25519 public keys authorized to call the admin
    /// endpoints (e.g. `POST /v1/admin/packs/{name}/{version}/tombstone`).
    ///
    /// Parsed from the comma-separated `FRAMESHIFT_ADMIN_PUBKEYS` env var.
    /// Stored in the same base64url-no-pad string representation produced by
    /// `Ed25519PublicKey`'s `Display` impl, so callers compare with a plain
    /// string equality against
    /// `verified_signer.pubkey.to_string()` (see
    /// [`crate::auth::VerifiedSigner`]). Default: empty (admin endpoints
    /// disabled; handlers return `404` rather than `403` so the route's
    /// existence is not disclosed).
    pub admin_pubkeys: Vec<String>,

    /// Whether pack reads resolve additive publisher ownership metadata.
    ///
    /// Set this to `false` for application rollback to the exact legacy
    /// response shape while retaining additive database rows and columns.
    /// Default: `true`.
    pub publisher_ownership_reads: bool,

    /// OIDC resource-server settings for account and publisher routes.
    pub oidc: OidcConfig,

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
            .field("trust_forwarded_for", &self.trust_forwarded_for)
            .field("signed_request_max_skew", &self.signed_request_max_skew)
            .field(
                "admin_pubkeys",
                &format!("[{} key(s)]", self.admin_pubkeys.len()),
            )
            .field("publisher_ownership_reads", &self.publisher_ownership_reads)
            .field("oidc", &self.oidc)
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

    /// Whether to trust XFF for rate limiting (maps to `TRUST_FORWARDED_FOR`).
    trust_forwarded_for: bool,

    /// Max signed-request clock skew in seconds (maps to
    /// `SIGNED_REQUEST_MAX_SKEW_SECS`).
    signed_request_max_skew_secs: u64,

    /// Comma-separated base64url-no-pad Ed25519 admin public keys (raw
    /// string, split into `Vec<String>` on convert). Maps to
    /// `FRAMESHIFT_ADMIN_PUBKEYS`.
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
/// `admin_pubkeys` is compared on every admin-route request.
fn split_comma_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
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
    /// mapping. `admin_pubkeys` is the sole exception: it is read from the
    /// prefixed `FRAMESHIFT_ADMIN_PUBKEYS` var via a second, narrowly-scoped
    /// `Env::prefixed(...).only(...)` merge layered on top of the unprefixed
    /// provider, so every other field keeps the established no-prefix
    /// convention.
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
            trust_forwarded_for: false,
            signed_request_max_skew: Duration::from_secs(300),
            admin_pubkeys: Vec::new(),
            publisher_ownership_reads: true,
            oidc: OidcConfig::disabled(),
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
            trust_forwarded_for: false,
            signed_request_max_skew: Duration::from_secs(300),
            admin_pubkeys: Vec::new(),
            publisher_ownership_reads: true,
            oidc: OidcConfig::disabled(),
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
            trust_forwarded_for: false,
            signed_request_max_skew: Duration::from_secs(300),
            admin_pubkeys: Vec::new(),
            publisher_ownership_reads: true,
            oidc: OidcConfig::disabled(),
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
            trust_forwarded_for: false,
            signed_request_max_skew: Duration::from_secs(300),
            admin_pubkeys: Vec::new(),
            publisher_ownership_reads: true,
            oidc: OidcConfig::disabled(),
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
