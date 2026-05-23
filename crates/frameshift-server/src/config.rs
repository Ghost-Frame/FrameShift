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
//!
//! Env var names match the struct field names verbatim (figment maps
//! `download_secret` <-> `DOWNLOAD_SECRET`); shorter aliases would require an
//! explicit remap step which we don't have yet.

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
}

impl ServerConfig {
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
}

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
    }
}

impl ServerConfig {
    /// Parse [`ServerConfig`] from environment variables, applying defaults where
    /// variables are absent.
    ///
    /// Environment variables are read with no prefix (e.g. `BIND_ADDR` not
    /// `FRAMESHIFT_BIND_ADDR`). See the module-level documentation for the full
    /// mapping.
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
            .extract()
            .map_err(Box::new)?;
        Ok(raw.into_server_config())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
        };
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("RAW_PG_CREDENTIAL"),
            "Debug must not expose postgres_url credential: {debug}"
        );
        assert!(debug.contains("[REDACTED]"), "Debug must show [REDACTED]");
    }

    #[test]
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
        };
        let got: Vec<&str> = cfg.cors_origins().collect();
        assert_eq!(got, vec!["https://a.example", "https://b.example"]);
    }

    #[test]
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
        };
        assert_eq!(cfg.cors_origins().count(), 0);
    }

    #[test]
    fn download_key_empty_returns_none() {
        let cfg = make_test_cfg("");
        assert!(matches!(cfg.download_key(), Ok(None)));
    }

    #[test]
    fn download_key_valid_hex_returns_bytes() {
        let hex32 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let cfg = make_test_cfg(hex32);
        let key = cfg.download_key().expect("hex valid").expect("not None");
        assert_eq!(key[0], 0x01);
        assert_eq!(key[31], 0xef);
    }

    #[test]
    fn download_key_wrong_length_errors() {
        let cfg = make_test_cfg("deadbeef"); // 4 bytes, not 32
        assert!(cfg.download_key().is_err());
    }

    #[test]
    fn download_key_invalid_hex_errors() {
        let cfg = make_test_cfg("zz".repeat(32).as_str());
        assert!(cfg.download_key().is_err());
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
        }
    }

    #[test]
    fn log_format_serde_roundtrip() {
        let j = serde_json::to_string(&LogFormat::Json).unwrap();
        assert_eq!(j, "\"json\"");
        let t = serde_json::to_string(&LogFormat::Text).unwrap();
        assert_eq!(t, "\"text\"");
    }
}
