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
    }
}

impl ServerConfig {
    /// Parse [`ServerConfig`] from environment variables, applying defaults where
    /// variables are absent.
    ///
    /// Environment variables are read with no prefix (e.g. `BIND_ADDR` not
    /// `PERSONIFY_BIND_ADDR`). See the module-level documentation for the full
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
        let cfg = ServerConfig {
            bind_addr: "127.0.0.1:3000".parse().unwrap(),
            postgres_url: SecretString::new("postgres://user:secret@host/db".into()),
            object_store_root: PathBuf::from("/tmp"),
            log_level: "info".into(),
            log_format: LogFormat::Text,
            max_request_bytes: 1_048_576,
            max_search_limit: 200,
            shutdown_grace: Duration::from_secs(30),
        };
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("secret"),
            "Debug must not expose postgres_url"
        );
        assert!(debug.contains("[REDACTED]"), "Debug must show [REDACTED]");
    }

    #[test]
    fn log_format_serde_roundtrip() {
        let j = serde_json::to_string(&LogFormat::Json).unwrap();
        assert_eq!(j, "\"json\"");
        let t = serde_json::to_string(&LogFormat::Text).unwrap();
        assert_eq!(t, "\"text\"");
    }
}
