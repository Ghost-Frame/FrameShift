//! Entry point for the `frameshift-server` binary.
//!
//! Parses configuration from environment variables, initializes tracing, wires
//! up the Postgres catalog adapter and filesystem object store, and calls
//! [`frameshift_server::run`] to serve until SIGTERM/SIGINT.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mimalloc::MiMalloc;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use frameshift_catalog_postgres::{PostgresCatalog, PostgresCatalogConfig};
use frameshift_memory::MemoryAdapter;
use frameshift_objects::PackStore;
use frameshift_objects_fs::{FsPackStore, FsPackStoreConfig};
use frameshift_objects_r2::{R2PackStore, R2PackStoreConfig};
use frameshift_server::metrics::Metrics;
use frameshift_server::{AppState, LogFormat, ServerConfig, ServerError};

/// Use mimalloc as the global allocator for improved throughput on
/// allocation-heavy workloads (many small async tasks).
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Initialize the `tracing` subscriber based on the resolved [`ServerConfig`].
///
/// Applies an [`tracing_subscriber::EnvFilter`] from `config.log_level`.
/// Falls back to `info` if the level string is invalid. Emits either
/// structured JSON or compact text output depending on `config.log_format`.
fn init_tracing(config: &ServerConfig) {
    let env_filter = tracing_subscriber::EnvFilter::try_new(&config.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(env_filter);

    match config.log_format {
        LogFormat::Json => registry
            .with(tracing_subscriber::fmt::layer().json())
            .init(),
        LogFormat::Text => registry.with(tracing_subscriber::fmt::layer()).init(),
    }
}

/// Build [`AppState`] by initializing the Postgres catalog, object store, and
/// optional memory adapter from the resolved config.
///
/// All backends are initialized before the TCP socket is bound so that startup
/// errors (bad connection string, unwritable directory, invalid memory config)
/// are surfaced immediately as `ServerError::Startup` rather than causing
/// runtime failures after the server is already accepting connections.
async fn build_state(config: Arc<ServerConfig>) -> Result<AppState, ServerError> {
    use secrecy::ExposeSecret as _;

    let catalog_config = PostgresCatalogConfig {
        url: secrecy::SecretString::new(config.postgres_url.expose_secret().to_string()),
        pool_size: 10,
        connect_timeout: Duration::from_secs(5),
        statement_timeout: Duration::from_secs(30),
    };

    let catalog = PostgresCatalog::new(catalog_config)
        .await
        .map_err(|e| ServerError::Startup(e.to_string()))?;

    let objects = build_object_store(&config).await?;
    let memory = build_memory_adapter(&config).await?;

    // Initialize the Prometheus registry once at startup; all handlers and the
    // metrics middleware share the same Arc<Metrics> through AppState.
    let metrics = Arc::new(Metrics::new());

    // Replay-nonce cache for signed-request auth. Retention is 2x the skew
    // window: once a request's timestamp is more than `max_skew` from now it is
    // rejected on the timestamp check alone, so the nonce can be forgotten.
    let nonce_ttl = config.signed_request_max_skew.saturating_mul(2);
    let auth_nonces = Arc::new(frameshift_server::auth::NonceCache::new(nonce_ttl));

    Ok(AppState {
        catalog: Arc::new(catalog),
        objects,
        runtime: None,
        memory,
        config,
        metrics,
        auth_nonces,
    })
}

/// Construct the configured [`PackStore`] backend and return it as
/// `Arc<dyn PackStore>` so handlers see a single trait object regardless
/// of which adapter was chosen.
///
/// Selected via `config.object_store_backend`:
///
/// - `"fs"` (default) -> [`FsPackStore`] rooted at `OBJECT_STORE_ROOT`.
/// - `"r2"` -> [`R2PackStore`] talking to the configured S3-compatible
///   endpoint with `R2_*` credentials.
///
/// Unknown values produce a [`ServerError::Startup`] so a typo in the env
/// fails fast rather than silently defaulting.
async fn build_object_store(config: &ServerConfig) -> Result<Arc<dyn PackStore>, ServerError> {
    match config.object_store_backend.as_str() {
        "fs" => {
            let fs_cfg = FsPackStoreConfig {
                root: config.object_store_root.clone(),
                verify_on_read: true,
                max_bytes: None,
                fsync_on_put: true,
            };
            let fs = FsPackStore::new(fs_cfg)
                .await
                .map_err(|e| ServerError::Startup(format!("FsPackStore: {e}")))?;
            Ok(Arc::new(fs))
        }
        "r2" => {
            let r2_cfg = R2PackStoreConfig {
                endpoint: config.r2_endpoint.clone(),
                bucket: config.r2_bucket.clone(),
                prefix: config.r2_prefix.clone(),
                region: config.r2_region.clone(),
                access_key_id: config.r2_access_key_id.clone(),
                secret_access_key: config.r2_secret_access_key.clone(),
            };
            let r2 =
                R2PackStore::new(r2_cfg).map_err(|e| ServerError::Startup(format!("R2: {e}")))?;
            tracing::info!(
                bucket = %config.r2_bucket,
                prefix = %config.r2_prefix,
                endpoint = %config.r2_endpoint,
                "R2 object store configured"
            );
            Ok(Arc::new(r2))
        }
        other => Err(ServerError::Startup(format!(
            "unknown OBJECT_STORE_BACKEND={other:?}; expected \"fs\" or \"r2\""
        ))),
    }
}

/// Construct the configured memory adapter based on `MEMORY_BACKEND`.
///
/// - `"none"` (default): returns `None` -- no memory adapter.
/// - `"http"`: builds an [`HttpAdapter`] from `MEMORY_HTTP_*` env vars.
/// - `"sqlite"`: builds a [`SqliteFtsAdapter`] from `MEMORY_SQLITE_PATH`.
///
/// Unknown values produce a [`ServerError::Startup`].
async fn build_memory_adapter(
    config: &ServerConfig,
) -> Result<Option<Arc<dyn MemoryAdapter>>, ServerError> {
    match config.memory_backend.as_str() {
        "none" => Ok(None),
        "http" => {
            use frameshift_memory_http::{HttpAdapter, HttpAdapterConfig};

            let endpoint: url::Url = config
                .memory_http_endpoint
                .parse()
                .map_err(|e| ServerError::Startup(format!("MEMORY_HTTP_ENDPOINT: {e}")))?;

            let auth = parse_memory_http_auth(&config.memory_http_auth)?;

            let adapter_config = HttpAdapterConfig {
                endpoint,
                auth,
                timeout: Duration::from_secs(config.memory_http_timeout_secs),
                user_agent: "frameshift-server".to_string(),
            };

            let adapter = HttpAdapter::new(adapter_config)
                .map_err(|e| ServerError::Startup(format!("HTTP memory adapter: {e}")))?;

            tracing::info!(
                endpoint = %config.memory_http_endpoint,
                "HTTP memory adapter configured"
            );

            Ok(Some(Arc::new(adapter)))
        }
        "sqlite" => {
            use frameshift_memory_sqlite_fts::{SqliteFtsAdapter, SqliteFtsConfig};

            if config.memory_sqlite_path.is_empty() {
                return Err(ServerError::Startup(
                    "MEMORY_BACKEND=sqlite requires MEMORY_SQLITE_PATH".into(),
                ));
            }

            let sqlite_config = SqliteFtsConfig {
                path: PathBuf::from(&config.memory_sqlite_path),
                pool_size: 4,
            };

            let adapter = SqliteFtsAdapter::new(sqlite_config)
                .await
                .map_err(|e| ServerError::Startup(format!("SQLite memory adapter: {e}")))?;

            tracing::info!(
                path = %config.memory_sqlite_path,
                "SQLite FTS memory adapter configured"
            );

            Ok(Some(Arc::new(adapter)))
        }
        other => Err(ServerError::Startup(format!(
            "unknown MEMORY_BACKEND={other:?}; expected \"none\", \"http\", or \"sqlite\""
        ))),
    }
}

/// Parse the `MEMORY_HTTP_AUTH` string into an [`HttpAuth`] variant.
///
/// Accepted formats:
/// - `"none"` -> `HttpAuth::None`
/// - `"bearer:<token>"` -> `HttpAuth::Bearer(<token>)`
fn parse_memory_http_auth(raw: &str) -> Result<frameshift_memory_http::HttpAuth, ServerError> {
    use frameshift_memory_http::HttpAuth;

    if raw == "none" || raw.is_empty() {
        return Ok(HttpAuth::None);
    }
    if let Some(token) = raw.strip_prefix("bearer:") {
        return Ok(HttpAuth::Bearer(secrecy::SecretString::new(
            token.to_string(),
        )));
    }
    Err(ServerError::Startup(format!(
        "unknown MEMORY_HTTP_AUTH={raw:?}; expected \"none\" or \"bearer:<token>\""
    )))
}

#[tokio::main]
async fn main() {
    let config = match ServerConfig::from_env() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    // Note: `from_env` returns `Box<figment::Error>` to avoid large Err variants.

    init_tracing(&config);
    tracing::debug!(?config, "resolved server configuration");

    let state = match build_state(Arc::clone(&config)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("startup failed: {e}");
            std::process::exit(3);
        }
    };

    if let Err(e) = frameshift_server::run(state).await {
        tracing::error!("server error: {e}");
        let code = match e {
            ServerError::Bind(_) => 2,
            ServerError::Startup(_) => 3,
            ServerError::Shutdown(_) => 1,
        };
        std::process::exit(code);
    }
}
