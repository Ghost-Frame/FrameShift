//! Entry point for the `frameshift-server` binary.
//!
//! Parses configuration from environment variables, initializes tracing, wires
//! up the Postgres catalog adapter and filesystem object store, and calls
//! [`frameshift_server::run`] to serve until SIGTERM/SIGINT.

use std::sync::Arc;
use std::time::Duration;

use mimalloc::MiMalloc;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use frameshift_catalog_postgres::{PostgresCatalog, PostgresCatalogConfig};
use frameshift_objects::PackStore;
use frameshift_objects_fs::{FsPackStore, FsPackStoreConfig};
use frameshift_objects_r2::{R2PackStore, R2PackStoreConfig};
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

/// Build [`AppState`] by initializing the Postgres catalog and filesystem
/// object store from the resolved config.
///
/// Both backends are initialized before the TCP socket is bound so that startup
/// errors (bad connection string, unwritable directory) are surfaced immediately
/// as `ServerError::Startup` rather than causing runtime failures after the
/// server is already accepting connections.
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

    Ok(AppState {
        catalog: Arc::new(catalog),
        objects,
        runtime: None,
        config,
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
async fn build_object_store(
    config: &ServerConfig,
) -> Result<Arc<dyn PackStore>, ServerError> {
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

