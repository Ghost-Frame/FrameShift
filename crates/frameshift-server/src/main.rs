//! Entry point for the `frameshift-server` binary.
//!
//! Parses configuration from environment variables, initializes tracing, wires
//! up backends via mock stubs (concrete adapters wired in milestone 2), and
//! calls [`frameshift_server::run`] to serve until SIGTERM/SIGINT.

use std::sync::Arc;

use mimalloc::MiMalloc;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

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

/// Build a placeholder [`AppState`] from the given config.
///
/// Concrete database and filesystem backends are wired in milestone 2.
/// This function provides no-op stubs so that the binary can start and serve
/// the skeleton endpoints (health, metrics, MCP placeholder) without any
/// external infrastructure.
async fn build_state(config: Arc<ServerConfig>) -> Result<AppState, ServerError> {
    // Placeholder backends -- replaced with real adapters in milestone 2.
    // The build_state function exists so that backend initialization errors
    // (connection refused, missing credentials) can be surfaced as
    // ServerError::Startup before the bind syscall.
    let catalog: Arc<dyn frameshift_catalog::CatalogBackend> = Arc::new(NoopCatalog);
    let objects: Arc<dyn frameshift_objects::PackStore> = Arc::new(NoopPackStore);

    Ok(AppState {
        catalog,
        objects,
        runtime: None,
        config,
    })
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

// ---------------------------------------------------------------------------
// Placeholder backend stubs (replaced by real adapters in milestone 2)
// ---------------------------------------------------------------------------

/// No-op catalog backend used until the Postgres adapter is wired in.
///
/// Every method returns a `CatalogError::BackendError` indicating the backend
/// is not configured. This allows the binary to start and serve `/healthz`
/// with a `healthy: false` catalog status.
struct NoopCatalog;

#[async_trait::async_trait]
impl frameshift_catalog::CatalogBackend for NoopCatalog {
    async fn register_author(
        &self,
        _record: frameshift_catalog::AuthorRecord,
    ) -> Result<(), frameshift_catalog::CatalogError> {
        Err(frameshift_catalog::CatalogError::BackendError(
            "catalog not configured".into(),
        ))
    }

    async fn lookup_author(
        &self,
        _pubkey: &frameshift_catalog::Ed25519PublicKey,
    ) -> Result<frameshift_catalog::AuthorRecord, frameshift_catalog::CatalogError> {
        Err(frameshift_catalog::CatalogError::BackendError(
            "catalog not configured".into(),
        ))
    }

    async fn lookup_author_by_handle(
        &self,
        _handle: &str,
    ) -> Result<frameshift_catalog::AuthorRecord, frameshift_catalog::CatalogError> {
        Err(frameshift_catalog::CatalogError::BackendError(
            "catalog not configured".into(),
        ))
    }

    async fn list_authors(
        &self,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<frameshift_catalog::AuthorRecord>, frameshift_catalog::CatalogError> {
        Ok(Vec::new())
    }

    async fn register_pack_version(
        &self,
        _record: frameshift_catalog::PackVersionRecord,
    ) -> Result<(), frameshift_catalog::CatalogError> {
        Err(frameshift_catalog::CatalogError::BackendError(
            "catalog not configured".into(),
        ))
    }

    async fn get_pack(
        &self,
        _name: &str,
    ) -> Result<frameshift_catalog::PackRecord, frameshift_catalog::CatalogError> {
        Err(frameshift_catalog::CatalogError::BackendError(
            "catalog not configured".into(),
        ))
    }

    async fn get_pack_version(
        &self,
        _name: &str,
        _version: &str,
    ) -> Result<frameshift_catalog::PackVersionRecord, frameshift_catalog::CatalogError> {
        Err(frameshift_catalog::CatalogError::BackendError(
            "catalog not configured".into(),
        ))
    }

    async fn list_pack_versions(
        &self,
        _name: &str,
    ) -> Result<Vec<frameshift_catalog::PackVersionRecord>, frameshift_catalog::CatalogError> {
        Ok(Vec::new())
    }

    async fn search_packs(
        &self,
        _filters: &frameshift_catalog::PackSearchFilters,
    ) -> Result<Vec<frameshift_catalog::PackSearchResult>, frameshift_catalog::CatalogError> {
        Ok(Vec::new())
    }

    async fn increment_download_counter(
        &self,
        _name: &str,
        _version: &str,
    ) -> Result<u64, frameshift_catalog::CatalogError> {
        Err(frameshift_catalog::CatalogError::BackendError(
            "catalog not configured".into(),
        ))
    }

    async fn tombstone_pack(
        &self,
        _name: &str,
        _version: &str,
        _record: frameshift_catalog::TombstoneRecord,
    ) -> Result<(), frameshift_catalog::CatalogError> {
        Err(frameshift_catalog::CatalogError::BackendError(
            "catalog not configured".into(),
        ))
    }

    async fn get_handle_pubkey(
        &self,
        _handle: &str,
    ) -> Result<frameshift_catalog::Ed25519PublicKey, frameshift_catalog::CatalogError> {
        Err(frameshift_catalog::CatalogError::BackendError(
            "catalog not configured".into(),
        ))
    }

    async fn set_handle_pubkey(
        &self,
        _handle: &str,
        _pubkey: frameshift_catalog::Ed25519PublicKey,
    ) -> Result<(), frameshift_catalog::CatalogError> {
        Err(frameshift_catalog::CatalogError::BackendError(
            "catalog not configured".into(),
        ))
    }

    async fn health(
        &self,
    ) -> Result<frameshift_catalog::HealthStatus, frameshift_catalog::CatalogError> {
        Ok(frameshift_catalog::HealthStatus {
            healthy: false,
            detail: "catalog backend not configured".to_string(),
        })
    }
}

/// No-op object store backend used until the filesystem adapter is wired in.
///
/// Every method returns an `ObjectStoreError::BackendError` indicating the
/// store is not configured. The `health` method returns `healthy: false`.
struct NoopPackStore;

#[async_trait::async_trait]
impl frameshift_objects::PackStore for NoopPackStore {
    async fn put(
        &self,
        _hash: &frameshift_objects::ObjectHash,
        _bytes: &[u8],
    ) -> Result<(), frameshift_objects::ObjectStoreError> {
        Err(frameshift_objects::ObjectStoreError::BackendError(
            "object store not configured".into(),
        ))
    }

    async fn get(
        &self,
        _hash: &frameshift_objects::ObjectHash,
    ) -> Result<Vec<u8>, frameshift_objects::ObjectStoreError> {
        Err(frameshift_objects::ObjectStoreError::BackendError(
            "object store not configured".into(),
        ))
    }

    async fn exists(
        &self,
        _hash: &frameshift_objects::ObjectHash,
    ) -> Result<bool, frameshift_objects::ObjectStoreError> {
        Ok(false)
    }

    async fn delete(
        &self,
        hash: &frameshift_objects::ObjectHash,
    ) -> Result<(), frameshift_objects::ObjectStoreError> {
        Err(frameshift_objects::ObjectStoreError::NotFound { hash: *hash })
    }

    async fn list_prefix(
        &self,
        _prefix: &[u8],
        _limit: usize,
    ) -> Result<Vec<frameshift_objects::ObjectHash>, frameshift_objects::ObjectStoreError> {
        Ok(Vec::new())
    }

    async fn health(
        &self,
    ) -> Result<frameshift_objects::ObjectStoreHealth, frameshift_objects::ObjectStoreError> {
        Ok(frameshift_objects::ObjectStoreHealth {
            healthy: false,
            total_objects: None,
            total_bytes: None,
            detail: "object store not configured".to_string(),
        })
    }
}
