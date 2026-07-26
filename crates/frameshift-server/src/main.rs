//! Entry point for the `frameshift-server` binary.
//!
//! Parses configuration from environment variables, initializes tracing, wires
//! the selected catalog and object-store adapters, and serves either the standard
//! route surface or explicitly enabled isolated publication admission.

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

    let account_auth =
        match frameshift_server::account_auth::OidcVerifier::from_config(&config.oidc) {
            Ok(verifier) => verifier,
            Err(error) => {
                tracing::error!(%error, "OIDC configuration invalid; account routes disabled");
                None
            }
        };

    Ok(AppState {
        catalog: Arc::new(catalog),
        objects,
        runtime: None,
        memory,
        config,
        metrics,
        auth_nonces,
        account_auth,
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

/// Resolved quarantine-store mode after fail-closed startup validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuarantineMode {
    /// Publication admission is not mounted.
    Disabled,
    /// Quarantined archives use an isolated filesystem root.
    Fs,
    /// Quarantined archives use an isolated S3-compatible location.
    R2,
}

/// Validate the quarantine selector and its account-authentication prerequisite.
fn quarantine_mode(
    backend: &str,
    account_auth_enabled: bool,
) -> Result<QuarantineMode, ServerError> {
    let mode = match backend {
        "disabled" => return Ok(QuarantineMode::Disabled),
        "fs" => QuarantineMode::Fs,
        "r2" => QuarantineMode::R2,
        other => {
            return Err(ServerError::Startup(format!(
                "unknown QUARANTINE_OBJECT_STORE_BACKEND={other:?}; expected \"disabled\", \"fs\", or \"r2\""
            )));
        }
    };

    if !account_auth_enabled {
        return Err(ServerError::Startup(
            "publication quarantine requires valid OIDC configuration".to_string(),
        ));
    }

    Ok(mode)
}

/// Normalize one S3-compatible location component for identity comparison.
fn normalized_store_component(raw: &str) -> &str {
    raw.trim().trim_matches('/')
}

/// Normalize an S3-compatible endpoint while preserving any case-sensitive path.
fn normalized_store_endpoint(raw: &str) -> String {
    url::Url::parse(raw.trim())
        .map(|parsed| parsed.as_str().trim_end_matches('/').to_string())
        .unwrap_or_else(|_| raw.trim().trim_end_matches('/').to_string())
}

/// Return whether two S3-compatible configurations resolve to the same location.
fn same_r2_location(public: [&str; 3], quarantine: [&str; 3]) -> bool {
    normalized_store_endpoint(public[0]) == normalized_store_endpoint(quarantine[0])
        && public[1..]
            .iter()
            .zip(&quarantine[1..])
            .all(|(left, right)| {
                normalized_store_component(left) == normalized_store_component(right)
            })
}

/// Reject filesystem roots that canonicalize to the same directory.
async fn ensure_distinct_fs_roots(
    public_root: &std::path::Path,
    quarantine_root: &std::path::Path,
) -> Result<(), ServerError> {
    let public = tokio::fs::canonicalize(public_root)
        .await
        .map_err(|e| ServerError::Startup(format!("public object-store root: {e}")))?;
    let quarantine = tokio::fs::canonicalize(quarantine_root)
        .await
        .map_err(|e| ServerError::Startup(format!("quarantine object-store root: {e}")))?;

    if public == quarantine {
        return Err(ServerError::Startup(
            "quarantine filesystem root must differ from the public object-store root".to_string(),
        ));
    }

    Ok(())
}

/// Construct an explicitly configured and isolated publication quarantine store.
async fn build_quarantine_store(
    config: &ServerConfig,
    account_auth_enabled: bool,
) -> Result<Option<Arc<dyn PackStore>>, ServerError> {
    match quarantine_mode(
        &config.quarantine_object_store_backend,
        account_auth_enabled,
    )? {
        QuarantineMode::Disabled => Ok(None),
        QuarantineMode::Fs => {
            let fs_config = FsPackStoreConfig {
                root: config.quarantine_object_store_root.clone(),
                verify_on_read: true,
                max_bytes: None,
                fsync_on_put: true,
            };
            let quarantine = FsPackStore::new(fs_config)
                .await
                .map_err(|e| ServerError::Startup(format!("quarantine FsPackStore: {e}")))?;

            if config.object_store_backend == "fs" {
                ensure_distinct_fs_roots(
                    &config.object_store_root,
                    &config.quarantine_object_store_root,
                )
                .await?;
            }

            tracing::info!(
                root = %config.quarantine_object_store_root.display(),
                "filesystem publication quarantine configured"
            );
            Ok(Some(Arc::new(quarantine)))
        }
        QuarantineMode::R2 => {
            if config.object_store_backend == "r2"
                && same_r2_location(
                    [&config.r2_endpoint, &config.r2_bucket, &config.r2_prefix],
                    [
                        &config.quarantine_r2_endpoint,
                        &config.quarantine_r2_bucket,
                        &config.quarantine_r2_prefix,
                    ],
                )
            {
                return Err(ServerError::Startup(
                    "quarantine R2 location must differ from the public object-store location"
                        .to_string(),
                ));
            }

            let r2_config = R2PackStoreConfig {
                endpoint: config.quarantine_r2_endpoint.clone(),
                bucket: config.quarantine_r2_bucket.clone(),
                prefix: config.quarantine_r2_prefix.clone(),
                region: config.quarantine_r2_region.clone(),
                access_key_id: config.quarantine_r2_access_key_id.clone(),
                secret_access_key: config.quarantine_r2_secret_access_key.clone(),
            };
            let quarantine = R2PackStore::new(r2_config)
                .map_err(|e| ServerError::Startup(format!("quarantine R2: {e}")))?;
            tracing::info!(
                bucket = %config.quarantine_r2_bucket,
                prefix = %config.quarantine_r2_prefix,
                endpoint = %config.quarantine_r2_endpoint,
                "R2 publication quarantine configured"
            );
            Ok(Some(Arc::new(quarantine)))
        }
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
/// Resolve configuration, initialize backends, and run the HTTP server.
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

    let quarantine = match build_quarantine_store(&config, state.account_auth.is_some()).await {
        Ok(store) => store,
        Err(e) => {
            tracing::error!("startup failed: {e}");
            std::process::exit(3);
        }
    };

    let server_result = match quarantine {
        Some(store) => frameshift_server::run_with_publication_admission(state, store).await,
        None => frameshift_server::run(state).await,
    };

    if let Err(e) = server_result {
        tracing::error!("server error: {e}");
        let code = match e {
            ServerError::Bind(_) => 2,
            ServerError::Startup(_) => 3,
            ServerError::Shutdown(_) => 1,
        };
        std::process::exit(code);
    }
}

#[cfg(test)]
/// Unit tests for fail-closed publication quarantine configuration.
mod tests {
    use super::*;

    #[test]
    /// The default selector keeps publication admission disabled without OIDC.
    fn quarantine_mode_accepts_disabled_without_account_auth() {
        assert_eq!(
            quarantine_mode("disabled", false).expect("disabled mode"),
            QuarantineMode::Disabled
        );
    }

    #[test]
    /// Both supported quarantine backends require account authentication.
    fn quarantine_mode_requires_account_auth() {
        assert!(matches!(
            quarantine_mode("fs", false),
            Err(ServerError::Startup(message)) if message.contains("OIDC")
        ));
        assert!(matches!(
            quarantine_mode("r2", false),
            Err(ServerError::Startup(message)) if message.contains("OIDC")
        ));
    }

    #[test]
    /// Both supported quarantine backends resolve when account authentication exists.
    fn quarantine_mode_accepts_supported_backends() {
        assert_eq!(
            quarantine_mode("fs", true).expect("filesystem mode"),
            QuarantineMode::Fs
        );
        assert_eq!(
            quarantine_mode("r2", true).expect("R2 mode"),
            QuarantineMode::R2
        );
    }

    #[test]
    /// Unknown quarantine selectors fail startup instead of silently disabling writes.
    fn quarantine_mode_rejects_unknown_backend() {
        assert!(matches!(
            quarantine_mode("typo", true),
            Err(ServerError::Startup(message))
                if message.contains("QUARANTINE_OBJECT_STORE_BACKEND")
        ));
    }

    #[test]
    /// R2 location comparison ignores harmless surrounding separators and whitespace.
    fn r2_location_comparison_normalizes_components() {
        assert!(same_r2_location(
            [" HTTPS://R2.EXAMPLE/ ", " packs ", "/public/"],
            ["https://r2.example", "packs", "public"],
        ));
        assert!(!same_r2_location(
            ["https://r2.example", "packs", "public"],
            ["https://r2.example", "packs", "quarantine"],
        ));
    }

    #[tokio::test]
    /// Filesystem location comparison rejects one canonical root and accepts two.
    async fn filesystem_location_comparison_enforces_separation() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let public = temp.path().join("public");
        let quarantine = temp.path().join("quarantine");
        std::fs::create_dir_all(&public).expect("public directory");
        std::fs::create_dir_all(&quarantine).expect("quarantine directory");

        ensure_distinct_fs_roots(&public, &quarantine)
            .await
            .expect("distinct roots");
        assert!(ensure_distinct_fs_roots(&public, &public).await.is_err());
    }
}
