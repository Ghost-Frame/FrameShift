//! [`AppState`] -- the shared application state threaded through every handler.
//!
//! `AppState` is constructed once at startup, wrapped in `axum::extract::State`,
//! and cloned cheaply into each request handler. All fields are behind `Arc`
//! pointers so that cloning `AppState` only bumps reference counts.

use std::sync::Arc;

use frameshift_catalog::CatalogBackend;
use frameshift_memory::MemoryAdapter;
use frameshift_objects::PackStore;

use crate::account_auth::BearerTokenVerifier;
use crate::auth::NonceCache;
use crate::config::ServerConfig;
use crate::mcp::McpDispatcher;
use crate::metrics::Metrics;
use crate::middleware::mcp_access::McpAccessRuntime;

/// Shared application state for the frameshift HTTP server.
///
/// Holds `Arc`-wrapped references to all backend services so that handlers can
/// access them via [`axum::extract::State<AppState>`] without any allocation
/// per request.
///
/// Every backend handle is `Arc`-wrapped, so cloning this state remains cheap
/// as narrowly scoped capabilities are added.
#[derive(Clone)]
pub struct AppState {
    /// Catalog backend: author registration, pack publication, search, etc.
    ///
    /// All catalog reads go through this. The concrete type is hidden behind
    /// `dyn CatalogBackend` so that test code can inject a `MockCatalog`
    /// without recompiling the server.
    pub catalog: Arc<dyn CatalogBackend>,

    /// Object store: content-addressed blob storage for pack archives.
    ///
    /// The download endpoint uses this to stream pack bytes after the catalog
    /// confirms the version exists.
    pub objects: Arc<dyn PackStore>,

    /// Optional persona runtime.
    ///
    /// Present when the server is started with an embedded runtime for direct
    /// persona loading. Absent in pure API-gateway mode. The remote MCP
    /// dispatcher intentionally does not receive this broader capability.
    pub runtime: Option<Arc<frameshift_runtime::Runtime>>,

    /// Optional memory adapter for persona memory operations.
    ///
    /// Configured via `MEMORY_BACKEND` env var. When `None`, personas with
    /// hard memory requirements fail to load.
    pub memory: Option<Arc<dyn MemoryAdapter>>,

    /// Resolved server configuration, shared read-only across all handlers.
    ///
    /// Stored behind `Arc` so that `ServerConfig` does not need to be `Copy`
    /// or have its `SecretString` fields re-cloned on every handler invocation.
    pub config: Arc<ServerConfig>,

    /// Prometheus metrics registry and all named collectors.
    ///
    /// Shared via `Arc` so cloning `AppState` only increments a reference
    /// count. Handlers and middleware both access collectors through this field.
    pub metrics: Arc<Metrics>,

    /// Replay-nonce cache for Ed25519 signed-request authentication.
    ///
    /// The signed-request middleware records each verified request nonce here
    /// to reject replays within the timestamp-skew window. Shared via `Arc`;
    /// the catalog provides the authoritative cross-instance nonce claim.
    pub auth_nonces: Arc<NonceCache>,

    /// Optional OIDC bearer verifier for account and publisher routes.
    ///
    /// `None` keeps all authenticated account routes unmounted.
    pub account_auth: Option<Arc<dyn BearerTokenVerifier>>,

    /// Optional validated Cloudflare Access runtime for the remote MCP route.
    ///
    /// `None` keeps `/mcp` entirely unmounted. A value is present only after
    /// every issuer, audience, JWKS, algorithm, and resource setting passes
    /// the dedicated fail-closed validation boundary.
    pub mcp_access: Option<Arc<McpAccessRuntime>>,

    /// Optional least-capability dispatcher for account-scoped remote MCP tools.
    ///
    /// Startup constructs this only alongside a validated MCP Access runtime.
    /// The router requires both values before mounting `/mcp`, so every partial
    /// configuration remains fail closed. The dispatcher owns only the catalog,
    /// public pack store, and account-persona state capabilities needed by its
    /// tools, never the embedded runtime, memory adapter, or credential vault.
    pub mcp_dispatcher: Option<Arc<dyn McpDispatcher>>,
}
