//! Remote Model Context Protocol endpoint.
//!
//! The router exposes exactly one stateless `POST /mcp` endpoint. It supports
//! handshake-era compatibility without creating sessions and the final
//! 2026-07-28 per-request metadata protocol without SSE. Transport validation
//! remains separate from account-aware tool discovery and execution through a
//! small typed dispatcher seam.

use std::sync::Arc;

use axum::http::header::CACHE_CONTROL;
use axum::http::HeaderValue;
use axum::routing::post;
use axum::{Extension, Router};
use tower_http::set_header::SetResponseHeaderLayer;

/// Account-scoped cloud persona discovery, verification, and mutation tools.
mod cloud_dispatcher;
/// Typed dispatcher contracts and protocol-facing tool values.
mod dispatcher;
/// Stateless HTTP and JSON-RPC validation implementation.
mod transport;

pub use cloud_dispatcher::CloudPersonaMcpDispatcher;
pub use dispatcher::{
    McpCallToolResult, McpDispatchError, McpDispatcher, McpListToolsRequest, McpListToolsResult,
    McpPrepareToolRequest, McpPreparedTool, McpPreparedToolCallRequest, McpProtocolVersion,
    McpRequestContext, McpTool, McpToolAnnotations, McpToolContent,
};
pub use transport::{
    McpTransportConfig, McpTransportConfigError, DEFAULT_MCP_MAX_BODY_BYTES,
    DEFAULT_MCP_MAX_TOOL_OUTPUT_CHARS, DEFAULT_MCP_PRIVATE_CACHE_TTL_MS,
    DEFAULT_MCP_REQUEST_TIMEOUT, FALLBACK_LEGACY_PROTOCOL_VERSION, LATEST_LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
};

use dispatcher::UnavailableMcpDispatcher;
use transport::handle_mcp;

/// Build the exact `/mcp` route with conservative transport defaults.
pub fn mcp_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    mcp_router_with_dispatcher(
        McpTransportConfig::default(),
        Arc::new(UnavailableMcpDispatcher),
    )
}

/// Build the exact `/mcp` route with an explicit policy and tool dispatcher.
pub fn mcp_router_with_dispatcher<S>(
    config: McpTransportConfig,
    dispatcher: Arc<dyn McpDispatcher>,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/mcp", post(handle_mcp))
        .layer(Extension(dispatcher))
        .layer(Extension(config))
        // Account-specific discovery and rendered prompts must never enter an HTTP cache.
        .layer(SetResponseHeaderLayer::overriding(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
}
