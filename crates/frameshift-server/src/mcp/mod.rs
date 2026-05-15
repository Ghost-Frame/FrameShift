//! MCP (Model Context Protocol) router -- milestone placeholder.
//!
//! Every method under `/mcp/*` returns `501 Not Implemented` with a JSON body
//! that explains which milestone will provide the real implementation. This
//! allows the routing structure to be finalized now so that the MCP surface
//! can land as new handlers inside this module without touching the skeleton.
//!
//! # Future surface
//!
//! The full MCP implementation will expose:
//! - SSE connection endpoint (`/mcp/sse`)
//! - JSON-RPC message endpoint (`/mcp/messages`)
//! - Tool listing (`/mcp/tools`)
//!
//! All of those are deferred to a follow-up milestone.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};

use crate::state::AppState;

/// Build the MCP sub-router mounted at `/mcp`.
///
/// Currently returns `501 Not Implemented` for every method on every path
/// under `/mcp/*`. The `any` handler catches all HTTP methods.
pub fn mcp_router() -> Router<AppState> {
    Router::new()
        .route("/{*path}", any(mcp_placeholder))
        .route("/", any(mcp_placeholder))
}

/// `ANY /mcp/*`
///
/// Placeholder for the MCP (Model Context Protocol) surface. Returns
/// `501 Not Implemented` for all methods and paths under `/mcp`.
///
/// # Response
///
/// `501 Not Implemented` with body:
/// ```json
/// {
///   "error": "MCP not implemented",
///   "detail": "The MCP surface is planned for a follow-up milestone."
/// }
/// ```
///
/// # Errors
///
/// This handler never returns an error; it always produces a `501` response.
async fn mcp_placeholder() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "MCP not implemented",
            "detail": "The MCP surface is planned for a follow-up milestone."
        })),
    )
        .into_response()
}
