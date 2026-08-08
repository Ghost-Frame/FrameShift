//! Typed dispatch boundary between the MCP HTTP transport and remote tools.
//!
//! The transport owns JSON-RPC, protocol-version, HTTP-header, timeout, and
//! output-limit enforcement. Implementations of [`McpDispatcher`] own only
//! account-scoped tool discovery and execution. This separation lets later
//! units add authenticated tools without weakening or duplicating transport
//! validation.

use std::fmt;

use async_trait::async_trait;
use axum::http::Extensions;
use serde::Serialize;
use serde_json::Value;

/// Protocol revisions accepted by the remote MCP endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpProtocolVersion {
    /// The first Streamable HTTP revision used as the no-header fallback.
    V2025_03_26,
    /// The June 2025 handshake-era revision.
    V2025_06_18,
    /// The final handshake-era revision.
    V2025_11_25,
    /// The stateless per-request metadata revision.
    V2026_07_28,
}

/// Provides stable wire values and era checks for supported revisions.
impl McpProtocolVersion {
    /// Return the exact date-based protocol revision used on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2025_03_26 => "2025-03-26",
            Self::V2025_06_18 => "2025-06-18",
            Self::V2025_11_25 => "2025-11-25",
            Self::V2026_07_28 => "2026-07-28",
        }
    }

    /// Report whether this revision uses stateless per-request metadata.
    pub const fn is_modern(self) -> bool {
        matches!(self, Self::V2026_07_28)
    }
}

/// Carries server-populated request context into account-scoped dispatch.
///
/// The extensions originate from Axum middleware. Client-supplied `_meta`
/// fields, including `clientInfo`, are never copied into this context and are
/// never treated as authentication.
pub struct McpRequestContext {
    protocol_version: McpProtocolVersion,
    extensions: Extensions,
}

/// Exposes validated protocol and server middleware context to dispatchers.
impl McpRequestContext {
    /// Construct context from a validated protocol version and request extensions.
    pub(crate) fn new(protocol_version: McpProtocolVersion, extensions: Extensions) -> Self {
        Self {
            protocol_version,
            extensions,
        }
    }

    /// Return the validated protocol revision for this request.
    pub const fn protocol_version(&self) -> McpProtocolVersion {
        self.protocol_version
    }

    /// Read a server-populated request extension by type.
    pub fn extension<T>(&self) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.extensions.get::<T>()
    }
}

/// Validated request passed to the tool-list dispatcher.
pub struct McpListToolsRequest {
    /// Optional opaque pagination cursor supplied by the client.
    pub cursor: Option<String>,
    /// Validated server-side request context.
    pub context: McpRequestContext,
}

/// Requests one immutable, account-authorized tool execution handle.
pub struct McpPrepareToolRequest {
    /// Exact case-sensitive tool name selected by the caller.
    pub name: String,
    /// Validated server-side request context.
    pub context: McpRequestContext,
}

/// Validated arguments passed to one already-authorized tool handle.
pub struct McpPreparedToolCallRequest {
    /// Tool arguments, guaranteed to be a JSON object.
    pub arguments: serde_json::Map<String, Value>,
}

/// MCP tool definition returned by the typed dispatcher.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    /// Unique case-sensitive tool name.
    pub name: String,
    /// Optional human-readable title displayed by clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional description supplied to the model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema 2020-12 input contract for the tool.
    pub input_schema: Value,
    /// Optional JSON Schema describing structured output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// Optional client-facing safety and interaction hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<McpToolAnnotations>,
}

/// Client-facing MCP tool behavior annotations.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolAnnotations {
    /// Human-readable title used by clients that prefer annotation titles.
    pub title: String,
    /// Whether the tool leaves user-visible state unchanged.
    pub read_only_hint: bool,
    /// Whether the tool may remove or replace persisted state.
    pub destructive_hint: bool,
    /// Whether repeating the same call has no additional visible effect.
    pub idempotent_hint: bool,
    /// Whether the tool can interact outside FrameShift-managed state.
    pub open_world_hint: bool,
}

/// Dispatcher result for `tools/list` before transport metadata is added.
#[derive(Clone, Debug, Default)]
pub struct McpListToolsResult {
    /// Tools visible to the authenticated request context.
    pub tools: Vec<McpTool>,
    /// Optional opaque cursor for the next deterministic page.
    pub next_cursor: Option<String>,
}

/// A content item returned by a remote tool.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpToolContent {
    /// Plain UTF-8 text for the model and user.
    Text {
        /// Text payload for this content item.
        text: String,
    },
}

/// Dispatcher result for `tools/call` before modern protocol fields are added.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpCallToolResult {
    /// Ordered content items produced by the tool.
    pub content: Vec<McpToolContent>,
    /// Optional structured JSON output matching the tool's output schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    /// Whether the call completed with an application-level tool error.
    pub is_error: bool,
}

/// Provides convenient, correctly shaped text results for remote tools.
impl McpCallToolResult {
    /// Construct a successful single-text-content result.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![McpToolContent::Text { text: text.into() }],
            structured_content: None,
            is_error: false,
        }
    }

    /// Construct an application-level error suitable for model self-correction.
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![McpToolContent::Text { text: text.into() }],
            structured_content: None,
            is_error: true,
        }
    }
}

/// Sanitized dispatcher failure mapped to a generic JSON-RPC server error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpDispatchError {
    /// The backing tool catalog is temporarily unavailable.
    Unavailable,
    /// An internal failure prevented a safe result from being produced.
    Internal,
}

/// Formats dispatcher errors without exposing implementation detail.
impl fmt::Display for McpDispatchError {
    /// Write a bounded generic description for diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("MCP dispatcher unavailable"),
            Self::Internal => formatter.write_str("MCP dispatcher failed"),
        }
    }
}

/// Marks sanitized dispatcher failures as standard Rust errors.
impl std::error::Error for McpDispatchError {}

/// One-shot tool handle whose definition and execution share one catalog snapshot.
///
/// Implementations capture the authenticated account context and immutable tool
/// revision during preparation. Consuming the handle for execution prevents the
/// transport from validating one dispatcher lookup and executing a later lookup.
#[async_trait]
pub trait McpPreparedTool: Send + Sync + 'static {
    /// Return the exact immutable definition that governs this handle.
    fn definition(&self) -> &McpTool;

    /// Consume this prepared handle and execute its already-authorized tool.
    async fn call(self: Box<Self>, request: McpPreparedToolCallRequest) -> McpCallToolResult;
}

/// Account-aware remote tool surface used by the HTTP transport.
#[async_trait]
pub trait McpDispatcher: Send + Sync + 'static {
    /// Return the tools visible in this request's server-authenticated context.
    async fn list_tools(
        &self,
        request: McpListToolsRequest,
    ) -> Result<McpListToolsResult, McpDispatchError>;

    /// Prepare one visible tool under an immutable definition and account context.
    async fn prepare_tool(
        &self,
        request: McpPrepareToolRequest,
    ) -> Result<Option<Box<dyn McpPreparedTool>>, McpDispatchError>;
}

/// Safe placeholder dispatcher used until account-scoped tools are installed.
#[derive(Debug, Default)]
pub(crate) struct UnavailableMcpDispatcher;

/// Supplies deterministic empty discovery and bounded unavailable call results.
#[async_trait]
impl McpDispatcher for UnavailableMcpDispatcher {
    /// Return an empty deterministic tool list.
    async fn list_tools(
        &self,
        _request: McpListToolsRequest,
    ) -> Result<McpListToolsResult, McpDispatchError> {
        Ok(McpListToolsResult::default())
    }

    /// Report that the placeholder exposes no prepared tools.
    async fn prepare_tool(
        &self,
        _request: McpPrepareToolRequest,
    ) -> Result<Option<Box<dyn McpPreparedTool>>, McpDispatchError> {
        Ok(None)
    }
}
