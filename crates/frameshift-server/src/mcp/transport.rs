//! Stateless Streamable HTTP transport for the remote MCP endpoint.
//!
//! This module deliberately owns every client-controlled protocol decision:
//! media negotiation, origin checks, body limits, JSON-RPC validation,
//! protocol-version selection, final-protocol metadata, and bounded responses.
//! Only validated tool requests and server-populated Axum extensions cross the
//! [`McpDispatcher`](super::McpDispatcher) boundary.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Extension, Request};
use axum::http::header::{ACCEPT, CONTENT_TYPE, ORIGIN};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as STANDARD_BASE64;
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Map, Value};

use super::dispatcher::{
    McpCallToolResult, McpDispatchError, McpDispatcher, McpListToolsRequest, McpListToolsResult,
    McpPrepareToolRequest, McpPreparedToolCallRequest, McpProtocolVersion, McpRequestContext,
    McpTool, McpToolContent,
};

/// Final stateless MCP protocol revision implemented by this transport.
pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

/// Latest handshake-era revision implemented for legacy clients.
pub const LATEST_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

/// Oldest supported revision and fallback for eligible no-header requests.
pub const FALLBACK_LEGACY_PROTOCOL_VERSION: &str = "2025-03-26";

/// Default maximum accepted request body, exactly one mebibyte.
pub const DEFAULT_MCP_MAX_BODY_BYTES: usize = 1_048_576;

/// Default per-request deadline, below the hosted connector's 300-second cap.
pub const DEFAULT_MCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(240);

/// Default tool-output limit, strictly below 150,000 Unicode characters.
pub const DEFAULT_MCP_MAX_TOOL_OUTPUT_CHARS: usize = 149_000;

/// Default private-cache lifetime for account-specific discovery results.
pub const DEFAULT_MCP_PRIVATE_CACHE_TTL_MS: u64 = 30_000;

/// Maximum legal request timeout, which is intentionally exclusive.
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Exclusive protocol-level maximum for configured tool output.
const MAX_TOOL_OUTPUT_CHARS: usize = 150_000;

/// Maximum number of elements accepted in the sole batch-capable legacy revision.
const MAX_BATCH_ITEMS: usize = 128;

/// Maximum UTF-8 byte length accepted for an echoed string request identifier.
const MAX_JSON_RPC_STRING_ID_BYTES: usize = 256;

/// Maximum number of tools accepted from one account-scoped discovery page.
const MAX_TOOLS_PER_PAGE: usize = 4_096;

/// Maximum number of content elements accepted from one tool execution.
const MAX_TOOL_CONTENT_ITEMS: usize = 4_096;

/// Maximum byte length accepted for a tool name at every transport boundary.
const MAX_TOOL_NAME_BYTES: usize = 256;

/// Maximum opaque cursor byte length accepted from either transport direction.
const MAX_TOOL_CURSOR_BYTES: usize = 4_096;

/// Maximum nesting depth accepted in dispatcher-provided JSON values.
const MAX_DISPATCH_JSON_DEPTH: usize = 64;

/// Maximum total JSON nodes visited in one dispatcher-provided response.
const MAX_DISPATCH_JSON_NODES: usize = 65_536;

/// Largest integer that every conforming JSON and JavaScript peer can compare exactly.
const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;

/// Short application error used when a dispatcher exceeds its output budget.
const OUTPUT_LIMIT_ERROR: &str = "Tool output exceeded the server limit.";

/// All revisions accepted by the endpoint, ordered newest first.
const SUPPORTED_PROTOCOL_VERSIONS: [McpProtocolVersion; 4] = [
    McpProtocolVersion::V2026_07_28,
    McpProtocolVersion::V2025_11_25,
    McpProtocolVersion::V2025_06_18,
    McpProtocolVersion::V2025_03_26,
];

/// Header carrying the negotiated protocol revision.
static MCP_PROTOCOL_VERSION: HeaderName = HeaderName::from_static("mcp-protocol-version");

/// Header binding a modern HTTP request to its JSON-RPC method.
static MCP_METHOD: HeaderName = HeaderName::from_static("mcp-method");

/// Header binding a modern tool call to its decoded JSON body name.
static MCP_NAME: HeaderName = HeaderName::from_static("mcp-name");

/// Runtime policy for the stateless MCP HTTP transport.
#[derive(Clone, Debug)]
pub struct McpTransportConfig {
    allowed_origins: Arc<HashSet<String>>,
    max_body_bytes: usize,
    request_timeout: Duration,
    max_tool_output_chars: usize,
    private_cache_ttl_ms: u64,
}

/// Reports an invalid transport policy before it reaches request handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpTransportConfigError {
    /// A configured origin cannot be represented as one HTTP header value.
    InvalidOrigin,
    /// The body limit must allow at least one byte.
    InvalidBodyLimit,
    /// The deadline must be nonzero and strictly below 300 seconds.
    InvalidRequestTimeout,
    /// The output cap must fit the serialized fixed error and stay below 150,000 chars.
    InvalidToolOutputLimit,
}

/// Formats transport-policy errors without including configured values.
impl std::fmt::Display for McpTransportConfigError {
    /// Write a stable description suitable for configuration diagnostics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOrigin => formatter.write_str("invalid MCP origin allowlist entry"),
            Self::InvalidBodyLimit => formatter.write_str("invalid MCP request body limit"),
            Self::InvalidRequestTimeout => formatter.write_str("invalid MCP request timeout"),
            Self::InvalidToolOutputLimit => formatter.write_str("invalid MCP tool output limit"),
        }
    }
}

/// Marks transport-policy validation failures as standard Rust errors.
impl std::error::Error for McpTransportConfigError {}

/// Supplies conservative production defaults for the MCP endpoint.
impl Default for McpTransportConfig {
    /// Build a policy that permits no present Origin until explicitly configured.
    fn default() -> Self {
        Self {
            allowed_origins: Arc::new(HashSet::new()),
            max_body_bytes: DEFAULT_MCP_MAX_BODY_BYTES,
            request_timeout: DEFAULT_MCP_REQUEST_TIMEOUT,
            max_tool_output_chars: DEFAULT_MCP_MAX_TOOL_OUTPUT_CHARS,
            private_cache_ttl_ms: DEFAULT_MCP_PRIVATE_CACHE_TTL_MS,
        }
    }
}

/// Validates and customizes the MCP HTTP transport policy.
impl McpTransportConfig {
    /// Replace the exact, case-sensitive allowlist for present Origin headers.
    pub fn with_allowed_origins<I, S>(mut self, origins: I) -> Result<Self, McpTransportConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut allowed = HashSet::new();
        for origin in origins {
            let origin = origin.into();
            let canonical = url::Url::parse(&origin)
                .ok()
                .filter(|url| matches!(url.scheme(), "http" | "https"))
                .filter(|url| url.host().is_some())
                .filter(|url| url.username().is_empty() && url.password().is_none())
                .filter(|url| {
                    url.path() == "/" && url.query().is_none() && url.fragment().is_none()
                })
                .map(|url| url.origin().ascii_serialization());
            if axum::http::HeaderValue::from_str(&origin).is_err()
                || canonical.as_deref() != Some(origin.as_str())
            {
                return Err(McpTransportConfigError::InvalidOrigin);
            }
            allowed.insert(origin);
        }
        self.allowed_origins = Arc::new(allowed);
        Ok(self)
    }

    /// Replace the exact maximum request-body byte count.
    pub fn with_max_body_bytes(
        mut self,
        max_body_bytes: usize,
    ) -> Result<Self, McpTransportConfigError> {
        if max_body_bytes == 0 {
            return Err(McpTransportConfigError::InvalidBodyLimit);
        }
        self.max_body_bytes = max_body_bytes;
        Ok(self)
    }

    /// Replace the request deadline while preserving the sub-300-second invariant.
    pub fn with_request_timeout(
        mut self,
        request_timeout: Duration,
    ) -> Result<Self, McpTransportConfigError> {
        if request_timeout.is_zero() || request_timeout >= MAX_REQUEST_TIMEOUT {
            return Err(McpTransportConfigError::InvalidRequestTimeout);
        }
        self.request_timeout = request_timeout;
        Ok(self)
    }

    /// Replace the Unicode-character cap applied to serialized tool results.
    pub fn with_max_tool_output_chars(
        mut self,
        max_tool_output_chars: usize,
    ) -> Result<Self, McpTransportConfigError> {
        if max_tool_output_chars < minimum_tool_output_chars()
            || max_tool_output_chars >= MAX_TOOL_OUTPUT_CHARS
        {
            return Err(McpTransportConfigError::InvalidToolOutputLimit);
        }
        self.max_tool_output_chars = max_tool_output_chars;
        Ok(self)
    }

    /// Replace the deterministic private-cache lifetime advertised to clients.
    pub fn with_private_cache_ttl_ms(mut self, private_cache_ttl_ms: u64) -> Self {
        self.private_cache_ttl_ms = private_cache_ttl_ms;
        self
    }

    /// Return whether an exact present Origin value is allowed.
    fn allows_origin(&self, origin: &str) -> bool {
        self.allowed_origins.contains(origin)
    }
}

/// Validated JSON-RPC identifier retained for the response envelope.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
enum JsonRpcId {
    /// String identifier, including the empty string.
    String(String),
    /// Signed integer identifier.
    Signed(i64),
    /// Unsigned integer identifier larger than the signed range.
    Unsigned(u64),
}

/// Structurally validated JSON-RPC request before protocol-era checks.
struct ParsedRequest {
    id: Option<JsonRpcId>,
    method: String,
    params: Option<Map<String, Value>>,
}

/// Structurally valid inbound message accepted by the Streamable HTTP endpoint.
enum ParsedInbound {
    /// A JSON-RPC request or notification that can be dispatched.
    Request(ParsedRequest),
    /// A JSON-RPC response that requires no server response.
    Response,
}

/// One validated message or the bounded legacy batch representation.
enum ParsedPayload {
    /// One request, notification, or response.
    Single(ParsedInbound),
    /// A nonempty legacy batch whose invalid items retain per-item errors.
    Batch(Vec<Result<ParsedInbound, ProtocolFailure>>),
}

/// Internal error description mapped to one bounded JSON-RPC response.
struct ProtocolFailure {
    status: StatusCode,
    id: Option<JsonRpcId>,
    code: i64,
    message: &'static str,
    data: Option<Value>,
}

/// Parsed modern metadata retained only for validation completeness.
struct ModernMetadata;

/// Validated tool-call arguments extracted from request parameters.
struct ValidatedToolCall {
    name: String,
    arguments: Map<String, Value>,
}

/// Primitive JSON type supported by one final-era custom header binding.
#[derive(Clone, Copy)]
enum HeaderBindingKind {
    /// An exact UTF-8 string, optionally transported through the base64 sentinel.
    String,
    /// A JSON safe integer compared numerically.
    Integer,
    /// A lowercase JSON boolean literal compared exactly.
    Boolean,
}

/// Compiled path and HTTP name for one trusted tool-schema header binding.
struct HeaderBinding {
    header_name: HeaderName,
    property_path: Vec<String>,
    kind: HeaderBindingKind,
}

/// Remaining structural and string budget for dispatcher-provided JSON.
struct JsonTraversalBudget {
    remaining_nodes: usize,
    remaining_string_bytes: usize,
}

/// Serve one bounded JSON-RPC exchange on the stateless MCP POST endpoint.
pub(crate) async fn handle_mcp(
    Extension(config): Extension<McpTransportConfig>,
    Extension(dispatcher): Extension<Arc<dyn McpDispatcher>>,
    request: Request,
) -> Response {
    let deadline = tokio::time::Instant::now() + config.request_timeout;
    match tokio::time::timeout_at(
        deadline,
        process_mcp_request(config, dispatcher, request, deadline),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => ProtocolFailure::request_timeout(None).into_response(),
    }
}

/// Process body collection, protocol validation, dispatch, and rendering under one deadline.
async fn process_mcp_request(
    config: McpTransportConfig,
    dispatcher: Arc<dyn McpDispatcher>,
    request: Request,
    deadline: tokio::time::Instant,
) -> Response {
    let (parts, body) = request.into_parts();

    if let Err(failure) = validate_origin(&parts.headers, &config) {
        return failure.into_response();
    }
    if let Err(failure) = validate_content_type(&parts.headers) {
        return failure.into_response();
    }
    if let Err(failure) = validate_accept(&parts.headers) {
        return failure.into_response();
    }

    let body = match to_bytes(body, config.max_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return ProtocolFailure::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                None,
                -32600,
                "Request body too large",
            )
            .into_response();
        }
    };
    if let Err(failure) = ensure_deadline(deadline, None) {
        return failure.into_response();
    }
    let payload = match parse_json_rpc_payload(&body) {
        Ok(payload) => payload,
        Err(failure) => return failure.into_response(),
    };
    if let Err(failure) = ensure_deadline(deadline, None) {
        return failure.into_response();
    }

    match payload {
        ParsedPayload::Single(ParsedInbound::Response) => {
            match validate_inbound_response_protocol(&parts.headers) {
                Ok(()) => StatusCode::ACCEPTED.into_response(),
                Err(failure) => failure.into_response(),
            }
        }
        ParsedPayload::Single(ParsedInbound::Request(parsed)) => {
            let id = parsed.id.clone();
            let version = match resolve_protocol_version(&parts.headers, &parsed) {
                Ok(version) => version,
                Err(failure) => return failure.with_id(id).into_response(),
            };
            if version.is_modern() {
                if let Err(failure) = validate_modern_request(&parts.headers, &parsed, version) {
                    return failure.with_id(id).into_response();
                }
            }
            if let Err(failure) = ensure_deadline(deadline, id.clone()) {
                return failure.into_response();
            }
            dispatch_request(
                parsed,
                version,
                parts.extensions,
                &parts.headers,
                &config,
                dispatcher,
                deadline,
            )
            .await
        }
        ParsedPayload::Batch(items) => {
            let version = match resolve_batch_protocol_version(&parts.headers) {
                Ok(version) => version,
                Err(failure) => return failure.into_response(),
            };
            dispatch_legacy_batch(
                items,
                version,
                parts.extensions,
                &parts.headers,
                &config,
                dispatcher,
                deadline,
            )
            .await
        }
    }
}

/// Reject work that crossed the one absolute transport deadline during synchronous processing.
fn ensure_deadline(
    deadline: tokio::time::Instant,
    id: Option<JsonRpcId>,
) -> Result<(), ProtocolFailure> {
    if tokio::time::Instant::now() >= deadline {
        return Err(ProtocolFailure::request_timeout(id));
    }
    Ok(())
}

/// Validate an optional Origin using exact allowlist equality.
fn validate_origin(
    headers: &HeaderMap,
    config: &McpTransportConfig,
) -> Result<(), ProtocolFailure> {
    let mut origins = headers.get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return Ok(());
    };
    if origins.next().is_some() {
        return Err(ProtocolFailure::new(
            StatusCode::FORBIDDEN,
            None,
            -32600,
            "Origin not allowed",
        ));
    }
    let origin = origin.to_str().map_err(|_| {
        ProtocolFailure::new(StatusCode::FORBIDDEN, None, -32600, "Origin not allowed")
    })?;
    if !config.allows_origin(origin) {
        return Err(ProtocolFailure::new(
            StatusCode::FORBIDDEN,
            None,
            -32600,
            "Origin not allowed",
        ));
    }
    Ok(())
}

/// Require one JSON-compatible Content-Type header.
fn validate_content_type(headers: &HeaderMap) -> Result<(), ProtocolFailure> {
    let values: Vec<_> = headers.get_all(CONTENT_TYPE).iter().collect();
    if values.len() != 1 {
        return Err(ProtocolFailure::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            None,
            -32600,
            "Content-Type must be JSON",
        ));
    }
    let media_type = values[0]
        .to_str()
        .ok()
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    let is_json = media_type.as_deref().is_some_and(|media_type| {
        media_type == "application/json"
            || (media_type.starts_with("application/") && media_type.ends_with("+json"))
    });
    if !is_json {
        return Err(ProtocolFailure::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            None,
            -32600,
            "Content-Type must be JSON",
        ));
    }
    Ok(())
}

/// Require a present Accept header, when supplied, to permit a JSON response.
fn validate_accept(headers: &HeaderMap) -> Result<(), ProtocolFailure> {
    let values: Vec<_> = headers.get_all(ACCEPT).iter().collect();
    if values.is_empty() {
        return Ok(());
    }
    let allows_json = values.iter().any(|value| {
        value
            .to_str()
            .ok()
            .is_some_and(|value| value.split(',').any(accept_range_allows_json))
    });
    if !allows_json {
        return Err(ProtocolFailure::new(
            StatusCode::NOT_ACCEPTABLE,
            None,
            -32600,
            "Accept must allow JSON",
        ));
    }
    Ok(())
}

/// Report whether one Accept media range positively permits `application/json`.
fn accept_range_allows_json(range: &str) -> bool {
    let mut segments = range.trim().split(';');
    let media_range = segments
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let mut quality = 1.0_f32;
    for parameter in segments {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            let Ok(parsed) = value.trim().parse::<f32>() else {
                return false;
            };
            if !(0.0..=1.0).contains(&parsed) {
                return false;
            }
            quality = parsed;
        }
    }
    quality > 0.0
        && matches!(
            media_range.as_str(),
            "application/json" | "application/*" | "*/*"
        )
}

/// Parse one JSON-RPC message or a bounded nonempty legacy batch.
fn parse_json_rpc_payload(body: &[u8]) -> Result<ParsedPayload, ProtocolFailure> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32700, "Parse error"))?;
    if let Value::Array(items) = value {
        if items.is_empty() || items.len() > MAX_BATCH_ITEMS {
            return Err(ProtocolFailure::new(
                StatusCode::BAD_REQUEST,
                None,
                -32600,
                "Invalid Request",
            ));
        }
        return Ok(ParsedPayload::Batch(
            items.into_iter().map(parse_json_rpc_message).collect(),
        ));
    }
    parse_json_rpc_message(value).map(ParsedPayload::Single)
}

/// Parse one structurally valid request, notification, or response object.
fn parse_json_rpc_message(value: Value) -> Result<ParsedInbound, ProtocolFailure> {
    let object = value.as_object().ok_or_else(|| {
        ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32600, "Invalid Request")
    })?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(ProtocolFailure::new(
            StatusCode::BAD_REQUEST,
            None,
            -32600,
            "Invalid Request",
        ));
    }
    if !object.contains_key("method") {
        return validate_json_rpc_response(object).map(|()| ParsedInbound::Response);
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| !method.is_empty())
        .ok_or_else(|| {
            ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32600, "Invalid Request")
        })?
        .to_owned();
    let id = parse_json_rpc_id(object.get("id"))?;
    let params = match object.get("params") {
        Some(Value::Object(params)) => Some(params.clone()),
        Some(_) => {
            return Err(ProtocolFailure::new(
                StatusCode::BAD_REQUEST,
                id,
                -32602,
                "Invalid params",
            ));
        }
        None => None,
    };
    Ok(ParsedInbound::Request(ParsedRequest { id, method, params }))
}

/// Validate an inbound response without retaining any client-controlled payload.
fn validate_json_rpc_response(object: &Map<String, Value>) -> Result<(), ProtocolFailure> {
    parse_json_rpc_id(object.get("id"))?.ok_or_else(|| {
        ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32600, "Invalid Request")
    })?;
    let has_result = object.contains_key("result");
    let valid_error = object.get("error").is_some_and(|error| {
        error.as_object().is_some_and(|error| {
            error.get("code").is_some_and(Value::is_i64)
                && error.get("message").is_some_and(Value::is_string)
        })
    });
    if has_result == object.contains_key("error") || (object.contains_key("error") && !valid_error)
    {
        return Err(ProtocolFailure::new(
            StatusCode::BAD_REQUEST,
            None,
            -32600,
            "Invalid Request",
        ));
    }
    Ok(())
}

/// Accept only string or integral, non-null JSON-RPC identifiers.
fn parse_json_rpc_id(value: Option<&Value>) -> Result<Option<JsonRpcId>, ProtocolFailure> {
    match value {
        None => Ok(None),
        Some(Value::String(id)) if id.len() <= MAX_JSON_RPC_STRING_ID_BYTES => {
            Ok(Some(JsonRpcId::String(id.clone())))
        }
        Some(Value::Number(id)) if id.is_i64() => Ok(id.as_i64().map(JsonRpcId::Signed)),
        Some(Value::Number(id)) if id.is_u64() => Ok(id.as_u64().map(JsonRpcId::Unsigned)),
        Some(_) => Err(ProtocolFailure::new(
            StatusCode::BAD_REQUEST,
            None,
            -32600,
            "Invalid Request",
        )),
    }
}

/// Resolve a supported revision while preserving the documented legacy fallback.
fn resolve_protocol_version(
    headers: &HeaderMap,
    request: &ParsedRequest,
) -> Result<McpProtocolVersion, ProtocolFailure> {
    let header = single_header(headers, &MCP_PROTOCOL_VERSION)?;
    if let Some(header) = header {
        let version = parse_supported_version(header).ok_or_else(|| {
            ProtocolFailure::unsupported_protocol_version(bounded_requested_version(header))
        })?;
        if !version.is_modern() && request_has_modern_metadata(request) {
            return Err(ProtocolFailure::header_mismatch());
        }
        if request.method == "initialize" && !version.is_modern() {
            let proposed = initialize_protocol_proposal(request)?;
            if proposed != version.as_str() {
                return Err(ProtocolFailure::header_mismatch());
            }
        }
        return Ok(version);
    }

    if request.method == "server/discover" || request_has_modern_metadata(request) {
        return Err(ProtocolFailure::header_mismatch());
    }
    if request.method == "initialize" {
        let proposed = initialize_protocol_proposal(request)?;
        if proposed == MODERN_PROTOCOL_VERSION {
            return Err(ProtocolFailure::header_mismatch());
        }
        return Ok(parse_supported_version(proposed)
            .filter(|version| !version.is_modern())
            .unwrap_or(McpProtocolVersion::V2025_11_25));
    }
    Ok(McpProtocolVersion::V2025_03_26)
}

/// Read the mandatory legacy initialize protocol proposal.
fn initialize_protocol_proposal(request: &ParsedRequest) -> Result<&str, ProtocolFailure> {
    let value = request
        .params
        .as_ref()
        .and_then(|params| params.get("protocolVersion"))
        .ok_or_else(|| {
            ProtocolFailure::new(
                StatusCode::BAD_REQUEST,
                request.id.clone(),
                -32602,
                "Invalid params",
            )
        })?;
    value.as_str().ok_or_else(|| {
        ProtocolFailure::new(
            StatusCode::BAD_REQUEST,
            request.id.clone(),
            -32602,
            "Invalid params",
        )
    })
}

/// Resolve the only protocol revision whose Streamable HTTP transport permits batches.
fn resolve_batch_protocol_version(
    headers: &HeaderMap,
) -> Result<McpProtocolVersion, ProtocolFailure> {
    let version = match single_header(headers, &MCP_PROTOCOL_VERSION)? {
        Some(header) => parse_supported_version(header).ok_or_else(|| {
            ProtocolFailure::unsupported_protocol_version(bounded_requested_version(header))
        })?,
        None => McpProtocolVersion::V2025_03_26,
    };
    if version != McpProtocolVersion::V2025_03_26 {
        return Err(ProtocolFailure::new(
            StatusCode::BAD_REQUEST,
            None,
            -32600,
            "Invalid Request",
        ));
    }
    Ok(version)
}

/// Accept inbound responses only for supported handshake-era transports.
fn validate_inbound_response_protocol(headers: &HeaderMap) -> Result<(), ProtocolFailure> {
    let Some(header) = single_header(headers, &MCP_PROTOCOL_VERSION)? else {
        return Ok(());
    };
    let version = parse_supported_version(header).ok_or_else(|| {
        ProtocolFailure::unsupported_protocol_version(bounded_requested_version(header))
    })?;
    if version.is_modern() {
        return Err(ProtocolFailure::new(
            StatusCode::BAD_REQUEST,
            None,
            -32600,
            "Invalid Request",
        ));
    }
    Ok(())
}

/// Detect final-era body metadata that cannot use the no-header legacy fallback.
fn request_has_modern_metadata(request: &ParsedRequest) -> bool {
    request
        .params
        .as_ref()
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
        .is_some_and(|metadata| {
            metadata.contains_key("io.modelcontextprotocol/protocolVersion")
                || metadata.contains_key("io.modelcontextprotocol/clientCapabilities")
        })
}

/// Map an exact wire revision to its typed representation.
fn parse_supported_version(value: &str) -> Option<McpProtocolVersion> {
    match value {
        "2025-03-26" => Some(McpProtocolVersion::V2025_03_26),
        "2025-06-18" => Some(McpProtocolVersion::V2025_06_18),
        "2025-11-25" => Some(McpProtocolVersion::V2025_11_25),
        "2026-07-28" => Some(McpProtocolVersion::V2026_07_28),
        _ => None,
    }
}

/// Bound an unsupported client revision before reflecting it in error data.
fn bounded_requested_version(value: &str) -> String {
    const MAX_REFLECTED_VERSION_CHARS: usize = 64;
    if value.chars().count() <= MAX_REFLECTED_VERSION_CHARS {
        value.to_owned()
    } else {
        "invalid".to_owned()
    }
}

/// Validate all mandatory final-era body and HTTP metadata.
fn validate_modern_request(
    headers: &HeaderMap,
    request: &ParsedRequest,
    version: McpProtocolVersion,
) -> Result<ModernMetadata, ProtocolFailure> {
    let params = request
        .params
        .as_ref()
        .ok_or_else(ProtocolFailure::header_mismatch)?;
    let metadata = params
        .get("_meta")
        .and_then(Value::as_object)
        .ok_or_else(ProtocolFailure::header_mismatch)?;
    let body_version = metadata
        .get("io.modelcontextprotocol/protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(ProtocolFailure::header_mismatch)?;
    if body_version != version.as_str() {
        return Err(ProtocolFailure::header_mismatch());
    }
    if !metadata
        .get("io.modelcontextprotocol/clientCapabilities")
        .is_some_and(Value::is_object)
    {
        return Err(ProtocolFailure::new(
            StatusCode::BAD_REQUEST,
            request.id.clone(),
            -32602,
            "Invalid params",
        ));
    }
    if let Some(client_info) = metadata.get("io.modelcontextprotocol/clientInfo") {
        let valid = client_info.as_object().is_some_and(|client_info| {
            client_info.get("name").is_some_and(Value::is_string)
                && client_info.get("version").is_some_and(Value::is_string)
        });
        if !valid {
            return Err(ProtocolFailure::new(
                StatusCode::BAD_REQUEST,
                request.id.clone(),
                -32602,
                "Invalid params",
            ));
        }
    }

    let method =
        single_header(headers, &MCP_METHOD)?.ok_or_else(ProtocolFailure::header_mismatch)?;
    if method != request.method {
        return Err(ProtocolFailure::header_mismatch());
    }
    Ok(ModernMetadata)
}

/// Read exactly one bounded UTF-8 header or return a header-mismatch failure.
fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a str>, ProtocolFailure> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ProtocolFailure::header_mismatch());
    }
    let value = value
        .to_str()
        .map_err(|_| ProtocolFailure::header_mismatch())?;
    Ok(Some(value))
}

/// Execute a bounded 2025-03-26 batch sequentially under the request's one deadline.
async fn dispatch_legacy_batch(
    items: Vec<Result<ParsedInbound, ProtocolFailure>>,
    version: McpProtocolVersion,
    extensions: axum::http::Extensions,
    headers: &HeaderMap,
    config: &McpTransportConfig,
    dispatcher: Arc<dyn McpDispatcher>,
    deadline: tokio::time::Instant,
) -> Response {
    let has_request = items
        .iter()
        .any(|item| matches!(item, Ok(ParsedInbound::Request(_))));
    let has_response = items
        .iter()
        .any(|item| matches!(item, Ok(ParsedInbound::Response)));
    if has_request && has_response {
        return ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32600, "Invalid Request")
            .into_response();
    }
    if items.iter().any(|item| {
        matches!(
            item,
            Ok(ParsedInbound::Request(request)) if request.method == "initialize"
        )
    }) {
        return ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32600, "Invalid Request")
            .into_response();
    }
    if items.iter().any(|item| {
        matches!(
            item,
            Ok(ParsedInbound::Request(request)) if request_has_modern_metadata(request)
        )
    }) {
        return ProtocolFailure::header_mismatch().into_response();
    }

    let mut replies = Vec::with_capacity(items.len());
    let mut encoded_bytes = 2_usize;
    for item in items {
        if let Err(failure) = ensure_deadline(deadline, None) {
            return failure.into_response();
        }
        match item {
            Err(failure) => {
                if let Err(failure) = push_bounded_batch_reply(
                    &mut replies,
                    &mut encoded_bytes,
                    failure.into_value(),
                    config.max_body_bytes,
                ) {
                    return failure.into_response();
                }
            }
            Ok(ParsedInbound::Response) => {}
            Ok(ParsedInbound::Request(request)) => {
                let expects_response = request.id.is_some();
                let response = dispatch_request(
                    request,
                    version,
                    extensions.clone(),
                    headers,
                    config,
                    Arc::clone(&dispatcher),
                    deadline,
                )
                .await;
                if expects_response {
                    let value = match response_json_value(response, config.max_body_bytes).await {
                        Ok(value) => value,
                        Err(failure) => return failure.into_response(),
                    };
                    if let Err(failure) = push_bounded_batch_reply(
                        &mut replies,
                        &mut encoded_bytes,
                        value,
                        config.max_body_bytes,
                    ) {
                        return failure.into_response();
                    }
                }
            }
        }
    }
    if let Err(failure) = ensure_deadline(deadline, None) {
        return failure.into_response();
    }
    if replies.is_empty() {
        StatusCode::ACCEPTED.into_response()
    } else {
        json_response_with_deadline(StatusCode::OK, Value::Array(replies), deadline, None)
    }
}

/// Add one response to a batch while enforcing the aggregate response-byte budget.
fn push_bounded_batch_reply(
    replies: &mut Vec<Value>,
    encoded_bytes: &mut usize,
    value: Value,
    max_response_bytes: usize,
) -> Result<(), ProtocolFailure> {
    let value_bytes = serde_json::to_vec(&value).map_err(|_| ProtocolFailure::internal(None))?;
    *encoded_bytes = encoded_bytes
        .saturating_add(value_bytes.len())
        .saturating_add(usize::from(!replies.is_empty()));
    if *encoded_bytes > max_response_bytes {
        return Err(ProtocolFailure::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            -32603,
            "Response exceeded the server limit",
        ));
    }
    replies.push(value);
    Ok(())
}

/// Decode one internally rendered JSON response for inclusion in a batch array.
async fn response_json_value(
    response: Response,
    max_response_bytes: usize,
) -> Result<Value, ProtocolFailure> {
    let bytes = to_bytes(response.into_body(), max_response_bytes)
        .await
        .map_err(|_| ProtocolFailure::internal(None))?;
    serde_json::from_slice(&bytes).map_err(|_| ProtocolFailure::internal(None))
}

/// Dispatch a fully era-validated MCP request to a core or tool method.
async fn dispatch_request(
    request: ParsedRequest,
    version: McpProtocolVersion,
    extensions: axum::http::Extensions,
    headers: &HeaderMap,
    config: &McpTransportConfig,
    dispatcher: Arc<dyn McpDispatcher>,
    deadline: tokio::time::Instant,
) -> Response {
    let response_id = request.id.clone();
    let response = match request.method.as_str() {
        "initialize" if !version.is_modern() => handle_initialize(request, version),
        "notifications/initialized" if !version.is_modern() => {
            handle_initialized_notification(request)
        }
        "ping" => handle_ping(request, version),
        "server/discover" if version.is_modern() => handle_discover(request, config),
        "tools/list" => {
            handle_tools_list(request, version, extensions, config, dispatcher, deadline).await
        }
        "tools/call" => {
            handle_tools_call(
                request, version, extensions, headers, config, dispatcher, deadline,
            )
            .await
        }
        _ => ProtocolFailure::new(
            StatusCode::NOT_FOUND,
            request.id,
            -32601,
            "Method not found",
        )
        .into_response(),
    };
    match ensure_deadline(deadline, response_id) {
        Ok(()) => response,
        Err(failure) => failure.into_response(),
    }
}

/// Return the negotiated legacy initialize result without creating a session.
fn handle_initialize(request: ParsedRequest, version: McpProtocolVersion) -> Response {
    let Some(id) = request.id else {
        return ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32600, "Invalid Request")
            .into_response();
    };
    let Some(params) = request.params else {
        return ProtocolFailure::new(StatusCode::BAD_REQUEST, Some(id), -32602, "Invalid params")
            .into_response();
    };
    if !valid_legacy_initialize_params(&params) {
        return ProtocolFailure::new(StatusCode::BAD_REQUEST, Some(id), -32602, "Invalid params")
            .into_response();
    }
    result_response(
        id,
        json!({
            "protocolVersion": version.as_str(),
            "capabilities": { "tools": {} },
            "serverInfo": server_info(),
            "instructions": "Use the listed FrameShift tools for account-scoped persona operations."
        }),
    )
}

/// Require every mandatory field in a handshake-era initialize request.
fn valid_legacy_initialize_params(params: &Map<String, Value>) -> bool {
    params.get("protocolVersion").is_some_and(Value::is_string)
        && params.get("capabilities").is_some_and(Value::is_object)
        && params.get("clientInfo").is_some_and(|value| {
            value.as_object().is_some_and(|client_info| {
                client_info.get("name").is_some_and(Value::is_string)
                    && client_info.get("version").is_some_and(Value::is_string)
            })
        })
}

/// Accept only the handshake-era initialized notification and emit no body.
fn handle_initialized_notification(request: ParsedRequest) -> Response {
    if request.id.is_some()
        || request
            .params
            .as_ref()
            .is_some_and(|params| !params.is_empty())
    {
        return ProtocolFailure::new(
            StatusCode::BAD_REQUEST,
            request.id,
            -32600,
            "Invalid Request",
        )
        .into_response();
    }
    StatusCode::ACCEPTED.into_response()
}

/// Return the empty core ping result for every supported revision.
fn handle_ping(request: ParsedRequest, version: McpProtocolVersion) -> Response {
    let Some(id) = request.id else {
        return ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32600, "Invalid Request")
            .into_response();
    };
    if version.is_modern() {
        result_response(
            id,
            json!({
                "resultType": "complete",
                "_meta": modern_result_metadata()
            }),
        )
    } else {
        result_response(id, json!({}))
    }
}

/// Return deterministic final-era server discovery and private cache metadata.
fn handle_discover(request: ParsedRequest, config: &McpTransportConfig) -> Response {
    let Some(id) = request.id else {
        return ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32600, "Invalid Request")
            .into_response();
    };
    result_response(
        id,
        json!({
            "resultType": "complete",
            "supportedVersions": supported_protocol_version_values(),
            "capabilities": { "tools": {} },
            "instructions": "Use the listed FrameShift tools for account-scoped persona operations.",
            "ttlMs": config.private_cache_ttl_ms,
            "cacheScope": "private",
            "_meta": modern_result_metadata()
        }),
    )
}

/// List tools through the typed dispatcher with deadline and deterministic order.
async fn handle_tools_list(
    request: ParsedRequest,
    version: McpProtocolVersion,
    extensions: axum::http::Extensions,
    config: &McpTransportConfig,
    dispatcher: Arc<dyn McpDispatcher>,
    deadline: tokio::time::Instant,
) -> Response {
    let Some(id) = request.id else {
        return ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32600, "Invalid Request")
            .into_response();
    };
    let cursor = match validate_list_params(request.params.as_ref()) {
        Ok(cursor) => cursor,
        Err(failure) => return failure.with_id(Some(id)).into_response(),
    };
    let result = match dispatcher
        .list_tools(McpListToolsRequest {
            cursor,
            context: McpRequestContext::new(version, extensions),
        })
        .await
    {
        Ok(result) => result,
        Err(error) => return dispatcher_failure(Some(id), error),
    };
    if let Err(failure) = ensure_deadline(deadline, Some(id.clone())) {
        return failure.into_response();
    }
    render_tool_list_response(id, result, version, config.clone(), deadline).await
}

/// Bound, sort, and serialize one dispatcher list away from the async reactor.
async fn render_tool_list_response(
    id: JsonRpcId,
    mut result: McpListToolsResult,
    version: McpProtocolVersion,
    config: McpTransportConfig,
    deadline: tokio::time::Instant,
) -> Response {
    let timeout_id = Some(id.clone());
    run_render_job(deadline, timeout_id, move || {
        if !list_result_within_transport_limits(&result, config.max_body_bytes) {
            return ProtocolFailure::internal(Some(id)).into_response();
        }
        result.tools.retain(|tool| {
            valid_wire_tool_definition_with_limit(tool, config.max_body_bytes)
                && (!version.is_modern() || compile_tool_header_bindings(tool).is_ok())
        });
        result
            .tools
            .sort_by(|left, right| left.name.cmp(&right.name));
        let value = json_rpc_result_value(id.clone(), list_result_value(result, version, &config));
        let encoded =
            serde_json::to_vec(&value).expect("bounded MCP list response must always serialize");
        if encoded.len() > config.max_body_bytes {
            return ProtocolFailure::internal(Some(id)).into_response();
        }
        encoded_json_response(StatusCode::OK, encoded)
    })
    .await
}

/// Validate aggregate tool-list structure before sorting or serialization.
fn list_result_within_transport_limits(result: &McpListToolsResult, max_bytes: usize) -> bool {
    if result.tools.len() > MAX_TOOLS_PER_PAGE
        || result
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > MAX_TOOL_CURSOR_BYTES)
    {
        return false;
    }
    let mut budget = JsonTraversalBudget {
        remaining_nodes: MAX_DISPATCH_JSON_NODES,
        remaining_string_bytes: max_bytes,
    };
    if let Some(cursor) = result.next_cursor.as_deref() {
        if !consume_dispatcher_string(cursor, MAX_TOOL_CURSOR_BYTES, &mut budget) {
            return false;
        }
    }
    result
        .tools
        .iter()
        .all(|tool| tool_definition_within_budget(tool, max_bytes, &mut budget))
}

/// Validate the optional opaque cursor and reject malformed list parameters.
fn validate_list_params(
    params: Option<&Map<String, Value>>,
) -> Result<Option<String>, ProtocolFailure> {
    match params.and_then(|params| params.get("cursor")) {
        None => Ok(None),
        Some(Value::String(cursor)) if cursor.len() <= MAX_TOOL_CURSOR_BYTES => {
            Ok(Some(cursor.clone()))
        }
        Some(_) => Err(ProtocolFailure::new(
            StatusCode::BAD_REQUEST,
            None,
            -32602,
            "Invalid params",
        )),
    }
}

/// Render a legacy or final-era tool-list result from one dispatcher value.
fn list_result_value(
    result: McpListToolsResult,
    version: McpProtocolVersion,
    config: &McpTransportConfig,
) -> Value {
    let mut value = json!({ "tools": result.tools });
    let object = value
        .as_object_mut()
        .expect("literal list result must be a JSON object");
    if let Some(next_cursor) = result.next_cursor {
        object.insert("nextCursor".to_owned(), Value::String(next_cursor));
    }
    if version.is_modern() {
        object.insert(
            "resultType".to_owned(),
            Value::String("complete".to_owned()),
        );
        object.insert(
            "ttlMs".to_owned(),
            Value::Number(config.private_cache_ttl_ms.into()),
        );
        object.insert("cacheScope".to_owned(), Value::String("private".to_owned()));
        object.insert("_meta".to_owned(), modern_result_metadata());
    }
    value
}

/// Execute a validated tool call with modern name binding and bounded output.
async fn handle_tools_call(
    request: ParsedRequest,
    version: McpProtocolVersion,
    extensions: axum::http::Extensions,
    headers: &HeaderMap,
    config: &McpTransportConfig,
    dispatcher: Arc<dyn McpDispatcher>,
    deadline: tokio::time::Instant,
) -> Response {
    let Some(id) = request.id.clone() else {
        return ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32600, "Invalid Request")
            .into_response();
    };
    let call = match validate_tool_call(request.params.as_ref()) {
        Ok(call) => call,
        Err(failure) => return failure.with_id(Some(id)).into_response(),
    };
    let prepared = match dispatcher
        .prepare_tool(McpPrepareToolRequest {
            name: call.name.clone(),
            context: McpRequestContext::new(version, extensions),
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(error) => return dispatcher_failure(Some(id), error),
    };
    if let Err(failure) = ensure_deadline(deadline, Some(id.clone())) {
        return failure.into_response();
    }
    let Some(prepared) = prepared else {
        return result_response(
            id,
            call_result_value(
                McpCallToolResult::error("This tool is not available."),
                version,
            ),
        );
    };
    if prepared.definition().name != call.name {
        return if version.is_modern() {
            ProtocolFailure::header_mismatch()
                .with_id(Some(id))
                .into_response()
        } else {
            ProtocolFailure::internal(Some(id)).into_response()
        };
    }
    if !valid_wire_tool_definition_with_limit(prepared.definition(), config.max_body_bytes) {
        return if version.is_modern() {
            ProtocolFailure::header_mismatch()
                .with_id(Some(id))
                .into_response()
        } else {
            ProtocolFailure::internal(Some(id)).into_response()
        };
    }
    if version.is_modern() {
        if let Err(failure) = validate_modern_tool_name(headers, &call.name) {
            return failure.with_id(Some(id)).into_response();
        }
        let bindings = match compile_tool_header_bindings(prepared.definition()) {
            Ok(bindings) => bindings,
            Err(failure) => return failure.with_id(Some(id)).into_response(),
        };
        if let Err(failure) = validate_tool_parameter_headers(headers, &call.arguments, &bindings) {
            return failure.with_id(Some(id)).into_response();
        }
    }
    let result = prepared
        .call(McpPreparedToolCallRequest {
            arguments: call.arguments,
        })
        .await;
    if let Err(failure) = ensure_deadline(deadline, Some(id.clone())) {
        return failure.into_response();
    }
    render_tool_call_response(id, result, version, config.max_tool_output_chars, deadline).await
}

/// Bound and serialize one dispatcher call result away from the async reactor.
async fn render_tool_call_response(
    id: JsonRpcId,
    result: McpCallToolResult,
    version: McpProtocolVersion,
    max_chars: usize,
    deadline: tokio::time::Instant,
) -> Response {
    let timeout_id = Some(id.clone());
    run_render_job(deadline, timeout_id, move || {
        let value = bounded_call_result_value(result, version, max_chars);
        result_response(id, value)
    })
    .await
}

/// Run bounded synchronous response work on a blocking worker under the shared deadline.
async fn run_render_job<F>(
    deadline: tokio::time::Instant,
    id: Option<JsonRpcId>,
    render: F,
) -> Response
where
    F: FnOnce() -> Response + Send + 'static,
{
    match tokio::time::timeout_at(deadline, tokio::task::spawn_blocking(render)).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => ProtocolFailure::internal(id).into_response(),
        Err(_) => ProtocolFailure::request_timeout(id).into_response(),
    }
}

/// Require a nonempty tool name and object arguments.
fn validate_tool_call(
    params: Option<&Map<String, Value>>,
) -> Result<ValidatedToolCall, ProtocolFailure> {
    let params = params.ok_or_else(|| {
        ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32602, "Invalid params")
    })?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty() && name.len() <= MAX_TOOL_NAME_BYTES)
        .ok_or_else(|| {
            ProtocolFailure::new(StatusCode::BAD_REQUEST, None, -32602, "Invalid params")
        })?
        .to_owned();
    let arguments = match params.get("arguments") {
        Some(Value::Object(arguments)) => arguments.clone(),
        None => Map::new(),
        Some(_) => {
            return Err(ProtocolFailure::new(
                StatusCode::BAD_REQUEST,
                None,
                -32602,
                "Invalid params",
            ));
        }
    };
    Ok(ValidatedToolCall { name, arguments })
}

/// Decode and compare the mandatory final-era `Mcp-Name` header.
fn validate_modern_tool_name(headers: &HeaderMap, body_name: &str) -> Result<(), ProtocolFailure> {
    let encoded =
        single_header(headers, &MCP_NAME)?.ok_or_else(ProtocolFailure::header_mismatch)?;
    let decoded = decode_mcp_name(encoded).ok_or_else(ProtocolFailure::header_mismatch)?;
    if decoded != body_name {
        return Err(ProtocolFailure::header_mismatch());
    }
    Ok(())
}

/// Validate the base tool wire schema shared by every supported revision.
fn valid_wire_tool_definition_with_limit(tool: &McpTool, max_bytes: usize) -> bool {
    !tool.name.is_empty()
        && tool.input_schema.get("type").and_then(Value::as_str) == Some("object")
        && tool.output_schema.as_ref().is_none_or(Value::is_object)
        && tool_definition_within_transport_limits(tool, max_bytes)
}

/// Validate one tool definition against standalone transport complexity limits.
fn tool_definition_within_transport_limits(tool: &McpTool, max_bytes: usize) -> bool {
    let mut budget = JsonTraversalBudget {
        remaining_nodes: MAX_DISPATCH_JSON_NODES,
        remaining_string_bytes: max_bytes,
    };
    tool_definition_within_budget(tool, max_bytes, &mut budget)
}

/// Consume one tool definition from a shared list-response complexity budget.
fn tool_definition_within_budget(
    tool: &McpTool,
    max_bytes: usize,
    budget: &mut JsonTraversalBudget,
) -> bool {
    if !consume_dispatcher_string(&tool.name, MAX_TOOL_NAME_BYTES, budget) {
        return false;
    }
    for text in [tool.title.as_deref(), tool.description.as_deref()]
        .into_iter()
        .flatten()
    {
        if !consume_dispatcher_string(text, max_bytes, budget) {
            return false;
        }
    }
    if !consume_dispatcher_json(&tool.input_schema, 0, budget) {
        return false;
    }
    if let Some(output_schema) = tool.output_schema.as_ref() {
        if !consume_dispatcher_json(output_schema, 0, budget) {
            return false;
        }
    }
    if let Some(annotations) = tool.annotations.as_ref() {
        if !consume_dispatcher_string(&annotations.title, max_bytes, budget) {
            return false;
        }
    }
    true
}

/// Consume a bounded dispatcher string without scanning oversized payloads.
fn consume_dispatcher_string(
    value: &str,
    field_limit: usize,
    budget: &mut JsonTraversalBudget,
) -> bool {
    if value.len() > field_limit || value.len() > budget.remaining_string_bytes {
        return false;
    }
    budget.remaining_string_bytes -= value.len();
    true
}

/// Traverse dispatcher JSON with explicit depth, node, and aggregate-string bounds.
fn consume_dispatcher_json(value: &Value, depth: usize, budget: &mut JsonTraversalBudget) -> bool {
    if depth > MAX_DISPATCH_JSON_DEPTH || budget.remaining_nodes == 0 {
        return false;
    }
    budget.remaining_nodes -= 1;
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(value) => {
            consume_dispatcher_string(value, budget.remaining_string_bytes, budget)
        }
        Value::Array(values) => {
            if values.len() > budget.remaining_nodes {
                return false;
            }
            values
                .iter()
                .all(|value| consume_dispatcher_json(value, depth + 1, budget))
        }
        Value::Object(values) => {
            if values.len() > budget.remaining_nodes {
                return false;
            }
            values.iter().all(|(key, value)| {
                consume_dispatcher_string(key, budget.remaining_string_bytes, budget)
                    && consume_dispatcher_json(value, depth + 1, budget)
            })
        }
    }
}

/// Compile every statically reachable `x-mcp-header` annotation in one trusted schema.
fn compile_tool_header_bindings(tool: &McpTool) -> Result<Vec<HeaderBinding>, ProtocolFailure> {
    if tool.input_schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(ProtocolFailure::header_mismatch());
    }
    let mut bindings = Vec::new();
    let mut names = HashSet::new();
    let mut path = Vec::new();
    collect_tool_header_bindings(
        &tool.input_schema,
        true,
        &mut path,
        &mut names,
        &mut bindings,
    )?;
    Ok(bindings)
}

/// Traverse a schema while preserving whether each node is reachable only through `properties`.
fn collect_tool_header_bindings(
    value: &Value,
    statically_reachable: bool,
    property_path: &mut Vec<String>,
    names: &mut HashSet<String>,
    bindings: &mut Vec<HeaderBinding>,
) -> Result<(), ProtocolFailure> {
    match value {
        Value::Object(object) => {
            if let Some(annotation) = object.get("x-mcp-header") {
                if !statically_reachable || property_path.is_empty() {
                    return Err(ProtocolFailure::header_mismatch());
                }
                bindings.push(parse_header_binding(
                    object,
                    annotation,
                    property_path,
                    names,
                )?);
            }
            for (keyword, child) in object {
                if keyword == "properties" && statically_reachable {
                    let properties = child
                        .as_object()
                        .ok_or_else(ProtocolFailure::header_mismatch)?;
                    for (property, schema) in properties {
                        property_path.push(property.clone());
                        let outcome = collect_tool_header_bindings(
                            schema,
                            true,
                            property_path,
                            names,
                            bindings,
                        );
                        property_path.pop();
                        outcome?;
                    }
                } else if keyword != "x-mcp-header" {
                    collect_tool_header_bindings(child, false, property_path, names, bindings)?;
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_tool_header_bindings(child, false, property_path, names, bindings)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Parse one primitive binding and enforce case-insensitive HTTP-name uniqueness.
fn parse_header_binding(
    schema: &Map<String, Value>,
    annotation: &Value,
    property_path: &[String],
    names: &mut HashSet<String>,
) -> Result<HeaderBinding, ProtocolFailure> {
    let suffix = annotation
        .as_str()
        .filter(|suffix| !suffix.is_empty() && suffix.bytes().all(is_tchar))
        .ok_or_else(ProtocolFailure::header_mismatch)?;
    let normalized = suffix.to_ascii_lowercase();
    if !names.insert(normalized.clone()) {
        return Err(ProtocolFailure::header_mismatch());
    }
    let kind = match schema.get("type").and_then(Value::as_str) {
        Some("string") => HeaderBindingKind::String,
        Some("integer") => HeaderBindingKind::Integer,
        Some("boolean") => HeaderBindingKind::Boolean,
        _ => return Err(ProtocolFailure::header_mismatch()),
    };
    let header_name = HeaderName::from_bytes(format!("mcp-param-{normalized}").as_bytes())
        .map_err(|_| ProtocolFailure::header_mismatch())?;
    Ok(HeaderBinding {
        header_name,
        property_path: property_path.to_vec(),
        kind,
    })
}

/// Report whether one ASCII byte is legal in an HTTP token.
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Validate every recognized custom header against its exact nested JSON argument.
fn validate_tool_parameter_headers(
    headers: &HeaderMap,
    arguments: &Map<String, Value>,
    bindings: &[HeaderBinding],
) -> Result<(), ProtocolFailure> {
    for binding in bindings {
        let mut values = headers.get_all(&binding.header_name).iter();
        let first = values.next();
        if values.next().is_some() {
            return Err(ProtocolFailure::header_mismatch());
        }
        let argument = argument_at_path(arguments, &binding.property_path)
            .filter(|argument| !argument.is_null());
        match (argument, first) {
            (None, None) => {}
            (None, Some(_)) | (Some(_), None) => {
                return Err(ProtocolFailure::header_mismatch());
            }
            (Some(argument), Some(header)) => {
                let header = header
                    .to_str()
                    .map_err(|_| ProtocolFailure::header_mismatch())?;
                if !header_matches_argument(header, argument, binding.kind) {
                    return Err(ProtocolFailure::header_mismatch());
                }
            }
        }
    }
    Ok(())
}

/// Resolve one nested property path without evaluating references or dynamic schema branches.
fn argument_at_path<'a>(
    arguments: &'a Map<String, Value>,
    property_path: &[String],
) -> Option<&'a Value> {
    let (first, rest) = property_path.split_first()?;
    let mut value = arguments.get(first)?;
    for property in rest {
        value = value.as_object()?.get(property)?;
    }
    Some(value)
}

/// Compare a custom HTTP value using the primitive type declared by the trusted schema.
fn header_matches_argument(header: &str, argument: &Value, kind: HeaderBindingKind) -> bool {
    match kind {
        HeaderBindingKind::String => argument
            .as_str()
            .and_then(|argument| decode_mcp_header_string(header).map(|header| header == argument))
            .unwrap_or(false),
        HeaderBindingKind::Boolean => argument
            .as_bool()
            .is_some_and(|argument| header == if argument { "true" } else { "false" }),
        HeaderBindingKind::Integer => safe_json_integer(argument).is_some_and(|argument| {
            header
                .parse::<i64>()
                .ok()
                .filter(|header| header.unsigned_abs() <= MAX_SAFE_JSON_INTEGER as u64)
                .is_some_and(|header| header == argument)
        }),
    }
}

/// Convert one JSON number to the interoperable signed safe-integer range.
fn safe_json_integer(value: &Value) -> Option<i64> {
    if let Some(value) = value.as_i64() {
        return (value.unsigned_abs() <= MAX_SAFE_JSON_INTEGER as u64).then_some(value);
    }
    if let Some(value) = value.as_u64() {
        return (value <= MAX_SAFE_JSON_INTEGER as u64).then_some(value as i64);
    }
    value.as_f64().and_then(|value| {
        (value.is_finite() && value.fract() == 0.0 && value.abs() <= MAX_SAFE_JSON_INTEGER as f64)
            .then_some(value as i64)
    })
}

/// Decode a custom string header using the exact final-era base64 sentinel.
fn decode_mcp_header_string(value: &str) -> Option<String> {
    const PREFIX: &str = "=?base64?";
    const SUFFIX: &str = "?=";
    if let Some(encoded) = value
        .strip_prefix(PREFIX)
        .and_then(|value| value.strip_suffix(SUFFIX))
    {
        let bytes = STANDARD_BASE64.decode(encoded).ok()?;
        return String::from_utf8(bytes).ok();
    }
    let bytes = value.as_bytes();
    let safe = bytes.first().is_none_or(|byte| !byte.is_ascii_whitespace())
        && bytes.last().is_none_or(|byte| !byte.is_ascii_whitespace())
        && bytes
            .iter()
            .all(|byte| matches!(*byte, 0x20..=0x7e | b'\t'));
    safe.then(|| value.to_owned())
}

/// Decode a plain ASCII or exact RFC-style base64 MCP header value.
fn decode_mcp_name(value: &str) -> Option<String> {
    const PREFIX: &str = "=?base64?";
    const SUFFIX: &str = "?=";
    if let Some(encoded) = value
        .strip_prefix(PREFIX)
        .and_then(|value| value.strip_suffix(SUFFIX))
    {
        let bytes = STANDARD_BASE64.decode(encoded).ok()?;
        return String::from_utf8(bytes).ok();
    }
    let bytes = value.as_bytes();
    let safe = !bytes.is_empty()
        && !bytes[0].is_ascii_whitespace()
        && !bytes[bytes.len() - 1].is_ascii_whitespace()
        && bytes
            .iter()
            .all(|byte| matches!(*byte, 0x20..=0x7e | b'\t'));
    safe.then(|| value.to_owned())
}

/// Return the smallest cap that can always carry the fixed bounded error result.
fn minimum_tool_output_chars() -> usize {
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .filter_map(|version| {
            serde_json::to_string(&call_result_value(
                McpCallToolResult::error(OUTPUT_LIMIT_ERROR),
                *version,
            ))
            .ok()
            .map(|value| value.chars().count())
        })
        .max()
        .unwrap_or(MAX_TOOL_OUTPUT_CHARS)
}

/// Return a bounded result value or the fixed overflow error.
fn bounded_call_result_value(
    result: McpCallToolResult,
    version: McpProtocolVersion,
    max_chars: usize,
) -> Value {
    if call_result_within_transport_limits(&result, max_chars) {
        let value = call_result_value(result, version);
        if serde_json::to_string(&value)
            .ok()
            .is_some_and(|encoded| encoded.chars().count() <= max_chars)
        {
            return value;
        }
    }
    call_result_value(McpCallToolResult::error(OUTPUT_LIMIT_ERROR), version)
}

/// Bound call-result complexity before cloning or serializing dispatcher values.
fn call_result_within_transport_limits(result: &McpCallToolResult, max_chars: usize) -> bool {
    if result.content.len() > MAX_TOOL_CONTENT_ITEMS {
        return false;
    }
    let mut budget = JsonTraversalBudget {
        remaining_nodes: MAX_DISPATCH_JSON_NODES,
        remaining_string_bytes: max_chars.saturating_mul(4),
    };
    for content in &result.content {
        match content {
            McpToolContent::Text { text } => {
                let field_limit = budget.remaining_string_bytes;
                if !consume_dispatcher_string(text, field_limit, &mut budget) {
                    return false;
                }
            }
        }
    }
    result
        .structured_content
        .as_ref()
        .is_none_or(|value| consume_dispatcher_json(value, 0, &mut budget))
}

/// Render a legacy or final-era tool-call result.
fn call_result_value(result: McpCallToolResult, version: McpProtocolVersion) -> Value {
    let mut value = serde_json::to_value(result)
        .expect("MCP call results contain only serializable JSON values");
    if version.is_modern() {
        let object = value
            .as_object_mut()
            .expect("serialized MCP call result must be a JSON object");
        object.insert(
            "resultType".to_owned(),
            Value::String("complete".to_owned()),
        );
        object.insert("_meta".to_owned(), modern_result_metadata());
    }
    value
}

/// Map a sanitized list-dispatch failure without exposing its source.
fn dispatcher_failure(id: Option<JsonRpcId>, _error: McpDispatchError) -> Response {
    ProtocolFailure::internal(id).into_response()
}

/// Build final-era response metadata shared by discovery and tool results.
fn modern_result_metadata() -> Value {
    json!({
        "io.modelcontextprotocol/serverInfo": server_info()
    })
}

/// Return stable server implementation metadata without client influence.
fn server_info() -> Value {
    json!({
        "name": "frameshift-server",
        "version": env!("CARGO_PKG_VERSION")
    })
}

/// Return every supported wire revision as final-protocol discovery data.
fn supported_protocol_version_values() -> Vec<&'static str> {
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .map(|version| version.as_str())
        .collect()
}

/// Build a successful JSON-RPC response with a validated non-null identifier.
fn result_response(id: JsonRpcId, result: Value) -> Response {
    json_response(StatusCode::OK, json_rpc_result_value(id, result))
}

/// Build one successful JSON-RPC value without serializing it on the caller's thread.
fn json_rpc_result_value(id: JsonRpcId, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

/// Serialize a bounded JSON value with an explicit JSON media type.
fn json_response(status: StatusCode, value: Value) -> Response {
    encoded_json_response(
        status,
        serde_json::to_vec(&value).expect("transport-generated JSON values must always serialize"),
    )
}

/// Return one already-serialized JSON body with the exact response media type.
fn encoded_json_response(status: StatusCode, encoded: Vec<u8>) -> Response {
    (
        status,
        [(CONTENT_TYPE, "application/json")],
        Body::from(encoded),
    )
        .into_response()
}

/// Serialize one JSON response and replace it if synchronous rendering crossed the deadline.
fn json_response_with_deadline(
    status: StatusCode,
    value: Value,
    deadline: tokio::time::Instant,
    id: Option<JsonRpcId>,
) -> Response {
    let encoded =
        serde_json::to_vec(&value).expect("transport-generated JSON values must always serialize");
    if let Err(failure) = ensure_deadline(deadline, id) {
        return failure.into_response();
    }
    (
        status,
        [(CONTENT_TYPE, "application/json")],
        Body::from(encoded),
    )
        .into_response()
}

/// Constructs and renders sanitized protocol failures.
impl ProtocolFailure {
    /// Construct one protocol failure without optional error data.
    fn new(status: StatusCode, id: Option<JsonRpcId>, code: i64, message: &'static str) -> Self {
        Self {
            status,
            id,
            code,
            message,
            data: None,
        }
    }

    /// Construct the final-protocol header mismatch required by the specification.
    fn header_mismatch() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            None,
            -32020,
            "Protocol header mismatch",
        )
    }

    /// Construct one fixed internal error without exposing a dispatcher or serializer source.
    fn internal(id: Option<JsonRpcId>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            id,
            -32603,
            "Internal error",
        )
    }

    /// Construct the single whole-request timeout used by every transport stage.
    fn request_timeout(id: Option<JsonRpcId>) -> Self {
        Self::new(StatusCode::GATEWAY_TIMEOUT, id, -32603, "Request timed out")
    }

    /// Construct an unsupported-version response with bounded requested data.
    fn unsupported_protocol_version(requested: String) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            id: None,
            code: -32022,
            message: "Unsupported protocol version",
            data: Some(json!({
                "requested": requested,
                "supported": supported_protocol_version_values()
            })),
        }
    }

    /// Attach a validated request identifier unless this failure already has one.
    fn with_id(mut self, id: Option<JsonRpcId>) -> Self {
        if self.id.is_none() {
            self.id = id;
        }
        self
    }

    /// Render this failure as one JSON-RPC error value for single or batch use.
    fn into_value(self) -> Value {
        let mut error = json!({
            "code": self.code,
            "message": self.message
        });
        if let Some(data) = self.data {
            error
                .as_object_mut()
                .expect("literal error must be a JSON object")
                .insert("data".to_owned(), data);
        }
        json!({
            "jsonrpc": "2.0",
            "id": self.id,
            "error": error
        })
    }

    /// Render this failure as a JSON-RPC error response.
    fn into_response(self) -> Response {
        let status = self.status;
        json_response(status, self.into_value())
    }
}

/// Focused checks for private transport scheduling invariants.
#[cfg(test)]
mod tests {
    use super::*;

    /// Blocking response rendering cannot hold the async request past its deadline.
    #[tokio::test]
    async fn blocking_render_job_returns_the_timeout_response() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(5);
        let response = run_render_job(deadline, None, || {
            std::thread::sleep(Duration::from_millis(50));
            StatusCode::OK.into_response()
        })
        .await;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }
}
