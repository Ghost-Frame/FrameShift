//! Contract tests for the stateless remote MCP HTTP transport.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::{to_bytes, Body, Bytes};
use axum::http::{Method, Request, Response, StatusCode};
use axum::{Extension, Router};
use base64::engine::general_purpose::STANDARD as STANDARD_BASE64;
use base64::Engine;
use frameshift_server::mcp::{
    mcp_router, mcp_router_with_dispatcher, McpCallToolResult, McpDispatchError, McpDispatcher,
    McpListToolsRequest, McpListToolsResult, McpPrepareToolRequest, McpPreparedTool,
    McpPreparedToolCallRequest, McpProtocolVersion, McpTool, McpToolContent, McpTransportConfig,
    McpTransportConfigError, DEFAULT_MCP_MAX_BODY_BYTES, DEFAULT_MCP_MAX_TOOL_OUTPUT_CHARS,
    DEFAULT_MCP_REQUEST_TIMEOUT, FALLBACK_LEGACY_PROTOCOL_VERSION, LATEST_LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
};
use http_body_util::channel::Channel;
use serde_json::{json, Map, Value};
use tower::ServiceExt;

/// Maximum response size accepted by the test decoder.
const TEST_RESPONSE_LIMIT: usize = 2 * 1_048_576;

/// Server-owned extension used to prove context provenance.
#[derive(Clone, Debug)]
struct TrustedMarker(&'static str);

/// Dispatcher observations retained for seam assertions.
#[derive(Debug, Default)]
struct DispatcherObservations {
    /// Validated revisions delivered to the dispatcher.
    versions: Vec<McpProtocolVersion>,
    /// Tool names delivered after header and body validation.
    names: Vec<String>,
    /// Tool names used for authoritative schema lookup.
    definition_names: Vec<String>,
    /// Values read from the server-populated request extension.
    trusted_markers: Vec<Option<&'static str>>,
}

/// Configurable dispatcher used to exercise timeout, output, and context behavior.
#[derive(Debug)]
struct TestDispatcher {
    /// Fixed tool-list result returned when no list error is configured.
    list_result: McpListToolsResult,
    /// Optional sanitized list failure.
    list_error: Option<McpDispatchError>,
    /// Fixed application-level call result.
    call_result: McpCallToolResult,
    /// Optional authoritative definition returned for an exact tool name.
    tool_definition: Option<McpTool>,
    /// Artificial execution delay used by timeout tests.
    delay: Duration,
    /// Recorded dispatcher inputs.
    observations: Arc<Mutex<DispatcherObservations>>,
}

/// One immutable test handle binding its definition, context, and call behavior.
#[derive(Debug)]
struct TestPreparedTool {
    /// Exact definition observed by the transport before execution.
    definition: McpTool,
    /// Fixed application result returned by this handle.
    call_result: McpCallToolResult,
    /// Artificial call delay used by timeout tests.
    delay: Duration,
    /// Protocol version captured during account-aware preparation.
    version: McpProtocolVersion,
    /// Server-owned marker captured during account-aware preparation.
    trusted_marker: Option<&'static str>,
    /// Shared dispatcher observations updated only when execution occurs.
    observations: Arc<Mutex<DispatcherObservations>>,
}

/// Builds and observes deterministic dispatcher behavior.
impl TestDispatcher {
    /// Construct a dispatcher with an empty list and successful call result.
    fn new() -> Self {
        Self {
            list_result: McpListToolsResult::default(),
            list_error: None,
            call_result: McpCallToolResult::text("ok"),
            tool_definition: None,
            delay: Duration::ZERO,
            observations: Arc::new(Mutex::new(DispatcherObservations::default())),
        }
    }

    /// Replace the fixed list result.
    fn with_list_result(mut self, list_result: McpListToolsResult) -> Self {
        self.list_result = list_result;
        self
    }

    /// Replace the fixed list error.
    fn with_list_error(mut self, list_error: McpDispatchError) -> Self {
        self.list_error = Some(list_error);
        self
    }

    /// Replace the fixed call result.
    fn with_call_result(mut self, call_result: McpCallToolResult) -> Self {
        self.call_result = call_result;
        self
    }

    /// Replace the authoritative modern tool definition.
    fn with_tool_definition(mut self, tool_definition: McpTool) -> Self {
        self.tool_definition = Some(tool_definition);
        self
    }

    /// Add an artificial delay to both dispatcher methods.
    fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Read recorded observations under the non-poisoned test mutex.
    fn observations(&self) -> std::sync::MutexGuard<'_, DispatcherObservations> {
        self.observations
            .lock()
            .expect("dispatcher observation mutex must not be poisoned")
    }

    /// Record one validated context and optional tool name.
    fn record(
        &self,
        request_version: McpProtocolVersion,
        name: Option<String>,
        marker: Option<&TrustedMarker>,
    ) {
        let mut observations = self
            .observations
            .lock()
            .expect("dispatcher observation mutex must not be poisoned");
        observations.versions.push(request_version);
        if let Some(name) = name {
            observations.names.push(name);
        }
        observations
            .trusted_markers
            .push(marker.map(|marker| marker.0));
    }
}

/// Executes the same immutable test definition that the transport validated.
#[async_trait]
impl McpPreparedTool for TestPreparedTool {
    /// Return this handle's immutable tool definition.
    fn definition(&self) -> &McpTool {
        &self.definition
    }

    /// Record one execution and return the handle's fixed result.
    async fn call(self: Box<Self>, _request: McpPreparedToolCallRequest) -> McpCallToolResult {
        tokio::time::sleep(self.delay).await;
        let mut observations = self
            .observations
            .lock()
            .expect("dispatcher observation mutex must not be poisoned");
        observations.versions.push(self.version);
        observations.names.push(self.definition.name.clone());
        observations.trusted_markers.push(self.trusted_marker);
        self.call_result.clone()
    }
}

/// Implements the production dispatcher seam with fixed test behavior.
#[async_trait]
impl McpDispatcher for TestDispatcher {
    /// Record context, optionally delay, and return the configured list outcome.
    async fn list_tools(
        &self,
        request: McpListToolsRequest,
    ) -> Result<McpListToolsResult, McpDispatchError> {
        self.record(
            request.context.protocol_version(),
            None,
            request.context.extension::<TrustedMarker>(),
        );
        tokio::time::sleep(self.delay).await;
        match self.list_error {
            Some(error) => Err(error),
            None => Ok(self.list_result.clone()),
        }
    }

    /// Prepare one exact immutable definition without recording execution.
    async fn prepare_tool(
        &self,
        request: McpPrepareToolRequest,
    ) -> Result<Option<Box<dyn McpPreparedTool>>, McpDispatchError> {
        self.observations
            .lock()
            .expect("dispatcher observation mutex must not be poisoned")
            .definition_names
            .push(request.name.clone());
        let version = request.context.protocol_version();
        let trusted_marker = request
            .context
            .extension::<TrustedMarker>()
            .map(|marker| marker.0);
        tokio::time::sleep(self.delay).await;
        let definition = match self.tool_definition.as_ref() {
            Some(tool) if tool.name == request.name => Some(tool.clone()),
            Some(_) => None,
            None => Some(tool(&request.name)),
        };
        Ok(definition.map(|definition| {
            Box::new(TestPreparedTool {
                definition,
                call_result: self.call_result.clone(),
                delay: self.delay,
                version,
                trusted_marker,
                observations: Arc::clone(&self.observations),
            }) as Box<dyn McpPreparedTool>
        }))
    }
}

/// Build the default state-free MCP router for isolated transport tests.
fn default_router() -> Router {
    mcp_router::<()>()
}

/// Build a state-free MCP router with an explicit dispatcher and policy.
fn configured_router(config: McpTransportConfig, dispatcher: Arc<dyn McpDispatcher>) -> Router {
    mcp_router_with_dispatcher::<()>(config, dispatcher)
}

/// Build one HTTP request from raw bytes and common JSON defaults.
fn raw_request(method: Method, path: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(body.into())
        .expect("test request must be valid")
}

/// Build one legacy JSON POST without MCP-specific HTTP headers.
fn legacy_request(body: Value) -> Request<Body> {
    raw_request(Method::POST, "/mcp", body.to_string())
}

/// Build the mandatory handshake-era initialize parameter set.
fn legacy_initialize_params(version: &str) -> Value {
    json!({
        "protocolVersion": version,
        "capabilities": {},
        "clientInfo": { "name": "legacy-client", "version": "1.0.0" }
    })
}

/// Add final-era metadata to the supplied method parameters.
fn modern_body(id: Value, method: &str, mut params: Map<String, Value>) -> Value {
    params.insert(
        "_meta".to_owned(),
        json!({
            "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": "transport-test-client",
                "version": "1.0.0"
            },
            "io.modelcontextprotocol/clientCapabilities": {}
        }),
    );
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params
    })
}

/// Build one compliant final-era request with method and optional name headers.
fn modern_request(id: Value, method: &str, params: Map<String, Value>) -> Request<Body> {
    let body = modern_body(id, method, params);
    Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("mcp-protocol-version", MODERN_PROTOCOL_VERSION)
        .header("mcp-method", method)
        .body(Body::from(body.to_string()))
        .expect("modern test request must be valid")
}

/// Build one compliant final-era tool call with a caller-selected name header.
fn modern_call_request(body_name: &str, header_name: &str) -> Request<Body> {
    modern_call_request_with_arguments(body_name, header_name, json!({ "value": 1 }))
}

/// Build one final-era tool call with caller-selected object arguments.
fn modern_call_request_with_arguments(
    body_name: &str,
    header_name: &str,
    arguments: Value,
) -> Request<Body> {
    let mut params = Map::new();
    params.insert("name".to_owned(), Value::String(body_name.to_owned()));
    params.insert("arguments".to_owned(), arguments);
    let body = modern_body(json!(7), "tools/call", params);
    Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("mcp-protocol-version", MODERN_PROTOCOL_VERSION)
        .header("mcp-method", "tools/call")
        .header("mcp-name", header_name)
        .body(Body::from(body.to_string()))
        .expect("modern call test request must be valid")
}

/// Send one request through a cloned Axum service.
async fn send(router: &Router, request: Request<Body>) -> Response<Body> {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("MCP router must produce a response");
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "every MCP response must prohibit HTTP caching"
    );
    response
}

/// Decode a JSON response and verify its explicit V1 media type.
async fn response_json(response: Response<Body>) -> Value {
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let bytes = to_bytes(response.into_body(), TEST_RESPONSE_LIMIT)
        .await
        .expect("test response body must be readable");
    serde_json::from_slice(&bytes).expect("MCP response must be valid JSON")
}

/// Read an entire bounded response without interpreting its media type.
async fn response_bytes(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), TEST_RESPONSE_LIMIT)
        .await
        .expect("test response body must be readable")
        .to_vec()
}

/// Assert the standard bounded JSON-RPC error shape.
async fn assert_rpc_error(response: Response<Body>, status: StatusCode, code: i64) -> Value {
    assert_eq!(response.status(), status);
    let body = response_json(response).await;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["error"]["code"], code);
    assert!(body["error"]["message"].as_str().is_some());
    body
}

/// Create a small deterministic tool definition for list tests.
fn tool(name: &str) -> McpTool {
    tool_with_schema(
        name,
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false
        }),
    )
}

/// Create a deterministic tool definition with a caller-selected input schema.
fn tool_with_schema(name: &str, input_schema: Value) -> McpTool {
    McpTool {
        name: name.to_owned(),
        title: None,
        description: Some(format!("Tool {name}")),
        input_schema,
        output_schema: None,
        annotations: None,
    }
}

/// Only the exact `/mcp` path is mounted and it accepts POST only.
#[tokio::test]
async fn endpoint_is_exact_and_post_only() {
    let router = default_router();
    for method in [Method::GET, Method::DELETE, Method::PUT] {
        let response = send(&router, raw_request(method, "/mcp", Body::empty())).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
    for path in ["/mcp/", "/mcp/sse", "/mcp/messages"] {
        let response = send(&router, raw_request(Method::POST, path, "{}")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

/// The BAV-compatible no-header initialize and list transcript remains stateless.
#[tokio::test]
async fn bav_legacy_fixture_uses_2025_03_26_without_a_session() {
    let router = default_router();
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": legacy_initialize_params(FALLBACK_LEGACY_PROTOCOL_VERSION)
    });
    let response = send(&router, legacy_request(initialize)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key("mcp-session-id"));
    let body = response_json(response).await;
    assert_eq!(
        body["result"]["protocolVersion"],
        FALLBACK_LEGACY_PROTOCOL_VERSION
    );

    let list = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    let response = send(&router, legacy_request(list)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key("mcp-session-id"));
    let body = response_json(response).await;
    assert_eq!(body["result"]["tools"], json!([]));
    assert!(body["result"].get("resultType").is_none());
}

/// Every explicit handshake-era revision initializes without creating protocol state.
#[tokio::test]
async fn explicit_legacy_versions_are_supported() {
    let router = default_router();
    for version in ["2025-03-26", "2025-06-18", "2025-11-25"] {
        let body = json!({
            "jsonrpc": "2.0",
            "id": version,
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": { "name": "legacy-client", "version": "1" }
            }
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", version)
            .body(Body::from(body.to_string()))
            .expect("legacy request must be valid");
        let response = send(&router, request).await;
        assert_eq!(response.status(), StatusCode::OK, "version {version}");
        assert!(!response.headers().contains_key("mcp-session-id"));
        let response = response_json(response).await;
        assert_eq!(response["result"]["protocolVersion"], version);
    }
}

/// An explicit legacy header cannot silently contradict initialize parameters.
#[tokio::test]
async fn legacy_header_body_version_mismatch_fails_closed() {
    let body = json!({
        "jsonrpc": "2.0",
        "id": "mismatch",
        "method": "initialize",
        "params": { "protocolVersion": LATEST_LEGACY_PROTOCOL_VERSION }
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", FALLBACK_LEGACY_PROTOCOL_VERSION)
        .body(Body::from(body.to_string()))
        .expect("legacy mismatch request must be valid");
    let response = send(&default_router(), request).await;
    let body = assert_rpc_error(response, StatusCode::BAD_REQUEST, -32020).await;
    assert_eq!(body["id"], "mismatch");
}

/// A no-header legacy initialize negotiates the latest supported legacy proposal.
#[tokio::test]
async fn no_header_initialize_honors_supported_legacy_proposal() {
    let request = legacy_request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": legacy_initialize_params("2025-06-18")
    }));
    let response = send(&default_router(), request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["result"]["protocolVersion"], "2025-06-18");
}

/// A final-era initialize proposal cannot downgrade through the no-header fallback.
#[tokio::test]
async fn no_header_modern_initialize_proposal_fails_closed() {
    let request = legacy_request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "protocolVersion": MODERN_PROTOCOL_VERSION }
    }));
    assert_rpc_error(
        send(&default_router(), request).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;
}

/// Every mandatory handshake-era initialize field is required with its exact shape.
#[tokio::test]
async fn legacy_initialize_requires_protocol_capabilities_and_client_info() {
    let invalid_params = [
        json!({
            "capabilities": {},
            "clientInfo": { "name": "client", "version": "1" }
        }),
        json!({
            "protocolVersion": FALLBACK_LEGACY_PROTOCOL_VERSION,
            "clientInfo": { "name": "client", "version": "1" }
        }),
        json!({
            "protocolVersion": FALLBACK_LEGACY_PROTOCOL_VERSION,
            "capabilities": {}
        }),
        json!({
            "protocolVersion": 1,
            "capabilities": {},
            "clientInfo": { "name": "client", "version": "1" }
        }),
        json!({
            "protocolVersion": FALLBACK_LEGACY_PROTOCOL_VERSION,
            "capabilities": [],
            "clientInfo": { "name": "client", "version": "1" }
        }),
        json!({
            "protocolVersion": FALLBACK_LEGACY_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "client" }
        }),
    ];
    for (index, params) in invalid_params.into_iter().enumerate() {
        let response = send(
            &default_router(),
            legacy_request(json!({
                "jsonrpc": "2.0",
                "id": index,
                "method": "initialize",
                "params": params
            })),
        )
        .await;
        assert_rpc_error(response, StatusCode::BAD_REQUEST, -32602).await;
    }

    let response = send(
        &default_router(),
        legacy_request(json!({
            "jsonrpc": "2.0",
            "id": "missing-params",
            "method": "initialize"
        })),
    )
    .await;
    assert_rpc_error(response, StatusCode::BAD_REQUEST, -32602).await;
}

/// Final-era per-request metadata cannot be interpreted under a legacy header.
#[tokio::test]
async fn legacy_header_with_modern_body_metadata_fails_closed() {
    let body = modern_body(json!(2), "tools/list", Map::new());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", LATEST_LEGACY_PROTOCOL_VERSION)
        .header("mcp-method", "tools/list")
        .body(Body::from(body.to_string()))
        .expect("cross-era request must be valid");
    assert_rpc_error(
        send(&default_router(), request).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;
}

/// The final-era discovery fixture advertises complete deterministic support.
#[tokio::test]
async fn modern_discover_fixture_is_complete_and_private() {
    let request = modern_request(json!("discover-1"), "server/discover", Map::new());
    let response = send(&default_router(), request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key("mcp-session-id"));
    let body = response_json(response).await;
    let result = &body["result"];
    assert_eq!(result["resultType"], "complete");
    assert_eq!(
        result["supportedVersions"],
        json!(["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"])
    );
    assert!(result["capabilities"]["tools"].is_object());
    assert_eq!(result["ttlMs"], 30_000);
    assert_eq!(result["cacheScope"], "private");
    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "frameshift-server"
    );
}

/// Tools list works in every supported revision and records the validated era.
#[tokio::test]
async fn tools_list_supports_all_protocol_versions() {
    let dispatcher = Arc::new(TestDispatcher::new());
    let router = configured_router(McpTransportConfig::default(), dispatcher.clone());
    for version in ["2025-03-26", "2025-06-18", "2025-11-25"] {
        let body = json!({
            "jsonrpc": "2.0",
            "id": version,
            "method": "tools/list",
            "params": {}
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", version)
            .body(Body::from(body.to_string()))
            .expect("legacy list request must be valid");
        let response = send(&router, request).await;
        assert_eq!(response.status(), StatusCode::OK, "version {version}");
    }
    let request = modern_request(json!(4), "tools/list", Map::new());
    let response = send(&router, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["result"]["resultType"], "complete");
    assert_eq!(body["result"]["cacheScope"], "private");
    assert!(body["result"]["ttlMs"].is_u64());

    assert_eq!(
        dispatcher.observations().versions.as_slice(),
        &[
            McpProtocolVersion::V2025_03_26,
            McpProtocolVersion::V2025_06_18,
            McpProtocolVersion::V2025_11_25,
            McpProtocolVersion::V2026_07_28,
        ]
    );
}

/// Ping and tools/call remain available under every explicit legacy revision.
#[tokio::test]
async fn legacy_ping_and_call_support_all_legacy_versions() {
    let router = default_router();
    for version in ["2025-03-26", "2025-06-18", "2025-11-25"] {
        for (id, method, params) in [
            (json!(1), "ping", json!({})),
            (
                json!(2),
                "tools/call",
                json!({ "name": "unavailable-tool", "arguments": {} }),
            ),
        ] {
            let body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params
            });
            let request = Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("mcp-protocol-version", version)
                .body(Body::from(body.to_string()))
                .expect("legacy core request must be valid");
            let response = send(&router, request).await;
            assert_eq!(response.status(), StatusCode::OK, "{version} {method}");
            let response = response_json(response).await;
            if method == "tools/call" {
                assert_eq!(response["result"]["isError"], true);
            }
        }
    }
}

/// Modern ping is a complete result and initialize is not its substitute.
#[tokio::test]
async fn modern_ping_is_complete_and_initialize_is_unknown() {
    let ping = modern_request(json!(1), "ping", Map::new());
    let response = send(&default_router(), ping).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["result"]["resultType"], "complete");

    let initialize = modern_request(json!(2), "initialize", Map::new());
    let response = send(&default_router(), initialize).await;
    assert_rpc_error(response, StatusCode::NOT_FOUND, -32601).await;
}

/// Required final-era metadata and mirrored headers fail with specified codes.
#[tokio::test]
async fn modern_metadata_and_header_mismatches_are_rejected() {
    let router = default_router();

    let mut wrong_version = modern_request(json!(1), "ping", Map::new());
    let mut body = modern_body(json!(1), "ping", Map::new());
    body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
        Value::String("2025-11-25".to_owned());
    *wrong_version.body_mut() = Body::from(body.to_string());
    assert_rpc_error(
        send(&router, wrong_version).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;

    let body = modern_body(json!(2), "ping", Map::new());
    let missing_method = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", MODERN_PROTOCOL_VERSION)
        .body(Body::from(body.to_string()))
        .expect("missing method request must be valid");
    assert_rpc_error(
        send(&router, missing_method).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;

    let body = modern_body(json!(3), "ping", Map::new());
    let wrong_method = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", MODERN_PROTOCOL_VERSION)
        .header("mcp-method", "tools/list")
        .body(Body::from(body.to_string()))
        .expect("wrong method request must be valid");
    assert_rpc_error(
        send(&router, wrong_method).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;

    let body = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "ping",
        "params": {}
    });
    let missing_metadata = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", MODERN_PROTOCOL_VERSION)
        .header("mcp-method", "ping")
        .body(Body::from(body.to_string()))
        .expect("missing metadata request must be valid");
    assert_rpc_error(
        send(&router, missing_metadata).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;

    let body = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "ping",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION
            }
        }
    });
    let missing_capabilities = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", MODERN_PROTOCOL_VERSION)
        .header("mcp-method", "ping")
        .body(Body::from(body.to_string()))
        .expect("missing capabilities request must be valid");
    assert_rpc_error(
        send(&router, missing_capabilities).await,
        StatusCode::BAD_REQUEST,
        -32602,
    )
    .await;

    let body = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "ping",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    let missing_body_version = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", MODERN_PROTOCOL_VERSION)
        .header("mcp-method", "ping")
        .body(Body::from(body.to_string()))
        .expect("missing body version request must be valid");
    assert_rpc_error(
        send(&router, missing_body_version).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;

    let body = modern_body(json!(7), "ping", Map::new());
    let missing_version_header = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-method", "ping")
        .body(Body::from(body.to_string()))
        .expect("missing version request must be valid");
    assert_rpc_error(
        send(&router, missing_version_header).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;
}

/// Unsupported present revisions return the specified supported-version data.
#[tokio::test]
async fn unsupported_present_protocol_version_is_rejected() {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "ping",
        "params": {}
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2099-01-01")
        .body(Body::from(body.to_string()))
        .expect("unsupported version request must be valid");
    let response = send(&default_router(), request).await;
    let body = assert_rpc_error(response, StatusCode::BAD_REQUEST, -32022).await;
    assert_eq!(body["id"], 9);
    assert_eq!(body["error"]["data"]["requested"], "2099-01-01");
    assert_eq!(
        body["error"]["data"]["supported"].as_array().map(Vec::len),
        Some(4)
    );
}

/// Modern tool names require exact decoded agreement with the request body.
#[tokio::test]
async fn modern_tool_name_header_is_required_decoded_and_matched() {
    let dispatcher = Arc::new(TestDispatcher::new());
    let router = configured_router(McpTransportConfig::default(), dispatcher.clone());

    let response = send(&router, modern_call_request("tool-a", "tool-b")).await;
    assert_rpc_error(response, StatusCode::BAD_REQUEST, -32020).await;

    let response = send(
        &router,
        modern_call_request("tool-a", "=?base64?not-valid%%%?="),
    )
    .await;
    assert_rpc_error(response, StatusCode::BAD_REQUEST, -32020).await;

    let unicode_name = "taco-🌮";
    let encoded = format!("=?base64?{}?=", STANDARD_BASE64.encode(unicode_name));
    let response = send(&router, modern_call_request(unicode_name, &encoded)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["result"]["resultType"], "complete");
    assert!(body["result"].get("ttlMs").is_none());
    assert_eq!(
        dispatcher.observations().names.as_slice(),
        &[unicode_name.to_owned()]
    );

    let body = modern_body(
        json!(8),
        "tools/call",
        Map::from_iter([
            ("name".to_owned(), Value::String("tool-a".to_owned())),
            ("arguments".to_owned(), json!({})),
        ]),
    );
    let missing_name = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", MODERN_PROTOCOL_VERSION)
        .header("mcp-method", "tools/call")
        .body(Body::from(body.to_string()))
        .expect("missing name request must be valid");
    assert_rpc_error(
        send(&router, missing_name).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;
}

/// Unrecognized custom MCP parameter headers are ignored until a tool declares one.
#[tokio::test]
async fn undeclared_custom_parameter_headers_are_not_interpreted() {
    let mut request = modern_call_request("plain-tool", "plain-tool");
    request.headers_mut().insert(
        "mcp-param-undeclared",
        "client-controlled"
            .parse()
            .expect("test header value must be valid"),
    );
    let response = send(&default_router(), request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["result"]["isError"], true);
}

/// Declared nested string headers are mandatory, exact, unique, and checked before execution.
#[tokio::test]
async fn declared_custom_string_headers_bind_exact_nested_arguments() {
    let definition = tool_with_schema(
        "bound-tool",
        json!({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "display": {
                            "type": "string",
                            "x-mcp-header": "Identity"
                        }
                    }
                }
            }
        }),
    );
    let dispatcher = Arc::new(TestDispatcher::new().with_tool_definition(definition));
    let router = configured_router(McpTransportConfig::default(), dispatcher.clone());

    let missing = modern_call_request_with_arguments(
        "bound-tool",
        "bound-tool",
        json!({ "user": { "display": "Zan" } }),
    );
    assert_rpc_error(
        send(&router, missing).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;

    let mut wrong = modern_call_request_with_arguments(
        "bound-tool",
        "bound-tool",
        json!({ "user": { "display": "Zan" } }),
    );
    wrong.headers_mut().insert(
        "mcp-param-identity",
        "Mallory".parse().expect("test header must be valid"),
    );
    assert_rpc_error(send(&router, wrong).await, StatusCode::BAD_REQUEST, -32020).await;
    assert!(dispatcher.observations().names.is_empty());

    let unicode = "Zan 🌮";
    let mut matched = modern_call_request_with_arguments(
        "bound-tool",
        "bound-tool",
        json!({ "user": { "display": unicode } }),
    );
    matched.headers_mut().insert(
        "mcp-param-identity",
        format!("=?base64?{}?=", STANDARD_BASE64.encode(unicode))
            .parse()
            .expect("encoded test header must be valid"),
    );
    assert_eq!(send(&router, matched).await.status(), StatusCode::OK);
    assert_eq!(dispatcher.observations().names, ["bound-tool"]);

    for literal in ["=?base64?literal", "Zan\tGIR"] {
        let mut plain = modern_call_request_with_arguments(
            "bound-tool",
            "bound-tool",
            json!({ "user": { "display": literal } }),
        );
        plain.headers_mut().insert(
            "mcp-param-identity",
            literal.parse().expect("plain test header must be valid"),
        );
        assert_eq!(send(&router, plain).await.status(), StatusCode::OK);
    }

    let mut duplicate = modern_call_request_with_arguments(
        "bound-tool",
        "bound-tool",
        json!({ "user": { "display": "Zan" } }),
    );
    duplicate.headers_mut().append(
        "mcp-param-identity",
        "Zan".parse().expect("test header must be valid"),
    );
    duplicate.headers_mut().append(
        "Mcp-Param-Identity",
        "Zan".parse().expect("test header must be valid"),
    );
    assert_rpc_error(
        send(&router, duplicate).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;

    let null_without_header = modern_call_request_with_arguments(
        "bound-tool",
        "bound-tool",
        json!({ "user": { "display": null } }),
    );
    assert_eq!(
        send(&router, null_without_header).await.status(),
        StatusCode::OK
    );

    let mut null_with_header = modern_call_request_with_arguments(
        "bound-tool",
        "bound-tool",
        json!({ "user": { "display": null } }),
    );
    null_with_header.headers_mut().insert(
        "mcp-param-identity",
        "Zan".parse().expect("test header must be valid"),
    );
    assert_rpc_error(
        send(&router, null_with_header).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;
    assert_eq!(dispatcher.observations().names.len(), 4);
}

/// Boolean and integer bindings compare with their protocol-defined primitive semantics.
#[tokio::test]
async fn declared_boolean_and_integer_headers_use_typed_comparison() {
    let definition = tool_with_schema(
        "typed-tool",
        json!({
            "type": "object",
            "properties": {
                "enabled": { "type": "boolean", "x-mcp-header": "Enabled" },
                "count": { "type": "integer", "x-mcp-header": "Count" }
            }
        }),
    );
    let dispatcher = Arc::new(TestDispatcher::new().with_tool_definition(definition));
    let router = configured_router(McpTransportConfig::default(), dispatcher.clone());

    let mut matched = modern_call_request_with_arguments(
        "typed-tool",
        "typed-tool",
        json!({ "enabled": true, "count": 1 }),
    );
    matched.headers_mut().insert(
        "mcp-param-enabled",
        "true".parse().expect("test header must be valid"),
    );
    matched.headers_mut().insert(
        "mcp-param-count",
        "01".parse().expect("test header must be valid"),
    );
    assert_eq!(send(&router, matched).await.status(), StatusCode::OK);

    let mut integral_float = modern_call_request_with_arguments(
        "typed-tool",
        "typed-tool",
        json!({ "enabled": true, "count": 1.0 }),
    );
    integral_float.headers_mut().insert(
        "mcp-param-enabled",
        "true".parse().expect("test header must be valid"),
    );
    integral_float.headers_mut().insert(
        "mcp-param-count",
        "1".parse().expect("test header must be valid"),
    );
    assert_eq!(send(&router, integral_float).await.status(), StatusCode::OK);

    let mut wrong_boolean = modern_call_request_with_arguments(
        "typed-tool",
        "typed-tool",
        json!({ "enabled": true, "count": 1 }),
    );
    wrong_boolean.headers_mut().insert(
        "mcp-param-enabled",
        "True".parse().expect("test header must be valid"),
    );
    wrong_boolean.headers_mut().insert(
        "mcp-param-count",
        "1".parse().expect("test header must be valid"),
    );
    assert_rpc_error(
        send(&router, wrong_boolean).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;

    let mut unsafe_integer = modern_call_request_with_arguments(
        "typed-tool",
        "typed-tool",
        json!({ "enabled": true, "count": 9_007_199_254_740_992_u64 }),
    );
    unsafe_integer.headers_mut().insert(
        "mcp-param-enabled",
        "true".parse().expect("test header must be valid"),
    );
    unsafe_integer.headers_mut().insert(
        "mcp-param-count",
        "9007199254740992"
            .parse()
            .expect("test header must be valid"),
    );
    assert_rpc_error(
        send(&router, unsafe_integer).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;
    assert_eq!(
        dispatcher.observations().names,
        ["typed-tool", "typed-tool"]
    );
}

/// Invalid or dynamically hidden header annotations are neither advertised nor executable.
#[tokio::test]
async fn invalid_custom_header_schemas_fail_closed() {
    let mut invalid_output_schema = tool("invalid-output-schema");
    invalid_output_schema.output_schema = Some(json!("not-an-object"));
    let invalid_tools = vec![
        tool_with_schema("missing-root-type", json!({ "properties": {} })),
        tool_with_schema("wrong-root-type", json!({ "type": "string" })),
        invalid_output_schema,
        tool_with_schema(
            "root-annotation",
            json!({ "type": "object", "x-mcp-header": "Root" }),
        ),
        tool_with_schema(
            "definition-annotation",
            json!({
                "type": "object",
                "$defs": {
                    "hidden": { "type": "string", "x-mcp-header": "Hidden" }
                }
            }),
        ),
        tool_with_schema(
            "duplicate-annotation",
            json!({
                "type": "object",
                "properties": {
                    "one": { "type": "string", "x-mcp-header": "Same" },
                    "two": { "type": "string", "x-mcp-header": "sAmE" }
                }
            }),
        ),
        tool_with_schema(
            "number-annotation",
            json!({
                "type": "object",
                "properties": {
                    "value": { "type": "number", "x-mcp-header": "Value" }
                }
            }),
        ),
        tool_with_schema(
            "array-annotation",
            json!({
                "type": "object",
                "properties": {
                    "values": {
                        "type": "array",
                        "items": { "type": "string", "x-mcp-header": "Item" }
                    }
                }
            }),
        ),
    ];
    let list_dispatcher = Arc::new(
        TestDispatcher::new().with_list_result(McpListToolsResult {
            tools: std::iter::once(tool("valid-tool"))
                .chain(invalid_tools.clone())
                .collect(),
            next_cursor: None,
        }),
    );
    let list_router = configured_router(McpTransportConfig::default(), list_dispatcher);
    let response = send(
        &list_router,
        modern_request(json!(1), "tools/list", Map::new()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["result"]["tools"].as_array().map(Vec::len), Some(1));
    assert_eq!(body["result"]["tools"][0]["name"], "valid-tool");

    for definition in invalid_tools {
        let name = definition.name.clone();
        let dispatcher = Arc::new(TestDispatcher::new().with_tool_definition(definition));
        let router = configured_router(McpTransportConfig::default(), dispatcher.clone());
        let response = send(&router, modern_call_request(&name, &name)).await;
        assert_rpc_error(response, StatusCode::BAD_REQUEST, -32020).await;
        assert!(dispatcher.observations().names.is_empty());
    }
}

/// JSON-RPC identifiers accept strings and integers but reject other JSON types.
#[tokio::test]
async fn json_rpc_id_forms_are_strict() {
    let router = default_router();
    for id in [
        json!(""),
        json!("request-1"),
        json!(0),
        json!(-7),
        json!(u64::MAX),
    ] {
        let request = legacy_request(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "ping",
            "params": {}
        }));
        let response = send(&router, request).await;
        assert_eq!(response.status(), StatusCode::OK, "valid id {id}");
        let body = response_json(response).await;
        assert_eq!(body["id"], id);
    }

    for id in [
        json!(null),
        json!(1.0),
        json!(1.5),
        json!(true),
        json!({}),
        json!([]),
    ] {
        let request = legacy_request(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "ping",
            "params": {}
        }));
        let response = send(&router, request).await;
        let body = assert_rpc_error(response, StatusCode::BAD_REQUEST, -32600).await;
        assert!(body["id"].is_null(), "invalid id {id}");
    }
}

/// A valid initialized notification returns 202 with no response body.
#[tokio::test]
async fn valid_notification_returns_accepted_without_a_body() {
    let request = legacy_request(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    let response = send(&default_router(), request).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response.headers().get("content-type").is_none());
    assert!(response_bytes(response).await.is_empty());
}

/// Inbound responses are accepted only for supported handshake-era transports.
#[tokio::test]
async fn inbound_responses_validate_the_explicit_protocol_revision() {
    let response_body = json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
    for version in [
        FALLBACK_LEGACY_PROTOCOL_VERSION,
        LATEST_LEGACY_PROTOCOL_VERSION,
    ] {
        let mut request = legacy_request(response_body.clone());
        request.headers_mut().insert(
            "mcp-protocol-version",
            version
                .parse()
                .expect("legacy version header must be valid"),
        );
        assert_eq!(
            send(&default_router(), request).await.status(),
            StatusCode::ACCEPTED
        );
    }

    let mut modern = legacy_request(response_body.clone());
    modern.headers_mut().insert(
        "mcp-protocol-version",
        MODERN_PROTOCOL_VERSION
            .parse()
            .expect("modern version header must be valid"),
    );
    assert_rpc_error(
        send(&default_router(), modern).await,
        StatusCode::BAD_REQUEST,
        -32600,
    )
    .await;

    let mut unsupported = legacy_request(response_body);
    unsupported.headers_mut().insert(
        "mcp-protocol-version",
        "2099-01-01"
            .parse()
            .expect("unsupported version header must be valid"),
    );
    assert_rpc_error(
        send(&default_router(), unsupported).await,
        StatusCode::BAD_REQUEST,
        -32022,
    )
    .await;
}

/// Unknown methods return the required HTTP and JSON-RPC mapping in both eras.
#[tokio::test]
async fn unknown_methods_return_404_method_not_found() {
    let legacy = legacy_request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "unknown/method",
        "params": {}
    }));
    assert_rpc_error(
        send(&default_router(), legacy).await,
        StatusCode::NOT_FOUND,
        -32601,
    )
    .await;

    let modern = modern_request(json!(2), "unknown/method", Map::new());
    assert_rpc_error(
        send(&default_router(), modern).await,
        StatusCode::NOT_FOUND,
        -32601,
    )
    .await;
}

/// Only the 2025-03-26 transport accepts bounded JSON-RPC batches.
#[tokio::test]
async fn legacy_2025_03_batches_return_only_request_results() {
    let batch = json!([
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} },
        7
    ]);
    let response = send(&default_router(), legacy_request(batch)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let replies = body.as_array().expect("legacy batch must return an array");
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0]["id"], 1);
    assert!(replies[0]["result"].is_object());
    assert!(replies[1]["id"].is_null());
    assert_eq!(replies[1]["error"]["code"], -32600);

    let notification_only = json!([
        { "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} }
    ]);
    let response = send(&default_router(), legacy_request(notification_only)).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response_bytes(response).await.is_empty());

    let response_only = json!([
        { "jsonrpc": "2.0", "id": 2, "result": {} },
        { "jsonrpc": "2.0", "id": 3, "error": { "code": -32000, "message": "failed" } }
    ]);
    let response = send(&default_router(), legacy_request(response_only)).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response_bytes(response).await.is_empty());
}

/// Legacy transport rejects arrays that mix request and response message classes.
#[tokio::test]
async fn legacy_batches_reject_mixed_request_and_response_messages() {
    let mixed = json!([
        { "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "result": {} }
    ]);
    assert_rpc_error(
        send(&default_router(), legacy_request(mixed)).await,
        StatusCode::BAD_REQUEST,
        -32600,
    )
    .await;
}

/// Later Streamable HTTP revisions reject arrays before any item can execute.
#[tokio::test]
async fn later_protocol_revisions_reject_json_rpc_batches() {
    for version in ["2025-06-18", "2025-11-25", MODERN_PROTOCOL_VERSION] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", version)
            .body(Body::from(
                json!([{ "jsonrpc": "2.0", "id": 1, "method": "ping" }]).to_string(),
            ))
            .expect("versioned batch request must be valid");
        assert_rpc_error(
            send(&default_router(), request).await,
            StatusCode::BAD_REQUEST,
            -32600,
        )
        .await;
    }
}

/// Legacy batches reject initialize and excessive item counts before dispatch.
#[tokio::test]
async fn legacy_batch_lifecycle_and_count_limits_fail_closed() {
    let initialize_batch = json!([{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": legacy_initialize_params(FALLBACK_LEGACY_PROTOCOL_VERSION)
    }]);
    assert_rpc_error(
        send(&default_router(), legacy_request(initialize_batch)).await,
        StatusCode::BAD_REQUEST,
        -32600,
    )
    .await;

    let modern_metadata_batch = Value::Array(vec![modern_body(json!(2), "tools/list", Map::new())]);
    assert_rpc_error(
        send(&default_router(), legacy_request(modern_metadata_batch)).await,
        StatusCode::BAD_REQUEST,
        -32020,
    )
    .await;

    let oversized = Value::Array(
        (0..129)
            .map(|id| json!({ "jsonrpc": "2.0", "id": id, "method": "ping" }))
            .collect(),
    );
    assert_rpc_error(
        send(&default_router(), legacy_request(oversized)).await,
        StatusCode::BAD_REQUEST,
        -32600,
    )
    .await;
}

/// Every item in a legacy batch consumes one shared deadline rather than a fresh timeout.
#[tokio::test]
async fn legacy_batch_uses_one_absolute_deadline() {
    let dispatcher = Arc::new(TestDispatcher::new().with_delay(Duration::from_millis(20)));
    let config = McpTransportConfig::default()
        .with_request_timeout(Duration::from_millis(30))
        .expect("short batch timeout must be valid");
    let router = configured_router(config, dispatcher);
    let request = legacy_request(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
        { "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }
    ]));
    let response = send(&router, request).await;
    assert_rpc_error(response, StatusCode::GATEWAY_TIMEOUT, -32603).await;
}

/// Parse, envelope, and parameter failures map to bounded JSON errors.
#[tokio::test]
async fn protocol_error_mapping_is_bounded_and_sanitized() {
    let router = default_router();
    let cases = [
        ("{".to_owned(), -32700),
        ("[]".to_owned(), -32600),
        (
            json!({"jsonrpc":"1.0","id":1,"method":"ping"}).to_string(),
            -32600,
        ),
        (
            json!({"jsonrpc":"2.0","id":1,"method":"ping","params":[]}).to_string(),
            -32602,
        ),
    ];
    for (raw, code) in cases {
        let request = raw_request(Method::POST, "/mcp", raw);
        let response = send(&router, request).await;
        let body = assert_rpc_error(response, StatusCode::BAD_REQUEST, code).await;
        let encoded = body.to_string();
        assert!(encoded.len() < 512);
        assert!(!encoded.contains("client-controlled-secret"));
    }
}

/// Content-Type and Accept negotiation permit JSON without permitting SSE-only clients.
#[tokio::test]
async fn media_type_and_accept_are_validated_compatibly() {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"ping","params":{}}).to_string();
    for content_type in [
        "application/json",
        "application/json; charset=utf-8",
        "application/mcp+json",
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", content_type)
            .header("accept", "application/json")
            .body(Body::from(body.clone()))
            .expect("media request must be valid");
        assert_eq!(
            send(&default_router(), request).await.status(),
            StatusCode::OK
        );
    }
    for accept in [
        "application/json",
        "*/*",
        "application/*",
        "text/event-stream, application/json",
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", accept)
            .body(Body::from(body.clone()))
            .expect("accept request must be valid");
        assert_eq!(
            send(&default_router(), request).await.status(),
            StatusCode::OK
        );
    }

    for content_type in [None, Some("text/plain"), Some("application/octet-stream")] {
        let mut builder = Request::builder().method(Method::POST).uri("/mcp");
        if let Some(content_type) = content_type {
            builder = builder.header("content-type", content_type);
        }
        let request = builder
            .body(Body::from(body.clone()))
            .expect("bad media request must be valid HTTP");
        assert_rpc_error(
            send(&default_router(), request).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            -32600,
        )
        .await;
    }
    for accept in [
        "text/event-stream",
        "application/json;q=0",
        "application/json;q=0.0",
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", accept)
            .body(Body::from(body.clone()))
            .expect("bad accept request must be valid");
        assert_rpc_error(
            send(&default_router(), request).await,
            StatusCode::NOT_ACCEPTABLE,
            -32600,
        )
        .await;
    }
}

/// The default body cap is exactly one MiB and oversized input returns 413.
#[tokio::test]
async fn request_body_limit_is_explicit_and_enforced() {
    assert_eq!(DEFAULT_MCP_MAX_BODY_BYTES, 1_048_576);
    let oversized = "x".repeat(DEFAULT_MCP_MAX_BODY_BYTES + 1);
    let request = raw_request(Method::POST, "/mcp", oversized);
    assert_rpc_error(
        send(&default_router(), request).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        -32600,
    )
    .await;
}

/// Slow request-body delivery consumes the same deadline as parsing and dispatch.
#[tokio::test]
async fn request_body_collection_is_bounded_by_the_transport_deadline() {
    let (mut sender, body) = Channel::<Bytes>::new(1);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = sender
            .send_data(Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#,
            ))
            .await;
    });
    let config = McpTransportConfig::default()
        .with_request_timeout(Duration::from_millis(5))
        .expect("short test timeout must be valid");
    let router = configured_router(config, Arc::new(TestDispatcher::new()));
    let request = raw_request(Method::POST, "/mcp", Body::new(body));
    let response = send(&router, request).await;
    let body = assert_rpc_error(response, StatusCode::GATEWAY_TIMEOUT, -32603).await;
    assert_eq!(body["error"]["message"], "Request timed out");
}

/// Present origins use exact configured equality while absent Origin remains valid.
#[tokio::test]
async fn origin_allowlist_is_exact_and_absence_is_allowed() {
    let config = McpTransportConfig::default()
        .with_allowed_origins(["https://claude.ai", "https://frameshift.example"])
        .expect("test origin allowlist must be valid");
    let router = configured_router(config, Arc::new(TestDispatcher::new()));
    let body = json!({"jsonrpc":"2.0","id":1,"method":"ping","params":{}}).to_string();

    let absent = raw_request(Method::POST, "/mcp", body.clone());
    assert_eq!(send(&router, absent).await.status(), StatusCode::OK);

    let allowed = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("origin", "https://claude.ai")
        .body(Body::from(body.clone()))
        .expect("allowed origin request must be valid");
    assert_eq!(send(&router, allowed).await.status(), StatusCode::OK);

    for origin in [
        "https://evilclaude.ai",
        "https://CLAUDE.ai",
        "https://claude.ai.evil.test",
    ] {
        let denied = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("origin", origin)
            .body(Body::from(body.clone()))
            .expect("denied origin request must be valid");
        assert_rpc_error(send(&router, denied).await, StatusCode::FORBIDDEN, -32600).await;
    }
}

/// Transport policy rejects wildcard origins and unsafe timeout or output caps.
#[test]
fn transport_configuration_preserves_hard_limits() {
    assert!(DEFAULT_MCP_REQUEST_TIMEOUT < Duration::from_secs(300));
    const { assert!(DEFAULT_MCP_MAX_TOOL_OUTPUT_CHARS < 150_000) };
    assert_eq!(
        McpTransportConfig::default()
            .with_allowed_origins(["*.example.com"])
            .expect_err("wildcard origin must fail"),
        McpTransportConfigError::InvalidOrigin
    );
    assert_eq!(
        McpTransportConfig::default()
            .with_request_timeout(Duration::from_secs(300))
            .expect_err("300-second timeout must fail"),
        McpTransportConfigError::InvalidRequestTimeout
    );
    assert_eq!(
        McpTransportConfig::default()
            .with_max_tool_output_chars(150_000)
            .expect_err("150,000-character output limit must fail"),
        McpTransportConfigError::InvalidToolOutputLimit
    );
}

/// Dispatcher context contains server extensions and ignores clientInfo for behavior.
#[tokio::test]
async fn dispatcher_receives_only_server_populated_context() {
    let dispatcher = Arc::new(TestDispatcher::new());
    let router = configured_router(McpTransportConfig::default(), dispatcher.clone())
        .layer(Extension(TrustedMarker("server-authenticated")));
    let request = modern_request(json!(1), "tools/list", Map::new());
    let response = send(&router, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        dispatcher.observations().trusted_markers.as_slice(),
        &[Some("server-authenticated")]
    );
}

/// Tool lists are deterministically sorted and private in the final protocol.
#[tokio::test]
async fn dispatcher_list_results_are_sorted_and_cache_scoped() {
    let dispatcher = Arc::new(TestDispatcher::new().with_list_result(McpListToolsResult {
        tools: vec![tool("z-last"), tool("a-first")],
        next_cursor: Some("cursor-2".to_owned()),
    }));
    let router = configured_router(McpTransportConfig::default(), dispatcher);
    let response = send(&router, modern_request(json!(1), "tools/list", Map::new())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["result"]["tools"][0]["name"], "a-first");
    assert_eq!(body["result"]["tools"][1]["name"], "z-last");
    assert_eq!(body["result"]["nextCursor"], "cursor-2");
    assert_eq!(body["result"]["cacheScope"], "private");
}

/// Application-level tool failures remain successful JSON-RPC results.
#[tokio::test]
async fn application_tool_errors_are_not_protocol_errors() {
    let dispatcher = Arc::new(
        TestDispatcher::new().with_call_result(McpCallToolResult::error("Try another input.")),
    );
    let router = configured_router(McpTransportConfig::default(), dispatcher);
    let response = send(&router, modern_call_request("test-tool", "test-tool")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert!(body.get("error").is_none());
    assert_eq!(body["result"]["isError"], true);
    assert_eq!(body["result"]["content"][0]["text"], "Try another input.");
}

/// Dispatcher infrastructure failures map to a fixed, secret-free server error.
#[tokio::test]
async fn dispatcher_list_failure_is_sanitized() {
    let dispatcher = Arc::new(TestDispatcher::new().with_list_error(McpDispatchError::Internal));
    let router = configured_router(McpTransportConfig::default(), dispatcher);
    let request = legacy_request(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/list",
        "params": {}
    }));
    let response = send(&router, request).await;
    let body = assert_rpc_error(response, StatusCode::INTERNAL_SERVER_ERROR, -32603).await;
    assert_eq!(body["error"]["message"], "Internal error");
}

/// Tool lookup and execution share one whole-request deadline.
#[tokio::test]
async fn tool_call_timeout_is_a_bounded_protocol_error() {
    let dispatcher = Arc::new(TestDispatcher::new().with_delay(Duration::from_millis(100)));
    let config = McpTransportConfig::default()
        .with_request_timeout(Duration::from_millis(5))
        .expect("short test timeout must be valid");
    let router = configured_router(config, dispatcher);
    let response = send(&router, modern_call_request("slow-tool", "slow-tool")).await;
    let body = assert_rpc_error(response, StatusCode::GATEWAY_TIMEOUT, -32603).await;
    assert_eq!(body["error"]["message"], "Request timed out");
}

/// Unicode output over the cap is replaced whole rather than split at a byte boundary.
#[tokio::test]
async fn tool_output_cap_is_unicode_safe_and_returns_bounded_error() {
    let oversized = "🦀".repeat(600);
    let dispatcher = Arc::new(
        TestDispatcher::new().with_call_result(McpCallToolResult::text(oversized.clone())),
    );
    let config = McpTransportConfig::default()
        .with_max_tool_output_chars(512)
        .expect("test output cap must fit the fixed error");
    let router = configured_router(config, dispatcher);
    let response = send(&router, modern_call_request("unicode-tool", "unicode-tool")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let text = body["result"]["content"][0]["text"]
        .as_str()
        .expect("bounded result must contain text");
    assert_eq!(text, "Tool output exceeded the server limit.");
    assert!(body["result"].to_string().chars().count() <= 512);
    assert!(!body.to_string().contains(&oversized));
    assert_eq!(body["result"]["isError"], true);
}

/// Empty content framing and structured JSON both count toward the serialized cap.
#[tokio::test]
async fn tool_output_cap_includes_structure_and_structured_content() {
    let empty_items = (0..128)
        .map(|_| McpToolContent::Text {
            text: String::new(),
        })
        .collect();
    let structural_dispatcher =
        Arc::new(TestDispatcher::new().with_call_result(McpCallToolResult {
            content: empty_items,
            structured_content: None,
            is_error: false,
        }));
    let structural_config = McpTransportConfig::default()
        .with_max_tool_output_chars(512)
        .expect("test output cap must fit the fixed error");
    let structural_router = configured_router(structural_config, structural_dispatcher);
    let response = send(
        &structural_router,
        modern_call_request("structural-tool", "structural-tool"),
    )
    .await;
    let body = response_json(response).await;
    assert_eq!(
        body["result"]["content"][0]["text"],
        "Tool output exceeded the server limit."
    );

    let structured_dispatcher =
        Arc::new(TestDispatcher::new().with_call_result(McpCallToolResult {
            content: Vec::new(),
            structured_content: Some(json!({ "large": "x".repeat(1_000) })),
            is_error: false,
        }));
    let config = McpTransportConfig::default()
        .with_max_tool_output_chars(512)
        .expect("test output cap must fit the fixed error");
    let structured_router = configured_router(config, structured_dispatcher);
    let response = send(
        &structured_router,
        modern_call_request("structured-tool", "structured-tool"),
    )
    .await;
    let body = response_json(response).await;
    assert_eq!(body["result"]["structuredContent"], Value::Null);
    assert_eq!(
        body["result"]["content"][0]["text"],
        "Tool output exceeded the server limit."
    );
}

/// Echoed string identifiers are bounded independently of the request-body cap.
#[tokio::test]
async fn oversized_string_request_ids_are_rejected_without_reflection() {
    let oversized_id = "i".repeat(257);
    let response = send(
        &default_router(),
        legacy_request(json!({
            "jsonrpc": "2.0",
            "id": oversized_id,
            "method": "ping",
            "params": {}
        })),
    )
    .await;
    let body = assert_rpc_error(response, StatusCode::BAD_REQUEST, -32600).await;
    assert!(body["id"].is_null());
    assert!(!body.to_string().contains(&"i".repeat(257)));
}
