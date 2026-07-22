/// MCP JSON-RPC 2.0 protocol types and response helpers.
use serde::{Deserialize, Serialize};

/// Incoming JSON-RPC 2.0 message (request or notification).
#[derive(Debug, Deserialize)]
pub struct JsonRpcMessage {
    /// JSON-RPC version string -- must be "2.0".
    pub jsonrpc: String,
    /// Request id. Absent for notifications.
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    /// The method name being invoked.
    pub method: String,
    /// Method parameters, if any.
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// Outgoing JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version string -- always "2.0".
    pub jsonrpc: &'static str,
    /// Echoed request id from the incoming message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    /// Successful result payload; mutually exclusive with `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error payload; mutually exclusive with `result`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// Error body for JSON-RPC error responses.
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    /// Numeric error code (e.g. -32700 for parse error, -32601 for method not found).
    pub code: i32,
    /// Human-readable error description.
    pub message: String,
}

/// MCP server info returned in the initialize response.
#[derive(Debug, Serialize)]
pub struct ServerInfo {
    /// The server's human-readable name.
    pub name: String,
    /// The server's version string.
    pub version: String,
}

/// MCP tool definition returned from tools/list.
#[derive(Debug, Serialize)]
pub struct ToolDef {
    /// Unique tool name used when calling via tools/call.
    pub name: String,
    /// Human-readable description of what the tool does.
    pub description: String,
    /// JSON Schema for the tool's input parameters.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Result of a tools/call invocation.
#[derive(Debug, Serialize)]
pub struct ToolResult {
    /// Content blocks returned by the tool.
    pub content: Vec<ToolContent>,
    /// Set to true when the tool call itself succeeded but the result
    /// represents an application-level error (e.g. persona not found).
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

/// A single content block within a tool result.
#[derive(Debug, Serialize)]
pub struct ToolContent {
    /// Content block type -- always "text" for this server.
    #[serde(rename = "type")]
    pub content_type: String,
    /// The text content of this block.
    pub text: String,
}

/// Definition of a single argument accepted by an MCP prompt.
///
/// Mirrors the MCP spec's prompt argument schema: each argument has a name,
/// optional description for client UIs, and a required flag.
#[derive(Debug, Serialize)]
pub struct PromptArgDef {
    /// Argument name as it will appear in `prompts/get` params.
    pub name: String,
    /// Human-readable description shown by the client.
    pub description: String,
    /// Whether the argument is required.
    pub required: bool,
}

/// MCP prompt definition returned from `prompts/list`.
///
/// Clients render these as user-invocable prompts (in Claude Code they
/// surface as `/mcp__servername__name` slash commands; in Gemini CLI as
/// `/name [args]` slash commands).
#[derive(Debug, Serialize)]
pub struct PromptDef {
    /// Unique prompt name used when calling via `prompts/get`.
    pub name: String,
    /// Human-readable description of what the prompt produces.
    pub description: String,
    /// Ordered list of argument definitions; empty when the prompt takes no arguments.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgDef>,
}

/// Result of a `prompts/get` invocation.
///
/// MCP clients append `messages` to the conversation. Each message has a
/// `role` ("user" | "assistant" | "system") and a content block.
#[derive(Debug, Serialize)]
pub struct PromptResult {
    /// Optional description shown to the user; clients may surface this in UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Ordered sequence of messages the client will insert into the conversation.
    pub messages: Vec<PromptMessage>,
}

/// A single message in a `PromptResult`.
///
/// Frameshift's prompts emit `"user"` role messages so the agent receives the
/// content as if the user had pasted it -- this matches the semantics of a
/// rendered persona that should steer subsequent turns.
#[derive(Debug, Serialize)]
pub struct PromptMessage {
    /// Role of the message author: "user", "assistant", or "system".
    pub role: String,
    /// Content block for this message.
    pub content: PromptContent,
}

/// Content block within a `PromptMessage`.
///
/// Currently always `type: "text"`; future versions may add resource refs.
#[derive(Debug, Serialize)]
pub struct PromptContent {
    /// Content block type -- always "text" for this server.
    #[serde(rename = "type")]
    pub content_type: String,
    /// The text content of this block.
    pub text: String,
}

/// Construct a successful JSON-RPC response with the given id and result value.
pub fn success_response(
    id: Option<serde_json::Value>,
    result: serde_json::Value,
) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

/// Construct a JSON-RPC error response with the given id, error code, and message.
pub fn error_response(id: Option<serde_json::Value>, code: i32, msg: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError { code, message: msg }),
    }
}

#[cfg(test)]
/// Serialization tests for MCP response and protocol payload types.
mod tests {
    use super::*;

    /// Verify that an initialize response carries the expected serverInfo.name field.
    #[test]
    fn initialize_response_has_server_info() {
        let result = serde_json::json!({
            "protocolVersion": "2025-11-25",
            "serverInfo": {
                "name": "frameshift-mcp",
                "version": "0.1.0"
            },
            "capabilities": {
                "tools": {}
            }
        });
        let response = success_response(Some(serde_json::json!(1)), result);
        let serialized = serde_json::to_value(&response).unwrap();
        assert_eq!(serialized["result"]["serverInfo"]["name"], "frameshift-mcp");
    }

    /// Verify the shape of an error response: must have error.code and error.message,
    /// no result field.
    #[test]
    fn error_response_format() {
        let response = error_response(
            Some(serde_json::json!(42)),
            -32601,
            "method not found".to_string(),
        );
        let serialized = serde_json::to_value(&response).unwrap();
        assert_eq!(serialized["jsonrpc"], "2.0");
        assert_eq!(serialized["id"], 42);
        assert_eq!(serialized["error"]["code"], -32601);
        assert_eq!(serialized["error"]["message"], "method not found");
        assert!(serialized.get("result").is_none() || serialized["result"].is_null());
    }
}
