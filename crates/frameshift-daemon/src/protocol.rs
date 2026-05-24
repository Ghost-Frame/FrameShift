//! JSON-RPC 2.0 wire types and helper functions for serializing
//! responses and parsing incoming requests over the Unix socket.

use serde::{Deserialize, Serialize};

/// Standard JSON-RPC 2.0 parse error code (-32700).
pub const PARSE_ERROR: i32 = -32700;
/// Standard JSON-RPC 2.0 invalid request code (-32600).
pub const INVALID_REQUEST: i32 = -32600;
/// Standard JSON-RPC 2.0 method not found code (-32601).
pub const METHOD_NOT_FOUND: i32 = -32601;
/// Standard JSON-RPC 2.0 invalid params code (-32602).
pub const INVALID_PARAMS: i32 = -32602;
/// Standard JSON-RPC 2.0 internal error code (-32603).
pub const INTERNAL_ERROR: i32 = -32603;

/// A JSON-RPC 2.0 request received from a client over the socket.
#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    /// Must equal "2.0".
    pub jsonrpc: String,
    /// Caller-supplied correlation id; null for notifications.
    pub id: Option<serde_json::Value>,
    /// Method name to invoke.
    pub method: String,
    /// Optional method-specific parameters.
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// A JSON-RPC 2.0 success response to send back to the client.
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    /// Always "2.0".
    pub jsonrpc: &'static str,
    /// Echo of the request id.
    pub id: serde_json::Value,
    /// The method's return value.
    pub result: serde_json::Value,
}

/// A JSON-RPC 2.0 error response to send back to the client.
#[derive(Debug, Serialize)]
pub struct RpcErrorResponse {
    /// Always "2.0".
    pub jsonrpc: &'static str,
    /// Echo of the request id.
    pub id: serde_json::Value,
    /// The structured error body.
    pub error: RpcErrorBody,
}

/// The error detail object embedded inside an error response.
#[derive(Debug, Serialize)]
pub struct RpcErrorBody {
    /// Numeric error code (see the PARSE_ERROR / METHOD_NOT_FOUND etc. constants).
    pub code: i32,
    /// Human-readable description of the error.
    pub message: String,
}

/// Serialize a success response to a newline-terminated JSON string.
pub fn success(id: serde_json::Value, result: serde_json::Value) -> String {
    let resp = RpcResponse {
        jsonrpc: "2.0",
        id,
        result,
    };
    let mut s = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
    s.push('\n');
    s
}

/// Serialize an error response to a newline-terminated JSON string.
pub fn error(id: serde_json::Value, code: i32, msg: impl Into<String>) -> String {
    let resp = RpcErrorResponse {
        jsonrpc: "2.0",
        id,
        error: RpcErrorBody {
            code,
            message: msg.into(),
        },
    };
    let mut s = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
    s.push('\n');
    s
}

/// Parse a raw JSON line into an `RpcRequest`.
///
/// Returns `Ok(request)` on success, or `Err(error_response_string)` where the
/// string is a ready-to-send JSON-RPC parse/invalid-request error response.
pub fn parse_request(line: &str) -> Result<RpcRequest, String> {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            return Err(error(serde_json::Value::Null, PARSE_ERROR, "parse error"));
        }
    };

    match serde_json::from_value::<RpcRequest>(value) {
        Ok(req) => Ok(req),
        Err(_) => Err(error(
            serde_json::Value::Null,
            INVALID_REQUEST,
            "invalid request",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a well-formed JSON-RPC 2.0 request deserializes correctly.
    #[test]
    fn parse_valid_request() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"gc","params":null}"#;
        let req = parse_request(line).expect("should parse");
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "gc");
        assert_eq!(req.id, Some(serde_json::json!(1)));
    }

    /// Verify that malformed JSON returns a parse-error response string.
    #[test]
    fn parse_malformed_json() {
        let result = parse_request("not json at all {{{");
        assert!(result.is_err());
        let err_str = result.unwrap_err();
        let parsed: serde_json::Value = serde_json::from_str(err_str.trim()).unwrap();
        assert_eq!(parsed["error"]["code"], PARSE_ERROR);
    }

    /// Verify that valid JSON missing the `method` field returns an invalid-request error.
    #[test]
    fn parse_missing_method() {
        let line = r#"{"jsonrpc":"2.0","id":2}"#;
        let result = parse_request(line);
        assert!(result.is_err());
        let err_str = result.unwrap_err();
        let parsed: serde_json::Value = serde_json::from_str(err_str.trim()).unwrap();
        assert_eq!(parsed["error"]["code"], INVALID_REQUEST);
    }
}
