//! Frameshift MCP server: reads JSON-RPC from stdin, writes to stdout.
//! Tracing output goes to stderr to avoid corrupting the MCP protocol.

use frameshift_client::Client;
use frameshift_mcp::protocol::{error_response, success_response, JsonRpcMessage, JsonRpcResponse};
use frameshift_mcp::{prompts, tools};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};

/// Newest MCP protocol revision implemented by this server.
const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";

/// Protocol revisions accepted for compatibility with older agent hosts.
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] =
    [LATEST_PROTOCOL_VERSION, "2025-06-18", "2024-11-05"];

/// Human-readable setup guidance returned to MCP hosts during initialization.
const SERVER_INSTRUCTIONS: &str = "FrameShift manages project-scoped agent personas. Set FRAMESHIFT_PROJECT_ROOT in this server's environment once, or pass project_root per call. When neither is provided, Claude Code's CLAUDE_PROJECT_DIR is used when available, followed by the server working directory. Set FRAMESHIFT_TARGET to claude, codex, gemini, or generic, or pass target to frameshift_use and active_persona; generic is the default. Start with frameshift_search, install with frameshift_install, choose with select_persona, then activate with frameshift_use.";

/// Main entry point. Initializes tracing, creates the client, then
/// runs the stdin JSON-RPC read loop writing responses to stdout.
#[tokio::main]
async fn main() {
    // Tracing to stderr -- stdout is reserved for MCP protocol
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Env-only vault provider: stdin/stdout here *are* the JSON-RPC protocol
    // channel, so there is never an interactive terminal to prompt on, and a
    // blocking stdin read would corrupt the protocol stream. Callers that
    // need vault-backed template tokens available to this server must export
    // FRAMESHIFT_VAULT_PASSPHRASE in its environment.
    let client = match Client::with_default_data_root_and_vault(Some(
        frameshift_client::env_only_vault_provider(),
    )) {
        Ok(c) => c,
        Err(e) => {
            // stdout is the protocol channel and no request id exists yet, so the
            // only useful signal is a clear stderr diagnostic and a nonzero exit
            // rather than a panic that gives the client an unexplained EOF.
            eprintln!("frameshift-mcp: failed to initialize client: {e}");
            std::process::exit(1);
        }
    };

    let mut stdin = tokio::io::stdin();
    let mut stdout = BufWriter::new(tokio::io::stdout());
    let mut pending: Vec<u8> = Vec::new();
    let mut line: Vec<u8> = Vec::new();

    loop {
        match read_capped_line(&mut stdin, &mut pending, &mut line, MAX_LINE_BYTES).await {
            Ok(LineRead::Eof) | Err(_) => break,
            Ok(LineRead::TooLong) => {
                let msg = "request line exceeds maximum size".to_string();
                let response = error_response(None, -32700, msg);
                write_response(&mut stdout, &response).await;
            }
            Ok(LineRead::Line) => {
                let text = String::from_utf8_lossy(&line);
                if let Some(response) = handle_message(&text, &client) {
                    write_response(&mut stdout, &response).await;
                }
            }
        }
    }
}

/// Maximum size in bytes of a single JSON-RPC line read from stdin. Larger lines
/// are rejected rather than buffered, bounding memory against a client that never
/// sends a newline.
const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// Outcome of one capped read from the input stream.
enum LineRead {
    /// A complete line (trailing newline stripped) was read into the output buffer.
    Line,
    /// The line exceeded the cap and was discarded; the stream is positioned just
    /// past its terminating newline.
    TooLong,
    /// End of input.
    Eof,
}

/// Serialize a JSON-RPC response and write it to stdout as one newline-terminated line.
async fn write_response(stdout: &mut BufWriter<tokio::io::Stdout>, response: &JsonRpcResponse) {
    let json = serde_json::to_string(response).unwrap_or_default();
    let _ = stdout.write_all(json.as_bytes()).await;
    let _ = stdout.write_all(b"\n").await;
    let _ = stdout.flush().await;
}

/// Read one newline-delimited line into `out`, capping its length at `max` bytes.
///
/// `pending` carries bytes read past the previous line between calls. If a line
/// exceeds `max` before a newline arrives, the rest of that line is discarded and
/// `TooLong` is returned, so a client that never sends a newline cannot drive
/// unbounded memory growth.
async fn read_capped_line<R>(
    reader: &mut R,
    pending: &mut Vec<u8>,
    out: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<LineRead>
where
    R: AsyncReadExt + Unpin,
{
    out.clear();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        if let Some(pos) = pending.iter().position(|&b| b == b'\n') {
            if pos > max {
                // The completed line is over the cap: discard it, newline included.
                pending.drain(..=pos);
                return Ok(LineRead::TooLong);
            }
            out.extend_from_slice(&pending[..pos]);
            pending.drain(..=pos);
            return Ok(LineRead::Line);
        }
        if pending.len() > max {
            // Over the cap with no newline yet: discard and skip to the next one.
            return drain_over_long(reader, pending, &mut chunk).await;
        }
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            if pending.is_empty() {
                return Ok(LineRead::Eof);
            }
            // Final line with no trailing newline at end of input.
            if pending.len() > max {
                pending.clear();
                return Ok(LineRead::TooLong);
            }
            out.extend_from_slice(pending);
            pending.clear();
            return Ok(LineRead::Line);
        }
        pending.extend_from_slice(&chunk[..n]);
    }
}

/// Discard input up to and including the next newline, then report `TooLong`.
async fn drain_over_long<R>(
    reader: &mut R,
    pending: &mut Vec<u8>,
    chunk: &mut [u8],
) -> std::io::Result<LineRead>
where
    R: AsyncReadExt + Unpin,
{
    loop {
        if let Some(pos) = pending.iter().position(|&b| b == b'\n') {
            pending.drain(..=pos);
            return Ok(LineRead::TooLong);
        }
        pending.clear();
        let n = reader.read(chunk).await?;
        if n == 0 {
            return Ok(LineRead::TooLong);
        }
        pending.extend_from_slice(&chunk[..n]);
    }
}

/// Handle a single JSON-RPC message line.
///
/// Returns None for notifications (no id present) so no response is written.
/// Returns Some(response) for requests that require a reply.
fn handle_message(line: &str, client: &Client) -> Option<JsonRpcResponse> {
    let msg: JsonRpcMessage = match serde_json::from_str(line) {
        Ok(m) => m,
        Err(e) => {
            return Some(error_response(None, -32700, format!("parse error: {e}")));
        }
    };

    // Notifications have no id -- do not respond to them.
    msg.id.as_ref()?;
    let id = msg.id.clone();

    match msg.method.as_str() {
        "initialize" => {
            // Advertise both tools and prompts; clients use these to decide
            // which surfaces (tools/list, prompts/list) to query and render.
            let protocol_version = negotiate_protocol_version(msg.params.as_ref());
            let result = serde_json::json!({
                "protocolVersion": protocol_version,
                "serverInfo": {
                    "name": "frameshift-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": {
                    "tools": {},
                    "prompts": {}
                },
                "instructions": SERVER_INSTRUCTIONS
            });
            Some(success_response(id, result))
        }
        "tools/list" => {
            let defs = tools::tool_definitions();
            let result = serde_json::json!({"tools": defs});
            Some(success_response(id, result))
        }
        "tools/call" => {
            let params = msg.params.unwrap_or(serde_json::Value::Null);
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Object(Default::default()));
            let tool_result = tools::call_tool(name, &arguments, client);
            Some(success_response(
                id,
                serde_json::to_value(tool_result).unwrap_or_default(),
            ))
        }
        "prompts/list" => {
            let defs = prompts::prompt_definitions();
            let result = serde_json::json!({"prompts": defs});
            Some(success_response(id, result))
        }
        "prompts/get" => {
            let params = msg.params.unwrap_or(serde_json::Value::Null);
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Object(Default::default()));
            match prompts::call_prompt(name, &arguments, client) {
                Ok(result) => Some(success_response(
                    id,
                    serde_json::to_value(result).unwrap_or_default(),
                )),
                Err(message) => Some(error_response(id, -32602, message)),
            }
        }
        _ => Some(error_response(
            id,
            -32601,
            format!("method not found: {}", msg.method),
        )),
    }
}

/// Echo a client protocol revision when supported, otherwise select the latest revision.
fn negotiate_protocol_version(params: Option<&serde_json::Value>) -> &'static str {
    let requested = params
        .and_then(|value| value.get("protocolVersion"))
        .and_then(serde_json::Value::as_str);
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|supported| Some(*supported) == requested)
        .unwrap_or(LATEST_PROTOCOL_VERSION)
}

#[cfg(test)]
/// JSON-RPC transport and MCP initialization integration tests.
mod tests {
    use super::*;
    use frameshift_client::{Client, ClientOptions, InstallRequest, InstallSource, PersonaSpec};
    use std::fs;

    /// Build a Client backed by a temporary data root.
    fn make_client(data_root: &std::path::Path) -> Client {
        Client::new(ClientOptions {
            data_root: data_root.to_path_buf(),
            config_root: None,
            vault: None,
        })
    }

    /// Verify that a JSON notification (no id field) produces no response.
    #[test]
    fn notification_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        // A notification has no "id" field.
        let line = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let result = handle_message(line, &client);
        assert!(
            result.is_none(),
            "notifications must not produce a response"
        );
    }

    /// Verify that an initialize request returns serverInfo.name.
    #[test]
    fn initialize_returns_server_info() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let response = handle_message(line, &client).expect("should produce a response");
        let serialized = serde_json::to_value(&response).unwrap();
        assert_eq!(serialized["result"]["serverInfo"]["name"], "frameshift-mcp");
        assert_eq!(
            serialized["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            serialized["result"]["protocolVersion"],
            LATEST_PROTOCOL_VERSION
        );
        assert!(serialized["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("FRAMESHIFT_PROJECT_ROOT"));
    }

    /// Initialize echoes an older supported revision for compatible hosts.
    #[test]
    fn initialize_negotiates_supported_older_protocol() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#;
        let response = handle_message(line, &client).expect("should produce a response");
        let serialized = serde_json::to_value(&response).unwrap();
        assert_eq!(serialized["result"]["protocolVersion"], "2024-11-05");
    }

    /// Verify that an unknown method returns a -32601 error.
    #[test]
    fn unknown_method_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"bogus/method"}"#;
        let response = handle_message(line, &client).expect("should produce a response");
        let serialized = serde_json::to_value(&response).unwrap();
        assert_eq!(serialized["error"]["code"], -32601);
    }

    /// Verify that tools/list returns the expected ten tool names.
    #[test]
    fn tools_list_returns_ten_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#;
        let response = handle_message(line, &client).expect("should produce a response");
        let serialized = serde_json::to_value(&response).unwrap();
        let tools = serialized["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 10);
    }

    /// Verify tools/call with frameshift_install succeeds end-to-end.
    #[test]
    fn tools_call_install_end_to_end() {
        let tmp = tempfile::tempdir().unwrap();
        let data_root = tmp.path().join("data");
        let pack_dir = tmp.path().join("pack");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(
            pack_dir.join("pack.toml"),
            "schema_version = 1\nname = \"mcp-test\"\nversion = \"0.1.0\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n",
        )
        .unwrap();
        fs::write(pack_dir.join("AGENTS.md"), "# MCP Test\n").unwrap();

        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&data_root);

        let args = serde_json::json!({
            "name": "frameshift_install",
            "arguments": {
                "spec": "mcp-test@0.1.0",
                "project_root": project_root.to_str().unwrap(),
                "from_path": pack_dir.to_str().unwrap()
            }
        });
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": args
        });
        let response =
            handle_message(&msg.to_string(), &client).expect("should produce a response");
        let serialized = serde_json::to_value(&response).unwrap();
        // Should be a success result (no error field).
        assert!(serialized.get("error").is_none() || serialized["error"].is_null());
        let content = &serialized["result"]["content"][0]["text"];
        assert!(content.as_str().unwrap().contains("mcp-test@0.1.0"));
    }

    /// Verify that a malformed JSON line produces a parse error response.
    #[test]
    fn malformed_json_returns_parse_error() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        let response =
            handle_message("not json {{{{", &client).expect("should produce error response");
        let serialized = serde_json::to_value(&response).unwrap();
        assert_eq!(serialized["error"]["code"], -32700);
    }

    /// Verify prompts/list returns the expected three prompt names.
    #[test]
    fn prompts_list_returns_three_prompts() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        let line = r#"{"jsonrpc":"2.0","id":4,"method":"prompts/list"}"#;
        let response = handle_message(line, &client).expect("should produce a response");
        let serialized = serde_json::to_value(&response).unwrap();
        let prompts = serialized["result"]["prompts"]
            .as_array()
            .expect("prompts array");
        assert_eq!(prompts.len(), 3);
        let names: Vec<&str> = prompts
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"active_persona"));
        assert!(names.contains(&"select_persona"));
        assert!(names.contains(&"automate_status"));
    }

    /// Verify the initialize response advertises both tools and prompts capabilities.
    #[test]
    fn initialize_advertises_prompts_capability() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        let line = r#"{"jsonrpc":"2.0","id":5,"method":"initialize","params":{}}"#;
        let response = handle_message(line, &client).expect("should produce a response");
        let serialized = serde_json::to_value(&response).unwrap();
        assert!(
            serialized["result"]["capabilities"]["prompts"].is_object(),
            "initialize must declare the prompts capability"
        );
        assert!(
            serialized["result"]["capabilities"]["tools"].is_object(),
            "initialize must declare the tools capability"
        );
    }

    /// Verify prompts/get with a known prompt and an empty project returns a graceful hint.
    #[test]
    fn prompts_get_active_persona_hints_when_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();
        let client = make_client(&tmp.path().join("data"));

        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "prompts/get",
            "params": {
                "name": "active_persona",
                "arguments": { "project_root": project_root.to_str().unwrap() }
            }
        });
        let response =
            handle_message(&msg.to_string(), &client).expect("should produce a response");
        let serialized = serde_json::to_value(&response).unwrap();
        assert!(
            serialized.get("error").is_none() || serialized["error"].is_null(),
            "expected success, got error: {:?}",
            serialized.get("error")
        );
        let text = serialized["result"]["messages"][0]["content"]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("No Frameshift persona is active"));
    }

    /// Verify prompts/get with an unknown prompt name returns a JSON-RPC error.
    #[test]
    fn prompts_get_unknown_prompt_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "prompts/get",
            "params": { "name": "no-such-prompt", "arguments": {} }
        });
        let response =
            handle_message(&msg.to_string(), &client).expect("should produce a response");
        let serialized = serde_json::to_value(&response).unwrap();
        assert_eq!(serialized["error"]["code"], -32602);
        assert!(serialized["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown prompt"));
    }

    /// Verify grow_append integration through the full message handler.
    #[test]
    fn tools_call_grow_append_integration() {
        let tmp = tempfile::tempdir().unwrap();
        let data_root = tmp.path().join("data");
        let pack_dir = tmp.path().join("pack");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(
            pack_dir.join("pack.toml"),
            "schema_version = 1\nname = \"growpersona\"\nversion = \"0.1.0\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n",
        )
        .unwrap();
        fs::write(pack_dir.join("AGENTS.md"), "# Grow Persona\n").unwrap();

        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&data_root);

        // Install persona first so growth dir exists.
        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: "growpersona".to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();

        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "frameshift_grow_append",
                "arguments": {
                    "project_root": project_root.to_str().unwrap(),
                    "persona": "growpersona",
                    "text": "Learned something useful."
                }
            }
        });

        let response =
            handle_message(&msg.to_string(), &client).expect("should produce a response");
        let serialized = serde_json::to_value(&response).unwrap();
        assert!(serialized.get("error").is_none() || serialized["error"].is_null());
        let content_text = serialized["result"]["content"][0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content_text).unwrap();
        assert_eq!(parsed["appended"], true);
    }

    /// The capped line reader rejects an over-long line and recovers on the next one.
    #[tokio::test]
    async fn read_capped_line_rejects_oversized_then_recovers() {
        // With max = 8, "toolongline" (11 bytes) exceeds the cap; "ok" does not.
        let input: &[u8] = b"toolongline\nok\n";
        let mut reader = input;
        let mut pending = Vec::new();
        let mut out = Vec::new();
        let r1 = read_capped_line(&mut reader, &mut pending, &mut out, 8)
            .await
            .unwrap();
        assert!(
            matches!(r1, LineRead::TooLong),
            "over-long line must be rejected"
        );
        let r2 = read_capped_line(&mut reader, &mut pending, &mut out, 8)
            .await
            .unwrap();
        assert!(matches!(r2, LineRead::Line));
        assert_eq!(out, b"ok");
        let r3 = read_capped_line(&mut reader, &mut pending, &mut out, 8)
            .await
            .unwrap();
        assert!(matches!(r3, LineRead::Eof));
    }

    /// frameshift_activate rejects a traversal persona name at the MCP boundary.
    #[test]
    fn tools_call_activate_rejects_traversal_persona() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(&tmp.path().join("data"));
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();
        let msg = serde_json::json!({
            "jsonrpc": "2.0", "id": 30, "method": "tools/call",
            "params": { "name": "frameshift_activate", "arguments": {
                "persona": "../evil",
                "project_root": project_root.to_str().unwrap()
            }}
        });
        let response = handle_message(&msg.to_string(), &client).expect("response");
        let serialized = serde_json::to_value(&response).unwrap();
        let text = serialized["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.starts_with("invalid persona name"),
            "expected boundary rejection, got: {text}"
        );
    }

    /// frameshift_use rejects a traversal persona name at the MCP boundary.
    #[test]
    fn tools_call_use_rejects_traversal_persona() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(&tmp.path().join("data"));
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();
        let msg = serde_json::json!({
            "jsonrpc": "2.0", "id": 31, "method": "tools/call",
            "params": { "name": "frameshift_use", "arguments": {
                "project_root": project_root.to_str().unwrap(),
                "persona": "../evil"
            }}
        });
        let response = handle_message(&msg.to_string(), &client).expect("response");
        let serialized = serde_json::to_value(&response).unwrap();
        let text = serialized["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.starts_with("invalid persona name"),
            "expected boundary rejection, got: {text}"
        );
    }
}
