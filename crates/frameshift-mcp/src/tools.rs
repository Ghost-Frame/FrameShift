/// Tool definitions and dispatch for the Frameshift MCP server.
///
/// Each tool maps directly to a frameshift-client or frameshift-growth operation.
use frameshift_capabilities::{CapabilityFilter, Tool as CapabilityTool};
use frameshift_client::{Client, InstallRequest, InstallSource, PersonaSpec};
use frameshift_orchestrator::{
    AuditLog, Embedder, Mode, ModeState, PolicyWeights, Preferences, SelectionInputs,
};
use frameshift_pack::{CapabilityManifest, PackManifest};

use crate::protocol::{ToolContent, ToolDef, ToolResult};

/// Return the process-wide semantic embedder, loading the model once on first
/// use. A failed load (offline, corrupt cache) is remembered as `None` so
/// repeated `frameshift_select` calls do not retry the download.
#[cfg(feature = "embeddings")]
fn shared_embedder() -> Option<&'static dyn Embedder> {
    use std::sync::OnceLock;
    static EMBEDDER: OnceLock<Option<frameshift_embed_candle::CandleEmbedder>> = OnceLock::new();
    EMBEDDER
        .get_or_init(
            || match frameshift_embed_candle::CandleEmbedder::from_hub() {
                Ok(e) => Some(e),
                Err(e) => {
                    eprintln!(
                        "warning: semantic embeddings unavailable ({e}); lexical ranking only"
                    );
                    None
                }
            },
        )
        .as_ref()
        .map(|e| e as &dyn Embedder)
}

/// Without the `embeddings` feature there is never an embedder.
#[cfg(not(feature = "embeddings"))]
fn shared_embedder() -> Option<&'static dyn Embedder> {
    None
}

/// Return the complete list of available MCP tools with their JSON Schema definitions.
pub fn tool_definitions() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "frameshift_install".to_string(),
            description: "Install a persona pack into the Frameshift central store for a project.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "spec": {"type": "string"},
                    "project_root": {"type": "string"},
                    "from_path": {"type": "string"}
                },
                "required": ["spec", "project_root"]
            }),
        },
        ToolDef {
            name: "frameshift_activate".to_string(),
            description: "Mark an installed persona as active for the given project.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "persona": {"type": "string"},
                    "project_root": {"type": "string"}
                },
                "required": ["persona", "project_root"]
            }),
        },
        ToolDef {
            name: "frameshift_list".to_string(),
            description: "List all personas installed for the given project.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": {"type": "string"}
                },
                "required": ["project_root"]
            }),
        },
        ToolDef {
            name: "frameshift_grow_append".to_string(),
            description: "Append a growth entry to a persona's growth log for the given project.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": {"type": "string"},
                    "persona": {"type": "string"},
                    "text": {"type": "string"}
                },
                "required": ["project_root", "persona", "text"]
            }),
        },
        ToolDef {
            name: "frameshift_select".to_string(),
            description: "Rank installed personas for the given project context. Returns a ranked list with score, confidence, and rationale. Read-only; does not change active state. Pass 'library' to rank from a catalog directory instead of installed personas.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": {"type": "string"},
                    "task": {"type": "string"},
                    "library": {"type": "string"}
                },
                "required": ["project_root"]
            }),
        },
        ToolDef {
            name: "frameshift_use".to_string(),
            description: "Activate a persona for the given project and return its rendered content.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": {"type": "string"},
                    "persona": {"type": "string"}
                },
                "required": ["project_root", "persona"]
            }),
        },
        ToolDef {
            name: "frameshift_automate".to_string(),
            description: "Manage automate-mode state for a project. Actions: on, off, status, lock, unlock.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": {"type": "string"},
                    "action": {
                        "type": "string",
                        "enum": ["on", "off", "status", "lock", "unlock"]
                    }
                },
                "required": ["project_root", "action"]
            }),
        },
        ToolDef {
            name: "frameshift_capabilities".to_string(),
            description: "Report the resolved persona's declared capability manifest and, when a candidate tool list is given, annotate which of those tools are allowed by it. Advisory only -- never blocks or hides any of this server's own MCP tools (persona `required_tools` names agent-side tools such as Read/Bash, a different namespace).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": {"type": "string"},
                    "persona": {"type": "string"},
                    "tools": {
                        "type": "array",
                        "description": "Candidate tools to evaluate. Each entry is either a bare tool-name string or an object {name, required_capabilities?}; when required_capabilities is omitted it defaults to [name].",
                        "items": {
                            "oneOf": [
                                {"type": "string"},
                                {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "required_capabilities": {
                                            "type": "array",
                                            "items": {"type": "string"}
                                        }
                                    },
                                    "required": ["name"]
                                }
                            ]
                        }
                    }
                },
                "required": ["project_root"]
            }),
        },
        ToolDef {
            name: "frameshift_prefs".to_string(),
            description: "View and adjust per-persona preference biases. Actions: show, bump, decay, reset.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": {"type": "string"},
                    "action": {
                        "type": "string",
                        "enum": ["show", "bump", "decay", "reset"]
                    },
                    "persona": {"type": "string"}
                },
                "required": ["project_root", "action"]
            }),
        },
    ]
}

/// Build a successful ToolResult wrapping a single text content block.
fn ok_result(text: String) -> ToolResult {
    ToolResult {
        content: vec![ToolContent {
            content_type: "text".to_string(),
            text,
        }],
        is_error: None,
    }
}

/// Build an error ToolResult wrapping a single text content block.
fn err_result(text: String) -> ToolResult {
    ToolResult {
        content: vec![ToolContent {
            content_type: "text".to_string(),
            text,
        }],
        is_error: Some(true),
    }
}

/// Dispatch a tool call by name, forwarding arguments to the appropriate client operation.
///
/// Returns a ToolResult -- errors are represented as is_error results rather than
/// propagated as Rust errors, matching the MCP protocol's expectation that tools/call
/// always returns a 200-level JSON-RPC response.
/// Validate a caller-supplied filesystem path argument.
///
/// At the MCP boundary the caller is a local agent, but a prompt-injected tool
/// call could pass a traversal path. Require the path to be absolute and to
/// contain no `..` component: this blocks relative/`..` escapes while still
/// letting the agent address any real project directory by absolute path.
fn validate_path_arg(raw: &str) -> Result<std::path::PathBuf, String> {
    use std::path::Component;
    let path = std::path::PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {raw:?}"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!("path must not contain '..': {raw:?}"));
    }
    Ok(path)
}

/// Resolve and parse the capability manifest for a persona in a project.
///
/// If `persona` is `None`, resolves the currently active persona from
/// `ProjectPaths.active_path`. Validates the resolved name, then reads and
/// parses `<personas_dir>/<name>/source/pack.toml`. Returns the resolved
/// persona name alongside its optional `CapabilityManifest` (a pack may
/// declare none). All failure modes (missing active persona, invalid name,
/// missing/unparseable manifest) are surfaced as a `String` error so callers
/// can decide whether to fail hard (the capabilities tool) or degrade
/// gracefully (call_use annotation).
fn load_capability_manifest(
    client: &Client,
    project_root: &std::path::Path,
    persona: Option<&str>,
) -> Result<(String, Option<CapabilityManifest>), String> {
    let paths = client
        .project_paths(project_root)
        .map_err(|e| format!("project_paths failed: {}", e))?;

    let name = match persona {
        Some(p) => p.to_string(),
        None => {
            if !paths.active_path.exists() {
                return Err("no active persona and no persona specified".to_string());
            }
            std::fs::read_to_string(&paths.active_path)
                .map_err(|e| format!("failed to read active persona marker: {}", e))?
                .trim()
                .to_string()
        }
    };

    if let Err(e) = frameshift_client::validate_persona_name(&name) {
        return Err(format!("invalid persona name: {e}"));
    }

    let manifest_path = paths
        .personas_dir
        .join(&name)
        .join("source")
        .join("pack.toml");
    let raw = std::fs::read_to_string(&manifest_path).map_err(|e| {
        format!(
            "failed to read pack manifest at {}: {}",
            manifest_path.display(),
            e
        )
    })?;
    let manifest: PackManifest =
        toml::from_str(&raw).map_err(|e| format!("failed to parse pack manifest: {}", e))?;

    Ok((name, manifest.capability_manifest))
}

/// Parse a single `tools` array entry into a `frameshift_capabilities::Tool`.
///
/// Accepts either a bare tool-name string (required capabilities default to
/// `[name]`) or an object `{name, required_capabilities?}` (defaulting the
/// same way when the field is absent). Returns `None` for entries that are
/// neither a string nor an object with a `name` field.
fn parse_tool_entry(entry: &serde_json::Value) -> Option<CapabilityTool> {
    if let Some(name) = entry.as_str() {
        return Some(CapabilityTool {
            name: name.to_string(),
            required_capabilities: vec![name.to_string()],
        });
    }
    let name = entry.get("name")?.as_str()?.to_string();
    let required_capabilities = match entry
        .get("required_capabilities")
        .and_then(|v| v.as_array())
    {
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        None => vec![name.clone()],
    };
    Some(CapabilityTool {
        name,
        required_capabilities,
    })
}

/// Handle the frameshift_capabilities tool call.
///
/// Reports the resolved persona's declared capability manifest. This is an
/// annotation/reporting channel only -- it never blocks or hides any of this
/// server's own MCP tools (the 8 management tools above are a different
/// namespace from the agent-side tool names a persona's `required_tools`
/// declares, e.g. Read/Bash). When a `tools` array argument is given, each
/// entry is evaluated against a `CapabilityFilter` built from the manifest and
/// annotated with `allowed`.
fn call_capabilities(arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let project_root_str = match arguments.get("project_root").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: project_root".to_string()),
    };
    let project_root = match validate_path_arg(project_root_str) {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };

    let persona_arg = arguments.get("persona").and_then(|v| v.as_str());

    let (persona, capability_manifest) =
        match load_capability_manifest(client, &project_root, persona_arg) {
            Ok(v) => v,
            Err(e) => return err_result(e),
        };

    let capability_manifest = match capability_manifest {
        None => {
            let text = serde_json::json!({
                "persona": persona,
                "capability_manifest": serde_json::Value::Null,
                "warning": "persona declares no capability manifest; all tools implicitly allowed",
            })
            .to_string();
            return ok_result(text);
        }
        Some(cap) => cap,
    };

    let filter = CapabilityFilter::from_manifest(&capability_manifest);

    let mut response = serde_json::json!({
        "persona": persona,
        "capability_manifest": capability_manifest,
        "declared": filter.declared(),
    });

    if let Some(tools_arg) = arguments.get("tools").and_then(|v| v.as_array()) {
        let annotated: Vec<serde_json::Value> = tools_arg
            .iter()
            .filter_map(parse_tool_entry)
            .map(|tool| {
                let allowed = filter.allows(&tool);
                serde_json::json!({
                    "name": tool.name,
                    "required_capabilities": tool.required_capabilities,
                    "allowed": allowed,
                })
            })
            .collect();
        response["tools"] = serde_json::Value::Array(annotated);
    }

    ok_result(response.to_string())
}

pub fn call_tool(name: &str, arguments: &serde_json::Value, client: &Client) -> ToolResult {
    match name {
        "frameshift_install" => call_install(arguments, client),
        "frameshift_activate" => call_activate(arguments, client),
        "frameshift_list" => call_list(arguments, client),
        "frameshift_grow_append" => call_grow_append(arguments, client),
        "frameshift_select" => call_select(arguments, client),
        "frameshift_use" => call_use(arguments, client),
        "frameshift_automate" => call_automate(arguments, client),
        "frameshift_prefs" => call_prefs(arguments, client),
        "frameshift_capabilities" => call_capabilities(arguments, client),
        _ => err_result(format!("unknown tool: {}", name)),
    }
}

/// Handle the frameshift_install tool call.
///
/// Parses the spec string, determines the install source (LocalPath or Registry),
/// then invokes client.install and returns the installed name@version.
fn call_install(arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let spec_str = match arguments.get("spec").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: spec".to_string()),
    };

    let project_root_str = match arguments.get("project_root").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: project_root".to_string()),
    };

    let spec = match spec_str.parse::<PersonaSpec>() {
        Ok(s) => s,
        Err(e) => return err_result(format!("invalid spec \"{}\": {}", spec_str, e)),
    };

    let project_root = match validate_path_arg(project_root_str) {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };

    let source = match arguments.get("from_path").and_then(|v| v.as_str()) {
        Some(p) => match validate_path_arg(p) {
            Ok(pb) => InstallSource::LocalPath(pb),
            Err(e) => return err_result(e),
        },
        None => InstallSource::Registry,
    };

    let request = InstallRequest {
        project_root,
        spec: spec.clone(),
        source,
    };

    match client.install(request) {
        Ok(report) => {
            let label = format!("{}@{}", report.persona.name, report.persona.version);
            let text = serde_json::json!({"installed": label}).to_string();
            ok_result(text)
        }
        Err(e) => err_result(format!("install failed: {}", e)),
    }
}

/// Handle the frameshift_activate tool call.
///
/// Writes the active persona marker to the central store.
fn call_activate(arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let persona = match arguments.get("persona").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: persona".to_string()),
    };
    // Validate at the MCP boundary so a traversal name is rejected here with a
    // clear error, mirroring call_grow_append (the client layer also guards it).
    if let Err(e) = frameshift_client::validate_persona_name(persona) {
        return err_result(format!("invalid persona name: {e}"));
    }

    let project_root_str = match arguments.get("project_root").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: project_root".to_string()),
    };

    let project_root = match validate_path_arg(project_root_str) {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };

    match client.activate(&project_root, persona) {
        Ok(()) => {
            // Annotate a soft memory requirement that the project cannot meet;
            // hard requirements already failed activation inside the client.
            let mut response = serde_json::json!({"activated": persona});
            if let Ok(status) = client.memory_requirement_status(&project_root, persona) {
                if status.soft_unmet() {
                    response["memory_warning"] = serde_json::json!(format!(
                        "{persona} works best with a memory adapter (memory_required = \
                         \"soft\") but this project declares none"
                    ));
                }
            }
            ok_result(response.to_string())
        }
        Err(e) => err_result(format!("activate failed: {}", e)),
    }
}

/// Handle the frameshift_list tool call.
///
/// Calls client.sync to get the current list of installed personas.
fn call_list(arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let project_root_str = match arguments.get("project_root").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: project_root".to_string()),
    };

    let project_root = match validate_path_arg(project_root_str) {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };

    match client.sync(&project_root) {
        Ok(report) => {
            let text = serde_json::json!({"personas": report.personas}).to_string();
            ok_result(text)
        }
        Err(e) => err_result(format!("list failed: {}", e)),
    }
}

/// Handle the frameshift_grow_append tool call.
///
/// Resolves the project_id from the client, then delegates to frameshift_growth::append.
fn call_grow_append(arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let project_root_str = match arguments.get("project_root").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: project_root".to_string()),
    };

    let persona = match arguments.get("persona").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: persona".to_string()),
    };
    // Validate at the MCP boundary: grow append joins the name into a growth.md
    // path in the client layer, which does not itself guard this path.
    if let Err(e) = frameshift_client::validate_persona_name(persona) {
        return err_result(format!("invalid persona name: {e}"));
    }

    let text = match arguments.get("text").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: text".to_string()),
    };

    let project_root = match validate_path_arg(project_root_str) {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };

    let project_id = match client.project_id(&project_root) {
        Ok(id) => id,
        Err(e) => return err_result(format!("could not determine project_id: {}", e)),
    };

    match frameshift_growth::append(client.data_root(), &project_id, persona, text) {
        Ok(()) => {
            let response_text = serde_json::json!({"appended": true}).to_string();
            ok_result(response_text)
        }
        Err(e) => err_result(format!("grow append failed: {}", e)),
    }
}

/// Handle the frameshift_select tool call.
///
/// Senses context from `project_root`, indexes installed personas, ranks them,
/// and returns `{ "ranked": [{persona, score, confidence, rationale}] }`.
/// When `library` is provided, ranks from that catalog directory instead of
/// the project-installed personas.
fn call_select(arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let project_root_str = match arguments.get("project_root").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: project_root".to_string()),
    };

    let project_root = match validate_path_arg(project_root_str) {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };
    let task_hint = arguments
        .get("task")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let library = match arguments.get("library").and_then(|v| v.as_str()) {
        Some(p) => match validate_path_arg(p) {
            Ok(pb) => Some(pb),
            Err(e) => return err_result(e),
        },
        None => None,
    };

    // Resolve orchestrator state dir and load preferences.
    let state_dir = match client.orchestrator_state_dir(&project_root) {
        Ok(d) => d,
        Err(e) => return err_result(format!("could not determine state dir: {}", e)),
    };
    let prefs = Preferences::load(&state_dir.join("automate-prefs.json")).unwrap_or_default();

    // When library is given, use catalog_root mode; otherwise installed source dirs.
    let (source_dirs, catalog_root) = if let Some(lib) = library {
        (vec![], Some(lib))
    } else {
        match client.installed_persona_source_dirs(&project_root) {
            Ok(dirs) => (dirs, None),
            Err(e) => return err_result(format!("could not list personas: {}", e)),
        }
    };

    let inputs = SelectionInputs {
        project_root: &project_root,
        task_hint: task_hint.as_deref(),
        source_dirs,
        catalog_root,
        prefs,
        weights: PolicyWeights::default(),
    };

    let ranked = match frameshift_orchestrator::select_with_embedder(&inputs, shared_embedder()) {
        Ok(r) => r,
        Err(e) => return err_result(format!("selection failed: {}", e)),
    };

    let entries: Vec<serde_json::Value> = ranked
        .iter()
        .take(5)
        .map(|s| {
            serde_json::json!({
                "persona": s.persona,
                "score": s.score,
                "confidence": s.confidence,
                "rationale": s.rationale,
            })
        })
        .collect();

    let text = serde_json::json!({ "ranked": entries }).to_string();
    ok_result(text)
}

/// Handle the frameshift_use tool call.
///
/// Activates the named persona and returns `{ "persona": name, "rendered": content }`.
fn call_use(arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let project_root_str = match arguments.get("project_root").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: project_root".to_string()),
    };

    let persona = match arguments.get("persona").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: persona".to_string()),
    };
    // Validate at the MCP boundary, mirroring call_grow_append/call_activate.
    if let Err(e) = frameshift_client::validate_persona_name(persona) {
        return err_result(format!("invalid persona name: {e}"));
    }

    let project_root = match validate_path_arg(project_root_str) {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };

    if let Err(e) = client.activate(&project_root, persona) {
        return err_result(format!("activate failed: {}", e));
    }

    let rendered = match client.rendered_persona(&project_root, persona, "claude") {
        Ok(r) => r,
        Err(e) => return err_result(format!("render failed: {}", e)),
    };

    let mut result = serde_json::json!({ "persona": persona, "rendered": rendered });

    // Best-effort capability annotation: a manifest read/parse failure here must
    // never fail the activation that already succeeded above -- just log it.
    match load_capability_manifest(client, &project_root, Some(persona)) {
        Ok((_, Some(cap))) => {
            let network_egress = cap.network_egress;
            match serde_json::to_value(&cap) {
                Ok(v) => result["capabilities"] = v,
                Err(e) => tracing::warn!(
                    "failed to serialize capability manifest for persona {}: {}",
                    persona,
                    e
                ),
            }
            if network_egress {
                result["capability_notes"] =
                    serde_json::json!(["persona declares network_egress = true"]);
            }
        }
        Ok((_, None)) => {}
        Err(e) => {
            tracing::warn!(
                "failed to load capability manifest for persona {}: {}",
                persona,
                e
            );
        }
    }

    ok_result(result.to_string())
}

/// Handle the frameshift_automate tool call.
///
/// Writes or reads automate-mode state files and returns the resulting mode/status JSON.
fn call_automate(arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let project_root_str = match arguments.get("project_root").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: project_root".to_string()),
    };

    let action = match arguments.get("action").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: action".to_string()),
    };

    let project_root = match validate_path_arg(project_root_str) {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };

    let state_dir = match client.orchestrator_state_dir(&project_root) {
        Ok(d) => d,
        Err(e) => return err_result(format!("could not determine state dir: {}", e)),
    };

    let mode_path = state_dir.join("automate.json");
    let audit_path = state_dir.join("automate-audit.jsonl");
    let lock_path = state_dir.join("automate-lock.json");

    match action {
        "on" => {
            let state = ModeState {
                mode: Mode::On,
                sensitivity: 0.5,
            };
            if let Err(e) = state.save(&mode_path) {
                return err_result(format!("failed to save mode: {}", e));
            }
            ok_result(
                serde_json::json!({ "mode": "on", "sensitivity": state.sensitivity }).to_string(),
            )
        }

        "off" => {
            let state = ModeState {
                mode: Mode::Off,
                sensitivity: 0.5,
            };
            if let Err(e) = state.save(&mode_path) {
                return err_result(format!("failed to save mode: {}", e));
            }
            ok_result(serde_json::json!({ "mode": "off" }).to_string())
        }

        "status" => {
            let mode_state = match ModeState::load(&mode_path) {
                Ok(s) => s,
                Err(e) => return err_result(format!("failed to load mode: {}", e)),
            };

            let paths = match client.project_paths(&project_root) {
                Ok(p) => p,
                Err(e) => return err_result(format!("project_paths failed: {}", e)),
            };
            let active = if paths.active_path.exists() {
                std::fs::read_to_string(&paths.active_path)
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            } else {
                String::new()
            };

            let locked = lock_path.exists();

            let audit = match AuditLog::load(&audit_path) {
                Ok(a) => a,
                Err(e) => return err_result(format!("failed to load audit: {}", e)),
            };
            let recent: Vec<serde_json::Value> = audit
                .recent(5)
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "timestamp": t.timestamp,
                        "from": t.from,
                        "to": t.to,
                        "confidence": t.confidence,
                        "rationale": t.rationale,
                    })
                })
                .collect();

            let text = serde_json::json!({
                "mode": match mode_state.mode { Mode::On => "on", Mode::Off => "off" },
                "active": active,
                "locked": locked,
                "recent_transitions": recent,
            })
            .to_string();
            ok_result(text)
        }

        "lock" => {
            if let Some(parent) = lock_path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    return err_result(format!("failed to create state dir: {}", e));
                }
            }
            let content = serde_json::json!({"locked": true}).to_string();
            if let Err(e) = std::fs::write(&lock_path, content) {
                return err_result(format!("failed to write lock: {}", e));
            }
            ok_result(serde_json::json!({ "locked": true }).to_string())
        }

        "unlock" => {
            if lock_path.exists() {
                if let Err(e) = std::fs::remove_file(&lock_path) {
                    return err_result(format!("failed to remove lock: {}", e));
                }
            }
            ok_result(serde_json::json!({ "locked": false }).to_string())
        }

        other => err_result(format!(
            "unknown action '{}'; expected: on, off, status, lock, unlock",
            other
        )),
    }
}

/// Handle the frameshift_prefs tool call.
///
/// Views or adjusts per-persona preference biases stored in `automate-prefs.json`.
/// Actions: show (list all biases), bump (increase persona bias), decay (decrease
/// persona bias), reset (clear all biases).
fn call_prefs(arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let project_root_str = match arguments.get("project_root").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: project_root".to_string()),
    };

    let action = match arguments.get("action").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: action".to_string()),
    };

    let project_root = match validate_path_arg(project_root_str) {
        Ok(p) => p,
        Err(e) => return err_result(e),
    };

    let state_dir = match client.orchestrator_state_dir(&project_root) {
        Ok(d) => d,
        Err(e) => return err_result(format!("could not determine state dir: {}", e)),
    };

    let prefs_path = state_dir.join("automate-prefs.json");

    match action {
        "show" => {
            let prefs = Preferences::load(&prefs_path).unwrap_or_default();
            let text =
                serde_json::json!({ "bias": prefs.bias, "entries": prefs.entries }).to_string();
            ok_result(text)
        }

        "bump" => {
            let persona = match arguments.get("persona").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return err_result("bump requires 'persona' argument".to_string()),
            };
            let mut prefs = Preferences::load(&prefs_path).unwrap_or_default();
            prefs.record_override(None, persona);
            if let Err(e) = prefs.save(&prefs_path) {
                return err_result(format!("failed to save preferences: {}", e));
            }
            let text = serde_json::json!({
                "persona": persona,
                "bias": prefs.bias_for(persona),
            })
            .to_string();
            ok_result(text)
        }

        "decay" => {
            let persona = match arguments.get("persona").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return err_result("decay requires 'persona' argument".to_string()),
            };
            let mut prefs = Preferences::load(&prefs_path).unwrap_or_default();
            prefs.decay(persona);
            if let Err(e) = prefs.save(&prefs_path) {
                return err_result(format!("failed to save preferences: {}", e));
            }
            let text = serde_json::json!({
                "persona": persona,
                "bias": prefs.bias_for(persona),
            })
            .to_string();
            ok_result(text)
        }

        "reset" => {
            let prefs = Preferences::new();
            if let Err(e) = prefs.save(&prefs_path) {
                return err_result(format!("failed to save preferences: {}", e));
            }
            ok_result(serde_json::json!({ "reset": true }).to_string())
        }

        other => err_result(format!(
            "unknown action '{}'; expected: show, bump, decay, reset",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frameshift_client::{ClientOptions, InstallRequest, InstallSource, PersonaSpec};
    use std::fs;

    /// validate_path_arg accepts clean absolute paths and rejects relative/`..`.
    #[test]
    fn validate_path_arg_guards_traversal() {
        assert!(validate_path_arg("/home/user/project").is_ok());
        assert!(validate_path_arg("relative/path").is_err());
        assert!(validate_path_arg("/home/user/../../etc").is_err());
        assert!(validate_path_arg("..").is_err());
    }

    /// Create a minimal pack directory suitable for install testing.
    fn make_pack_dir(dir: &std::path::Path, name: &str, version: &str) {
        fs::create_dir_all(dir).unwrap();
        let manifest = format!(
            "schema_version = 1\nname = \"{}\"\nversion = \"{}\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n",
            name, version
        );
        fs::write(dir.join("pack.toml"), manifest).unwrap();
        fs::write(
            dir.join("AGENTS.md"),
            format!("# {}\n\nTest content.\n", name),
        )
        .unwrap();
    }

    /// Create a pack directory like `make_pack_dir`, but with a
    /// `[capability_manifest]` table declaring `required_tools = ["Read", "Bash"]`
    /// and `network_egress = false`.
    fn make_pack_dir_with_capabilities(dir: &std::path::Path, name: &str, version: &str) {
        fs::create_dir_all(dir).unwrap();
        let manifest = format!(
            "schema_version = 1\nname = \"{}\"\nversion = \"{}\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n\n[capability_manifest]\nrequired_tools = [\"Read\", \"Bash\"]\nnetwork_egress = false\n",
            name, version
        );
        fs::write(dir.join("pack.toml"), manifest).unwrap();
        fs::write(
            dir.join("AGENTS.md"),
            format!("# {}\n\nTest content.\n", name),
        )
        .unwrap();
    }

    /// Create a Client pointed at a temporary data root with no config overlay.
    fn make_client(data_root: &std::path::Path) -> Client {
        Client::new(ClientOptions {
            data_root: data_root.to_path_buf(),
            config_root: None,
        })
    }

    /// Verify that tool_definitions returns the expected number of tools
    /// (4 original + 4 automate/prefs additions + 1 capabilities).
    #[test]
    fn tool_definitions_returns_nine() {
        let defs = tool_definitions();
        assert_eq!(defs.len(), 9);
    }

    /// Verify that calling an unknown tool name returns an is_error result.
    #[test]
    fn tool_call_unknown_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        let result = call_tool("nonexistent_tool", &serde_json::json!({}), &client);
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].text.contains("unknown tool"));
    }

    /// Verify that frameshift_install succeeds with a local pack path and
    /// returns {"installed": "name@version"}.
    #[test]
    fn tool_call_install_with_local_path() {
        let tmp = tempfile::tempdir().unwrap();
        let pack_dir = tmp.path().join("pack");
        make_pack_dir(&pack_dir, "test", "0.1.0");

        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));

        let args = serde_json::json!({
            "spec": "test@0.1.0",
            "project_root": project_root.to_str().unwrap(),
            "from_path": pack_dir.to_str().unwrap()
        });

        let result = call_tool("frameshift_install", &args, &client);
        assert!(
            result.is_error.is_none(),
            "unexpected error: {:?}",
            result.content[0].text
        );
        assert!(result.content[0].text.contains("test@0.1.0"));
    }

    /// Verify that frameshift_list returns a JSON object with a "personas" array.
    #[test]
    fn tool_call_list_returns_personas() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));

        let args = serde_json::json!({
            "project_root": project_root.to_str().unwrap()
        });

        let result = call_tool("frameshift_list", &args, &client);
        assert!(
            result.is_error.is_none(),
            "unexpected error: {:?}",
            result.content[0].text
        );
        let parsed: serde_json::Value = serde_json::from_str(&result.content[0].text).unwrap();
        assert!(parsed["personas"].is_array());
    }

    /// Verify that frameshift_grow_append returns {"appended": true} after
    /// installing a persona and then appending a growth entry.
    #[test]
    fn tool_call_grow_append_result() {
        let tmp = tempfile::tempdir().unwrap();
        let data_root = tmp.path().join("data");
        let pack_dir = tmp.path().join("pack");
        make_pack_dir(&pack_dir, "growtest", "0.1.0");

        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&data_root);

        // Install first so the growth directory exists.
        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: "growtest".to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();

        let args = serde_json::json!({
            "project_root": project_root.to_str().unwrap(),
            "persona": "growtest",
            "text": "Something learned today."
        });

        let result = call_tool("frameshift_grow_append", &args, &client);
        assert!(
            result.is_error.is_none(),
            "unexpected error: {:?}",
            result.content[0].text
        );
        let parsed: serde_json::Value = serde_json::from_str(&result.content[0].text).unwrap();
        assert_eq!(parsed["appended"], true);
    }

    /// Verify that frameshift_select returns a ranked array (empty for no installed personas).
    #[test]
    fn tool_call_select_returns_ranked() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));

        let args = serde_json::json!({
            "project_root": project_root.to_str().unwrap()
        });

        let result = call_tool("frameshift_select", &args, &client);
        assert!(
            result.is_error.is_none(),
            "unexpected error: {:?}",
            result.content[0].text
        );
        let parsed: serde_json::Value = serde_json::from_str(&result.content[0].text).unwrap();
        assert!(
            parsed["ranked"].is_array(),
            "result must have a 'ranked' array"
        );
    }

    /// Verify that frameshift_automate status returns mode and active fields.
    #[test]
    fn tool_call_automate_status_returns_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));

        let args = serde_json::json!({
            "project_root": project_root.to_str().unwrap(),
            "action": "status"
        });

        let result = call_tool("frameshift_automate", &args, &client);
        assert!(
            result.is_error.is_none(),
            "unexpected error: {:?}",
            result.content[0].text
        );
        let parsed: serde_json::Value = serde_json::from_str(&result.content[0].text).unwrap();
        assert!(parsed["mode"].is_string(), "result must have 'mode' string");
    }

    /// frameshift_prefs show on a fresh project returns an empty bias map.
    #[test]
    fn tool_call_prefs_show_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));

        let result = call_tool(
            "frameshift_prefs",
            &serde_json::json!({
                "project_root": project_root.to_str().unwrap(),
                "action": "show"
            }),
            &client,
        );
        assert!(
            result.is_error.is_none(),
            "unexpected error: {:?}",
            result.content[0].text
        );
        let parsed: serde_json::Value = serde_json::from_str(&result.content[0].text).unwrap();
        assert!(
            parsed["bias"].is_object(),
            "result must have a 'bias' object"
        );
        assert_eq!(
            parsed["bias"].as_object().unwrap().len(),
            0,
            "fresh project must have no recorded biases"
        );
    }

    /// frameshift_prefs bump increases a persona's bias and persists across calls.
    #[test]
    fn tool_call_prefs_bump_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));
        let root_str = project_root.to_str().unwrap();

        // Bump a persona.
        let bump = call_tool(
            "frameshift_prefs",
            &serde_json::json!({
                "project_root": root_str,
                "action": "bump",
                "persona": "rust"
            }),
            &client,
        );
        assert!(
            bump.is_error.is_none(),
            "bump failed: {:?}",
            bump.content[0].text
        );
        let bump_parsed: serde_json::Value = serde_json::from_str(&bump.content[0].text).unwrap();
        let bumped_bias = bump_parsed["bias"].as_f64().unwrap();
        assert!(bumped_bias > 0.0, "bump must produce a positive bias");

        // Show should now reflect the bump.
        let show = call_tool(
            "frameshift_prefs",
            &serde_json::json!({"project_root": root_str, "action": "show"}),
            &client,
        );
        let show_parsed: serde_json::Value = serde_json::from_str(&show.content[0].text).unwrap();
        assert_eq!(
            show_parsed["bias"]["rust"].as_f64().unwrap(),
            bumped_bias,
            "show must report the bumped bias"
        );
    }

    /// frameshift_prefs reset clears every recorded bias.
    #[test]
    fn tool_call_prefs_reset_clears_biases() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));
        let root_str = project_root.to_str().unwrap();

        // Seed a bias.
        call_tool(
            "frameshift_prefs",
            &serde_json::json!({
                "project_root": root_str,
                "action": "bump",
                "persona": "rust"
            }),
            &client,
        );

        // Reset.
        let reset = call_tool(
            "frameshift_prefs",
            &serde_json::json!({"project_root": root_str, "action": "reset"}),
            &client,
        );
        assert!(reset.is_error.is_none());
        let reset_parsed: serde_json::Value = serde_json::from_str(&reset.content[0].text).unwrap();
        assert_eq!(reset_parsed["reset"], true);

        // Show must now be empty.
        let show = call_tool(
            "frameshift_prefs",
            &serde_json::json!({"project_root": root_str, "action": "show"}),
            &client,
        );
        let show_parsed: serde_json::Value = serde_json::from_str(&show.content[0].text).unwrap();
        assert_eq!(
            show_parsed["bias"].as_object().unwrap().len(),
            0,
            "reset must leave an empty bias map"
        );
    }

    /// frameshift_prefs bump without 'persona' argument is an error.
    #[test]
    fn tool_call_prefs_bump_requires_persona() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));

        let result = call_tool(
            "frameshift_prefs",
            &serde_json::json!({
                "project_root": project_root.to_str().unwrap(),
                "action": "bump"
            }),
            &client,
        );
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].text.contains("persona"));
    }

    /// frameshift_select with a `library` argument indexes that catalog
    /// directory instead of the project's installed personas. With a single
    /// pack present the ranked array must be non-empty.
    #[test]
    fn tool_call_select_with_library_indexes_catalog() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        // A "catalog" directory containing one pack.
        let catalog_root = tmp.path().join("catalog");
        let pack_dir = catalog_root.join("cat-persona");
        make_pack_dir(&pack_dir, "cat-persona", "0.1.0");

        let client = make_client(&tmp.path().join("data"));

        let result = call_tool(
            "frameshift_select",
            &serde_json::json!({
                "project_root": project_root.to_str().unwrap(),
                "library": catalog_root.to_str().unwrap()
            }),
            &client,
        );
        assert!(
            result.is_error.is_none(),
            "unexpected error: {:?}",
            result.content[0].text
        );
        let parsed: serde_json::Value = serde_json::from_str(&result.content[0].text).unwrap();
        let ranked = parsed["ranked"]
            .as_array()
            .expect("result must have a 'ranked' array");
        assert!(
            !ranked.is_empty(),
            "library mode must rank at least the one pack present"
        );
        assert!(
            ranked.iter().any(|entry| entry["persona"] == "cat-persona"),
            "ranked list must include the catalog pack"
        );
    }

    /// Verify that frameshift_automate on/off round-trip persists mode.
    #[test]
    fn tool_call_automate_on_off_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));
        let root_str = project_root.to_str().unwrap();

        let on_result = call_tool(
            "frameshift_automate",
            &serde_json::json!({"project_root": root_str, "action": "on"}),
            &client,
        );
        assert!(on_result.is_error.is_none());

        let status = call_tool(
            "frameshift_automate",
            &serde_json::json!({"project_root": root_str, "action": "status"}),
            &client,
        );
        assert!(status.is_error.is_none());
        let parsed: serde_json::Value = serde_json::from_str(&status.content[0].text).unwrap();
        assert_eq!(parsed["mode"], "on");

        // Turn it back off.
        call_tool(
            "frameshift_automate",
            &serde_json::json!({"project_root": root_str, "action": "off"}),
            &client,
        );
        let status2 = call_tool(
            "frameshift_automate",
            &serde_json::json!({"project_root": root_str, "action": "status"}),
            &client,
        );
        let parsed2: serde_json::Value = serde_json::from_str(&status2.content[0].text).unwrap();
        assert_eq!(parsed2["mode"], "off");
    }

    /// frameshift_capabilities reports the active persona's manifest and
    /// annotates a candidate tool list: Read (declared) is allowed, WebFetch
    /// (undeclared) is not, and the manifest's required_tools is echoed back.
    #[test]
    fn tool_call_capabilities_returns_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let data_root = tmp.path().join("data");
        let pack_dir = tmp.path().join("pack");
        make_pack_dir_with_capabilities(&pack_dir, "captest", "0.1.0");

        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&data_root);

        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: "captest".to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();
        client.activate(&project_root, "captest").unwrap();

        let args = serde_json::json!({
            "project_root": project_root.to_str().unwrap(),
            "tools": ["Read", "WebFetch"]
        });
        let result = call_tool("frameshift_capabilities", &args, &client);
        assert!(
            result.is_error.is_none(),
            "unexpected error: {:?}",
            result.content[0].text
        );
        let parsed: serde_json::Value = serde_json::from_str(&result.content[0].text).unwrap();
        assert_eq!(
            parsed["capability_manifest"]["required_tools"],
            serde_json::json!(["Read", "Bash"])
        );
        let tools = parsed["tools"].as_array().unwrap();
        let read = tools.iter().find(|t| t["name"] == "Read").unwrap();
        assert_eq!(read["allowed"], true);
        let web_fetch = tools.iter().find(|t| t["name"] == "WebFetch").unwrap();
        assert_eq!(web_fetch["allowed"], false);
    }

    /// frameshift_capabilities on a persona with no capability manifest
    /// returns a null manifest and a warning, rather than an error.
    #[test]
    fn tool_call_capabilities_no_manifest_warns() {
        let tmp = tempfile::tempdir().unwrap();
        let data_root = tmp.path().join("data");
        let pack_dir = tmp.path().join("pack");
        make_pack_dir(&pack_dir, "plaintest", "0.1.0");

        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&data_root);

        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: "plaintest".to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();
        client.activate(&project_root, "plaintest").unwrap();

        let args = serde_json::json!({
            "project_root": project_root.to_str().unwrap()
        });
        let result = call_tool("frameshift_capabilities", &args, &client);
        assert!(
            result.is_error.is_none(),
            "unexpected error: {:?}",
            result.content[0].text
        );
        let parsed: serde_json::Value = serde_json::from_str(&result.content[0].text).unwrap();
        assert!(parsed["capability_manifest"].is_null());
        assert!(parsed["warning"].is_string());
    }

    /// frameshift_use annotates its result with the activated persona's
    /// capability manifest when one is declared.
    #[test]
    fn tool_call_use_annotates_capabilities() {
        let tmp = tempfile::tempdir().unwrap();
        let data_root = tmp.path().join("data");
        let pack_dir = tmp.path().join("pack");
        make_pack_dir_with_capabilities(&pack_dir, "usecaps", "0.1.0");

        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&data_root);

        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: "usecaps".to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();

        let args = serde_json::json!({
            "project_root": project_root.to_str().unwrap(),
            "persona": "usecaps"
        });
        let result = call_tool("frameshift_use", &args, &client);
        assert!(
            result.is_error.is_none(),
            "unexpected error: {:?}",
            result.content[0].text
        );
        let parsed: serde_json::Value = serde_json::from_str(&result.content[0].text).unwrap();
        assert_eq!(
            parsed["capabilities"]["required_tools"],
            serde_json::json!(["Read", "Bash"])
        );
    }
}
