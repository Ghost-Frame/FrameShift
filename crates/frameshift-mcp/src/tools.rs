/// Tool definitions and dispatch for the Frameshift MCP server.
///
/// Each tool maps directly to a frameshift-client or frameshift-growth operation.
use frameshift_capabilities::{CapabilityFilter, Tool as CapabilityTool};
use frameshift_client::{Client, InstallRequest, InstallSource, PersonaSpec, RegistrySearchQuery};
use frameshift_orchestrator::{
    AuditLog, Embedder, Mode, ModeState, PolicyWeights, Preferences, SelectionInputs,
};
use frameshift_pack::{CapabilityManifest, PackManifest};

use crate::context::{resolve_render_target, validate_absolute_path, with_project_root};
use crate::protocol::{ToolContent, ToolDef, ToolResult};

/// Return the process-wide semantic embedder, loading the model once on first
/// use. A failed load (offline, corrupt cache) is remembered as `None` so
/// repeated `frameshift_select` calls do not retry the download.
#[cfg(feature = "embeddings")]
fn shared_embedder() -> Option<&'static dyn Embedder> {
    use std::sync::OnceLock;
    /// Model wrapped in the persistent embedding cache, so each distinct text
    /// is embedded once per model even across server restarts.
    type Cached = frameshift_orchestrator::CachedEmbedder<frameshift_embed_candle::CandleEmbedder>;
    static EMBEDDER: OnceLock<Option<Cached>> = OnceLock::new();
    EMBEDDER
        .get_or_init(
            || match frameshift_embed_candle::CandleEmbedder::from_hub() {
                Ok(e) => Some(frameshift_orchestrator::CachedEmbedder::new(
                    e,
                    frameshift_embed_candle::default_cache_path(
                        frameshift_embed_candle::DEFAULT_MODEL_ID,
                    ),
                )),
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
                    "project_root": project_root_schema(),
                    "from_path": {"type": "string"}
                },
                "required": ["spec"]
            }),
        },
        ToolDef {
            name: "frameshift_activate".to_string(),
            description: "Mark an installed persona as active for the given project.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "persona": {"type": "string"},
                    "project_root": project_root_schema()
                },
                "required": ["persona"]
            }),
        },
        ToolDef {
            name: "frameshift_list".to_string(),
            description: "List all personas installed for the given project.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": project_root_schema()
                }
            }),
        },
        ToolDef {
            name: "frameshift_grow_append".to_string(),
            description: "Append a growth entry to a persona's growth log for the given project.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": project_root_schema(),
                    "persona": {"type": "string"},
                    "text": {"type": "string"}
                },
                "required": ["persona", "text"]
            }),
        },
        ToolDef {
            name: "frameshift_select".to_string(),
            description: "Rank installed personas for the given project context. Returns a ranked list with score, confidence, and rationale. Read-only; does not change active state. Pass 'library' to rank from a catalog directory instead of installed personas.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": project_root_schema(),
                    "task": {"type": "string"},
                    "library": {"type": "string"}
                }
            }),
        },
        ToolDef {
            name: "frameshift_use".to_string(),
            description: "Activate a persona for the given project and return its rendered content.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": project_root_schema(),
                    "persona": {"type": "string"},
                    "target": render_target_schema()
                },
                "required": ["persona"]
            }),
        },
        ToolDef {
            name: "frameshift_automate".to_string(),
            description: "Manage automate-mode state for a project. Actions: on, off, status, lock, unlock. Enabling Automate stores policy only; the connected host or daemon must invoke selection and activation.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": project_root_schema(),
                    "action": {
                        "type": "string",
                        "enum": ["on", "off", "status", "lock", "unlock"]
                    },
                    "sensitivity": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Optional for action 'on'. 0 is stable and 1 is responsive. Omit it to preserve the project's current setting."
                    }
                },
                "required": ["action"]
            }),
        },
        ToolDef {
            name: "frameshift_capabilities".to_string(),
            description: "Report the resolved persona's declared capability manifest and, when a candidate tool list is given, annotate which of those tools are allowed by it. Advisory only -- never blocks or hides any of this server's own MCP tools (persona `required_tools` names agent-side tools such as Read/Bash, a different namespace).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": project_root_schema(),
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
                "required": []
            }),
        },
        ToolDef {
            name: "frameshift_prefs".to_string(),
            description: "View and adjust per-persona preference biases. Actions: show, bump, decay, reset.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_root": project_root_schema(),
                    "action": {
                        "type": "string",
                        "enum": ["show", "bump", "decay", "reset"]
                    },
                    "persona": {"type": "string"}
                },
                "required": ["action"]
            }),
        },
        ToolDef {
            name: "frameshift_search".to_string(),
            description: "Search the registry's pack catalog by free-text query, optionally restricted to a single tag, and return matching packs with name, latest version, download count, tags, and description. Read-only; does not install anything. Use this to discover packs before calling frameshift_install.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "tag": {
                        "type": "string",
                        "description": "Restrict results to packs carrying this tag."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 20, capped at 100)."
                    }
                },
                "required": ["query"]
            }),
        },
    ]
}

/// Return the shared schema for the optional project context argument.
fn project_root_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "string",
        "description": "Absolute project path. Omit to use FRAMESHIFT_PROJECT_ROOT, Claude Code's CLAUDE_PROJECT_DIR, then the server working directory."
    })
}

/// Return the shared schema for an optional agent render target.
fn render_target_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "string",
        "enum": ["claude", "codex", "gemini", "generic"],
        "description": "Agent output target. Omit to use FRAMESHIFT_TARGET, then generic."
    })
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
    let path = std::path::PathBuf::from(raw);
    validate_absolute_path(&path)
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
        .map_err(|e| format!("project_paths failed: {e}"))?;

    let name = match persona {
        Some(p) => p.to_string(),
        // Marker path goes through the failure-aware resolver so a persona
        // whose last sync failed produces an actionable message instead of a
        // raw missing-pack.toml IO error below.
        None => match client.active_persona_state(project_root) {
            Ok(frameshift_client::ActivePersonaState::Materialized(name)) => name,
            Ok(frameshift_client::ActivePersonaState::Unmaterialized(name)) => {
                return Err(format!(
                    "active persona '{name}' is not materialized (its last sync failed); \
                     run `frameshift sync` to see why, then reinstall or activate another persona"
                ));
            }
            Ok(frameshift_client::ActivePersonaState::None) => {
                return Err("no active persona and no persona specified".to_string());
            }
            Err(e) => return Err(format!("failed to resolve active persona: {e}")),
        },
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
        toml::from_str(&raw).map_err(|e| format!("failed to parse pack manifest: {e}"))?;

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

/// Applies shared project defaults and dispatches one MCP tool invocation.
pub fn call_tool(name: &str, arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let resolved_arguments = if project_scoped_tool(name) {
        match with_project_root(arguments) {
            Ok(resolved) => resolved,
            Err(error) => return err_result(error),
        }
    } else {
        arguments.clone()
    };
    let arguments = &resolved_arguments;

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
        "frameshift_search" => call_search(arguments, client),
        _ => err_result(format!("unknown tool: {name}")),
    }
}

/// Return whether a tool operates on project-scoped Frameshift state.
fn project_scoped_tool(name: &str) -> bool {
    matches!(
        name,
        "frameshift_install"
            | "frameshift_activate"
            | "frameshift_list"
            | "frameshift_grow_append"
            | "frameshift_select"
            | "frameshift_use"
            | "frameshift_automate"
            | "frameshift_capabilities"
            | "frameshift_prefs"
    )
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
        Err(e) => return err_result(format!("invalid spec \"{spec_str}\": {e}")),
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
            // Same additive `failures` shape as `call_list`: OTHER locked
            // personas that could not be materialized during this install.
            let failures: Vec<serde_json::Value> = report
                .materialize_failures
                .iter()
                .map(|f| serde_json::json!({"persona": f.persona, "error": f.error}))
                .collect();
            let text = serde_json::json!({"installed": label, "failures": failures}).to_string();
            ok_result(text)
        }
        Err(e) => err_result(format!("install failed: {e}")),
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
        Err(e) => err_result(format!("activate failed: {e}")),
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
            // `failures` is additive: locked personas that could not be
            // materialized this sync, each with its cause.
            let failures: Vec<serde_json::Value> = report
                .failures
                .iter()
                .map(|f| serde_json::json!({"persona": f.persona, "error": f.error}))
                .collect();
            let text =
                serde_json::json!({"personas": report.personas, "failures": failures}).to_string();
            ok_result(text)
        }
        Err(e) => err_result(format!("list failed: {e}")),
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
        Err(e) => return err_result(format!("could not determine project_id: {e}")),
    };

    match frameshift_growth::append(client.data_root(), &project_id, persona, text) {
        Ok(()) => {
            let response_text = serde_json::json!({"appended": true}).to_string();
            ok_result(response_text)
        }
        Err(e) => err_result(format!("grow append failed: {e}")),
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
        Err(e) => return err_result(format!("could not determine state dir: {e}")),
    };
    let prefs = Preferences::load(&state_dir.join("automate-prefs.json")).unwrap_or_default();

    // When library is given, use catalog_root mode; otherwise installed source dirs.
    let (source_dirs, catalog_root) = if let Some(lib) = library {
        (vec![], Some(lib))
    } else {
        match client.installed_persona_source_dirs(&project_root) {
            Ok(dirs) => (dirs, None),
            Err(e) => return err_result(format!("could not list personas: {e}")),
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
        Err(e) => return err_result(format!("selection failed: {e}")),
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
    let target = match resolve_render_target(arguments) {
        Ok(target) => target,
        Err(error) => return err_result(error),
    };

    if let Err(e) = client.activate(&project_root, persona) {
        return err_result(format!("activate failed: {e}"));
    }

    let rendered = match client.rendered_persona(&project_root, persona, &target) {
        Ok(r) => r,
        Err(e) => return err_result(format!("render failed: {e}")),
    };

    let mut result = serde_json::json!({
        "persona": persona,
        "target": target,
        "rendered": rendered
    });

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
        Err(e) => return err_result(format!("could not determine state dir: {e}")),
    };

    let mode_path = state_dir.join("automate.json");
    let audit_path = state_dir.join("automate-audit.jsonl");
    let lock_path = state_dir.join("automate-lock.json");

    match action {
        "on" => {
            let state = match updated_mode_state(&mode_path, Mode::On, arguments.get("sensitivity"))
            {
                Ok(state) => state,
                Err(error) => return err_result(error),
            };
            if let Err(e) = state.save(&mode_path) {
                return err_result(format!("failed to save mode: {e}"));
            }
            ok_result(
                serde_json::json!({ "mode": "on", "sensitivity": state.sensitivity }).to_string(),
            )
        }

        "off" => {
            let state = match updated_mode_state(&mode_path, Mode::Off, None) {
                Ok(state) => state,
                Err(error) => return err_result(error),
            };
            if let Err(e) = state.save(&mode_path) {
                return err_result(format!("failed to save mode: {e}"));
            }
            ok_result(
                serde_json::json!({ "mode": "off", "sensitivity": state.sensitivity }).to_string(),
            )
        }

        "status" => {
            let mode_state = match ModeState::load(&mode_path) {
                Ok(s) => s,
                Err(e) => return err_result(format!("failed to load mode: {e}")),
            };

            let paths = match client.project_paths(&project_root) {
                Ok(p) => p,
                Err(e) => return err_result(format!("project_paths failed: {e}")),
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
                Err(e) => return err_result(format!("failed to load audit: {e}")),
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
                "sensitivity": mode_state.sensitivity,
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
                    return err_result(format!("failed to create state dir: {e}"));
                }
            }
            let content = serde_json::json!({"locked": true}).to_string();
            if let Err(e) = std::fs::write(&lock_path, content) {
                return err_result(format!("failed to write lock: {e}"));
            }
            ok_result(serde_json::json!({ "locked": true }).to_string())
        }

        "unlock" => {
            if lock_path.exists() {
                if let Err(e) = std::fs::remove_file(&lock_path) {
                    return err_result(format!("failed to remove lock: {e}"));
                }
            }
            ok_result(serde_json::json!({ "locked": false }).to_string())
        }

        other => err_result(format!(
            "unknown action '{other}'; expected: on, off, status, lock, unlock"
        )),
    }
}

/// Load Automate state and change its mode without discarding sensitivity.
fn updated_mode_state(
    mode_path: &std::path::Path,
    mode: Mode,
    requested_sensitivity: Option<&serde_json::Value>,
) -> Result<ModeState, String> {
    let current = ModeState::load(mode_path).map_err(|e| format!("failed to load mode: {e}"))?;
    let sensitivity = match requested_sensitivity {
        Some(value) => value
            .as_f64()
            .ok_or_else(|| "sensitivity must be a number from 0.0 through 1.0".to_string())?,
        None => f64::from(current.sensitivity),
    };

    if !sensitivity.is_finite() || !(0.0..=1.0).contains(&sensitivity) {
        return Err(format!(
            "sensitivity must be a finite number from 0.0 through 1.0, got {sensitivity}"
        ));
    }

    Ok(ModeState {
        mode,
        sensitivity: sensitivity as f32,
    })
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
        Err(e) => return err_result(format!("could not determine state dir: {e}")),
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
                return err_result(format!("failed to save preferences: {e}"));
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
                return err_result(format!("failed to save preferences: {e}"));
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
                return err_result(format!("failed to save preferences: {e}"));
            }
            ok_result(serde_json::json!({ "reset": true }).to_string())
        }

        other => err_result(format!(
            "unknown action '{other}'; expected: show, bump, decay, reset"
        )),
    }
}

/// Default result-page size for `frameshift_search` when the caller omits
/// `limit`. Matches the registry server's own default (see
/// `frameshift_server::routes::packs`) so behavior is consistent whether the
/// caller specifies a limit or not.
const DEFAULT_SEARCH_LIMIT: u32 = 20;

/// Upper bound on `frameshift_search`'s `limit` argument, enforced on the MCP
/// side regardless of what the registry server itself would allow. Keeps a
/// single tool call from flooding the calling agent's context with an
/// unbounded result page.
const MAX_SEARCH_LIMIT: u32 = 100;

/// Resolve the `limit` argument for `frameshift_search` into a validated page
/// size.
///
/// A missing, non-numeric, zero, or negative value falls back to
/// [`DEFAULT_SEARCH_LIMIT`]; any positive value is clamped to
/// `[1, MAX_SEARCH_LIMIT]`.
fn parse_search_limit(arguments: &serde_json::Value) -> u32 {
    arguments
        .get("limit")
        .and_then(|v| v.as_u64())
        .filter(|&n| n > 0)
        .map(|n| n.clamp(1, MAX_SEARCH_LIMIT as u64) as u32)
        .unwrap_or(DEFAULT_SEARCH_LIMIT)
}

/// Resolve the optional `tag` argument for `frameshift_search`.
///
/// Returns `None` when `tag` is absent or not a JSON string, matching how
/// `RegistrySearchQuery::tag` treats "no filter" -- mirrors the CLI's
/// `--tag` flag, which is likewise optional.
fn parse_search_tag(arguments: &serde_json::Value) -> Option<String> {
    arguments
        .get("tag")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Handle the frameshift_search tool call.
///
/// Searches the registry's pack catalog (`GET /v1/packs`) via
/// `client.search_registry`, mirroring the CLI's `frameshift search`
/// subcommand (`frameshift_cli::cmd::search::run_search`), including its
/// optional `--tag` filter. Returns `{ "results": [{name, latest_version,
/// description, tags, total_downloads, score}, ...] }` so MCP-only agents can
/// discover packs before calling `frameshift_install`.
fn call_search(arguments: &serde_json::Value, client: &Client) -> ToolResult {
    let query = match arguments.get("query").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: query".to_string()),
    };

    let limit = parse_search_limit(arguments);
    let tag = parse_search_tag(arguments);

    let search_query = RegistrySearchQuery {
        query: Some(query.to_string()),
        tag,
        limit: Some(limit),
        offset: None,
    };

    match client.search_registry(&search_query) {
        Ok(results) => {
            let entries: Vec<serde_json::Value> = results
                .iter()
                .map(|hit| {
                    serde_json::json!({
                        "name": hit.pack.name,
                        "latest_version": hit.pack.latest_version,
                        "description": hit.pack.description,
                        "tags": hit.pack.tags,
                        "total_downloads": hit.pack.total_downloads,
                        "score": hit.score,
                    })
                })
                .collect();
            ok_result(serde_json::json!({ "results": entries }).to_string())
        }
        Err(e) => err_result(format!("search failed: {e}")),
    }
}

#[cfg(test)]
/// Unit and integration tests for every published MCP tool.
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
            "schema_version = 1\nname = \"{name}\"\nversion = \"{version}\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n"
        );
        fs::write(dir.join("pack.toml"), manifest).unwrap();
        fs::write(
            dir.join("AGENTS.md"),
            format!("# {name}\n\nTest content.\n"),
        )
        .unwrap();
    }

    /// Create a pack directory like `make_pack_dir`, but with a
    /// `[capability_manifest]` table declaring `required_tools = ["Read", "Bash"]`
    /// and `network_egress = false`.
    fn make_pack_dir_with_capabilities(dir: &std::path::Path, name: &str, version: &str) {
        fs::create_dir_all(dir).unwrap();
        let manifest = format!(
            "schema_version = 1\nname = \"{name}\"\nversion = \"{version}\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n\n[capability_manifest]\nrequired_tools = [\"Read\", \"Bash\"]\nnetwork_egress = false\n"
        );
        fs::write(dir.join("pack.toml"), manifest).unwrap();
        fs::write(
            dir.join("AGENTS.md"),
            format!("# {name}\n\nTest content.\n"),
        )
        .unwrap();
    }

    /// Create a Client pointed at a temporary data root with no config overlay.
    fn make_client(data_root: &std::path::Path) -> Client {
        Client::new(ClientOptions {
            data_root: data_root.to_path_buf(),
            config_root: None,
            vault: None,
        })
    }

    /// Verify that tool_definitions returns the expected number of tools
    /// (4 original + 4 automate/prefs additions + 1 capabilities + 1 search).
    #[test]
    fn tool_definitions_returns_ten() {
        let defs = tool_definitions();
        assert_eq!(defs.len(), 10);
    }

    /// Automate advertises an optional sensitivity constrained to the public range.
    #[test]
    fn tool_definitions_constrain_automate_sensitivity() {
        let definitions = tool_definitions();
        let automate = definitions
            .iter()
            .find(|definition| definition.name == "frameshift_automate")
            .expect("tool_definitions must include frameshift_automate");
        let sensitivity = &automate.input_schema["properties"]["sensitivity"];

        assert_eq!(sensitivity["type"], "number");
        assert_eq!(sensitivity["minimum"], 0.0);
        assert_eq!(sensitivity["maximum"], 1.0);
    }

    /// frameshift_search is present in tool_definitions with `query` required
    /// and `limit`/`tag` present but optional in its input schema, matching
    /// the CLI's `frameshift search --tag` surface.
    #[test]
    fn tool_definitions_includes_search() {
        let defs = tool_definitions();
        let search = defs
            .iter()
            .find(|d| d.name == "frameshift_search")
            .expect("tool_definitions must include frameshift_search");

        let required = search.input_schema["required"]
            .as_array()
            .expect("input_schema.required must be an array");
        assert!(
            required.iter().any(|v| v == "query"),
            "query must be a required argument"
        );
        assert!(
            !required.iter().any(|v| v == "limit"),
            "limit must not be required"
        );
        assert!(
            !required.iter().any(|v| v == "tag"),
            "tag must not be required"
        );
        assert!(
            search.input_schema["properties"]["limit"].is_object(),
            "limit must be a declared property"
        );
        assert!(
            search.input_schema["properties"]["tag"].is_object(),
            "tag must be a declared property"
        );
    }

    /// Project-scoped tool schemas expose project_root as an optional default
    /// and frameshift_use advertises every supported render target.
    #[test]
    fn tool_definitions_expose_project_and_target_defaults() {
        let definitions = tool_definitions();
        for definition in definitions
            .iter()
            .filter(|definition| project_scoped_tool(&definition.name))
        {
            let required = definition.input_schema["required"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            assert!(
                !required.iter().any(|value| value == "project_root"),
                "{} must allow the server project default",
                definition.name
            );
        }

        let use_tool = definitions
            .iter()
            .find(|definition| definition.name == "frameshift_use")
            .unwrap();
        assert_eq!(
            use_tool.input_schema["properties"]["target"]["enum"],
            serde_json::json!(["claude", "codex", "gemini", "generic"])
        );
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

    /// Verify that Automate mode toggles preserve an explicit sensitivity.
    #[test]
    fn tool_call_automate_on_off_preserves_sensitivity() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));
        let root_str = project_root.to_str().unwrap();

        let on_result = call_tool(
            "frameshift_automate",
            &serde_json::json!({
                "project_root": root_str,
                "action": "on",
                "sensitivity": 0.8
            }),
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
        assert!((parsed["sensitivity"].as_f64().unwrap() - 0.8).abs() < 1e-6);

        // Turn it back off.
        let off_result = call_tool(
            "frameshift_automate",
            &serde_json::json!({"project_root": root_str, "action": "off"}),
            &client,
        );
        assert!(off_result.is_error.is_none());
        let status2 = call_tool(
            "frameshift_automate",
            &serde_json::json!({"project_root": root_str, "action": "status"}),
            &client,
        );
        let parsed2: serde_json::Value = serde_json::from_str(&status2.content[0].text).unwrap();
        assert_eq!(parsed2["mode"], "off");
        assert!((parsed2["sensitivity"].as_f64().unwrap() - 0.8).abs() < 1e-6);

        // Turn it back on without a value and preserve the prior policy again.
        let on_again = call_tool(
            "frameshift_automate",
            &serde_json::json!({"project_root": root_str, "action": "on"}),
            &client,
        );
        assert!(on_again.is_error.is_none());
        let parsed3: serde_json::Value = serde_json::from_str(&on_again.content[0].text).unwrap();
        assert_eq!(parsed3["mode"], "on");
        assert!((parsed3["sensitivity"].as_f64().unwrap() - 0.8).abs() < 1e-6);
    }

    /// Verify that Automate rejects malformed and out-of-range sensitivities.
    #[test]
    fn tool_call_automate_rejects_invalid_sensitivity() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));
        let root_str = project_root.to_str().unwrap();

        for invalid in [
            serde_json::json!(-0.1),
            serde_json::json!(1.1),
            serde_json::json!("responsive"),
        ] {
            let result = call_tool(
                "frameshift_automate",
                &serde_json::json!({
                    "project_root": root_str,
                    "action": "on",
                    "sensitivity": invalid
                }),
                &client,
            );

            assert!(result.is_error.is_some());
        }
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
        assert_eq!(parsed["target"], "generic");
        assert_eq!(
            parsed["capabilities"]["required_tools"],
            serde_json::json!(["Read", "Bash"])
        );
    }

    /// frameshift_use rejects an unknown render target before activation.
    #[test]
    fn tool_call_use_rejects_unknown_render_target() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();
        let client = make_client(&tmp.path().join("data"));

        let result = call_tool(
            "frameshift_use",
            &serde_json::json!({
                "project_root": project_root,
                "persona": "missing",
                "target": "unknown-agent"
            }),
            &client,
        );
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].text.contains("invalid render target"));
    }

    /// frameshift_search rejects a call with no `query` argument, without
    /// ever reaching the network (call_search must validate before dispatch).
    #[test]
    fn tool_call_search_requires_query() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());

        let result = call_tool("frameshift_search", &serde_json::json!({}), &client);
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].text.contains("query"));
    }

    /// parse_search_limit falls back to DEFAULT_SEARCH_LIMIT when `limit` is
    /// absent, non-numeric, zero, or negative.
    #[test]
    fn parse_search_limit_defaults_on_missing_or_invalid() {
        assert_eq!(
            parse_search_limit(&serde_json::json!({})),
            DEFAULT_SEARCH_LIMIT
        );
        assert_eq!(
            parse_search_limit(&serde_json::json!({"limit": "not a number"})),
            DEFAULT_SEARCH_LIMIT
        );
        assert_eq!(
            parse_search_limit(&serde_json::json!({"limit": 0})),
            DEFAULT_SEARCH_LIMIT
        );
        assert_eq!(
            parse_search_limit(&serde_json::json!({"limit": -5})),
            DEFAULT_SEARCH_LIMIT
        );
    }

    /// parse_search_limit passes through an in-range positive value and
    /// clamps one above MAX_SEARCH_LIMIT down to the cap.
    #[test]
    fn parse_search_limit_clamps_to_range() {
        assert_eq!(parse_search_limit(&serde_json::json!({"limit": 5})), 5);
        assert_eq!(
            parse_search_limit(&serde_json::json!({"limit": MAX_SEARCH_LIMIT})),
            MAX_SEARCH_LIMIT
        );
        assert_eq!(
            parse_search_limit(&serde_json::json!({"limit": MAX_SEARCH_LIMIT as u64 + 1000})),
            MAX_SEARCH_LIMIT
        );
    }

    /// parse_search_tag returns `None` when `tag` is absent or not a string,
    /// and `Some(_)` with the string value when present.
    #[test]
    fn parse_search_tag_extracts_optional_string() {
        assert_eq!(parse_search_tag(&serde_json::json!({})), None);
        assert_eq!(parse_search_tag(&serde_json::json!({"tag": 5})), None);
        assert_eq!(
            parse_search_tag(&serde_json::json!({"tag": "rust"})),
            Some("rust".to_string())
        );
    }
}
