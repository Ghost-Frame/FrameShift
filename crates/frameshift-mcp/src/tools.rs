/// Tool definitions and dispatch for the Frameshift MCP server.
///
/// Each tool maps directly to a frameshift-client or frameshift-growth operation.
use frameshift_client::{Client, InstallRequest, InstallSource, PersonaSpec};
use frameshift_orchestrator::{
    AuditLog, Mode, ModeState, PolicyWeights, Preferences, SelectionInputs,
};

use crate::protocol::{ToolContent, ToolDef, ToolResult};

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

    let project_root = std::path::PathBuf::from(project_root_str);

    let source = match arguments.get("from_path").and_then(|v| v.as_str()) {
        Some(p) => InstallSource::LocalPath(std::path::PathBuf::from(p)),
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

    let project_root_str = match arguments.get("project_root").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: project_root".to_string()),
    };

    let project_root = std::path::PathBuf::from(project_root_str);

    match client.activate(&project_root, persona) {
        Ok(()) => {
            let text = serde_json::json!({"activated": persona}).to_string();
            ok_result(text)
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

    let project_root = std::path::PathBuf::from(project_root_str);

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

    let text = match arguments.get("text").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_result("missing required argument: text".to_string()),
    };

    let project_root = std::path::PathBuf::from(project_root_str);

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

    let project_root = std::path::PathBuf::from(project_root_str);
    let task_hint = arguments
        .get("task")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let library = arguments
        .get("library")
        .and_then(|v| v.as_str())
        .map(std::path::PathBuf::from);

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

    let ranked = match frameshift_orchestrator::select(&inputs) {
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

    let project_root = std::path::PathBuf::from(project_root_str);

    if let Err(e) = client.activate(&project_root, persona) {
        return err_result(format!("activate failed: {}", e));
    }

    let rendered = match client.rendered_persona(&project_root, persona, "claude") {
        Ok(r) => r,
        Err(e) => return err_result(format!("render failed: {}", e)),
    };

    let text = serde_json::json!({ "persona": persona, "rendered": rendered }).to_string();
    ok_result(text)
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

    let project_root = std::path::PathBuf::from(project_root_str);

    let state_dir = match client.orchestrator_state_dir(&project_root) {
        Ok(d) => d,
        Err(e) => return err_result(format!("could not determine state dir: {}", e)),
    };

    let mode_path = state_dir.join("automate.json");
    let audit_path = state_dir.join("automate-audit.jsonl");
    let lock_path = state_dir.join("automate-lock.json");

    match action {
        "on" => {
            let state = ModeState { mode: Mode::On };
            if let Err(e) = state.save(&mode_path) {
                return err_result(format!("failed to save mode: {}", e));
            }
            ok_result(serde_json::json!({ "mode": "on" }).to_string())
        }

        "off" => {
            let state = ModeState { mode: Mode::Off };
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

    let project_root = std::path::PathBuf::from(project_root_str);

    let state_dir = match client.orchestrator_state_dir(&project_root) {
        Ok(d) => d,
        Err(e) => return err_result(format!("could not determine state dir: {}", e)),
    };

    let prefs_path = state_dir.join("automate-prefs.json");

    match action {
        "show" => {
            let prefs = Preferences::load(&prefs_path).unwrap_or_default();
            let text = serde_json::json!({ "bias": prefs.bias }).to_string();
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
            prefs.record_override(Some(persona), "__manual_decay__");
            prefs.bias.remove("__manual_decay__");
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

    /// Create a minimal pack directory suitable for install testing.
    fn make_pack_dir(dir: &std::path::Path, name: &str, version: &str) {
        fs::create_dir_all(dir).unwrap();
        let manifest = format!(
            "schema_version = 1\nname = \"{}\"\nversion = \"{}\"\nauthor_handle = \"test\"\nauthor_pubkey = \"local-unsigned\"\n",
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

    /// Verify that tool_definitions returns the expected number of tools (4 original + 4 new).
    #[test]
    fn tool_definitions_returns_eight() {
        let defs = tool_definitions();
        assert_eq!(defs.len(), 8);
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
        assert!(parsed["bias"].is_object(), "result must have a 'bias' object");
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
        assert!(bump.is_error.is_none(), "bump failed: {:?}", bump.content[0].text);
        let bump_parsed: serde_json::Value =
            serde_json::from_str(&bump.content[0].text).unwrap();
        let bumped_bias = bump_parsed["bias"].as_f64().unwrap();
        assert!(bumped_bias > 0.0, "bump must produce a positive bias");

        // Show should now reflect the bump.
        let show = call_tool(
            "frameshift_prefs",
            &serde_json::json!({"project_root": root_str, "action": "show"}),
            &client,
        );
        let show_parsed: serde_json::Value =
            serde_json::from_str(&show.content[0].text).unwrap();
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
        let reset_parsed: serde_json::Value =
            serde_json::from_str(&reset.content[0].text).unwrap();
        assert_eq!(reset_parsed["reset"], true);

        // Show must now be empty.
        let show = call_tool(
            "frameshift_prefs",
            &serde_json::json!({"project_root": root_str, "action": "show"}),
            &client,
        );
        let show_parsed: serde_json::Value =
            serde_json::from_str(&show.content[0].text).unwrap();
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
}
