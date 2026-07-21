//! MCP prompt definitions and dispatch.
//!
//! Prompts are the universal "surface Frameshift in any MCP-capable agent"
//! mechanism: clients render them as user-invocable commands (slash commands
//! in Claude Code / Gemini / Cline / opencode / Goose / etc., quick-actions
//! in IDE plugins) and call `prompts/get` to materialize the rendered text
//! into the conversation.
//!
//! No agent-specific knowledge lives here -- every MCP-speaking agent that
//! implements the protocol surfaces these the same way.

use std::path::{Path, PathBuf};

use frameshift_client::Client;
use frameshift_orchestrator::{feedback::Preferences, policy::PolicyWeights, run::SelectionInputs};

use crate::context::{resolve_render_target, validate_absolute_path, with_project_root};
use crate::protocol::{PromptArgDef, PromptContent, PromptDef, PromptMessage, PromptResult};

/// Return the static list of prompts this server publishes.
///
/// Mirrors the `tools::tool_definitions` pattern. Stable ordering for
/// deterministic test output.
pub fn prompt_definitions() -> Vec<PromptDef> {
    vec![
        PromptDef {
            name: "active_persona".to_string(),
            description: "Insert the project's active Frameshift persona into the conversation. \
                 Use this at session start to load the persona without any hook glue."
                .to_string(),
            arguments: vec![
                project_root_argument(),
                PromptArgDef {
                    name: "target".to_string(),
                    description: "Optional agent output target: claude, codex, gemini, or generic. Defaults to FRAMESHIFT_TARGET, then generic.".to_string(),
                    required: false,
                },
            ],
        },
        PromptDef {
            name: "select_persona".to_string(),
            description: "Rank Frameshift personas for the current project context and return the \
                 top candidates with score, confidence, and rationale. Activate the chosen \
                 one with the `frameshift_use` tool."
                .to_string(),
            arguments: vec![
                project_root_argument(),
                PromptArgDef {
                    name: "task".to_string(),
                    description: "Optional one-line description of the task to steer the ranker."
                        .to_string(),
                    required: false,
                },
                PromptArgDef {
                    name: "library".to_string(),
                    description: "Optional path to a persona library directory to rank from \
                         instead of the project-installed personas."
                        .to_string(),
                    required: false,
                },
            ],
        },
        PromptDef {
            name: "automate_status".to_string(),
            description: "Report Frameshift automate-mode state for this project: mode (On/Off), \
                 active persona, and recent persona transitions from the audit log."
                .to_string(),
            arguments: vec![project_root_argument()],
        },
    ]
}

/// Build the optional project argument shared by every Frameshift prompt.
fn project_root_argument() -> PromptArgDef {
    PromptArgDef {
        name: "project_root".to_string(),
        description: "Absolute project path. Omit to use FRAMESHIFT_PROJECT_ROOT, Claude Code's CLAUDE_PROJECT_DIR, then the server working directory.".to_string(),
        required: false,
    }
}

/// Dispatch a `prompts/get` invocation to the appropriate prompt handler.
///
/// Returns `Ok(PromptResult)` on success and `Err(message)` on application
/// errors. The caller (the main dispatcher in `main.rs`) translates `Err` to
/// a JSON-RPC error response.
pub fn call_prompt(
    name: &str,
    arguments: &serde_json::Value,
    client: &Client,
) -> Result<PromptResult, String> {
    let resolved_arguments = if known_prompt(name) {
        with_project_root(arguments)?
    } else {
        arguments.clone()
    };
    let arguments = &resolved_arguments;

    match name {
        "active_persona" => call_active_persona(arguments, client),
        "select_persona" => call_select_persona(arguments, client),
        "automate_status" => call_automate_status(arguments, client),
        _ => Err(format!("unknown prompt: {name}")),
    }
}

/// Return whether a name identifies one of this server's project-scoped prompts.
fn known_prompt(name: &str) -> bool {
    matches!(
        name,
        "active_persona" | "select_persona" | "automate_status"
    )
}

/// Handle the `active_persona` prompt.
///
/// Reads the per-project `active` marker, then renders the named persona for
/// the resolved agent target and returns it as a single user-role message. When no
/// persona is active for the project, returns a hint pointing at the
/// `select_persona` prompt instead of erroring.
fn call_active_persona(
    arguments: &serde_json::Value,
    client: &Client,
) -> Result<PromptResult, String> {
    let project_root = get_required_path(arguments, "project_root")?;
    let target = resolve_render_target(arguments)?;

    // Failure-aware resolution: a persona can be active-by-marker while its
    // materialized content is gone (its last sync failed and the half-built
    // dir was cleaned). Surface that as guidance, not a raw render error.
    let active_name = match client
        .active_persona_state(&project_root)
        .map_err(|e| format!("could not resolve active persona: {e}"))?
    {
        frameshift_client::ActivePersonaState::Materialized(name) => name,
        frameshift_client::ActivePersonaState::Unmaterialized(name) => {
            return Ok(text_message_result(
                None,
                format!(
                    "The active Frameshift persona '{name}' is not materialized: its last \
                     sync failed. Run `frameshift sync` to see why, then reinstall it or \
                     activate another persona via the `frameshift_use` tool."
                ),
            ));
        }
        frameshift_client::ActivePersonaState::None => {
            return Ok(text_message_result(
                None,
                "No Frameshift persona is active for this project. \
                 Invoke the `select_persona` prompt to choose one, then activate \
                 it via the `frameshift_use` tool."
                    .to_string(),
            ));
        }
    };

    let rendered = client
        .rendered_persona(&project_root, &active_name, &target)
        .map_err(|e| format!("could not read rendered persona '{active_name}': {e}"))?;

    Ok(text_message_result(
        Some(format!(
            "Active Frameshift persona: {active_name} ({target})"
        )),
        rendered,
    ))
}

/// Handle the `select_persona` prompt.
///
/// Runs `orchestrator::select` over installed personas (or a catalog
/// directory when `library` is given) and returns the top five candidates
/// with score, confidence, and rationale as a single user-role message. The
/// message instructs the model to invoke `frameshift_use` to activate the
/// chosen persona.
fn call_select_persona(
    arguments: &serde_json::Value,
    client: &Client,
) -> Result<PromptResult, String> {
    let project_root = get_required_path(arguments, "project_root")?;

    let task_hint = arguments
        .get("task")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let catalog_root = arguments
        .get("library")
        .map(|_| get_required_path(arguments, "library"))
        .transpose()?;

    let state_dir = client
        .orchestrator_state_dir(&project_root)
        .map_err(|e| format!("could not determine state dir: {e}"))?;
    let prefs = Preferences::load(&state_dir.join("automate-prefs.json")).unwrap_or_default();

    let source_dirs = if catalog_root.is_some() {
        Vec::new()
    } else {
        client
            .installed_persona_source_dirs(&project_root)
            .map_err(|e| format!("could not list personas: {e}"))?
    };

    let inputs = SelectionInputs {
        project_root: &project_root,
        task_hint: task_hint.as_deref(),
        source_dirs,
        catalog_root,
        prefs,
        weights: PolicyWeights::default(),
    };

    let ranked =
        frameshift_orchestrator::select(&inputs).map_err(|e| format!("selection failed: {e}"))?;

    if ranked.is_empty() {
        return Ok(text_message_result(
            None,
            "No Frameshift personas are available to rank for this project. \
             Install personas first via `frameshift_install` or provide a \
             `library` argument."
                .to_string(),
        ));
    }

    let mut body = String::from(
        "Frameshift selection ranked the following personas for this context. \
         Pick the best match and call the `frameshift_use` tool with the \
         persona name to activate it.\n\n",
    );
    body.push_str("| persona | score | confidence | rationale |\n");
    body.push_str("|---|---|---|---|\n");
    for entry in ranked.iter().take(5) {
        body.push_str(&format!(
            "| {} | {:.3} | {:.3} | {} |\n",
            entry.persona, entry.score, entry.confidence, entry.rationale
        ));
    }

    Ok(text_message_result(
        Some("Frameshift persona ranking".to_string()),
        body,
    ))
}

/// Handle the `automate_status` prompt.
///
/// Reads `automate.json`, the `active` marker, and the last few entries of
/// `automate-audit.jsonl` for the project. Returns a compact summary as a
/// single user-role message.
fn call_automate_status(
    arguments: &serde_json::Value,
    client: &Client,
) -> Result<PromptResult, String> {
    let project_root = get_required_path(arguments, "project_root")?;

    let state_dir = client
        .orchestrator_state_dir(&project_root)
        .map_err(|e| format!("could not determine state dir: {e}"))?;

    // Mode: present from automate.json if it exists, else implicitly Off.
    let mode_path = state_dir.join("automate.json");
    let mode = if mode_path.exists() {
        match std::fs::read_to_string(&mode_path) {
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(v) => v
                    .get("mode")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                Err(_) => "unknown".to_string(),
            },
            Err(_) => "unknown".to_string(),
        }
    } else {
        "off".to_string()
    };

    // Active persona name from the project's active marker.
    let paths = client
        .project_paths(&project_root)
        .map_err(|e| format!("could not resolve project paths: {e}"))?;
    let active = if paths.active_path.exists() {
        std::fs::read_to_string(&paths.active_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    // Recent audit transitions: last three lines of audit jsonl.
    let audit_path = state_dir.join("automate-audit.jsonl");
    let mut recent: Vec<String> = Vec::new();
    if audit_path.exists() {
        if let Ok(raw) = std::fs::read_to_string(&audit_path) {
            for line in raw.lines().rev().take(3) {
                recent.push(line.to_string());
            }
            recent.reverse();
        }
    }

    let mut body = String::new();
    body.push_str(&format!("mode: {mode}\n"));
    if active.is_empty() {
        body.push_str("active persona: (none)\n");
    } else {
        body.push_str(&format!("active persona: {active}\n"));
    }
    if recent.is_empty() {
        body.push_str("recent transitions: none\n");
    } else {
        body.push_str("recent transitions:\n");
        for line in recent {
            body.push_str(&format!("  {line}\n"));
        }
    }

    Ok(text_message_result(
        Some("Frameshift automate status".to_string()),
        body,
    ))
}

/// Extract a required string argument and convert it to a PathBuf.
fn get_required_path(arguments: &serde_json::Value, key: &str) -> Result<PathBuf, String> {
    let s = arguments
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing required argument: {key}"))?;
    let path = PathBuf::from(s);
    validate_absolute_path(&path)
}

/// Build a one-message PromptResult containing a user-role text block.
///
/// The `user` role is intentional: rendered Frameshift content steers the
/// agent's next turn as if the user had pasted it. Some clients distinguish
/// `system` from `user` for prompt content; `user` is the spec-compliant
/// default and works in every conforming client.
fn text_message_result(description: Option<String>, text: String) -> PromptResult {
    PromptResult {
        description,
        messages: vec![PromptMessage {
            role: "user".to_string(),
            content: PromptContent {
                content_type: "text".to_string(),
                text,
            },
        }],
    }
}

/// Path-only access helper kept here so the prompts module is self-contained.
///
/// Used in tests; not exported from the crate.
#[allow(dead_code)]
fn project_root_arg_from_path(p: &Path) -> serde_json::Value {
    serde_json::json!({ "project_root": p.to_str().unwrap() })
}

#[cfg(test)]
/// Unit tests for MCP prompt schemas, path guards, and rendered responses.
mod tests {
    use super::*;
    use frameshift_client::{Client, ClientOptions, InstallRequest, InstallSource, PersonaSpec};
    use std::fs;

    /// Build a Client backed by a temporary data root.
    fn make_client(data_root: &Path) -> Client {
        Client::new(ClientOptions {
            data_root: data_root.to_path_buf(),
            config_root: None,
            vault: None,
        })
    }

    /// Install a minimal persona into a temp project and return (client, project_root).
    fn install_minimal_persona(tmp: &tempfile::TempDir, name: &str) -> (Client, PathBuf) {
        let pack_dir = tmp.path().join(format!("pack-{name}"));
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(
            pack_dir.join("pack.toml"),
            format!(
                "schema_version = 1\nname = \"{name}\"\nversion = \"0.1.0\"\n\
                 author_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n"
            ),
        )
        .unwrap();
        fs::write(
            pack_dir.join("AGENTS.md"),
            format!("# {name}\n\nRust code. cargo clippy rustc.\n"),
        )
        .unwrap();

        let project_root = tmp.path().join(format!("project-{name}"));
        fs::create_dir_all(&project_root).unwrap();

        let client = make_client(&tmp.path().join("data"));
        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: name.to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();
        (client, project_root)
    }

    /// prompt_definitions returns the three expected prompts in stable order.
    #[test]
    fn prompt_definitions_lists_expected_prompts() {
        let defs = prompt_definitions();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["active_persona", "select_persona", "automate_status"]
        );
    }

    /// Every prompt declares project_root as an optional defaultable argument.
    #[test]
    fn every_prompt_defaults_project_root() {
        for def in prompt_definitions() {
            let arg = def
                .arguments
                .iter()
                .find(|a| a.name == "project_root")
                .unwrap_or_else(|| panic!("{}: missing project_root", def.name));
            assert!(!arg.required, "{}: project_root must be optional", def.name);
        }
    }

    /// call_prompt with an unknown name returns an error.
    #[test]
    fn unknown_prompt_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        let err = call_prompt("nonexistent", &serde_json::json!({}), &client).unwrap_err();
        assert!(err.contains("unknown prompt"));
    }

    /// active_persona returns a hint when no persona is active.
    #[test]
    fn active_persona_hints_when_no_active() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();
        let client = make_client(&tmp.path().join("data"));

        let result = call_prompt(
            "active_persona",
            &project_root_arg_from_path(&project_root),
            &client,
        )
        .unwrap();
        assert_eq!(result.messages.len(), 1);
        let text = &result.messages[0].content.text;
        assert!(
            text.contains("No Frameshift persona is active"),
            "expected hint text, got: {text}"
        );
    }

    /// active_persona returns the rendered body after activate.
    #[test]
    fn active_persona_returns_rendered_after_activate() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_minimal_persona(&tmp, "rusty");
        client.activate(&project_root, "rusty").unwrap();

        let result = call_prompt(
            "active_persona",
            &project_root_arg_from_path(&project_root),
            &client,
        )
        .unwrap();
        let text = &result.messages[0].content.text;
        assert!(
            text.contains("rusty") || text.contains("Rusty") || text.contains("cargo"),
            "expected persona body content, got: {text}"
        );
        assert_eq!(result.messages[0].role, "user");
    }

    /// select_persona returns ranked candidates as a table.
    #[test]
    fn select_persona_returns_ranked_table() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_minimal_persona(&tmp, "rusty");

        let args = serde_json::json!({
            "project_root": project_root.to_str().unwrap(),
            "task": "fix a clippy warning"
        });
        let result = call_prompt("select_persona", &args, &client).unwrap();
        let text = &result.messages[0].content.text;
        assert!(text.contains("rusty"), "expected ranked entry, got: {text}");
        assert!(text.contains("|"), "expected markdown table delimiters");
    }

    /// select_persona empty-personas returns a graceful hint.
    #[test]
    fn select_persona_hints_when_no_personas() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();
        let client = make_client(&tmp.path().join("data"));

        let result = call_prompt(
            "select_persona",
            &project_root_arg_from_path(&project_root),
            &client,
        )
        .unwrap();
        let text = &result.messages[0].content.text;
        assert!(
            text.contains("No Frameshift personas are available"),
            "expected empty-personas hint, got: {text}"
        );
    }

    /// automate_status reports mode "off" when no automate.json exists.
    #[test]
    fn automate_status_reports_off_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_minimal_persona(&tmp, "rusty");

        let result = call_prompt(
            "automate_status",
            &project_root_arg_from_path(&project_root),
            &client,
        )
        .unwrap();
        let text = &result.messages[0].content.text;
        assert!(
            text.contains("mode: off"),
            "expected mode: off, got: {text}"
        );
    }

    /// All prompts accept an omitted project root by using the process working directory.
    #[test]
    fn missing_project_root_uses_working_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let client = make_client(tmp.path());
        for name in ["active_persona", "select_persona", "automate_status"] {
            assert!(
                call_prompt(name, &serde_json::json!({}), &client).is_ok(),
                "{name}: omitted project_root should resolve from server context"
            );
        }
    }

    /// select_persona applies the filesystem boundary guard to its optional library.
    #[test]
    fn select_persona_rejects_unsafe_library_path() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();
        let client = make_client(&tmp.path().join("data"));
        let args = serde_json::json!({
            "project_root": project_root,
            "library": "/tmp/../etc"
        });

        let error = call_prompt("select_persona", &args, &client).unwrap_err();
        assert!(error.contains("must not contain '..'"), "got: {error}");
    }
}
