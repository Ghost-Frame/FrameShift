//! Method dispatch for the JSON-RPC daemon.
//!
//! Each handler receives the optional params object and a reference to the
//! shared `Client`, performs the requested operation, and returns either a
//! JSON result value or a `(code, message)` error tuple that maps directly
//! to a JSON-RPC error response.

use frameshift_client::{Client, InstallRequest, InstallSource, PersonaSpec};
use serde_json::Value;
use std::path::{Component, PathBuf};

/// Dispatch a JSON-RPC method call to the appropriate handler function.
///
/// Returns `Ok(Value)` on success or `Err((code, message))` on failure.
/// The error code should be one of the JSON-RPC standard codes defined in
/// `crate::protocol`.
pub fn dispatch(
    method: &str,
    params: Option<Value>,
    client: &Client,
) -> Result<Value, (i32, String)> {
    match method {
        "project_id" => handle_project_id(params, client),
        "install" => handle_install(params, client),
        "activate" => handle_activate(params, client),
        "sync" => handle_sync(params, client),
        "gc" => handle_gc(params, client),
        "grow.append" => handle_grow_append(params, client),
        "shutdown" => Ok(serde_json::json!({"shutting_down": true})),
        _ => Err((
            crate::protocol::METHOD_NOT_FOUND,
            format!("unknown method: {method}"),
        )),
    }
}

/// Handle the `project_id` method.
///
/// Params: `{ "project_root": "<path>" }`
/// Returns: `{ "project_id": "<hex-id>" }`
fn handle_project_id(params: Option<Value>, client: &Client) -> Result<Value, (i32, String)> {
    let root = get_path(&params, "project_root")?;
    let project_id = client
        .project_id(&root)
        .map_err(|e| (crate::protocol::INTERNAL_ERROR, e.to_string()))?;
    Ok(serde_json::json!({ "project_id": project_id }))
}

/// Handle the `install` method.
///
/// Params: `{ "spec": "<name>@<version>", "project_root": "<path>", "from_path": "<optional-pack-dir>" }`
/// Returns: `{ "persona": "<name>", "version": "<ver>", "hash": "<hex>" }`
fn handle_install(params: Option<Value>, client: &Client) -> Result<Value, (i32, String)> {
    let spec_str = get_str(&params, "spec")?;
    let root = get_path(&params, "project_root")?;

    let spec: PersonaSpec = spec_str
        .parse()
        .map_err(|e: frameshift_client::ClientError| {
            (crate::protocol::INVALID_PARAMS, e.to_string())
        })?;

    let source = if let Some(from_path) = params
        .as_ref()
        .and_then(|p| p.get("from_path"))
        .and_then(|v| v.as_str())
    {
        InstallSource::LocalPath(validate_path_arg(from_path, "from_path")?)
    } else {
        InstallSource::Registry
    };

    let report = client
        .install(InstallRequest {
            project_root: root,
            spec,
            source,
        })
        .map_err(|e| (crate::protocol::INTERNAL_ERROR, e.to_string()))?;

    // Same additive `failures` shape as `handle_sync`: OTHER locked personas
    // that could not be materialized while installing this one.
    let failures: Vec<serde_json::Value> = report
        .materialize_failures
        .iter()
        .map(|f| serde_json::json!({ "persona": f.persona, "error": f.error }))
        .collect();
    Ok(serde_json::json!({
        "persona": report.persona.name,
        "version": report.persona.version,
        "hash": report.persona.hash,
        "failures": failures,
    }))
}

/// Handle the `activate` method.
///
/// Params: `{ "persona": "<name>", "project_root": "<path>" }`
/// Returns: `{ "activated": "<name>" }`
fn handle_activate(params: Option<Value>, client: &Client) -> Result<Value, (i32, String)> {
    let persona = get_str(&params, "persona")?;
    let root = get_path(&params, "project_root")?;

    client
        .activate(&root, &persona)
        .map_err(|e| (crate::protocol::INTERNAL_ERROR, e.to_string()))?;

    Ok(serde_json::json!({ "activated": persona }))
}

/// Handle the `sync` method.
///
/// Params: `{ "project_root": "<path>" }`
/// Returns: `{ "personas": ["<name>", ...] }`
fn handle_sync(params: Option<Value>, client: &Client) -> Result<Value, (i32, String)> {
    let root = get_path(&params, "project_root")?;

    let report = client
        .sync(&root)
        .map_err(|e| (crate::protocol::INTERNAL_ERROR, e.to_string()))?;

    // `failures` is additive: locked personas that could not be materialized
    // this sync (e.g. an unrenderable cached pack), each with its cause.
    let failures: Vec<serde_json::Value> = report
        .failures
        .iter()
        .map(|f| serde_json::json!({ "persona": f.persona, "error": f.error }))
        .collect();
    Ok(serde_json::json!({ "personas": report.personas, "failures": failures }))
}

/// Handle the `gc` method.
///
/// Params: none required.
/// Returns: `{ "removed": <count> }`
fn handle_gc(_params: Option<Value>, client: &Client) -> Result<Value, (i32, String)> {
    let report = client
        .gc()
        .map_err(|e| (crate::protocol::INTERNAL_ERROR, e.to_string()))?;

    Ok(serde_json::json!({ "removed": report.removed_hashes.len() }))
}

/// Handle the `grow.append` method.
///
/// Params: `{ "project_root": "<path>", "persona": "<name>", "text": "<growth-entry>" }`
/// Returns: `{ "appended": true }`
fn handle_grow_append(params: Option<Value>, client: &Client) -> Result<Value, (i32, String)> {
    let root = get_path(&params, "project_root")?;
    let persona = get_str(&params, "persona")?;
    let text = get_str(&params, "text")?;

    let project_id = client
        .project_id(&root)
        .map_err(|e| (crate::protocol::INTERNAL_ERROR, e.to_string()))?;

    frameshift_growth::append(client.data_root(), &project_id, &persona, &text)
        .map_err(|e| (crate::protocol::INTERNAL_ERROR, e.to_string()))?;

    Ok(serde_json::json!({ "appended": true }))
}

/// Extract a required string field from the params object.
///
/// Returns `Err((INVALID_PARAMS, message))` if the field is absent or not a string.
fn get_str(params: &Option<Value>, key: &str) -> Result<String, (i32, String)> {
    params
        .as_ref()
        .and_then(|p| p.get(key))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            (
                crate::protocol::INVALID_PARAMS,
                format!("missing required param: {key}"),
            )
        })
}

/// Extract and validate a required absolute filesystem path from the params object.
fn get_path(params: &Option<Value>, key: &str) -> Result<PathBuf, (i32, String)> {
    let raw = get_str(params, key)?;
    validate_path_arg(&raw, key)
}

/// Reject relative paths and lexical parent-directory traversal at the IPC boundary.
fn validate_path_arg(raw: &str, key: &str) -> Result<PathBuf, (i32, String)> {
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err((
            crate::protocol::INVALID_PARAMS,
            format!("{key} path must be absolute: {path:?}"),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err((
            crate::protocol::INVALID_PARAMS,
            format!("{key} path must not contain '..': {path:?}"),
        ));
    }
    Ok(path)
}

#[cfg(test)]
/// Tests JSON-RPC dispatch results and validation at the daemon boundary.
mod tests {
    use super::*;
    use frameshift_client::{Client, ClientOptions};

    /// Build a test Client backed by a temporary directory.
    fn test_client(tmp: &tempfile::TempDir) -> Client {
        Client::new(ClientOptions {
            data_root: tmp.path().to_path_buf(),
            config_root: None,
            vault: None,
        })
    }

    /// Build valid method parameters around a supplied project root.
    fn path_method_params(project_root: &str) -> [(&'static str, Value); 5] {
        [
            (
                "project_id",
                serde_json::json!({ "project_root": project_root }),
            ),
            (
                "install",
                serde_json::json!({
                    "spec": "devtools@1.0.0",
                    "project_root": project_root
                }),
            ),
            (
                "activate",
                serde_json::json!({
                    "persona": "devtools",
                    "project_root": project_root
                }),
            ),
            ("sync", serde_json::json!({ "project_root": project_root })),
            (
                "grow.append",
                serde_json::json!({
                    "project_root": project_root,
                    "persona": "devtools",
                    "text": "test entry"
                }),
            ),
        ]
    }

    /// Assert that every project-scoped daemon method rejects an unsafe path.
    fn assert_project_path_rejected(project_root: &str, expected_message: &str) {
        let tmp = tempfile::tempdir().unwrap();
        let client = test_client(&tmp);

        for (method, params) in path_method_params(project_root) {
            let (code, message) = dispatch(method, Some(params), &client).unwrap_err();
            assert_eq!(code, crate::protocol::INVALID_PARAMS, "method: {method}");
            assert!(
                message.contains(expected_message),
                "method {method} returned unexpected message: {message}"
            );
        }
    }

    /// Verify that dispatching an unknown method returns METHOD_NOT_FOUND.
    #[test]
    fn dispatch_unknown_method() {
        let tmp = tempfile::tempdir().unwrap();
        let client = test_client(&tmp);
        let result = dispatch("nonexistent.method", None, &client);
        assert!(result.is_err());
        let (code, _msg) = result.unwrap_err();
        assert_eq!(code, crate::protocol::METHOD_NOT_FOUND);
    }

    /// Verify that `project_id` returns a non-empty string id for a real directory.
    #[test]
    fn handle_project_id_returns_string() {
        let tmp = tempfile::tempdir().unwrap();
        let client = test_client(&tmp);
        // Use the tempdir itself as the project root -- it exists on disk.
        let params = serde_json::json!({ "project_root": tmp.path().to_str().unwrap() });
        let result = dispatch("project_id", Some(params), &client);
        assert!(
            result.is_ok(),
            "unexpected error: {:?}",
            result.unwrap_err()
        );
        let val = result.unwrap();
        let id = val["project_id"]
            .as_str()
            .expect("project_id should be a string");
        assert!(!id.is_empty());
    }

    /// Verify that every project-scoped method rejects relative project roots.
    #[test]
    fn project_methods_reject_relative_roots() {
        assert_project_path_rejected("relative/project", "project_root path must be absolute");
    }

    /// Verify that every project-scoped method rejects lexical parent traversal.
    #[test]
    fn project_methods_reject_parent_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let unsafe_root = tmp.path().join("project").join("..").join("outside");
        assert_project_path_rejected(
            unsafe_root.to_str().unwrap(),
            "project_root path must not contain '..'",
        );
    }

    /// Verify that install rejects unsafe local pack paths before client operations.
    #[test]
    fn install_rejects_unsafe_local_source_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let client = test_client(&tmp);
        let parent_path = tmp.path().join("pack").join("..").join("outside");
        let cases = [
            ("relative/pack", "from_path path must be absolute"),
            (
                parent_path.to_str().unwrap(),
                "from_path path must not contain '..'",
            ),
        ];

        for (from_path, expected_message) in cases {
            let params = serde_json::json!({
                "spec": "devtools@1.0.0",
                "project_root": tmp.path(),
                "from_path": from_path
            });

            let (code, message) = dispatch("install", Some(params), &client).unwrap_err();
            assert_eq!(code, crate::protocol::INVALID_PARAMS);
            assert!(message.contains(expected_message));
        }
    }

    /// Verify that `gc` returns a result containing the `removed` key.
    #[test]
    fn handle_gc_returns_removed_key() {
        let tmp = tempfile::tempdir().unwrap();
        let client = test_client(&tmp);
        let result = dispatch("gc", None, &client);
        assert!(
            result.is_ok(),
            "unexpected error: {:?}",
            result.unwrap_err()
        );
        let val = result.unwrap();
        assert!(
            val.get("removed").is_some(),
            "result must have 'removed' key"
        );
    }
}
