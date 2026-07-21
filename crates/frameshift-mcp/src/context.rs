//! Shared project and render-target resolution for MCP tools and prompts.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// Environment variable used to configure the server's default project.
pub(crate) const PROJECT_ROOT_ENV: &str = "FRAMESHIFT_PROJECT_ROOT";

/// Project root supplied automatically to stdio servers by Claude Code.
const CLAUDE_PROJECT_ROOT_ENV: &str = "CLAUDE_PROJECT_DIR";

/// Environment variable used to configure the server's default render target.
pub(crate) const RENDER_TARGET_ENV: &str = "FRAMESHIFT_TARGET";

/// Render targets materialized by the Frameshift client.
const RENDER_TARGETS: [&str; 4] = ["claude", "codex", "gemini", "generic"];

/// Resolve a project root from an explicit argument, the server environment,
/// or the process working directory, in that order.
pub(crate) fn resolve_project_root(arguments: &serde_json::Value) -> Result<PathBuf, String> {
    let environment_root = std::env::var_os(PROJECT_ROOT_ENV);
    let claude_project_root = std::env::var_os(CLAUDE_PROJECT_ROOT_ENV);
    let current_dir = std::env::current_dir()
        .map_err(|error| format!("could not determine the server working directory: {error}"))?;
    resolve_project_root_from(
        arguments,
        environment_root.as_deref(),
        claude_project_root.as_deref(),
        &current_dir,
    )
}

/// Resolve a project root from supplied defaults so precedence can be tested
/// without mutating process-wide environment variables or working directory.
fn resolve_project_root_from(
    arguments: &serde_json::Value,
    environment_root: Option<&OsStr>,
    claude_project_root: Option<&OsStr>,
    current_dir: &Path,
) -> Result<PathBuf, String> {
    let explicit_root = match arguments.get("project_root") {
        None => None,
        Some(serde_json::Value::String(value)) if !value.trim().is_empty() => {
            Some(PathBuf::from(value))
        }
        Some(serde_json::Value::String(_)) => {
            return Err("project_root must be a non-empty absolute path".to_string());
        }
        Some(_) => return Err("project_root must be a JSON string".to_string()),
    };
    let candidate = explicit_root
        .or_else(|| {
            environment_root
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| {
            claude_project_root
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| current_dir.to_path_buf());
    validate_absolute_path(&candidate)
}

/// Clone an argument object and add its fully resolved project root.
pub(crate) fn with_project_root(
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let project_root = resolve_project_root(arguments)?;
    let mut resolved = arguments.as_object().cloned().ok_or_else(|| {
        "arguments must be a JSON object before project defaults can be applied".to_string()
    })?;
    resolved.insert(
        "project_root".to_string(),
        serde_json::Value::String(project_root.to_string_lossy().into_owned()),
    );
    Ok(serde_json::Value::Object(resolved))
}

/// Resolve a render target from an explicit argument, the server environment,
/// or the agent-neutral `generic` target, in that order.
pub(crate) fn resolve_render_target(arguments: &serde_json::Value) -> Result<String, String> {
    let environment_target = std::env::var(RENDER_TARGET_ENV).ok();
    resolve_render_target_from(arguments, environment_target.as_deref())
}

/// Resolve and validate a render target against the four materialized targets.
fn resolve_render_target_from(
    arguments: &serde_json::Value,
    environment_target: Option<&str>,
) -> Result<String, String> {
    let explicit_target = match arguments.get("target") {
        None => None,
        Some(serde_json::Value::String(value)) if !value.trim().is_empty() => Some(value.as_str()),
        Some(serde_json::Value::String(_)) => {
            return Err("target must be a non-empty string".to_string());
        }
        Some(_) => return Err("target must be a JSON string".to_string()),
    };
    let candidate = explicit_target
        .or_else(|| environment_target.filter(|value| !value.trim().is_empty()))
        .unwrap_or("generic")
        .trim()
        .to_ascii_lowercase();

    if RENDER_TARGETS.contains(&candidate.as_str()) {
        Ok(candidate)
    } else {
        Err(format!(
            "invalid render target {candidate:?}; expected one of: claude, codex, gemini, generic"
        ))
    }
}

/// Enforce the MCP filesystem boundary for a project or library path.
pub(crate) fn validate_absolute_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {:?}", path));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!("path must not contain '..': {:?}", path));
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
/// Tests for deterministic project and target precedence.
mod tests {
    use super::*;

    /// An explicit project argument wins over environment and working-directory defaults.
    #[test]
    fn explicit_project_root_has_highest_precedence() {
        let arguments = serde_json::json!({"project_root": "/explicit/project"});
        let resolved = resolve_project_root_from(
            &arguments,
            Some(OsStr::new("/environment/project")),
            Some(OsStr::new("/claude/project")),
            Path::new("/working/project"),
        )
        .unwrap();
        assert_eq!(resolved, Path::new("/explicit/project"));
    }

    /// The environment project is used when the call omits project_root.
    #[test]
    fn environment_project_root_precedes_working_directory() {
        let resolved = resolve_project_root_from(
            &serde_json::json!({}),
            Some(OsStr::new("/environment/project")),
            Some(OsStr::new("/claude/project")),
            Path::new("/working/project"),
        )
        .unwrap();
        assert_eq!(resolved, Path::new("/environment/project"));
    }

    /// Claude Code's stable project root precedes the process working directory.
    #[test]
    fn claude_project_root_precedes_working_directory() {
        let resolved = resolve_project_root_from(
            &serde_json::json!({}),
            None,
            Some(OsStr::new("/claude/project")),
            Path::new("/working/project"),
        )
        .unwrap();
        assert_eq!(resolved, Path::new("/claude/project"));
    }

    /// The working directory is the final project fallback.
    #[test]
    fn working_directory_is_final_project_fallback() {
        let resolved = resolve_project_root_from(
            &serde_json::json!({}),
            None,
            None,
            Path::new("/working/project"),
        )
        .unwrap();
        assert_eq!(resolved, Path::new("/working/project"));
    }

    /// Empty environment variables are ignored instead of becoming invalid paths.
    #[test]
    fn empty_environment_roots_fall_back_to_working_directory() {
        let resolved = resolve_project_root_from(
            &serde_json::json!({}),
            Some(OsStr::new("")),
            Some(OsStr::new("")),
            Path::new("/working/project"),
        )
        .unwrap();
        assert_eq!(resolved, Path::new("/working/project"));
    }

    /// Explicit project values must be non-empty JSON strings.
    #[test]
    fn malformed_explicit_project_roots_are_rejected() {
        for arguments in [
            serde_json::json!({"project_root": 42}),
            serde_json::json!({"project_root": null}),
            serde_json::json!({"project_root": ""}),
        ] {
            assert!(resolve_project_root_from(
                &arguments,
                Some(OsStr::new("/environment/project")),
                None,
                Path::new("/working/project"),
            )
            .is_err());
        }
    }

    /// Explicit targets win and invalid targets fail before a client operation.
    #[test]
    fn render_target_precedence_and_validation_are_deterministic() {
        let explicit =
            resolve_render_target_from(&serde_json::json!({"target": "CoDeX"}), Some("claude"))
                .unwrap();
        assert_eq!(explicit, "codex");

        let environment =
            resolve_render_target_from(&serde_json::json!({}), Some("gemini")).unwrap();
        assert_eq!(environment, "gemini");
        assert_eq!(
            resolve_render_target_from(&serde_json::json!({}), None).unwrap(),
            "generic"
        );
        assert!(
            resolve_render_target_from(&serde_json::json!({"target": "unknown"}), None).is_err()
        );
        assert_eq!(
            resolve_render_target_from(&serde_json::json!({}), Some("  ")).unwrap(),
            "generic"
        );
        for arguments in [
            serde_json::json!({"target": 42}),
            serde_json::json!({"target": null}),
            serde_json::json!({"target": ""}),
        ] {
            assert!(resolve_render_target_from(&arguments, Some("claude")).is_err());
        }
    }
}
