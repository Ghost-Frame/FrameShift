//! Binary entry point for the Frameshift daemon.
//!
//! Initializes tracing, builds the `Client`, binds the Unix socket, optionally
//! starts the file watcher on the data root, and then drives the JSON-RPC
//! serve loop until a `shutdown` RPC is received or the process is killed.

use frameshift_daemon::{orchestrator, watcher};
use frameshift_orchestrator::controller::{SwitchController, SwitchPolicy};
use std::sync::Arc;
use tokio::net::UnixListener;
use tracing_subscriber::EnvFilter;

/// Derive a project root path from a file-change event path.
///
/// Looks for the pattern `<data_root>/projects/<id>/` in the changed path
/// and returns `<data_root>/projects/<id>` as the project root candidate.
/// Returns `None` when the path does not fall under a projects subdirectory.
fn derive_project_root_from_path(
    data_root: &std::path::Path,
    changed_path: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let projects_root = data_root.join("projects");
    // Walk ancestors looking for a path that is a direct child of projects_root.
    for ancestor in changed_path.ancestors() {
        if let Some(parent) = ancestor.parent() {
            if parent == projects_root {
                return Some(ancestor.to_path_buf());
            }
        }
    }
    None
}

/// Async entry point.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured tracing output. Level is controlled via RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Build the shared client using XDG-derived paths.
    let client = Arc::new(
        frameshift_client::Client::with_default_data_root()
            .expect("failed to initialize frameshift client"),
    );

    // Determine the socket directory from XDG_RUNTIME_DIR (fallback: /tmp).
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let socket_dir = std::path::PathBuf::from(&runtime_dir).join("frameshift");
    std::fs::create_dir_all(&socket_dir)?;
    let socket_path = socket_dir.join("daemon.sock");

    // Remove a stale socket from a previous run if present.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!(path = %socket_path.display(), "daemon listening");

    // Shutdown signalling channel; `serve` watches this for `true`.
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start file watcher on the data root so the daemon can react to external changes.
    // Events are forwarded to the orchestrator evaluation hook; the watcher is kept
    // alive by the binding below for the duration of the process.
    let data_root = client.data_root().to_path_buf();
    let watch_client = Arc::clone(&client);
    match watcher::start_watcher(&data_root) {
        Ok((_watcher, mut rx)) => {
            // Spawn a task that reacts to file-change events from the data root.
            // Each received path is treated as a project-root hint: we derive the
            // project root by walking up to find a frameshift projects directory,
            // or fall back to the data root itself. Automate mode is OFF by default
            // so this task is a no-op until the user explicitly enables it.
            let mut controller = SwitchController::new(SwitchPolicy::default());
            tokio::spawn(async move {
                while let Some(changed_path) = rx.recv().await {
                    // Derive a candidate project root from the changed path.
                    // Heuristic: find the "projects/<id>" ancestor under the data root.
                    // If no projects directory is found, skip (not a project event).
                    let project_root = derive_project_root_from_path(&data_root, &changed_path);
                    if let Some(root) = project_root {
                        orchestrator::evaluate_and_apply(
                            watch_client.as_ref(),
                            &mut controller,
                            &root,
                        );
                    }
                }
            });
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to start file watcher; orchestrator hook disabled");
        }
    }

    // Drive the JSON-RPC server loop.
    frameshift_daemon::socket::serve(listener, client, shutdown_rx).await;

    // Best-effort socket cleanup on graceful shutdown.
    let _ = std::fs::remove_file(&socket_path);
    tracing::info!("daemon shut down cleanly");

    Ok(())
}
