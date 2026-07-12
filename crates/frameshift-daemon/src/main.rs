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

    // Build the shared client using XDG-derived paths. The vault provider is
    // env-only: the daemon runs unattended with no interactive terminal, so
    // a passphrase prompt would simply hang the process. Operators who need
    // vault-backed template tokens available to the daemon must export
    // FRAMESHIFT_VAULT_PASSPHRASE in its environment.
    let client = Arc::new(
        frameshift_client::Client::with_default_data_root_and_vault(Some(
            frameshift_client::env_only_vault_provider(),
        ))
        .expect("failed to initialize frameshift client"),
    );

    // Determine the socket directory from XDG_RUNTIME_DIR (fallback: /tmp).
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let socket_dir = std::path::PathBuf::from(&runtime_dir).join("frameshift");
    std::fs::create_dir_all(&socket_dir)?;
    // Restrict the socket directory to the owner (0700). Critical when
    // XDG_RUNTIME_DIR is unset and we fall back to the world-writable /tmp:
    // without this, any local user could reach (and drive) the daemon socket.
    // Applied unconditionally so a directory left over from a prior run with
    // looser permissions is tightened.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700))?;
    let socket_path = socket_dir.join("daemon.sock");

    // Remove a stale socket from a previous run if present.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    // Restrict the socket itself to the owner (0600) as a second layer beyond
    // the directory mode and the per-connection peer-uid check in serve().
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    tracing::info!(path = %socket_path.display(), "daemon listening");

    // Shutdown signalling channel. `serve`'s accept loop watches `shutdown_rx`
    // for `true`; `shutdown_tx` is cloned into every accepted connection so a
    // `shutdown` RPC on any one of them can flip the flag and stop the loop.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start file watcher on the data root so the daemon can react to external changes.
    // Events are forwarded to the orchestrator evaluation hook; the watcher is kept
    // alive by the binding below for the duration of the process.
    let data_root = client.data_root().to_path_buf();
    let watch_client = Arc::clone(&client);
    // Hold the watcher handle for the whole process lifetime. Dropping the
    // handle stops OS file notifications, so it must outlive the serve loop
    // below. Previously it was bound inside the match arm (`Ok((_watcher, ..))`)
    // and dropped immediately after startup, silently disabling the watcher.
    let _watcher_guard = match watcher::start_watcher(&data_root) {
        Ok((watcher, mut rx)) => {
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
            Some(watcher)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to start file watcher; orchestrator hook disabled");
            None
        }
    };

    // Drive the JSON-RPC server loop. The watcher handle above stays alive for
    // the duration of this call. `shutdown_tx` is threaded through so that a
    // `shutdown` RPC received on any connection can signal the accept loop
    // to stop.
    frameshift_daemon::socket::serve(listener, client, shutdown_rx, shutdown_tx).await;

    // Best-effort socket cleanup on graceful shutdown.
    let _ = std::fs::remove_file(&socket_path);
    tracing::info!("daemon shut down cleanly");

    Ok(())
}
