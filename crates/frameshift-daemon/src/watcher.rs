//! File system watcher for the Frameshift daemon.
//!
//! Wraps `notify::RecommendedWatcher` and bridges its synchronous callback
//! API to a tokio `mpsc` channel so that the async main loop can react to
//! file-change events without blocking.

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use tokio::sync::mpsc;

/// Start a recursive file watcher on `watch_dir`.
///
/// Returns a `(watcher, receiver)` pair. The `watcher` must be kept alive for
/// the duration of the watch -- dropping it stops delivery of events. The
/// `receiver` yields the path associated with each change event. Simple
/// forward-all strategy: every raw notify event that carries a path is
/// forwarded immediately; callers that need debouncing should apply their own
/// `tokio::time::sleep` or channel drain logic.
pub fn start_watcher(
    watch_dir: &Path,
) -> Result<
    (
        RecommendedWatcher,
        mpsc::UnboundedReceiver<std::path::PathBuf>,
    ),
    crate::error::DaemonError,
> {
    let (tx, rx) = mpsc::unbounded_channel::<std::path::PathBuf>();

    // The notify callback runs on an internal thread. We clone the sender
    // into the closure so the async receiver side can be used normally.
    let watcher = RecommendedWatcher::new(
        move |result: notify::Result<notify::Event>| match result {
            Ok(event) => {
                for path in event.paths {
                    // Best-effort send; ignore errors from a closed receiver.
                    let _ = tx.send(path);
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "notify watcher error");
            }
        },
        Config::default(),
    )
    .map_err(|e| crate::error::DaemonError::Watcher(e.to_string()))?;

    // Activate the watch. The watcher is returned so the caller owns it.
    let mut w = watcher;
    w.watch(watch_dir, RecursiveMode::Recursive)
        .map_err(|e| crate::error::DaemonError::Watcher(e.to_string()))?;

    Ok((w, rx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Verify that file write events are forwarded through the channel.
    #[tokio::test]
    async fn watcher_sends_event_on_file_write() {
        let tmp = tempfile::tempdir().unwrap();
        let watch_path = tmp.path().to_path_buf();

        let (_watcher, mut rx) = start_watcher(&watch_path).expect("watcher should start");

        // Write a file to trigger an event.
        let file_path = watch_path.join("trigger.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        // Wait up to 2 seconds for the event.
        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
        assert!(
            event.is_ok() && event.unwrap().is_some(),
            "expected a file-change event within 2 seconds"
        );
    }
}
