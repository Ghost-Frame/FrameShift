//! File system watcher for the Frameshift daemon.
//!
//! Wraps `notify::RecommendedWatcher` and bridges its synchronous callback
//! API to a tokio `mpsc` channel so that the async main loop can react to
//! file-change events without blocking.

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::mpsc;

/// Fixed window used to coalesce filesystem notifications from one save.
const WATCH_EVENT_BATCH_WINDOW: Duration = Duration::from_millis(100);

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

/// Receive one path and collect every additional path queued during the batch window.
///
/// A fixed window bounds latency even when the watched tree changes continuously.
/// The final queued batch is returned after sender closure; `None` is returned only
/// when the channel is closed and empty.
pub async fn recv_path_batch(rx: &mut mpsc::UnboundedReceiver<PathBuf>) -> Option<Vec<PathBuf>> {
    let first_path = rx.recv().await?;
    tokio::time::sleep(WATCH_EVENT_BATCH_WINDOW).await;

    let mut paths = vec![first_path];
    while let Ok(path) = rx.try_recv() {
        paths.push(path);
    }
    Some(paths)
}

#[cfg(test)]
/// Tests for raw watcher delivery and fixed-window path batching.
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

    /// Verify that paths queued during the fixed window are returned together.
    #[tokio::test]
    async fn path_batch_collects_burst_and_preserves_final_queue() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(PathBuf::from("first")).unwrap();

        let delayed_tx = tx.clone();
        let delayed_send = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            delayed_tx.send(PathBuf::from("second")).unwrap();
        });
        drop(tx);

        let batch = recv_path_batch(&mut rx).await.expect("batch should arrive");
        delayed_send.await.unwrap();

        assert_eq!(batch, vec![PathBuf::from("first"), PathBuf::from("second")]);
        assert!(recv_path_batch(&mut rx).await.is_none());
    }
}
