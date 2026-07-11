//! Unix socket server for the JSON-RPC daemon.
//!
//! Accepts connections on the provided `UnixListener`, spawns a tokio task
//! for each connection, and drives the request/response loop until the
//! connection closes or a `shutdown` RPC is received.

use crate::handler::dispatch;
use crate::protocol;
use frameshift_client::Client;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::watch;

/// Accept connections on `listener` and serve JSON-RPC requests.
///
/// The function returns when either the shutdown watch channel is set to
/// `true` or the listener itself errors. Each accepted connection is driven
/// in its own independent tokio task and is given a clone of `shutdown_tx` so
/// that a `shutdown` RPC received on that connection can flip the watch
/// channel and stop this accept loop.
pub async fn serve(
    listener: UnixListener,
    client: Arc<Client>,
    mut shutdown_rx: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
) {
    loop {
        tokio::select! {
            // Accept a new connection.
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        // Authenticate the peer by uid: this daemon mutates the
                        // owning user's persona state, so only that user's uid may
                        // drive it. This is defense in depth on top of the 0700
                        // socket directory created in main.
                        match stream.peer_cred() {
                            Ok(cred) => {
                                let own_uid = unsafe { libc::getuid() };
                                if cred.uid() != own_uid {
                                    tracing::warn!(
                                        peer_uid = cred.uid(),
                                        own_uid,
                                        "rejecting IPC connection from foreign uid"
                                    );
                                    continue;
                                }
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "could not read peer credentials; rejecting connection");
                                continue;
                            }
                        }
                        let client = Arc::clone(&client);
                        let conn_shutdown_tx = shutdown_tx.clone();
                        tokio::spawn(handle_connection(stream, client, conn_shutdown_tx));
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "accept error; stopping server loop");
                        break;
                    }
                }
            }
            // Observe shutdown signal.
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::info!("shutdown signal received; stopping accept loop");
                    break;
                }
            }
        }
    }
}

/// Drive the JSON-RPC request/response loop for a single accepted connection.
///
/// Reads newline-delimited JSON lines, dispatches each to `handler::dispatch`,
/// writes the response, and stops when the connection closes or the client
/// sends a `shutdown` method call. On a `shutdown` call this also sends
/// `true` on `shutdown_tx`, which signals the `serve` accept loop (running in
/// a different task) to stop accepting new connections.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    client: Arc<Client>,
    shutdown_tx: watch::Sender<bool>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let reader = BufReader::new(read_half);
    let mut lines = reader.lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => break, // connection closed
            Err(err) => {
                tracing::warn!(error = %err, "read error on connection");
                break;
            }
        };

        let request = match protocol::parse_request(&line) {
            Ok(req) => req,
            Err(err_response) => {
                let _ = write_half.write_all(err_response.as_bytes()).await;
                continue;
            }
        };

        let id = request.id.clone().unwrap_or(serde_json::Value::Null);
        let method = request.method.clone();
        let params = request.params.clone();
        let is_shutdown = method == "shutdown";

        // Run the synchronous client operation on a blocking thread.
        let client_ref = Arc::clone(&client);
        let response =
            tokio::task::spawn_blocking(move || dispatch(&method, params, &client_ref)).await;

        let response_str = match response {
            Ok(Ok(result)) => protocol::success(id, result),
            Ok(Err((code, msg))) => protocol::error(id, code, msg),
            Err(join_err) => protocol::error(
                id,
                protocol::INTERNAL_ERROR,
                format!("internal task error: {join_err}"),
            ),
        };

        if write_half.write_all(response_str.as_bytes()).await.is_err() {
            break;
        }

        if is_shutdown {
            // Signal the accept loop to stop. The send only fails if every
            // receiver (the `serve` loop and every other connection's clone)
            // has already been dropped, meaning the server is already gone;
            // that error carries no actionable information here.
            let _ = shutdown_tx.send(true);
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frameshift_client::ClientOptions;
    use tokio::net::UnixStream;
    use tokio::time::{timeout, Duration};

    /// Build a test Client backed by a temporary directory.
    fn test_client(tmp: &tempfile::TempDir) -> Client {
        Client::new(ClientOptions {
            data_root: tmp.path().to_path_buf(),
            config_root: None,
        })
    }

    /// Verify that sending the `shutdown` RPC on one connection both returns
    /// the canned `{"shutting_down": true}` reply and causes `serve`'s accept
    /// loop to return. This is the end-to-end proof that the watch channel is
    /// actually wired up, rather than the RPC merely closing the calling
    /// connection while the server keeps accepting new ones.
    #[tokio::test]
    async fn shutdown_rpc_terminates_serve() {
        let data_dir = tempfile::tempdir().unwrap();
        let client = Arc::new(test_client(&data_dir));

        let socket_dir = tempfile::tempdir().unwrap();
        let socket_path = socket_dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind should succeed");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(serve(listener, client, shutdown_rx, shutdown_tx));

        // Connect and send a `shutdown` request.
        let mut stream = UnixStream::connect(&socket_path)
            .await
            .expect("connect should succeed");
        stream
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"shutdown\"}\n")
            .await
            .expect("write should succeed");

        // Read the canned reply back to confirm the RPC was handled normally.
        let mut reader = BufReader::new(&mut stream);
        let mut response_line = String::new();
        timeout(Duration::from_secs(2), reader.read_line(&mut response_line))
            .await
            .expect("response should arrive within 2 seconds")
            .expect("read should succeed");
        let response: serde_json::Value =
            serde_json::from_str(response_line.trim()).expect("response should be valid JSON");
        assert_eq!(response["result"]["shutting_down"], true);

        // The accept loop in `serve` must observe the shutdown signal and
        // return on its own; if the sender were never wired up this join
        // would hang and the timeout below would fail the test.
        timeout(Duration::from_secs(2), serve_handle)
            .await
            .expect("serve() should return after a shutdown RPC")
            .expect("serve task should not panic");
    }
}
