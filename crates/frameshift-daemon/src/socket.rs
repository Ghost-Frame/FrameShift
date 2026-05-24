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
/// in its own independent tokio task.
pub async fn serve(
    listener: UnixListener,
    client: Arc<Client>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            // Accept a new connection.
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        let client = Arc::clone(&client);
                        let shutdown_tx_clone = shutdown.clone();
                        tokio::spawn(handle_connection(stream, client, shutdown_tx_clone));
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "accept error; stopping server loop");
                        break;
                    }
                }
            }
            // Observe shutdown signal.
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
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
/// sends a `shutdown` method call.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    client: Arc<Client>,
    _shutdown: watch::Receiver<bool>,
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
            break;
        }
    }
}
