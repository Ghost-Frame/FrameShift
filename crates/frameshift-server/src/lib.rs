//! # frameshift-server
//!
//! Layer 6 HTTP server skeleton for the frameshift persona marketplace.
//!
//! This crate exposes two public entry points:
//!
//! - [`app`] -- builds the [`axum::Router`] with all routes and middleware wired
//!   up, suitable for use in integration tests via `tower::ServiceExt::oneshot`.
//! - [`run`] -- the full server lifecycle: parse config, bind socket, serve with
//!   graceful shutdown on SIGTERM/SIGINT.
//!
//! ## Architecture
//!
//! ```text
//! main.rs
//!   -> run(config)
//!        -> app(state)          <- this function is the testable unit
//!             -> router.rs      <- sub-router composition + middleware
//!                  -> routes/   <- individual handler modules
//!                  -> mcp/      <- MCP placeholder (501)
//! ```
//!
//! ## Milestone scope
//!
//! Currently shipped:
//! - READ endpoints for `/v1/packs*`, `/v1/authors/*`, `/v1/handles/*`.
//! - WRITE endpoints gated by Ed25519 *signed-request* authentication (see
//!   [`crate::auth`]): `POST /v1/packs` (publish), `POST /v1/authors`
//!   (handle registration), and `POST /v1/authors/{handle}/rotate` (key
//!   rotation). Every mutating request carries an Ed25519 signature over
//!   `method | path | sha256(body) | timestamp | nonce`, with timestamp-skew
//!   and nonce-replay protection. Publish additionally verifies the pack's own
//!   content signature against the handle's currently-registered key.
//! - Signed download URLs: `POST /v1/downloads` (mint) and `GET /dl/{hash}`.
//! - Operational endpoints: `/healthz`, `/metrics` (real Prometheus registry).
//! - Admin: `POST /v1/admin/packs/{name}/{version}/tombstone`, gated by the
//!   same signed-request middleware plus an operator-controlled pubkey
//!   allowlist (`FRAMESHIFT_ADMIN_PUBKEYS`; see [`crate::routes::admin`]).
//! - MCP placeholder: `/mcp/*` returns 501.
//!
//! Deferred (M5+): OAuth 2.1, transparency log, and the full MCP surface.

pub mod auth;
pub mod config;
pub mod download;
pub mod error;
pub mod mcp;
pub mod metrics;
pub mod middleware;
pub mod router;
pub mod routes;
pub mod state;

use std::net::SocketAddr;

pub use config::{LogFormat, ServerConfig};
pub use error::AppError;
pub use router::app;
pub use state::AppState;

/// Top-level server error.
///
/// Returned by [`run`] when the server cannot start or encounters a fatal
/// shutdown error.
#[derive(thiserror::Error, Debug)]
pub enum ServerError {
    /// The server could not bind to the configured address.
    ///
    /// Common causes: address already in use, insufficient permissions for
    /// ports below 1024.
    #[error("bind: {0}")]
    Bind(#[from] std::io::Error),

    /// A backend failed to initialize before the server started accepting
    /// connections.
    #[error("backend startup: {0}")]
    Startup(String),

    /// The graceful shutdown sequence encountered an error.
    #[error("shutdown: {0}")]
    Shutdown(String),
}

/// Run the frameshift HTTP server until SIGTERM or SIGINT.
///
/// Constructs an [`AppState`] from the provided `config`, binds to
/// `config.bind_addr`, and begins serving HTTP requests. On receipt of
/// SIGTERM or SIGINT, initiates graceful shutdown: in-flight requests are
/// given `config.shutdown_grace` to complete before the server exits.
///
/// # Errors
///
/// - [`ServerError::Bind`] if the socket cannot be bound.
/// - [`ServerError::Startup`] if a backend cannot be initialized (placeholder;
///   concrete checks are deferred to milestone 2).
/// - [`ServerError::Shutdown`] if the graceful shutdown sequence fails.
pub async fn run(state: AppState) -> Result<(), ServerError> {
    let addr: SocketAddr = state.config.bind_addr;
    let shutdown_grace = state.config.shutdown_grace;

    let router = app(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {addr}");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(shutdown_grace))
        .await
        .map_err(ServerError::Bind)?;

    Ok(())
}

/// Wait for a graceful shutdown signal (SIGTERM or Ctrl-C).
///
/// Returns when either signal is received. After the signal, in-flight
/// requests are given `grace` duration to complete before the listener is
/// closed. A second Ctrl-C during the grace period will be ignored; the
/// server exits naturally after the grace period expires.
async fn shutdown_signal(grace: std::time::Duration) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {
            tracing::info!("received Ctrl-C, shutting down");
        }
        () = terminate => {
            tracing::info!("received SIGTERM, shutting down");
        }
    }

    tracing::info!(
        "draining in-flight requests (grace period: {}s)",
        grace.as_secs()
    );
    tokio::time::sleep(grace).await;
}
