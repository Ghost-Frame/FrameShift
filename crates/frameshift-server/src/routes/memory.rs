//! `GET /v1/memory/health` -- read-only health surface for the configured
//! memory backend.
//!
//! This module does not expose any memory read/write operations (store,
//! search, recall, list, forget); it only reports whether a memory backend
//! is configured and, if so, whether it is currently reachable. Wiring the
//! full memory CRUD surface and the embedded `Runtime` is out of scope here.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::state::AppState;

/// Response body for `GET /v1/memory/health`.
#[derive(Debug, Serialize)]
pub struct MemoryHealthResponse {
    /// Whether a memory backend is configured (`state.memory.is_some()`).
    pub configured: bool,

    /// The configured `MEMORY_BACKEND` value (e.g. `"none"`, `"http"`, `"sqlite"`).
    pub backend: String,

    /// Whether the configured backend is reachable and operational.
    ///
    /// Always `false` when `configured` is `false`.
    pub healthy: bool,

    /// Human-readable description of the current health state.
    pub message: String,

    /// Round-trip latency to the backing store, in milliseconds, when the
    /// adapter measured one. `None` when unconfigured or unmeasured.
    pub latency_ms: Option<u64>,
}

/// Build the memory sub-router, mounted at `/v1/memory`.
///
/// Routes:
/// - `GET /health` -> [`memory_health`]
pub fn memory_router() -> Router<AppState> {
    Router::new().route("/health", get(memory_health))
}

/// `GET /v1/memory/health`
///
/// Reports whether a memory backend is configured and, if so, its current
/// health as reported by [`frameshift_memory::MemoryAdapter::health`].
///
/// # Response
///
/// Always responds `200 OK`, mirroring `/healthz` -- callers must inspect the
/// `configured` and `healthy` fields rather than relying on the HTTP status.
///
/// # Errors
///
/// This handler never returns an HTTP error. Backend failures are represented
/// as `healthy: false` in the response body; the underlying error is logged
/// via `tracing::warn` but never included in the body.
pub async fn memory_health(State(state): State<AppState>) -> (StatusCode, Json<MemoryHealthResponse>) {
    let Some(adapter) = state.memory.as_ref() else {
        return (
            StatusCode::OK,
            Json(MemoryHealthResponse {
                configured: false,
                backend: state.config.memory_backend.clone(),
                healthy: false,
                message: "no memory backend configured".to_string(),
                latency_ms: None,
            }),
        );
    };

    match adapter.health().await {
        Ok(h) => (
            StatusCode::OK,
            Json(MemoryHealthResponse {
                configured: true,
                backend: state.config.memory_backend.clone(),
                healthy: h.healthy,
                message: h.message,
                latency_ms: h.latency_ms,
            }),
        ),
        Err(e) => {
            // Log the raw error internally; never expose it in the public response.
            tracing::warn!(error = %e, "memory backend health check failed");
            (
                StatusCode::OK,
                Json(MemoryHealthResponse {
                    configured: true,
                    backend: state.config.memory_backend.clone(),
                    healthy: false,
                    message: "backend unavailable".to_string(),
                    latency_ms: None,
                }),
            )
        }
    }
}
