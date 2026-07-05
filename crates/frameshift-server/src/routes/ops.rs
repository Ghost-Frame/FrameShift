//! Operational endpoints: health check and Prometheus metrics.
//!
//! These endpoints are unauthenticated and serve monitoring infrastructure.
//! They are mounted at `/healthz` and `/metrics` (outside `/v1`).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::state::AppState;

/// Build the operations sub-router.
///
/// Mounts:
/// - `GET /healthz` -> [`healthz`]
/// - `GET /metrics` -> [`metrics`]
pub fn ops_router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
}

/// Combined health response body.
///
/// Reports the health of the catalog and object store backends, plus the
/// running binary version. `ok` is the AND of all backend health flags.
///
/// Callers MUST NOT use `ok` alone for alerting; check individual backend
/// fields to distinguish which subsystem is degraded.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// `true` if all backends are healthy; `false` if any backend is degraded.
    ///
    /// This is the quick-check field for load balancers. Always `true` at the
    /// HTTP level (the endpoint returns 200 even when `ok` is `false`) so that
    /// health-check traffic is never blocked by backend degradation.
    pub ok: bool,

    /// Health status of the catalog backend.
    ///
    /// `healthy: false` means catalog reads and writes may fail.
    pub catalog: CatalogHealthSummary,

    /// Health status of the object store backend.
    ///
    /// `healthy: false` means pack download requests may fail.
    pub objects: ObjectsHealthSummary,

    /// Health status of the memory backend, when one is configured.
    ///
    /// `None` when `state.memory` is `None` (no `MEMORY_BACKEND` configured).
    /// An absent/unconfigured memory backend never affects `ok`: nothing else
    /// in the server currently consumes memory, so there is no functionality
    /// to report as degraded. When `Some`, its `healthy` flag participates in
    /// `ok` the same way `catalog` and `objects` do.
    pub memory: Option<MemoryHealthSummary>,

    /// The running server version (`CARGO_PKG_VERSION`).
    pub version: &'static str,
}

/// Health summary for the catalog backend, included in [`HealthResponse`].
#[derive(Debug, Serialize)]
pub struct CatalogHealthSummary {
    /// Whether the catalog backend is fully operational.
    pub healthy: bool,

    /// Human-readable description of the current health state.
    pub detail: String,
}

/// Health summary for the object store backend, included in [`HealthResponse`].
#[derive(Debug, Serialize)]
pub struct ObjectsHealthSummary {
    /// Whether the object store is fully operational.
    pub healthy: bool,

    /// Optional count of stored objects (may be `None` if expensive to compute).
    pub total_objects: Option<u64>,

    /// Optional total bytes stored (may be `None` if expensive to compute).
    pub total_bytes: Option<u64>,

    /// Human-readable description of the current health state.
    pub detail: String,
}

/// Health summary for the memory backend, included in [`HealthResponse`]
/// only when a memory backend is configured.
#[derive(Debug, Serialize)]
pub struct MemoryHealthSummary {
    /// Whether the configured memory backend is fully operational.
    pub healthy: bool,

    /// Human-readable description of the current health state.
    pub detail: String,
}

/// `GET /healthz`
///
/// Returns the health status of all backends. Always responds with `200 OK`
/// regardless of backend health -- callers must inspect the `ok` field and
/// individual backend fields to determine degradation.
///
/// # Response
///
/// `200 OK` with body:
/// ```json
/// {
///   "ok": true,
///   "catalog": { "healthy": true, "detail": "ok" },
///   "objects": { "healthy": true, "total_objects": null, "total_bytes": null, "detail": "ok" },
///   "memory": null,
///   "version": "0.1.0"
/// }
/// ```
///
/// `memory` is `null` when no `MEMORY_BACKEND` is configured; otherwise it is
/// an object with `healthy` and `detail`, and its `healthy` flag participates
/// in the top-level `ok` field.
///
/// # Backend calls
///
/// - `catalog.health()` -- may return `CatalogError::BackendError` which is
///   mapped to `healthy: false`.
/// - `objects.health()` -- may return `ObjectStoreError::BackendError` which is
///   mapped to `healthy: false`.
/// - `memory.health()` (only when configured) -- may return
///   `MemoryError` which is mapped to `healthy: false`.
///
/// # Errors
///
/// This handler never returns an HTTP error. Backend failures are represented
/// as `healthy: false` in the response body.
pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let catalog_health = match state.catalog.health().await {
        Ok(h) => CatalogHealthSummary {
            healthy: h.healthy,
            detail: h.detail,
        },
        Err(e) => {
            // Log the raw error internally; never expose it in the public response.
            tracing::warn!(error = %e, "catalog health check failed");
            CatalogHealthSummary {
                healthy: false,
                detail: "backend unavailable".to_string(),
            }
        }
    };

    let objects_health = match state.objects.health().await {
        Ok(h) => ObjectsHealthSummary {
            healthy: h.healthy,
            total_objects: h.total_objects,
            total_bytes: h.total_bytes,
            detail: h.detail,
        },
        Err(e) => {
            // Log the raw error internally; never expose it in the public response.
            tracing::warn!(error = %e, "object store health check failed");
            ObjectsHealthSummary {
                healthy: false,
                total_objects: None,
                total_bytes: None,
                detail: "backend unavailable".to_string(),
            }
        }
    };

    // Only probe and fold in memory health when a backend is actually
    // configured. An unconfigured backend must never flip `ok` to false --
    // nothing else in the server consumes memory yet.
    let memory_health = match &state.memory {
        Some(adapter) => Some(match adapter.health().await {
            Ok(h) => MemoryHealthSummary {
                healthy: h.healthy,
                detail: h.message,
            },
            Err(e) => {
                // Log the raw error internally; never expose it in the public response.
                tracing::warn!(error = %e, "memory health check failed");
                MemoryHealthSummary {
                    healthy: false,
                    detail: "backend unavailable".to_string(),
                }
            }
        }),
        None => None,
    };

    let ok = catalog_health.healthy
        && objects_health.healthy
        && memory_health.as_ref().is_none_or(|m| m.healthy);

    (
        StatusCode::OK,
        Json(HealthResponse {
            ok,
            catalog: catalog_health,
            objects: objects_health,
            memory: memory_health,
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

/// `GET /metrics`
///
/// Returns Prometheus-format metrics as a plain-text exposition document.
///
/// # Security note
///
/// This endpoint is currently unauthenticated. In production deployments the
/// endpoint should be restricted to internal monitoring infrastructure (e.g.
/// via a network policy, a reverse-proxy ACL, or a bearer token check added
/// here). Exposing internal metric names and counts to the public internet is
/// low-risk but is nonetheless an information leak that should be revisited
/// before internet-facing deployment.
///
/// # Response
///
/// `200 OK` with `Content-Type: text/plain; version=0.0.4` and the current
/// metric values in the Prometheus text exposition format.
///
/// # Errors
///
/// This handler never returns an HTTP error. If encoding fails internally the
/// body will be empty (the error is logged via `tracing::error`).
pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state.metrics.encode_text(),
    )
}
