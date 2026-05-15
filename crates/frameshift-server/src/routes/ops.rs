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
///   "version": "0.1.0"
/// }
/// ```
///
/// # Backend calls
///
/// - `catalog.health()` -- may return `CatalogError::BackendError` which is
///   mapped to `healthy: false`.
/// - `objects.health()` -- may return `ObjectStoreError::BackendError` which is
///   mapped to `healthy: false`.
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
        Err(e) => CatalogHealthSummary {
            healthy: false,
            detail: e.to_string(),
        },
    };

    let objects_health = match state.objects.health().await {
        Ok(h) => ObjectsHealthSummary {
            healthy: h.healthy,
            total_objects: h.total_objects,
            total_bytes: h.total_bytes,
            detail: h.detail,
        },
        Err(e) => ObjectsHealthSummary {
            healthy: false,
            total_objects: None,
            total_bytes: None,
            detail: e.to_string(),
        },
    };

    let ok = catalog_health.healthy && objects_health.healthy;

    (
        StatusCode::OK,
        Json(HealthResponse {
            ok,
            catalog: catalog_health,
            objects: objects_health,
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

/// `GET /metrics`
///
/// Returns Prometheus-format metrics as plain text.
///
/// At this milestone the metrics surface is a placeholder that returns an
/// empty Prometheus text document. A full Prometheus registry integration
/// is deferred to a follow-up milestone.
///
/// # Response
///
/// `200 OK` with `Content-Type: text/plain; version=0.0.4` and an empty body.
///
/// # Errors
///
/// This handler never returns an HTTP error.
pub async fn metrics() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        "",
    )
}
