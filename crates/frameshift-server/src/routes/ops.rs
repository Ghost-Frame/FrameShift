//! Operational endpoints: health check and Prometheus metrics.
//!
//! Health is public; metrics require an explicitly configured bearer token.
//! They are mounted at `/healthz` and `/metrics` (outside `/v1`).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
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

/// Reduce a backend's rich health detail to a fixed public-safe string.
///
/// Adapters return operator-facing detail strings (filesystem paths, pool
/// counts, raw driver errors) that must never cross the unauthenticated
/// `/healthz` boundary. Callers should log the real detail via `tracing`
/// before discarding it in favor of this sanitized value.
fn sanitized_detail(healthy: bool) -> String {
    if healthy {
        "ok".to_string()
    } else {
        "degraded".to_string()
    }
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
/// # Public boundary sanitization
///
/// This is an unauthenticated, internet-facing endpoint. Adapters
/// (`frameshift-catalog-postgres`, `frameshift-objects-fs`, ...) return rich
/// `detail` strings for operator-facing surfaces (structured logs, internal
/// dashboards) that may embed filesystem paths, pool internals, or raw driver
/// error text. None of that may reach this public response. Every `detail`
/// field in the returned JSON is therefore reduced to the fixed string `"ok"`
/// (healthy) or `"degraded"` (unhealthy); the adapter's real detail is logged
/// server-side via `tracing` (`info` when healthy, `warn` when degraded) and
/// never serialized.
///
/// # Errors
///
/// This handler never returns an HTTP error. Backend failures are represented
/// as `healthy: false` in the response body.
pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let catalog_health = match state.catalog.health().await {
        Ok(h) => {
            // The adapter's detail may embed internals (e.g. pool counts, raw
            // driver errors); log it server-side but never expose it publicly.
            if h.healthy {
                tracing::info!(detail = %h.detail, "catalog health check ok");
            } else {
                tracing::warn!(detail = %h.detail, "catalog health check degraded");
            }
            CatalogHealthSummary {
                healthy: h.healthy,
                detail: sanitized_detail(h.healthy),
            }
        }
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
        Ok(h) => {
            // The adapter's detail may embed the object store's absolute
            // filesystem root path; log it server-side, never expose it.
            if h.healthy {
                tracing::info!(detail = %h.detail, "object store health check ok");
            } else {
                tracing::warn!(detail = %h.detail, "object store health check degraded");
            }
            ObjectsHealthSummary {
                healthy: h.healthy,
                total_objects: h.total_objects,
                total_bytes: h.total_bytes,
                detail: sanitized_detail(h.healthy),
            }
        }
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
            Ok(h) => {
                // The adapter's message may embed backend internals; log it
                // server-side, never expose it in the public response.
                if h.healthy {
                    tracing::info!(detail = %h.message, "memory health check ok");
                } else {
                    tracing::warn!(detail = %h.message, "memory health check degraded");
                }
                MemoryHealthSummary {
                    healthy: h.healthy,
                    detail: sanitized_detail(h.healthy),
                }
            }
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
/// Requires the configured `METRICS_BEARER_TOKEN`. When no token is configured
/// the endpoint returns `404`; missing or incorrect credentials return `401`.
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
pub async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    use secrecy::ExposeSecret as _;
    let expected = state.config.metrics_bearer_token.expose_secret();
    if expected.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state.metrics.encode_text(),
    )
        .into_response()
}

/// Compare secret byte strings without data-dependent early exits.
fn constant_time_eq(expected: &[u8], presented: &[u8]) -> bool {
    let mut difference = expected.len() ^ presented.len();
    let length = expected.len().max(presented.len());
    for index in 0..length {
        let left = expected.get(index).copied().unwrap_or(0);
        let right = presented.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
}
