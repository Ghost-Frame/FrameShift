//! `POST /v1/telemetry/selection` -- opt-in persona-selection telemetry sink.
//!
//! The client (`frameshift_client::selection`) sends this payload only when a
//! project has explicitly opted in AND a telemetry endpoint is configured; see
//! `crates/frameshift-client/src/selection.rs`. This endpoint is a lightweight
//! LOG + METRIC sink: it does not persist anything to the catalog or a
//! database. There is intentionally no storage here -- telemetry is a
//! best-effort observability signal, not a durable record.
//!
//! The request body is capped well below the server's global request-body
//! limit (a selection event is a handful of short fields) so a malformed or
//! abusive caller cannot use this endpoint to push large bodies through.

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use crate::state::AppState;

/// Maximum accepted request body size for this route, in bytes.
///
/// The payload is four short fields (persona, session, project_id, a u64
/// timestamp); 4 KiB is generous headroom while still rejecting anything
/// resembling abuse long before it reaches the global `max_request_bytes`
/// limit.
const MAX_TELEMETRY_BODY_BYTES: usize = 4 * 1024;

/// Request body for `POST /v1/telemetry/selection`.
///
/// Field names and types mirror `frameshift_client::selection::SelectionTelemetry`
/// exactly (borrowed `&str` on the client side serializes identically to owned
/// `String` here) so the wire contract matches what the client actually sends.
#[derive(Debug, Deserialize)]
pub struct SelectionTelemetryPayload {
    /// The persona that was selected.
    pub persona: String,
    /// Opaque session identifier.
    pub session: String,
    /// Opaque project identifier (content-addressed, not a path).
    pub project_id: String,
    /// Unix epoch seconds at which the selection occurred.
    pub recorded_at_unix: u64,
}

/// Build the telemetry sub-router, mounted at `/v1/telemetry`.
///
/// Routes:
/// - `POST /selection` -> [`post_selection_telemetry`], with a per-route body
///   size limit tighter than the server-wide default.
pub fn telemetry_router() -> Router<AppState> {
    Router::new()
        .route("/selection", post(post_selection_telemetry))
        .route_layer(DefaultBodyLimit::max(MAX_TELEMETRY_BODY_BYTES))
}

/// `POST /v1/telemetry/selection`
///
/// Accepts an opt-in persona-selection telemetry event and records it as a
/// structured `tracing` log plus an increment of the shared
/// `http_requests_total` request counter (via [`crate::middleware::metrics::MetricsLayer`],
/// already applied to every route). No database write, no catalog call --
/// this is a fire-and-forget observability sink.
///
/// # Response
///
/// `204 No Content` on success.
///
/// # Errors
///
/// Oversized bodies never reach this handler: the route-level
/// [`DefaultBodyLimit`] rejects them with `413 Payload Too Large` before JSON
/// deserialization runs. Malformed JSON is rejected by the `Json` extractor
/// with `400 Bad Request`.
pub async fn post_selection_telemetry(
    State(_state): State<AppState>,
    Json(payload): Json<SelectionTelemetryPayload>,
) -> StatusCode {
    // Structured log line -- the sink of record for this opt-in signal. No PII
    // beyond the opaque, content-addressed project_id and session id.
    tracing::info!(
        persona = %payload.persona,
        session = %payload.session,
        project_id = %payload.project_id,
        recorded_at_unix = payload.recorded_at_unix,
        "selection telemetry received"
    );
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deserializing a payload shaped like the client's `SelectionTelemetry`
    /// succeeds with matching field values.
    #[test]
    fn payload_deserializes_from_client_shaped_json() {
        let json = r#"{"persona":"rust","session":"sess-1","project_id":"proj-1","recorded_at_unix":42}"#;
        let payload: SelectionTelemetryPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.persona, "rust");
        assert_eq!(payload.session, "sess-1");
        assert_eq!(payload.project_id, "proj-1");
        assert_eq!(payload.recorded_at_unix, 42);
    }
}
