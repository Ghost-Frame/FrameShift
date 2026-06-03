//! Telemetry endpoints under `/v1/telemetry`.
//!
//! Ingest is opt-in and gated by the same session header used by publish.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use frameshift_catalog::records::{TelemetryKind, TelemetrySignal};
use serde::Deserialize;

use crate::error::AppError;
use crate::routes::packs::verify_session_header;
use crate::state::AppState;

/// One telemetry signal supplied by the client ingest API.
#[derive(Debug, Deserialize)]
pub struct SignalDto {
    /// The pack name associated with the signal.
    pub pack_name: String,
    /// Optional version string. Empty means whole-pack counters.
    #[serde(default)]
    pub version: String,
    /// The closed telemetry kind set.
    pub kind: TelemetryKind,
    /// Optional signal-specific key.
    #[serde(default)]
    pub key: String,
    /// Counter increment for this signal.
    #[serde(default)]
    pub count: u64,
    /// Optional scalar payload for this signal.
    #[serde(default)]
    pub value: Option<f64>,
}

/// Maximum number of signals accepted in a single ingest request.
const MAX_SIGNALS: usize = 500;

/// Build the `/v1/telemetry` router.
pub fn telemetry_router() -> Router<AppState> {
    Router::new().route("/", post(ingest))
}

/// `POST /v1/telemetry` ingests a batch of opt-in telemetry signals.
async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Vec<SignalDto>>,
) -> Result<StatusCode, AppError> {
    verify_session_header(&headers)?;
    if body.len() > MAX_SIGNALS {
        return Err(AppError::BadRequest(format!(
            "at most {MAX_SIGNALS} signals per request"
        )));
    }

    let signals = body
        .into_iter()
        .map(|signal| TelemetrySignal {
            pack_name: signal.pack_name,
            version: signal.version,
            kind: signal.kind,
            key: signal.key,
            count: signal.count,
            value: signal.value,
        })
        .collect();

    state
        .catalog
        .ingest_telemetry(signals)
        .await
        .map_err(|error| AppError::from_catalog(error, "telemetry"))?;

    Ok(StatusCode::ACCEPTED)
}

/// `GET /v1/packs/{name}/telemetry` returns all accumulated signals for a pack.
pub async fn get_pack_telemetry(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<TelemetrySignal>>, AppError> {
    let signals = state
        .catalog
        .get_telemetry(&name, None)
        .await
        .map_err(|error| AppError::from_catalog(error, "telemetry"))?;
    Ok(Json(signals))
}
