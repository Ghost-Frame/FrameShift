//! Opt-in telemetry emitter for Frameshift clients.
//!
//! Aggregates locally available growth signals and posts them to the registry.

use std::path::Path;

use serde::Serialize;

use crate::ClientError;

/// JSON signal payload accepted by the telemetry ingest endpoint.
#[derive(Debug, Serialize)]
struct SignalDto<'a> {
    /// The persona pack name associated with the signal.
    pack_name: &'a str,
    /// Version string. Empty means whole-pack counters.
    version: &'a str,
    /// Signal kind string.
    kind: &'a str,
    /// Optional sub-key for the signal.
    key: &'a str,
    /// Counter value for this signal.
    count: u64,
    /// Optional scalar payload.
    value: Option<f64>,
}

/// Build selection counters from the project growth log and POST them to the registry.
pub fn flush_for_persona(
    data_root: &Path,
    project_id: &str,
    persona: &str,
    api_base: &str,
    session_token: &str,
) -> Result<usize, ClientError> {
    let entries = frameshift_growth::read_entries(
        data_root,
        project_id,
        persona,
        frameshift_growth::Scope::Project,
    )
    .map_err(|error| ClientError::Telemetry(error.to_string()))?;
    let selection_entries: Vec<_> = entries
        .into_iter()
        .filter(|entry| entry.intent.as_deref() == Some("selection"))
        .collect();
    let total = selection_entries.len() as u64;
    let auto = selection_entries
        .iter()
        .filter(|entry| entry.auto_selected)
        .count() as u64;
    if total == 0 {
        return Ok(0);
    }

    let signals = vec![
        SignalDto {
            pack_name: persona,
            version: "",
            kind: "selection_count",
            key: "",
            count: total,
            value: None,
        },
        SignalDto {
            pack_name: persona,
            version: "",
            kind: "auto_select_count",
            key: "",
            count: auto,
            value: None,
        },
    ];

    let response = reqwest::blocking::Client::new()
        .post(format!("{}/telemetry", api_base.trim_end_matches('/')))
        .header("x-frameshift-session", session_token)
        .json(&signals)
        .send()
        .map_err(|error| ClientError::Telemetry(error.to_string()))?;
    if !response.status().is_success() {
        return Err(ClientError::Telemetry(format!(
            "telemetry POST failed: HTTP {}",
            response.status()
        )));
    }

    Ok(signals.len())
}
