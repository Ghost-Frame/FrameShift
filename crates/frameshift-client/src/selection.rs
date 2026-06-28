//! Persona-selection history and opt-in telemetry.
//!
//! Two distinct concerns live here, deliberately separated by privacy posture:
//!
//! - **Selection history** is a per-project, append-only JSONL log of which
//!   persona was selected and why. It is written to the central project state
//!   directory and never leaves the machine; the intelligent-selection feature
//!   reads it back to learn from past choices.
//! - **Telemetry** is the optional, off-by-default network side. It is sent
//!   only when the project has explicitly opted in *and* a telemetry endpoint is
//!   configured via the environment. There is intentionally no default
//!   endpoint, so a stock client never phones home.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::ClientError;

/// Environment variable naming the telemetry endpoint. When unset (or blank),
/// telemetry is disabled regardless of the project's opt-in flag. There is no
/// default value on purpose: the public client must not ship a phone-home URL.
pub const TELEMETRY_URL_ENV: &str = "FRAMESHIFT_TELEMETRY_URL";

/// Filename of the per-project local selection history, stored as JSON Lines in
/// the central project state directory.
pub const SELECTION_HISTORY_FILENAME: &str = "selection-history.jsonl";

/// A single persona-selection event recorded to the local history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectionEvent {
    /// The persona that was selected.
    pub persona: String,
    /// Opaque identifier of the session the selection happened in.
    pub session: String,
    /// True when the selection was made automatically (e.g. automate mode),
    /// false when the user chose it explicitly.
    pub auto: bool,
    /// Optional human-readable rationale for the selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unix epoch seconds at which the event was recorded.
    pub recorded_at_unix: u64,
}

/// The minimal payload sent to a telemetry endpoint. Carries no filesystem
/// paths or user-identifying data beyond the opaque project id and session.
#[derive(Debug, Clone, Serialize)]
pub struct SelectionTelemetry<'a> {
    /// The persona that was selected.
    pub persona: &'a str,
    /// Opaque session identifier.
    pub session: &'a str,
    /// Opaque project identifier (content-addressed, not a path).
    pub project_id: &'a str,
    /// Unix epoch seconds at which the selection occurred.
    pub recorded_at_unix: u64,
}

/// Current wall-clock time as Unix epoch seconds, saturating to 0 if the system
/// clock is before the epoch.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append one selection event as a JSON line to `history_path`, creating the
/// file (but not its parent directory) if it does not yet exist.
pub fn append_selection_event(
    history_path: &Path,
    event: &SelectionEvent,
) -> Result<(), ClientError> {
    use std::io::Write as _;
    // Serialize to a single line; JSONL requires exactly one object per line.
    let line = serde_json::to_string(event).map_err(|e| ClientError::JsonSerialize(e.to_string()))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_path)
        .map_err(|source| ClientError::Io {
            path: history_path.to_path_buf(),
            source,
        })?;
    writeln!(file, "{line}").map_err(|source| ClientError::Io {
        path: history_path.to_path_buf(),
        source,
    })
}

/// Resolve the telemetry endpoint from the environment, returning `None` when
/// the variable is unset or blank (which disables telemetry entirely).
pub fn telemetry_endpoint() -> Option<String> {
    std::env::var(TELEMETRY_URL_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// POST a telemetry payload to `endpoint`. Callers are responsible for the
/// opt-in and endpoint-presence checks before invoking this; this function only
/// performs the network request and maps the outcome to a `ClientError`.
pub fn post_selection_telemetry(
    endpoint: &str,
    payload: &SelectionTelemetry<'_>,
) -> Result<(), ClientError> {
    match ureq::post(endpoint)
        .set("Content-Type", "application/json")
        .send_json(payload)
    {
        Ok(_) => Ok(()),
        // A non-2xx response: surface the status so callers can log it.
        Err(ureq::Error::Status(status, response)) => Err(ClientError::RegistryRejected {
            url: endpoint.to_string(),
            status,
            message: response.into_string().unwrap_or_default(),
        }),
        // Transport-level failure (DNS, connection, TLS, etc.).
        Err(ureq::Error::Transport(transport)) => Err(ClientError::RegistryHttp {
            url: endpoint.to_string(),
            detail: transport.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// append_selection_event creates the file and writes one JSON line per call.
    #[test]
    fn append_writes_one_jsonl_line_per_event() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(SELECTION_HISTORY_FILENAME);
        let event = SelectionEvent {
            persona: "rust".to_string(),
            session: "sess-1".to_string(),
            auto: false,
            reason: Some("manual pick".to_string()),
            recorded_at_unix: 42,
        };
        append_selection_event(&path, &event).unwrap();
        append_selection_event(&path, &event).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2, "each call appends exactly one line");
        let parsed: SelectionEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed, event);
    }

    /// telemetry_endpoint is None when the env var is unset or blank.
    #[test]
    fn telemetry_endpoint_absent_by_default() {
        // The variable is not set in the test environment, so telemetry is off.
        // (Set/clear is avoided here to keep the test free of global env races.)
        if std::env::var(TELEMETRY_URL_ENV).is_err() {
            assert_eq!(telemetry_endpoint(), None);
        }
    }
}
