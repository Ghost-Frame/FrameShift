//! Persona-selection history and opt-in telemetry.
//!
//! Two distinct concerns live here, deliberately separated by privacy posture:
//!
//! - **Selection history** is a per-project, append-only, write-only JSONL
//!   audit log of which persona was selected and why. It is written to the
//!   central project state directory and never leaves the machine. Nothing in
//!   this codebase reads it back today -- it is not the mechanism the
//!   intelligent-selection feature learns from. That mechanism is the
//!   separate `Preferences` store persisted to `automate-prefs.json`
//!   (`frameshift_orchestrator::Preferences`, written by the CLI's `use`,
//!   `feedback`, and `prefs` commands and read by `select`/`automate`).
//!   `selection-history.jsonl` exists purely as a local record for future
//!   analysis or export.
//! - **Telemetry** is the optional, off-by-default network side. It is sent
//!   only when the project has explicitly opted in *and* a telemetry endpoint is
//!   configured via the environment. There is intentionally no default
//!   endpoint, so a stock client never phones home.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::ClientError;

/// Environment variable that OVERRIDES the telemetry endpoint. When unset (or
/// blank), the endpoint is derived from the configured registry base URL so that
/// opting in works against the same host that serves the registry. Telemetry is
/// always gated on the project's opt-in flag regardless of this value, so the
/// client still never sends anything unless the user has explicitly opted in.
pub const TELEMETRY_URL_ENV: &str = "FRAMESHIFT_TELEMETRY_URL";

/// Path appended to the registry base URL to form the default telemetry endpoint.
const TELEMETRY_PATH: &str = "/v1/telemetry/selection";

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
    let line =
        serde_json::to_string(event).map_err(|e| ClientError::JsonSerialize(e.to_string()))?;
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

/// Resolve the telemetry endpoint. An explicit `FRAMESHIFT_TELEMETRY_URL` wins;
/// otherwise the endpoint is derived from the configured registry base URL. This
/// returning a URL does not by itself cause anything to be sent: the caller still
/// gates on `ProjectConfig.telemetry_opt_in`.
pub fn telemetry_endpoint() -> String {
    if let Ok(explicit) = std::env::var(TELEMETRY_URL_ENV) {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    format!("{}{}", crate::registry::registry_base_url(), TELEMETRY_PATH)
}

/// POST a telemetry payload to `endpoint`. Callers are responsible for the
/// opt-in and endpoint-presence checks before invoking this; this function only
/// performs the network request and maps the outcome to a `ClientError`.
pub fn post_selection_telemetry(
    endpoint: &str,
    payload: &SelectionTelemetry<'_>,
) -> Result<(), ClientError> {
    match crate::registry::http_agent()
        .post(endpoint)
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

    /// Without an override, telemetry_endpoint derives from the registry base URL.
    #[test]
    fn telemetry_endpoint_derives_from_registry_when_no_override() {
        // Avoid mutating env here to keep the test free of global env races; only
        // assert the derive path when no override is present.
        if std::env::var(TELEMETRY_URL_ENV).is_err() {
            let endpoint = telemetry_endpoint();
            assert!(
                endpoint.ends_with(TELEMETRY_PATH),
                "derived endpoint should end with the telemetry path, got {endpoint}"
            );
        }
    }
}
