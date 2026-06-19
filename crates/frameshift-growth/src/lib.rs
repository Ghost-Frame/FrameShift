//! Append-only local growth log for Frameshift personas.
//!
//! Each persona installation has a `growth.md` file in the central store.
//! This crate provides a single `append` function that adds timestamped
//! entries. Growth is local-only -- it never leaves the machine.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use serde::{Deserialize, Serialize};

/// Build the create+append `OpenOptions` used for every growth file.
///
/// Growth logs are strictly local and may reference private infrastructure,
/// so on Unix the file is created with mode `0o600` (owner-only) to honor the
/// growth-privacy invariant. The mode applies only when the file is created;
/// pre-existing files keep their current permissions.
fn growth_open_options() -> fs::OpenOptions {
    let mut opts = fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    opts.mode(0o600);
    opts
}

/// Errors from growth file operations.
#[derive(Debug, thiserror::Error)]
pub enum GrowthError {
    /// Failed to write to the growth file.
    #[error("failed to write to growth file at {path}: {source}")]
    Io {
        /// Path of the growth file.
        path: PathBuf,
        /// Underlying IO error.
        source: std::io::Error,
    },

    /// The persona name contains path traversal characters.
    #[error("invalid persona name: {0}")]
    InvalidPersonaName(String),

    /// The project ID contains path traversal characters.
    #[error("invalid project id: {0}")]
    InvalidProjectId(String),
}

/// Append a growth entry with the current UTC timestamp.
pub fn append(
    data_root: &Path,
    project_id: &str,
    persona_name: &str,
    entry_text: &str,
) -> Result<(), GrowthError> {
    let ts = format_utc_now();
    append_with_timestamp(data_root, project_id, persona_name, entry_text, &ts)
}

/// Append a growth entry with a caller-supplied timestamp string.
///
/// Exposed for test determinism -- production callers should use `append`.
pub fn append_with_timestamp(
    data_root: &Path,
    project_id: &str,
    persona_name: &str,
    entry_text: &str,
    timestamp: &str,
) -> Result<(), GrowthError> {
    validate_path_component(project_id)
        .map_err(|_| GrowthError::InvalidProjectId(project_id.to_string()))?;
    validate_path_component(persona_name)
        .map_err(|_| GrowthError::InvalidPersonaName(persona_name.to_string()))?;

    let growth_path = data_root
        .join("projects")
        .join(project_id)
        .join("personas")
        .join(persona_name)
        .join("growth.md");

    if let Some(parent) = growth_path.parent() {
        fs::create_dir_all(parent).map_err(|source| GrowthError::Io {
            path: growth_path.clone(),
            source,
        })?;
    }

    let mut file = growth_open_options()
        .open(&growth_path)
        .map_err(|source| GrowthError::Io {
            path: growth_path.clone(),
            source,
        })?;

    // Enforce owner-only perms even when appending to a pre-existing file --
    // growth.md holds local learnings and must never be world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }

    writeln!(file, "---\n<!-- growth: {} -->\n\n{}\n", timestamp, entry_text)
        .map_err(|source| GrowthError::Io {
            path: growth_path,
            source,
        })?;

    Ok(())
}

/// Reject path components containing traversal sequences or separators.
fn validate_path_component(s: &str) -> Result<(), ()> {
    if s.is_empty() || s.contains("..") || s.contains('/') || s.contains('\\') {
        return Err(());
    }
    Ok(())
}

/// Format the current UTC time as an RFC3339 timestamp.
fn format_utc_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
///
/// Uses Howard Hinnant's civil_from_days algorithm.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Scope of a growth entry: project-specific or global.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Learning specific to this project.
    Project,
    /// Universal learning applicable across projects.
    Global,
}

/// A structured growth entry in JSONL format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrowthEntry {
    /// RFC3339 timestamp.
    pub ts: String,
    /// Session ID (e.g., PID) that recorded this entry.
    pub session: String,
    /// Project ID hash.
    pub project_id: String,
    /// Persona name.
    pub persona: String,
    /// Whether the persona was auto-selected.
    pub auto_selected: bool,
    /// Task description at time of learning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    /// Classified intent at time of learning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// The actual learning text.
    pub text: String,
    /// Scope of this learning.
    pub scope: Scope,
}

/// Append a JSONL growth entry to the appropriate file based on scope.
///
/// Project-scope entries go to `{data_root}/projects/{pid}/personas/{name}/growth.jsonl`.
/// Global-scope entries go to `{data_root}/personas/{name}/growth.jsonl`.
pub fn append_jsonl(
    data_root: &Path,
    project_id: &str,
    persona_name: &str,
    entry: &GrowthEntry,
) -> Result<(), GrowthError> {
    validate_path_component(project_id)
        .map_err(|_| GrowthError::InvalidProjectId(project_id.to_string()))?;
    validate_path_component(persona_name)
        .map_err(|_| GrowthError::InvalidPersonaName(persona_name.to_string()))?;

    let path = match entry.scope {
        Scope::Project => data_root
            .join("projects")
            .join(project_id)
            .join("personas")
            .join(persona_name)
            .join("growth.jsonl"),
        Scope::Global => data_root
            .join("personas")
            .join(persona_name)
            .join("growth.jsonl"),
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| GrowthError::Io {
            path: path.clone(),
            source,
        })?;
    }

    let mut line = serde_json::to_string(entry).map_err(|e| GrowthError::Io {
        path: path.clone(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;
    line.push('\n');

    let mut file = growth_open_options()
        .open(&path)
        .map_err(|source| GrowthError::Io { path: path.clone(), source })?;
    file.write_all(line.as_bytes())
        .map_err(|source| GrowthError::Io { path, source })?;

    Ok(())
}

/// Read all JSONL growth entries for a persona in a given scope.
pub fn read_entries(
    data_root: &Path,
    project_id: &str,
    persona_name: &str,
    scope: Scope,
) -> Result<Vec<GrowthEntry>, GrowthError> {
    // Validate selectors before they are joined into the store path, matching
    // the append paths -- an untrusted project_id/persona_name like `../..`
    // could otherwise traverse out and read arbitrary growth logs.
    validate_path_component(project_id)
        .map_err(|_| GrowthError::InvalidPersonaName(project_id.to_string()))?;
    validate_path_component(persona_name)
        .map_err(|_| GrowthError::InvalidPersonaName(persona_name.to_string()))?;

    let path = match scope {
        Scope::Project => data_root
            .join("projects")
            .join(project_id)
            .join("personas")
            .join(persona_name)
            .join("growth.jsonl"),
        Scope::Global => data_root
            .join("personas")
            .join(persona_name)
            .join("growth.jsonl"),
    };

    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = fs::read_to_string(&path).map_err(|source| GrowthError::Io {
        path: path.clone(),
        source,
    })?;

    let mut entries = Vec::new();
    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: GrowthEntry = serde_json::from_str(trimmed).map_err(|e| GrowthError::Io {
            path: path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Return the last N entries for a persona, combining project + global scope.
pub fn recent_entries(
    data_root: &Path,
    project_id: &str,
    persona_name: &str,
    n: usize,
) -> Result<Vec<GrowthEntry>, GrowthError> {
    let mut project = read_entries(data_root, project_id, persona_name, Scope::Project)?;
    let global = read_entries(data_root, project_id, persona_name, Scope::Global)?;
    project.extend(global);
    project.sort_by(|a, b| b.ts.cmp(&a.ts));
    project.truncate(n);
    Ok(project)
}

/// Migrate a legacy growth.md file to growth.jsonl format.
///
/// Parses the markdown format (entries separated by `---` with
/// `<!-- growth: TIMESTAMP -->` headers) and writes each entry
/// as a JSONL line with `scope: Project` and no session attribution.
pub fn migrate_growth_md(
    data_root: &Path,
    project_id: &str,
    persona_name: &str,
) -> Result<usize, GrowthError> {
    validate_path_component(project_id)
        .map_err(|_| GrowthError::InvalidProjectId(project_id.to_string()))?;
    validate_path_component(persona_name)
        .map_err(|_| GrowthError::InvalidPersonaName(persona_name.to_string()))?;

    let md_path = data_root
        .join("projects")
        .join(project_id)
        .join("personas")
        .join(persona_name)
        .join("growth.md");

    if !md_path.exists() {
        return Ok(0);
    }

    let content = fs::read_to_string(&md_path).map_err(|source| GrowthError::Io {
        path: md_path.clone(),
        source,
    })?;

    let mut count = 0;
    let mut current_ts: Option<String> = None;
    let mut current_text = String::new();

    for line in content.lines() {
        if line.trim() == "---" {
            // Flush previous entry if we have one.
            if let Some(ts) = current_ts.take() {
                let text = current_text.trim().to_string();
                if !text.is_empty() {
                    let entry = GrowthEntry {
                        ts,
                        session: String::new(),
                        project_id: project_id.to_string(),
                        persona: persona_name.to_string(),
                        auto_selected: false,
                        task: None,
                        intent: None,
                        text,
                        scope: Scope::Project,
                    };
                    append_jsonl(data_root, project_id, persona_name, &entry)?;
                    count += 1;
                }
            }
            current_text.clear();
            continue;
        }

        // Check for timestamp comment.
        if line.trim().starts_with("<!-- growth:") {
            let ts = line
                .trim()
                .trim_start_matches("<!-- growth:")
                .trim_end_matches("-->")
                .trim()
                .to_string();
            current_ts = Some(ts);
            continue;
        }

        if current_ts.is_some() {
            current_text.push_str(line);
            current_text.push('\n');
        }
    }

    // Flush trailing entry.
    if let Some(ts) = current_ts {
        let text = current_text.trim().to_string();
        if !text.is_empty() {
            let entry = GrowthEntry {
                ts,
                session: String::new(),
                project_id: project_id.to_string(),
                persona: persona_name.to_string(),
                auto_selected: false,
                task: None,
                intent: None,
                text,
                scope: Scope::Project,
            };
            append_jsonl(data_root, project_id, persona_name, &entry)?;
            count += 1;
        }
    }

    Ok(count)
}

/// Produce an algorithmic summary of growth entries.
///
/// Takes the most recent entry per unique intent category, deduplicates
/// near-identical entries by Jaccard similarity on tokens, and caps at 10
/// entries concatenated into a single string.
pub fn summarize(
    data_root: &Path,
    project_id: &str,
    persona_name: &str,
    scope: Scope,
) -> Result<String, GrowthError> {
    let entries = read_entries(data_root, project_id, persona_name, scope)?;
    if entries.is_empty() {
        return Ok(String::new());
    }

    // Most recent entry per intent category.
    let mut by_intent: std::collections::BTreeMap<String, &GrowthEntry> = std::collections::BTreeMap::new();
    let mut no_intent: Vec<&GrowthEntry> = Vec::new();

    // Process entries in reverse chronological order.
    for entry in entries.iter().rev() {
        if let Some(intent) = &entry.intent {
            by_intent.entry(intent.clone()).or_insert(entry);
        } else {
            no_intent.push(entry);
        }
    }

    let mut selected: Vec<&str> = by_intent.values().map(|e| e.text.as_str()).collect();
    // Cap the per-intent entries at the summary limit, and use saturating_sub so
    // more than 10 unique intents cannot underflow `10 - len` (debug panic /
    // release over-return).
    selected.truncate(10);
    for entry in no_intent.iter().take(10usize.saturating_sub(selected.len())) {
        // Simple Jaccard dedup: skip if > 50% token overlap with any selected entry.
        let tokens: std::collections::HashSet<&str> = entry.text.split_whitespace().collect();
        let is_dup = selected.iter().any(|existing| {
            let existing_tokens: std::collections::HashSet<&str> = existing.split_whitespace().collect();
            let intersection = tokens.intersection(&existing_tokens).count();
            let union = tokens.union(&existing_tokens).count();
            if union == 0 { return true; }
            (intersection as f32 / union as f32) > 0.5
        });
        if !is_dup {
            selected.push(&entry.text);
        }
        if selected.len() >= 10 {
            break;
        }
    }

    Ok(selected.join(". "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_creates_file_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        append_with_timestamp(
            tmp.path(),
            "proj1",
            "cryptographic",
            "first entry",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        let path = tmp
            .path()
            .join("projects/proj1/personas/cryptographic/growth.md");
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("first entry"));
    }

    #[cfg(unix)]
    #[test]
    fn append_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        append_with_timestamp(
            tmp.path(),
            "proj1",
            "cryptographic",
            "private infra note",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        let path = tmp
            .path()
            .join("projects/proj1/personas/cryptographic/growth.md");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "growth file must be owner-only readable");
    }

    #[test]
    fn append_accumulates_entries() {
        let tmp = tempfile::tempdir().unwrap();
        append_with_timestamp(
            tmp.path(),
            "proj1",
            "rust",
            "entry one",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        append_with_timestamp(
            tmp.path(),
            "proj1",
            "rust",
            "entry two",
            "2026-01-02T00:00:00Z",
        )
        .unwrap();
        let path = tmp.path().join("projects/proj1/personas/rust/growth.md");
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("entry one"));
        assert!(content.contains("entry two"));
        assert!(content.find("entry one") < content.find("entry two"));
    }

    #[test]
    fn append_rejects_traversal_in_persona_name() {
        let tmp = tempfile::tempdir().unwrap();
        let result = append_with_timestamp(
            tmp.path(),
            "proj1",
            "../../etc/shadow",
            "evil",
            "2026-01-01T00:00:00Z",
        );
        assert!(result.is_err());
    }

    #[test]
    fn append_rejects_traversal_in_project_id() {
        let tmp = tempfile::tempdir().unwrap();
        let result = append_with_timestamp(
            tmp.path(),
            "../../etc",
            "persona",
            "evil",
            "2026-01-01T00:00:00Z",
        );
        assert!(result.is_err());
    }

    #[test]
    fn append_with_timestamp_inserts_header() {
        let tmp = tempfile::tempdir().unwrap();
        append_with_timestamp(
            tmp.path(),
            "p",
            "persona",
            "body text",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        let path = tmp.path().join("projects/p/personas/persona/growth.md");
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("2026-01-01T00:00:00Z"));
        assert!(content.contains("body text"));
    }

    #[test]
    fn append_rejects_empty_persona_name() {
        let tmp = tempfile::tempdir().unwrap();
        let result = append_with_timestamp(tmp.path(), "proj", "", "text", "ts");
        assert!(result.is_err());
    }

    #[test]
    fn format_utc_now_produces_valid_timestamp() {
        let ts = format_utc_now();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
    }

    #[test]
    fn append_jsonl_writes_structured_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let entry = GrowthEntry {
            ts: "2026-05-24T14:30:00Z".to_string(),
            session: "12345".to_string(),
            project_id: "abc123".to_string(),
            persona: "rust".to_string(),
            auto_selected: false,
            task: Some("debugging compilation error".to_string()),
            intent: Some("debugging".to_string()),
            text: "Learned orphan rules".to_string(),
            scope: Scope::Project,
        };
        append_jsonl(tmp.path(), "abc123", "rust", &entry).unwrap();

        let path = tmp.path().join("projects/abc123/personas/rust/growth.jsonl");
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        let parsed: GrowthEntry = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.text, "Learned orphan rules");
    }

    #[test]
    fn append_global_writes_to_global_path() {
        let tmp = tempfile::tempdir().unwrap();
        let entry = GrowthEntry {
            ts: "2026-05-24T14:30:00Z".to_string(),
            session: "12345".to_string(),
            project_id: "abc123".to_string(),
            persona: "rust".to_string(),
            auto_selected: false,
            task: None,
            intent: None,
            text: "thiserror over anyhow in libraries".to_string(),
            scope: Scope::Global,
        };
        append_jsonl(tmp.path(), "abc123", "rust", &entry).unwrap();

        let path = tmp.path().join("personas/rust/growth.jsonl");
        assert!(path.exists());
    }

    #[test]
    fn read_entries_returns_all_entries() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..3 {
            let entry = GrowthEntry {
                ts: format!("2026-05-24T14:3{i}:00Z"),
                session: "s1".to_string(),
                project_id: "p1".to_string(),
                persona: "rust".to_string(),
                auto_selected: false,
                task: None,
                intent: None,
                text: format!("entry {i}"),
                scope: Scope::Project,
            };
            append_jsonl(tmp.path(), "p1", "rust", &entry).unwrap();
        }
        let entries = read_entries(tmp.path(), "p1", "rust", Scope::Project).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn migrate_md_to_jsonl() {
        let tmp = tempfile::tempdir().unwrap();
        let md_path = tmp.path().join("projects/p1/personas/rust/growth.md");
        fs::create_dir_all(md_path.parent().unwrap()).unwrap();
        fs::write(&md_path, "---\n<!-- growth: 2026-05-19T03:19:52Z -->\n\nDiscovered a useful pattern\n\n---\n<!-- growth: 2026-05-20T10:00:00Z -->\n\nLearned about orphan rules\n\n").unwrap();

        migrate_growth_md(tmp.path(), "p1", "rust").unwrap();

        let entries = read_entries(tmp.path(), "p1", "rust", Scope::Project).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "Discovered a useful pattern");
        assert_eq!(entries[1].text, "Learned about orphan rules");
        assert_eq!(entries[0].scope, Scope::Project);
    }

    #[test]
    fn summarize_deduplicates_and_caps() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..15 {
            let entry = GrowthEntry {
                ts: format!("2026-05-{:02}T10:00:00Z", i + 1),
                session: "s1".to_string(),
                project_id: "p1".to_string(),
                persona: "rust".to_string(),
                auto_selected: false,
                task: None,
                intent: if i % 3 == 0 { Some("debugging".to_string()) } else { None },
                text: format!("learning number {i}"),
                scope: Scope::Project,
            };
            append_jsonl(tmp.path(), "p1", "rust", &entry).unwrap();
        }

        let summary = summarize(tmp.path(), "p1", "rust", Scope::Project).unwrap();
        let line_count = summary.lines().filter(|l| !l.is_empty()).count();
        assert!(line_count <= 10, "summary should cap at 10 entries, got {line_count}");
        assert!(!summary.is_empty());
    }
}
