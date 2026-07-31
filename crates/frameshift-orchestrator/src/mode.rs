//! Durable on/off state for automate mode.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::OrchestratorError;

/// Whether automate mode is enabled or disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Automate mode is disabled.
    Off,
    /// Automate mode is enabled.
    On,
}

/// Returns the default switching sensitivity value (0.5).
///
/// Used as the serde default for `ModeState::sensitivity` to ensure backward
/// compatibility with persisted files that predate the sensitivity field.
fn default_sensitivity() -> f32 {
    0.5
}

/// Persisted automate mode state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeState {
    /// The current mode (on or off).
    pub mode: Mode,

    /// Switching sensitivity in the range [0.0, 1.0].
    ///
    /// 0.0 = stable (rarely switches), 1.0 = responsive (switches eagerly).
    /// Defaults to 0.5 when loading legacy files that lack this field.
    #[serde(default = "default_sensitivity")]
    pub sensitivity: f32,
}

impl ModeState {
    /// Load mode state from a JSON file.
    ///
    /// Returns `ModeState { mode: Mode::Off }` if the file does not exist.
    pub fn load(path: &Path) -> Result<Self, OrchestratorError> {
        if !path.exists() {
            return Ok(ModeState {
                mode: Mode::Off,
                sensitivity: default_sensitivity(),
            });
        }
        let data = std::fs::read_to_string(path)?;
        let state = serde_json::from_str(&data)?;
        Ok(state)
    }

    /// Persist mode state to a JSON file, creating parent directories as needed.
    ///
    /// The write is atomic: data is serialized to a uniquely-named temp file in
    /// the same directory and then renamed over the target, mirroring
    /// `Preferences::save` and `CachedEmbedder::persist_raw`, so a crash or a
    /// concurrent writer never leaves a half-written `automate.json` that
    /// `load` would fail to parse.
    pub fn save(&self, path: &Path) -> Result<(), OrchestratorError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("automate.json");
        let tmp_path = path.with_file_name(format!(".{file_name}.tmp.{}", std::process::id()));
        std::fs::write(&tmp_path, data.as_bytes())?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Load returns Off when file does not exist.
    #[test]
    fn load_missing_returns_off() {
        let tmp = TempDir::new().unwrap();
        let state = ModeState::load(&tmp.path().join("mode.json")).unwrap();
        assert_eq!(state.mode, Mode::Off);
        assert!((state.sensitivity - 0.5).abs() < f32::EPSILON);
    }

    /// Save then load round-trips Mode::On with default sensitivity.
    #[test]
    fn save_load_roundtrip_on() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("mode.json");
        let state = ModeState {
            mode: Mode::On,
            sensitivity: 0.5,
        };
        state.save(&path).unwrap();
        let loaded = ModeState::load(&path).unwrap();
        assert_eq!(loaded.mode, Mode::On);
        assert!((loaded.sensitivity - 0.5).abs() < f32::EPSILON);
    }

    /// Save then load round-trips Mode::Off with default sensitivity.
    #[test]
    fn save_load_roundtrip_off() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("mode.json");
        let state = ModeState {
            mode: Mode::Off,
            sensitivity: 0.5,
        };
        state.save(&path).unwrap();
        let loaded = ModeState::load(&path).unwrap();
        assert_eq!(loaded.mode, Mode::Off);
        assert!((loaded.sensitivity - 0.5).abs() < f32::EPSILON);
    }

    /// Loading a legacy JSON file that lacks the sensitivity field defaults to 0.5.
    #[test]
    fn legacy_file_missing_sensitivity_defaults_to_half() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("mode.json");
        // Write a legacy-format file with no sensitivity field.
        std::fs::write(&path, r#"{"mode":"on"}"#).unwrap();
        let loaded = ModeState::load(&path).unwrap();
        assert_eq!(loaded.mode, Mode::On);
        assert!((loaded.sensitivity - 0.5).abs() < f32::EPSILON);
    }

    /// A successful save leaves no leftover temp file behind and produces a
    /// file `load` can parse cleanly, proving the write is atomic (temp file
    /// + rename) rather than a direct in-place write.
    #[test]
    fn save_leaves_no_temp_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("automate.json");

        let state = ModeState {
            mode: Mode::On,
            sensitivity: 0.7,
        };
        state.save(&path).unwrap();

        assert!(path.exists());
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        // No temp file should remain after a successful save.
        assert!(leftovers.is_empty());
        // And the saved file loads cleanly.
        let loaded = ModeState::load(&path).unwrap();
        assert_eq!(loaded.mode, Mode::On);
    }
}
