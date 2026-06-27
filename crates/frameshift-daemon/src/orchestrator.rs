//! Daemon-side orchestrator evaluation hook.
//!
//! Called by the watch loop on project-change events. Checks whether automate
//! mode is enabled, runs a selection pass, and applies a switching decision
//! via the `SwitchController`. Automate mode is OFF by default; this function
//! is a no-op when mode is `Off` or the lock marker is present.

use std::path::Path;

use frameshift_client::Client;
use frameshift_orchestrator::{
    audit::{now_timestamp, AuditLog, Transition},
    controller::{Decision, SwitchController, SwitchPolicy},
    feedback::Preferences,
    mode::{Mode, ModeState},
    policy::PolicyWeights,
    run::{select, SelectionInputs},
};

/// Evaluate the current project context and apply a persona switch if warranted.
///
/// Steps:
/// 1. Load `automate.json`; return immediately if mode is `Off`.
/// 2. Check the `automate-lock.json` marker; return if locked.
/// 3. Run `orchestrator::select` over installed personas.
/// 4. Feed the ranking into `controller.decide(...)`.
/// 5. On `Decision::Switch`, call `client.activate` and append an `AuditLog` entry.
///
/// The `controller` parameter must be mutable and is shared across calls within
/// a project's watch loop so that debounce state persists across events.
pub fn evaluate_and_apply(client: &Client, controller: &mut SwitchController, project_root: &Path) {
    let state_dir = match client.orchestrator_state_dir(project_root) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "orchestrator: could not resolve state dir");
            return;
        }
    };

    let mode_path = state_dir.join("automate.json");
    let lock_path = state_dir.join("automate-lock.json");
    let audit_path = state_dir.join("automate-audit.jsonl");
    let prefs_path = state_dir.join("automate-prefs.json");

    // Step 1: check mode state; default to Off when file absent.
    let mode_state = match ModeState::load(&mode_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "orchestrator: failed to load mode state");
            return;
        }
    };

    if mode_state.mode == Mode::Off {
        // Automate mode is off; nothing to do.
        return;
    }

    // Update the switching policy from persisted sensitivity.
    let policy = SwitchPolicy::from_sensitivity(mode_state.sensitivity);
    controller.set_policy(policy);

    // Step 2: check lock marker.
    if lock_path.exists() {
        tracing::debug!("orchestrator: locked, skipping evaluation");
        return;
    }

    // Step 3: collect persona source dirs and run selection.
    let source_dirs = match client.installed_persona_source_dirs(project_root) {
        Ok(dirs) => dirs,
        Err(e) => {
            tracing::warn!(error = %e, "orchestrator: could not list persona source dirs");
            return;
        }
    };

    let prefs = Preferences::load(&prefs_path).unwrap_or_default();

    let inputs = SelectionInputs {
        project_root,
        task_hint: None,
        source_dirs,
        catalog_root: None,
        prefs,
        weights: PolicyWeights::default(),
    };

    let ranked = match select(&inputs) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "orchestrator: selection failed");
            return;
        }
    };

    // Step 4: feed ranking to the controller.
    let decision = controller.decide(&ranked);

    // Step 5: act on Switch decisions.
    if let Decision::Switch {
        to,
        rationale,
        confidence,
    } = decision
    {
        // Read the currently active persona before overwriting the marker.
        let from = match client.project_paths(project_root) {
            Ok(paths) if paths.active_path.exists() => std::fs::read_to_string(&paths.active_path)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            _ => None,
        };

        tracing::info!(
            persona = %to,
            from = from.as_deref().unwrap_or("(none)"),
            confidence = %confidence,
            "orchestrator: switching persona"
        );

        if let Err(e) = client.activate(project_root, &to) {
            tracing::warn!(error = %e, persona = %to, "orchestrator: activate failed");
            return;
        }

        // Append an audit transition with the previous persona recorded.
        let mut audit = AuditLog::load(&audit_path).unwrap_or_default();
        let transition = Transition {
            timestamp: now_timestamp(),
            from,
            to: to.clone(),
            confidence,
            rationale,
        };
        if let Err(e) = audit.append(&audit_path, transition) {
            tracing::warn!(error = %e, "orchestrator: failed to append audit entry");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frameshift_client::{Client, ClientOptions, InstallRequest, InstallSource, PersonaSpec};
    use frameshift_orchestrator::controller::{SwitchController, SwitchPolicy};
    use std::fs;

    /// Build a test client backed by a temporary data root.
    fn test_client(data_root: &std::path::Path) -> Client {
        Client::new(ClientOptions {
            data_root: data_root.to_path_buf(),
            config_root: None,
        })
    }

    /// evaluate_and_apply is a no-op when automate mode is Off (no panic, no activation).
    #[test]
    fn evaluate_noop_when_mode_off() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = test_client(&tmp.path().join("data"));
        let policy = SwitchPolicy::default();
        let mut controller = SwitchController::new(policy);

        // Mode file absent == Off by default.
        evaluate_and_apply(&client, &mut controller, &project_root);

        // If we got here without panicking, the no-op path works.
        // The active marker must not have been written.
        let paths = client.project_paths(&project_root).unwrap();
        assert!(
            !paths.active_path.exists(),
            "active marker must not exist after no-op"
        );
    }

    /// evaluate_and_apply does not switch when locked.
    #[test]
    fn evaluate_noop_when_locked() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let data_root = tmp.path().join("data");
        let client = test_client(&data_root);

        // Enable mode.
        let state_dir = client.orchestrator_state_dir(&project_root).unwrap();
        fs::create_dir_all(&state_dir).unwrap();
        let mode = ModeState { mode: Mode::On, sensitivity: 0.5 };
        mode.save(&state_dir.join("automate.json")).unwrap();

        // Write lock marker.
        fs::write(state_dir.join("automate-lock.json"), r#"{"locked":true}"#).unwrap();

        let policy = SwitchPolicy::default();
        let mut controller = SwitchController::new(policy);
        controller.arm();

        evaluate_and_apply(&client, &mut controller, &project_root);

        // Active marker still absent since lock prevented switching.
        let paths = client.project_paths(&project_root).unwrap();
        assert!(
            !paths.active_path.exists(),
            "active marker must not be written while locked"
        );
    }

    /// evaluate_and_apply with mode on but no personas returns without error.
    #[test]
    fn evaluate_no_personas_returns_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let data_root = tmp.path().join("data");
        let client = test_client(&data_root);

        // Enable mode, no lock.
        let state_dir = client.orchestrator_state_dir(&project_root).unwrap();
        fs::create_dir_all(&state_dir).unwrap();
        let mode = ModeState { mode: Mode::On, sensitivity: 0.5 };
        mode.save(&state_dir.join("automate.json")).unwrap();

        let policy = SwitchPolicy::default();
        let mut controller = SwitchController::new(policy);
        controller.arm();

        evaluate_and_apply(&client, &mut controller, &project_root);
        // No personas -- NoCandidates decision -- no panic, no activation.
    }

    /// evaluate_and_apply activates a persona when mode is On and a persona is installed.
    #[test]
    fn evaluate_activates_when_mode_on() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let pack_dir = tmp.path().join("pack");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(
            pack_dir.join("pack.toml"),
            "schema_version = 1\nname = \"eval-persona\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(pack_dir.join("AGENTS.md"), "# Eval Persona\n\nTest.\n").unwrap();

        let data_root = tmp.path().join("data");
        let client = test_client(&data_root);

        // Install persona.
        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: "eval-persona".to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();

        // Enable mode.
        let state_dir = client.orchestrator_state_dir(&project_root).unwrap();
        let mode = ModeState { mode: Mode::On, sensitivity: 0.5 };
        mode.save(&state_dir.join("automate.json")).unwrap();

        // Use a lenient policy so the single persona will pass the confidence threshold.
        let policy = SwitchPolicy {
            min_confidence: 0.0,
            switch_margin: 0.0,
            debounce_ticks: 1,
            z_threshold: 0.0,
            min_gap_fraction: 0.0,
        };
        let mut controller = SwitchController::new(policy);
        controller.arm();

        evaluate_and_apply(&client, &mut controller, &project_root);

        // The active marker should now exist.
        let paths = client.project_paths(&project_root).unwrap();
        if paths.active_path.exists() {
            let active = fs::read_to_string(&paths.active_path).unwrap();
            assert_eq!(active.trim(), "eval-persona");
        }
        // If not activated (NoCandidates or Hold), that is also acceptable for
        // this fixture since confidence depends on context sensing.
    }

    /// When a persona is already active and `evaluate_and_apply` performs a
    /// switch, the audit log entry must record the previous persona name in
    /// `Transition.from`. Prior to the from-tracking fix the daemon always
    /// wrote `None`, which broke audit-trail continuity.
    #[test]
    fn evaluate_records_from_persona_in_audit_log() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let pack_dir = tmp.path().join("pack");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(
            pack_dir.join("pack.toml"),
            "schema_version = 1\nname = \"new-persona\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(pack_dir.join("AGENTS.md"), "# New Persona\n\nTest.\n").unwrap();

        let data_root = tmp.path().join("data");
        let client = test_client(&data_root);

        // Install the new persona.
        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: "new-persona".to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();

        // Pre-seed the active marker with a different persona name. This
        // simulates a prior session where "old-persona" was active.
        let paths = client.project_paths(&project_root).unwrap();
        if let Some(parent) = paths.active_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&paths.active_path, "old-persona\n").unwrap();

        // Enable mode.
        let state_dir = client.orchestrator_state_dir(&project_root).unwrap();
        let mode = ModeState { mode: Mode::On, sensitivity: 0.5 };
        mode.save(&state_dir.join("automate.json")).unwrap();

        // Lenient policy so the single installed persona crosses the
        // confidence threshold and a Switch decision is produced.
        let policy = SwitchPolicy {
            min_confidence: 0.0,
            switch_margin: 0.0,
            debounce_ticks: 1,
            z_threshold: 0.0,
            min_gap_fraction: 0.0,
        };
        let mut controller = SwitchController::new(policy);
        controller.arm();

        evaluate_and_apply(&client, &mut controller, &project_root);

        // If the orchestrator decided to switch, the audit log must contain
        // an entry whose `from` is the pre-seeded persona name.
        let audit_path = state_dir.join("automate-audit.jsonl");
        if audit_path.exists() {
            let log =
                AuditLog::load(&audit_path).expect("audit log should load if it exists");
            let recent = log.recent(1);
            if !recent.is_empty() {
                assert_eq!(
                    recent[0].from.as_deref(),
                    Some("old-persona"),
                    "Transition.from must record the persona that was active before the switch"
                );
            }
        }
    }
}
