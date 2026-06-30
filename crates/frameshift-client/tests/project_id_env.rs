use frameshift_client::{Client, ClientOptions};
use std::fs;
use tempfile::TempDir;

// Lives in its own test binary on purpose: it mutates the process-global
// `FRAMESHIFT_PROJECT_ID` env var. Integration test files compile to separate
// binaries (separate processes), so this can never race with the parallel
// tests in install_flow.rs that read project_id.
#[test]
fn project_id_env_override_is_used_verbatim() {
    let temp = TempDir::new().expect("tempdir");
    let data_root = temp.path().join("data-root");
    let project_root = temp.path().join("project");
    fs::create_dir_all(&project_root).expect("create project");

    std::env::set_var("FRAMESHIFT_PROJECT_ID", "team-alpha");
    let client = Client::new(ClientOptions {
        data_root,
        config_root: None,
    });
    let result = client.project_id(&project_root);
    std::env::remove_var("FRAMESHIFT_PROJECT_ID");

    assert_eq!(result.expect("project id"), "team-alpha");
}
