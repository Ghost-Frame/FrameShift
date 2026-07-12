//! CLI handler for the `frameshift vault <init|set|get|rm|list>` subcommand.
//!
//! Operates on the current project's vault (`ProjectPaths::vault_path`, a
//! sibling of `config.toml` in the central store), which holds the
//! `{{token}}` values a templated pack (one shipping `pack.template.toml`)
//! substitutes at render time. All operations go through
//! `frameshift-vault-local::LocalAgeBackend` and, before any write,
//! `frameshift_vault::validate`.
//!
//! # Passphrase resolution
//!
//! Every subcommand resolves the vault passphrase the same way (see
//! [`resolve_passphrase`]): `FRAMESHIFT_VAULT_PASSPHRASE` first, then --
//! only when stdin is an interactive terminal -- a hidden `rpassword`
//! prompt. A non-interactive invocation with no env var set fails with a
//! typed error rather than hanging on a prompt nobody can answer.

use std::collections::BTreeMap;
use std::io::IsTerminal;

use clap::{Args, Subcommand};
use frameshift_client::{Client, ProjectPaths, VAULT_PASSPHRASE_ENV};
use frameshift_vault::{
    validate, Auth, Identity, Preferences, RuntimeMode, VaultBackend, VaultData, VaultError,
};
use frameshift_vault_local::{LocalAgeBackend, Recipients};
use secrecy::SecretString;

use crate::util::CliError;

/// Arguments for the `vault` subcommand.
#[derive(Debug, Args)]
pub struct VaultArgs {
    /// Action to perform on the project vault.
    #[command(subcommand)]
    pub action: VaultAction,
}

/// Available vault actions.
#[derive(Debug, Subcommand)]
pub enum VaultAction {
    /// Create an empty vault for the current project. Refuses if one
    /// already exists at `ProjectPaths::vault_path`.
    Init,
    /// Set a token value in the vault. Prompts for the value (hidden, never
    /// echoed) when `--value` is omitted.
    Set {
        /// Token key to set.
        key: String,
        /// Value to store. If omitted, prompted for interactively (hidden).
        #[arg(long)]
        value: Option<String>,
    },
    /// Print a token's raw value to stdout.
    Get {
        /// Token key to read.
        key: String,
    },
    /// Remove a token from the vault.
    Rm {
        /// Token key to remove.
        key: String,
    },
    /// List every token key currently set in the vault. Never prints values.
    List,
}

/// Execute the `vault` subcommand for the project rooted at the current
/// working directory.
pub fn run_vault(client: &Client, args: VaultArgs) -> Result<(), CliError> {
    let project_root = std::env::current_dir()?;
    let paths = client.project_paths(&project_root)?;

    match args.action {
        VaultAction::Init => run_init(&paths),
        VaultAction::Set { key, value } => run_set(&paths, &key, value),
        VaultAction::Get { key } => run_get(&paths, &key),
        VaultAction::Rm { key } => run_rm(&paths, &key),
        VaultAction::List => run_list(&paths),
    }
}

/// Resolve the vault passphrase: [`VAULT_PASSPHRASE_ENV`] first, then --
/// only when stdin is an interactive terminal -- a hidden `rpassword`
/// prompt.
///
/// Shared by every `frameshift vault` subcommand in this module and by the
/// CLI's render-time vault provider (`main::cli_open_vault`), so both call
/// sites resolve the passphrase identically.
///
/// # Errors
///
/// Returns [`VaultError::BackendUnavailable`] when the env var is unset (or
/// empty) and stdin is not a terminal -- this call never blocks waiting on a
/// prompt that cannot be answered -- or when the prompt itself fails to read.
pub(crate) fn resolve_passphrase() -> Result<SecretString, VaultError> {
    if let Ok(value) = std::env::var(VAULT_PASSPHRASE_ENV) {
        if !value.is_empty() {
            return Ok(SecretString::new(value));
        }
    }

    if std::io::stdin().is_terminal() {
        let entered = rpassword::prompt_password("vault passphrase: ").map_err(|e| {
            VaultError::BackendUnavailable(format!("failed to read passphrase: {e}"))
        })?;
        return Ok(SecretString::new(entered));
    }

    Err(VaultError::BackendUnavailable(format!(
        "vault passphrase not available: set {VAULT_PASSPHRASE_ENV} or run interactively"
    )))
}

/// Build the [`LocalAgeBackend`] for `paths.vault_path`, resolving the
/// passphrase via [`resolve_passphrase`].
fn open_backend(paths: &ProjectPaths) -> Result<LocalAgeBackend, CliError> {
    let passphrase = resolve_passphrase()?;
    Ok(LocalAgeBackend::new(
        paths.vault_path.clone(),
        Recipients::Passphrase(passphrase),
    ))
}

/// Build an empty vault for a fresh project.
///
/// The `identity` section is a placeholder, not a real key: this vault
/// stores template token values for `{{token}}` substitution, not a
/// personal identity, but `frameshift_vault::validate` requires non-empty
/// identity fields regardless of how the vault is used. `handle` is set to
/// the project id so the vault file is self-describing; `keypair_pub` is
/// explicitly `"unset"` rather than a fabricated key, since this backend
/// uses passphrase (not recipient-key) encryption and no age keypair is
/// ever generated or consulted here.
fn empty_vault_data(project_id: &str) -> VaultData {
    VaultData {
        schema_version: frameshift_vault::MAX_SUPPORTED_SCHEMA_VERSION,
        identity: Identity {
            keypair_pub: "unset".to_owned(),
            handle: project_id.to_owned(),
        },
        auth: Auth {
            methods: vec!["passphrase".to_owned()],
            unlock: "passphrase".to_owned(),
        },
        preferences: Preferences {
            runtime_mode: RuntimeMode::Rendered,
            publish_intent: "no".to_owned(),
            recovery: "own-backup".to_owned(),
        },
        memory: None,
        variables: BTreeMap::new(),
        overlays: BTreeMap::new(),
    }
}

/// Execute `vault init` -- create an empty vault, refusing if one exists.
fn run_init(paths: &ProjectPaths) -> Result<(), CliError> {
    let backend = open_backend(paths)?;
    if backend.exists()? {
        return Err(CliError::Vault(format!(
            "vault already exists at {}; refusing to overwrite",
            paths.vault_path.display()
        )));
    }

    let data = empty_vault_data(&paths.project_id);
    validate(&data)?;
    backend.save(&data)?;
    println!("vault initialised at {}", paths.vault_path.display());
    Ok(())
}

/// Execute `vault set <key> [--value <v>]` -- store `value` (prompted, hidden,
/// if not given on the command line) under `key`.
fn run_set(paths: &ProjectPaths, key: &str, value: Option<String>) -> Result<(), CliError> {
    let backend = open_backend(paths)?;
    let mut data = backend.open()?;

    let value = match value {
        Some(value) => value,
        None => rpassword::prompt_password(format!("value for '{key}': "))
            .map_err(|e| CliError::Vault(format!("failed to read value: {e}")))?,
    };

    data.set_variable(key.to_owned(), value);
    validate(&data)?;
    backend.save(&data)?;
    println!("set {key}");
    Ok(())
}

/// Read a token's raw value from the vault. Separated from [`run_get`] so
/// the value is directly assertable in tests without capturing stdout.
fn get_value(paths: &ProjectPaths, key: &str) -> Result<String, CliError> {
    let backend = open_backend(paths)?;
    let data = backend.open()?;
    data.get_variable(key)
        .map(str::to_owned)
        .ok_or_else(|| CliError::Vault(format!("key '{key}' is not set in the vault")))
}

/// Execute `vault get <key>` -- print the token's raw value to stdout. This
/// is the subcommand's entire purpose: the value goes to stdout unredacted
/// so callers can pipe it (e.g. `frameshift vault get api_key | some-tool`).
fn run_get(paths: &ProjectPaths, key: &str) -> Result<(), CliError> {
    println!("{}", get_value(paths, key)?);
    Ok(())
}

/// Execute `vault rm <key>` -- remove the token, erroring if it was unset.
fn run_rm(paths: &ProjectPaths, key: &str) -> Result<(), CliError> {
    let backend = open_backend(paths)?;
    let mut data = backend.open()?;
    if data.remove_variable(key).is_none() {
        return Err(CliError::Vault(format!(
            "key '{key}' is not set in the vault"
        )));
    }
    backend.save(&data)?;
    println!("removed {key}");
    Ok(())
}

/// List every token key currently set in the vault, in sorted order. Never
/// returns values. Separated from [`run_list`] so the key set is directly
/// assertable in tests without capturing stdout.
fn list_keys(paths: &ProjectPaths) -> Result<Vec<String>, CliError> {
    let backend = open_backend(paths)?;
    let data = backend.open()?;
    Ok(data.variables().keys().cloned().collect())
}

/// Execute `vault list` -- print every token key, one per line, never a value.
fn run_list(paths: &ProjectPaths) -> Result<(), CliError> {
    for key in list_keys(paths)? {
        println!("{key}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    /// Serializes tests in this module that mutate the process-global
    /// `FRAMESHIFT_VAULT_PASSPHRASE` env var. Rust's default test harness
    /// runs every `#[test]` in this binary on parallel threads, and env vars
    /// are process-global; no other test file in this crate reads or writes
    /// this specific env var, so serializing within this module is
    /// sufficient (mirrors the reasoning documented on
    /// `frameshift-client/tests/project_id_env.rs`, which isolates its own
    /// env-mutating test into a separate binary instead, since it shares a
    /// crate with tests that are not under this module's lock).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Build a [`ProjectPaths`] rooted at `tmp` without touching a real
    /// `Client`/data root -- every field is `pub`, so a fresh literal is the
    /// simplest fixture for vault-only tests.
    fn test_paths(tmp: &Path) -> ProjectPaths {
        ProjectPaths {
            project_root: tmp.to_path_buf(),
            project_id: "test-project".to_owned(),
            config_path: tmp.join("config.toml"),
            lock_path: tmp.join("lock.toml"),
            vault_path: tmp.join("vault.age"),
            cache_dir: tmp.join("cache"),
            project_state_dir: tmp.to_path_buf(),
            active_path: tmp.join("active"),
            personas_dir: tmp.join("personas"),
        }
    }

    /// Set [`VAULT_PASSPHRASE_ENV`] for the duration of the caller's guard.
    fn set_env_passphrase(value: &str) {
        std::env::set_var(VAULT_PASSPHRASE_ENV, value);
    }

    /// Clear [`VAULT_PASSPHRASE_ENV`].
    fn clear_env_passphrase() {
        std::env::remove_var(VAULT_PASSPHRASE_ENV);
    }

    /// `init` -> `set` -> `get`/`list` -> `rm` round-trips correctly through
    /// the age-encrypted backend when the passphrase comes from the env var.
    #[test]
    fn round_trip_init_set_get_list_rm_via_env_passphrase() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_env_passphrase("hunter2");

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = test_paths(tmp.path());

        run_init(&paths).expect("init");
        run_set(&paths, "greeting", Some("hello".to_owned())).expect("set greeting");
        run_set(&paths, "api_key", Some("secret-value".to_owned())).expect("set api_key");

        assert_eq!(
            get_value(&paths, "greeting").expect("get greeting"),
            "hello"
        );
        assert_eq!(
            get_value(&paths, "api_key").expect("get api_key"),
            "secret-value"
        );

        let keys = list_keys(&paths).expect("list");
        assert_eq!(keys, vec!["api_key".to_string(), "greeting".to_string()]);

        run_rm(&paths, "api_key").expect("rm api_key");
        let keys_after_rm = list_keys(&paths).expect("list after rm");
        assert_eq!(keys_after_rm, vec!["greeting".to_string()]);
        assert!(
            get_value(&paths, "api_key").is_err(),
            "api_key must be gone after rm"
        );

        clear_env_passphrase();
    }

    /// `init` on a project that already has a vault refuses to overwrite it.
    #[test]
    fn init_refuses_when_vault_already_exists() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_env_passphrase("hunter2");

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = test_paths(tmp.path());

        run_init(&paths).expect("first init succeeds");
        let err = run_init(&paths).expect_err("second init must refuse");
        assert!(
            matches!(err, CliError::Vault(_)),
            "expected CliError::Vault, got {err:?}"
        );

        clear_env_passphrase();
    }

    /// `get`/`rm` on a key that was never set name the key in the error.
    #[test]
    fn get_and_rm_unknown_key_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_env_passphrase("hunter2");

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = test_paths(tmp.path());
        run_init(&paths).expect("init");

        let get_err = get_value(&paths, "missing").expect_err("get must fail");
        assert!(matches!(get_err, CliError::Vault(msg) if msg.contains("missing")));

        let rm_err = run_rm(&paths, "missing").expect_err("rm must fail");
        assert!(matches!(rm_err, CliError::Vault(msg) if msg.contains("missing")));

        clear_env_passphrase();
    }

    /// Opening the vault with the wrong passphrase propagates as
    /// `CliError::Vault` (wrapping the underlying `VaultError::Crypto`), not
    /// a panic.
    #[test]
    fn wrong_passphrase_propagates_as_cli_error_not_panic() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = test_paths(tmp.path());

        set_env_passphrase("correct-horse");
        run_init(&paths).expect("init with correct passphrase");

        set_env_passphrase("battery-staple");
        let err = get_value(&paths, "anything").expect_err("wrong passphrase must fail, not panic");
        assert!(
            matches!(err, CliError::Vault(_)),
            "expected CliError::Vault, got {err:?}"
        );

        clear_env_passphrase();
    }
}
