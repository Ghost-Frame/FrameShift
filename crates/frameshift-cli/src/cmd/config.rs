//! CLI handler for the `frameshift config <get|set>` subcommand.
//!
//! Reads and writes the current project's central config
//! (`projects/<id>/config.toml`) via `frameshift_client::Client::project_config`
//! and `Client::save_project_config`. Keys are scoped to an explicit allowlist
//! so unknown keys fail clearly instead of silently no-op-ing; the allowlist is
//! expected to grow as more `ProjectConfig` fields become CLI-settable.

use clap::{Args, Subcommand};
use frameshift_client::Client;

use crate::util::CliError;

/// Arguments for the `config` subcommand.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Action to perform on the project config.
    #[command(subcommand)]
    pub action: ConfigAction,
}

/// Available config actions.
#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print the current value of a config key.
    Get {
        /// Config key to read (see the allowlist in `cmd::config`).
        key: String,
    },
    /// Set a config key to a new value, persisting it to config.toml.
    Set {
        /// Config key to write (see the allowlist in `cmd::config`).
        key: String,
        /// New value for the key.
        value: String,
    },
}

/// The single config key currently exposed through this subcommand.
///
/// Kept as a named constant (rather than inlined) so the allowlist has one
/// obvious place to grow when more `ProjectConfig` fields become settable.
const KEY_TELEMETRY_OPT_IN: &str = "telemetry_opt_in";

/// Execute the `config` subcommand. The project is the current working
/// directory, matching every sibling subcommand's resolution.
pub fn run_config(client: &Client, args: ConfigArgs) -> Result<(), CliError> {
    let project_root = std::env::current_dir()?;
    match args.action {
        ConfigAction::Get { key } => run_get(client, &project_root, &key),
        ConfigAction::Set { key, value } => run_set(client, &project_root, &key, &value),
    }
}

/// Execute `config get <key>` -- print the key's current value to stdout.
/// Takes the project root explicitly so tests can target a temp project.
fn run_get(client: &Client, project_root: &std::path::Path, key: &str) -> Result<(), CliError> {
    let config = client.project_config(project_root)?;

    match key {
        KEY_TELEMETRY_OPT_IN => {
            println!("{}", config.telemetry_opt_in);
            Ok(())
        }
        other => Err(unknown_key_error(other)),
    }
}

/// Execute `config set <key> <value>` -- parse `value` for `key`'s type,
/// persist the updated config, and confirm on stdout. Creates config.toml
/// with defaults for any fields not being set, if the file did not already
/// exist.
/// Takes the project root explicitly so tests can target a temp project.
fn run_set(
    client: &Client,
    project_root: &std::path::Path,
    key: &str,
    value: &str,
) -> Result<(), CliError> {
    let mut config = client.project_config(project_root)?;

    match key {
        KEY_TELEMETRY_OPT_IN => {
            config.telemetry_opt_in = parse_bool(key, value)?;
        }
        other => return Err(unknown_key_error(other)),
    }

    client.save_project_config(project_root, &config)?;
    println!("{key} = {value}");
    Ok(())
}

/// Build the "unknown key" error for a key that is not in the allowlist.
fn unknown_key_error(key: &str) -> CliError {
    CliError::Config(format!(
        "unknown config key '{key}'; known keys: {KEY_TELEMETRY_OPT_IN}"
    ))
}

/// Parse `value` as a strict `true`/`false` boolean for `key`, rejecting any
/// other spelling (e.g. `1`, `yes`) with a clear error naming the key.
fn parse_bool(key: &str, value: &str) -> Result<bool, CliError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(CliError::Config(format!(
            "invalid value '{other}' for key '{key}'; expected 'true' or 'false'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frameshift_client::ClientOptions;

    /// Build a `Client` rooted at a fresh temp directory so tests never touch
    /// the developer's real `$XDG_DATA_HOME/frameshift` store.
    fn test_client(tmp: &std::path::Path) -> Client {
        Client::new(ClientOptions {
            data_root: tmp.to_path_buf(),
            config_root: None,
            vault: None,
        })
    }

    /// `config get telemetry_opt_in` on a project with no config.toml yet
    /// reads the default (`false`) without erroring.
    #[test]
    fn get_defaults_to_false_when_config_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let client = test_client(tmp.path());
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).expect("create project dir");

        let config = client.project_config(&project_root).expect("read config");
        assert!(!config.telemetry_opt_in);
    }

    /// `config set telemetry_opt_in true` followed by a read round-trips the
    /// new value, creating config.toml along the way.
    #[test]
    fn set_then_get_round_trips_true() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let client = test_client(tmp.path());
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).expect("create project dir");

        run_set(&client, &project_root, KEY_TELEMETRY_OPT_IN, "true").expect("set should succeed");

        let config = client.project_config(&project_root).expect("read config");
        assert!(config.telemetry_opt_in);
    }

    /// Setting `telemetry_opt_in` back to `false` after it was `true`
    /// persists the flip rather than leaving the stale value in place.
    #[test]
    fn set_then_get_round_trips_false_after_true() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let client = test_client(tmp.path());
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).expect("create project dir");

        run_set(&client, &project_root, KEY_TELEMETRY_OPT_IN, "true")
            .expect("first set should succeed");
        run_set(&client, &project_root, KEY_TELEMETRY_OPT_IN, "false")
            .expect("second set should succeed");

        let config = client.project_config(&project_root).expect("read config");
        assert!(!config.telemetry_opt_in);
    }

    /// `config get` on an unknown key returns `CliError::Config` naming the
    /// rejected key.
    #[test]
    fn get_unknown_key_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let client = test_client(tmp.path());
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).expect("create project dir");

        let err = run_get(&client, &project_root, "not_a_real_key").unwrap_err();
        match err {
            CliError::Config(msg) => assert!(msg.contains("not_a_real_key")),
            other => panic!("expected CliError::Config, got {other:?}"),
        }
    }

    /// `config set` on an unknown key returns `CliError::Config` and does not
    /// write anything.
    #[test]
    fn set_unknown_key_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let client = test_client(tmp.path());
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).expect("create project dir");

        let err = run_set(&client, &project_root, "not_a_real_key", "true").unwrap_err();
        assert!(matches!(err, CliError::Config(_)));
    }

    /// `config set telemetry_opt_in <garbage>` rejects any spelling other
    /// than the literal strings `true`/`false`.
    #[test]
    fn set_rejects_non_boolean_value() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let client = test_client(tmp.path());
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).expect("create project dir");

        let err = run_set(&client, &project_root, KEY_TELEMETRY_OPT_IN, "yes").unwrap_err();
        assert!(matches!(err, CliError::Config(_)));
    }

    /// Clap parsing: `config get telemetry_opt_in` parses into `Get`.
    #[test]
    fn parse_get_with_key() {
        use clap::Parser;

        /// Helper command hosting `ConfigAction` so clap can parse a full
        /// `frameshift config <action> ...` invocation in isolation.
        #[derive(Debug, Parser)]
        #[command(name = "frameshift", no_binary_name = true)]
        struct TestCli {
            #[command(subcommand)]
            action: ConfigAction,
        }

        let parsed =
            TestCli::try_parse_from(["get", "telemetry_opt_in"]).expect("get should parse");
        match parsed.action {
            ConfigAction::Get { key } => assert_eq!(key, "telemetry_opt_in"),
            other => panic!("expected Get, got {other:?}"),
        }
    }

    /// Clap parsing: `config set telemetry_opt_in true` parses into `Set`.
    #[test]
    fn parse_set_with_key_and_value() {
        use clap::Parser;

        /// Helper command hosting `ConfigAction` so clap can parse a full
        /// `frameshift config <action> ...` invocation in isolation.
        #[derive(Debug, Parser)]
        #[command(name = "frameshift", no_binary_name = true)]
        struct TestCli {
            #[command(subcommand)]
            action: ConfigAction,
        }

        let parsed =
            TestCli::try_parse_from(["set", "telemetry_opt_in", "true"]).expect("set should parse");
        match parsed.action {
            ConfigAction::Set { key, value } => {
                assert_eq!(key, "telemetry_opt_in");
                assert_eq!(value, "true");
            }
            other => panic!("expected Set, got {other:?}"),
        }
    }
}
