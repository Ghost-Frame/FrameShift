//! Local and server-side publisher-key lifecycle commands.
//!
//! Private seeds never enter command arguments or output. Native platform
//! credential storage is preferred, with an age-encrypted fallback unlocked by
//! `FRAMESHIFT_KEY_PASSPHRASE` or a hidden terminal prompt. Account bearer
//! tokens use the same environment-or-hidden-prompt rule.

use std::io::IsTerminal as _;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use frameshift_client::{
    Client, ClientError, EnrolledPublisherKey, EnrolledPublisherKeyState, LocalPublisherKeyState,
    PublisherKeyInventory, PublisherKeyMetadata,
};
use secrecy::{ExposeSecret as _, SecretString};

use crate::util::{validate_server_url, CliError};

/// Environment variable containing a bearer token for account-owned key operations.
pub(crate) const ACCESS_TOKEN_ENV: &str = "FRAMESHIFT_ACCESS_TOKEN";
/// Environment variable containing the age-fallback key-storage passphrase.
pub(crate) const KEY_PASSPHRASE_ENV: &str = "FRAMESHIFT_KEY_PASSPHRASE";
/// Environment variable containing a recovery-package passphrase.
const RECOVERY_PASSPHRASE_ENV: &str = "FRAMESHIFT_RECOVERY_PASSPHRASE";

/// Arguments for the `keys` subcommand group.
#[derive(Debug, Args)]
pub struct KeysArgs {
    /// Publisher-key operation to execute.
    #[command(subcommand)]
    pub command: KeysCommand,
}

/// Supported local and remote publisher-key operations.
#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Initialize secure key storage and migrate the legacy seed when present.
    Init,
    /// List local metadata without opening private key material.
    List,
    /// Create a new local key without selecting it when another key is active.
    Create {
        /// Device or purpose label.
        #[arg(long)]
        label: String,
    },
    /// Change a local key's user-visible label.
    Label {
        /// Stable local key identifier.
        key_id: String,
        /// Replacement device or purpose label.
        #[arg(long)]
        label: String,
    },
    /// Select a local key for future signatures.
    Select {
        /// Stable local key identifier.
        key_id: String,
    },
    /// Enroll a local key under an account-owned publisher profile.
    Enroll {
        /// Registry server URL.
        #[arg(long)]
        server: String,
        /// Publisher profile handle.
        #[arg(long)]
        publisher: String,
        /// Local key identifier; defaults to the selected key.
        #[arg(long)]
        key_id: Option<String>,
    },
    /// List public server records for an account-owned publisher profile.
    RemoteList {
        /// Registry server URL.
        #[arg(long)]
        server: String,
        /// Publisher profile handle.
        #[arg(long)]
        publisher: String,
    },
    /// Create and enroll a replacement key, then revoke the previously selected key.
    Rotate {
        /// Registry server URL.
        #[arg(long)]
        server: String,
        /// Publisher profile handle.
        #[arg(long)]
        publisher: String,
        /// Device or purpose label for the replacement key.
        #[arg(long)]
        label: String,
    },
    /// Revoke an enrolled local key and retain its local historical metadata.
    Revoke {
        /// Registry server URL.
        #[arg(long)]
        server: String,
        /// Publisher profile handle.
        #[arg(long)]
        publisher: String,
        /// Stable local key identifier.
        key_id: String,
    },
    /// Revoke a server key by UUID when the originating device is unavailable.
    RemoteRevoke {
        /// Registry server URL.
        #[arg(long)]
        server: String,
        /// Publisher profile handle.
        #[arg(long)]
        publisher: String,
        /// Server-assigned publisher-key UUID.
        remote_key_id: String,
    },
    /// Enroll a new replacement key after account recovery on another device.
    Recover {
        /// Registry server URL.
        #[arg(long)]
        server: String,
        /// Publisher profile handle.
        #[arg(long)]
        publisher: String,
        /// Device or purpose label for the replacement key.
        #[arg(long)]
        label: String,
    },
    /// Export one private key into a user-controlled encrypted recovery package.
    Export {
        /// Stable local key identifier.
        key_id: String,
        /// New recovery-package path; existing files are never overwritten.
        #[arg(long)]
        out: PathBuf,
    },
    /// Import and select an encrypted recovery package.
    Import {
        /// Recovery-package path.
        #[arg(long)]
        input: PathBuf,
        /// Optional replacement label for the restored key.
        #[arg(long)]
        label: Option<String>,
    },
}

/// Execute one publisher-key lifecycle command.
pub fn run_keys(args: KeysArgs) -> Result<(), CliError> {
    let client = Client::with_default_data_root()?;
    match args.command {
        KeysCommand::Init => initialize(&client),
        KeysCommand::List => list_local(&client),
        KeysCommand::Create { label } => create(&client, &label),
        KeysCommand::Label {
            key_id,
            label: replacement,
        } => label(&client, &key_id, &replacement),
        KeysCommand::Select { key_id } => select(&client, &key_id),
        KeysCommand::Enroll {
            server,
            publisher,
            key_id,
        } => enroll(&client, &server, &publisher, key_id.as_deref()),
        KeysCommand::RemoteList { server, publisher } => list_remote(&client, &server, &publisher),
        KeysCommand::Rotate {
            server,
            publisher,
            label,
        } => rotate(&client, &server, &publisher, &label),
        KeysCommand::Revoke {
            server,
            publisher,
            key_id,
        } => revoke(&client, &server, &publisher, &key_id),
        KeysCommand::RemoteRevoke {
            server,
            publisher,
            remote_key_id,
        } => revoke_remote(&client, &server, &publisher, &remote_key_id),
        KeysCommand::Recover {
            server,
            publisher,
            label,
        } => recover(&client, &server, &publisher, &label),
        KeysCommand::Export { key_id, out } => export(&client, &key_id, &out),
        KeysCommand::Import { input, label } => import(&client, &input, label.as_deref()),
    }
}

/// Initialize secure key storage and report legacy migration without exposing seed bytes.
fn initialize(client: &Client) -> Result<(), CliError> {
    let store = client.publisher_key_store();
    let (result, _) = with_key_passphrase(|passphrase| store.initialize(passphrase))?;
    let active = result.inventory.active_key_id.as_deref().unwrap_or("none");
    println!("publisher key storage initialized; selected {active}");
    if let Some(path) = result.legacy_quarantine_path {
        println!(
            "legacy seed migrated byte-for-byte; owner-only plaintext recovery quarantine retained at {}",
            path.display()
        );
    }
    Ok(())
}

/// Print local public metadata in stable inventory order.
fn list_local(client: &Client) -> Result<(), CliError> {
    let Some(inventory) = client.publisher_key_store().load_inventory()? else {
        println!("no local publisher keys");
        return Ok(());
    };
    for key in &inventory.keys {
        print_local_key(&inventory, key);
    }
    Ok(())
}

/// Create one local publisher key through native or encrypted secret storage.
fn create(client: &Client, label: &str) -> Result<(), CliError> {
    let store = client.publisher_key_store();
    let (key, _) = with_key_passphrase(|passphrase| store.create_key(label, passphrase))?;
    println!("created local publisher key {} ({})", key.id, key.label);
    Ok(())
}

/// Replace one local key label.
fn label(client: &Client, key_id: &str, replacement: &str) -> Result<(), CliError> {
    let key = client
        .publisher_key_store()
        .label_key(key_id, replacement)?;
    println!("labeled local publisher key {} as {}", key.id, key.label);
    Ok(())
}

/// Select one active local key for future artifact signatures.
fn select(client: &Client, key_id: &str) -> Result<(), CliError> {
    let key = client.publisher_key_store().select_key(key_id)?;
    println!("selected local publisher key {} ({})", key.id, key.label);
    Ok(())
}

/// Enroll either an explicit local key or the currently selected key.
fn enroll(
    client: &Client,
    server: &str,
    publisher: &str,
    key_id: Option<&str>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let key_id = match key_id {
        Some(key_id) => key_id.to_string(),
        None => selected_key(client)?.id,
    };
    let token = resolve_access_token()?;
    let (remote, _) = with_key_passphrase(|passphrase| {
        client.enroll_publisher_key(server, publisher, &key_id, &token, passphrase)
    })?;
    println!(
        "enrolled local key {} as remote key {} for {}",
        key_id, remote.id, publisher
    );
    Ok(())
}

/// List public server-side key records for one publisher.
fn list_remote(client: &Client, server: &str, publisher: &str) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token()?;
    let keys = client.list_publisher_keys(server, publisher, &token)?;
    if keys.is_empty() {
        println!("no enrolled publisher keys");
        return Ok(());
    }
    for key in &keys {
        println!(
            "{}\t{:?}\t{}\t{}\t{}",
            key.id, key.state, key.label, key.public_key, key.created_at
        );
    }
    Ok(())
}

/// Rotate from the selected key to a newly enrolled key without a lockout window.
fn rotate(client: &Client, server: &str, publisher: &str, label: &str) -> Result<(), CliError> {
    validate_server_url(server)?;
    let old = selected_key(client)?;
    let token = resolve_access_token()?;
    let remote_keys = client.list_publisher_keys(server, publisher, &token)?;
    let old_remote = active_remote_key(&remote_keys, &old.public_key)?.clone();

    let store = client.publisher_key_store();
    let (replacement, passphrase) =
        with_key_passphrase(|passphrase| store.create_key(label, passphrase))?;
    let enrolled = client
        .enroll_publisher_key(
            server,
            publisher,
            &replacement.id,
            &token,
            passphrase.as_ref(),
        )
        .map_err(|error| {
            CliError::Keys(format!(
                "replacement key {} was created locally but enrollment failed: {error}",
                replacement.id
            ))
        })?;
    store.select_key(&replacement.id)?;
    store.mark_revocation_pending(&old.id)?;

    if let Err(error) = client.revoke_publisher_key(server, publisher, &old_remote.id, &token) {
        if is_definitive_revoke_rejection(&error) {
            let local_state = match store.cancel_revocation(&old.id) {
                Ok(_) => format!("local key {} was restored as active", old.id),
                Err(cancel_error) => format!(
                    "local key {} remains revocation_pending because restoration failed: {cancel_error}",
                    old.id
                ),
            };
            return Err(CliError::Keys(format!(
                "replacement key {} remains enrolled and selected, but the registry rejected revocation of old remote key {}: {error}; {local_state}",
                replacement.id, old_remote.id
            )));
        }
        return Err(CliError::Keys(format!(
            "replacement key {} remains enrolled and selected, but revoking old remote key {} had an unconfirmed result: {error}; local key {} remains revocation_pending and can be reconciled with `frameshift keys revoke`",
            replacement.id, old_remote.id, old.id
        )));
    }
    store.mark_revoked(&old.id).map_err(|error| {
        CliError::Keys(format!(
            "remote key {} was revoked, but local key {} remains revocation_pending: {error}",
            old_remote.id, old.id
        ))
    })?;
    println!(
        "rotated publisher {} from local key {} to {} (remote {})",
        publisher, old.id, replacement.id, enrolled.id
    );
    Ok(())
}

/// Revoke one enrolled key with a durable local intent for crash-safe reconciliation.
fn revoke(client: &Client, server: &str, publisher: &str, key_id: &str) -> Result<(), CliError> {
    validate_server_url(server)?;
    let local = local_key(client, key_id)?;
    if local.state == LocalPublisherKeyState::Revoked {
        return Err(CliError::Keys(format!(
            "local publisher key {key_id} is already revoked"
        )));
    }
    let token = resolve_access_token()?;
    let remote_keys = client.list_publisher_keys(server, publisher, &token)?;
    let remote = remote_key_for_public_key(&remote_keys, &local.public_key)?;
    let store = client.publisher_key_store();
    if remote.state == EnrolledPublisherKeyState::Revoked {
        store.mark_revoked(key_id)?;
        println!(
            "reconciled revoked local key {} with remote key {} for {}",
            key_id, remote.id, publisher
        );
        return Ok(());
    }
    store.mark_revocation_pending(key_id)?;
    if let Err(error) = client.revoke_publisher_key(server, publisher, &remote.id, &token) {
        if is_definitive_revoke_rejection(&error) {
            let local_state = match store.cancel_revocation(key_id) {
                Ok(_) => "the local key was restored as active".to_string(),
                Err(cancel_error) => format!(
                    "the local key remains revocation_pending because restoration failed: {cancel_error}"
                ),
            };
            return Err(CliError::Keys(format!(
                "the registry rejected revocation of remote key {}: {error}; {local_state}",
                remote.id
            )));
        }
        return Err(CliError::Keys(format!(
            "remote revocation result is unconfirmed: {error}; local key {key_id} remains revocation_pending and cannot sign; retry this command to reconcile"
        )));
    }
    store.mark_revoked(key_id).map_err(|error| {
        CliError::Keys(format!(
            "remote key {} was revoked, but local key {key_id} remains revocation_pending: {error}",
            remote.id
        ))
    })?;
    println!(
        "revoked local key {} and remote key {} for {}",
        key_id, remote.id, publisher
    );
    Ok(())
}

/// Revoke a remote key by UUID for lost-device recovery without touching local secrets.
fn revoke_remote(
    client: &Client,
    server: &str,
    publisher: &str,
    remote_key_id: &str,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token()?;
    let revoked = client.revoke_publisher_key(server, publisher, remote_key_id, &token)?;
    println!(
        "revoked remote key {} ({}) for {}",
        revoked.id, revoked.label, publisher
    );
    Ok(())
}

/// Create and enroll a replacement key after account recovery on a new device.
fn recover(client: &Client, server: &str, publisher: &str, label: &str) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token()?;
    let store = client.publisher_key_store();
    let (replacement, passphrase) =
        with_key_passphrase(|passphrase| store.create_key(label, passphrase))?;
    let enrolled = client
        .enroll_publisher_key(
            server,
            publisher,
            &replacement.id,
            &token,
            passphrase.as_ref(),
        )
        .map_err(|error| {
            CliError::Keys(format!(
                "replacement key {} was created locally but enrollment failed: {error}",
                replacement.id
            ))
        })?;
    store.select_key(&replacement.id)?;
    println!(
        "enrolled recovery key {} as remote key {} for {}",
        replacement.id, enrolled.id, publisher
    );
    Ok(())
}

/// Export one key into a new passphrase-encrypted recovery package.
fn export(client: &Client, key_id: &str, output: &std::path::Path) -> Result<(), CliError> {
    let recovery_passphrase = resolve_new_recovery_passphrase()?;
    let store = client.publisher_key_store();
    let (_, _) = with_key_passphrase(|storage_passphrase| {
        store.export_recovery(key_id, output, storage_passphrase, &recovery_passphrase)
    })?;
    println!(
        "exported encrypted recovery package for {} to {}",
        key_id,
        output.display()
    );
    Ok(())
}

/// Import and select one encrypted recovery package.
fn import(client: &Client, input: &std::path::Path, label: Option<&str>) -> Result<(), CliError> {
    let recovery_passphrase = resolve_recovery_passphrase()?;
    let store = client.publisher_key_store();
    let (metadata, _) = with_key_passphrase(|storage_passphrase| {
        store.import_recovery(input, &recovery_passphrase, storage_passphrase, label)
    })?;
    println!(
        "imported and selected publisher key {} ({})",
        metadata.id, metadata.label
    );
    Ok(())
}

/// Resolve the selected active local metadata record.
fn selected_key(client: &Client) -> Result<PublisherKeyMetadata, CliError> {
    let inventory = require_inventory(client)?;
    let key_id = inventory
        .active_key_id
        .as_deref()
        .ok_or_else(|| CliError::Keys("no active local publisher key is selected".to_string()))?;
    inventory
        .keys
        .iter()
        .find(|key| key.id == key_id && key.state == LocalPublisherKeyState::Active)
        .cloned()
        .ok_or_else(|| CliError::Keys("selected publisher key metadata is invalid".to_string()))
}

/// Resolve one local metadata record by stable identifier.
fn local_key(client: &Client, key_id: &str) -> Result<PublisherKeyMetadata, CliError> {
    require_inventory(client)?
        .keys
        .into_iter()
        .find(|key| key.id == key_id)
        .ok_or_else(|| CliError::Keys(format!("local publisher key {key_id} was not found")))
}

/// Require a previously initialized local inventory.
fn require_inventory(client: &Client) -> Result<PublisherKeyInventory, CliError> {
    client
        .publisher_key_store()
        .load_inventory()?
        .ok_or_else(|| {
            CliError::Keys(
                "publisher key storage is not initialized; run `frameshift keys init`".to_string(),
            )
        })
}

/// Find the unique active remote record matching one public key.
fn active_remote_key<'a>(
    keys: &'a [EnrolledPublisherKey],
    public_key: &str,
) -> Result<&'a EnrolledPublisherKey, CliError> {
    let mut matches = keys.iter().filter(|key| {
        key.public_key == public_key && key.state == EnrolledPublisherKeyState::Active
    });
    let found = matches.next().ok_or_else(|| {
        CliError::Keys("no active remote key matches the requested local key".to_string())
    })?;
    if matches.next().is_some() {
        return Err(CliError::Keys(
            "multiple active remote keys share the requested public key".to_string(),
        ));
    }
    Ok(found)
}

/// Find the unique remote record for one public key regardless of lifecycle state.
fn remote_key_for_public_key<'a>(
    keys: &'a [EnrolledPublisherKey],
    public_key: &str,
) -> Result<&'a EnrolledPublisherKey, CliError> {
    let mut matches = keys.iter().filter(|key| key.public_key == public_key);
    let found = matches.next().ok_or_else(|| {
        CliError::Keys("no remote key matches the requested local key".to_string())
    })?;
    if matches.next().is_some() {
        return Err(CliError::Keys(
            "multiple remote keys share the requested public key".to_string(),
        ));
    }
    Ok(found)
}

/// Return whether an HTTP response proves the registry rejected revocation.
fn is_definitive_revoke_rejection(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::RegistryRejected {
            status: 400..=499,
            ..
        }
    )
}

/// Print one local metadata record without opening or displaying its secret.
fn print_local_key(inventory: &PublisherKeyInventory, key: &PublisherKeyMetadata) {
    let selected = if inventory.active_key_id.as_deref() == Some(key.id.as_str()) {
        "selected"
    } else {
        "unselected"
    };
    println!(
        "{}\t{:?}\t{}\t{:?}\t{}\t{}",
        key.id, key.state, selected, key.secret_backend, key.label, key.public_key
    );
}

/// Run an operation with an environment passphrase and one hidden-prompt fallback.
pub(crate) fn with_key_passphrase<T>(
    mut operation: impl FnMut(Option<&SecretString>) -> Result<T, ClientError>,
) -> Result<(T, Option<SecretString>), CliError> {
    let initial = secret_from_env(KEY_PASSPHRASE_ENV)?;
    match operation(initial.as_ref()) {
        Ok(value) => Ok((value, initial)),
        Err(error) if initial.is_none() && needs_storage_passphrase(&error) => {
            let passphrase =
                prompt_secret("publisher key storage passphrase: ", KEY_PASSPHRASE_ENV)?;
            operation(Some(&passphrase))
                .map(|value| (value, Some(passphrase)))
                .map_err(CliError::from)
        }
        Err(error) => Err(CliError::from(error)),
    }
}

/// Read an optional bearer token from the environment without prompting.
pub(crate) fn access_token_from_env() -> Result<Option<SecretString>, CliError> {
    secret_from_env(ACCESS_TOKEN_ENV)
}

/// Resolve a bearer token from the environment or a hidden interactive prompt.
fn resolve_access_token() -> Result<SecretString, CliError> {
    match access_token_from_env()? {
        Some(token) => Ok(token),
        None => prompt_secret("account access token: ", ACCESS_TOKEN_ENV),
    }
}

/// Resolve a recovery passphrase, requiring confirmation for newly written packages.
fn resolve_new_recovery_passphrase() -> Result<SecretString, CliError> {
    if let Some(passphrase) = secret_from_env(RECOVERY_PASSPHRASE_ENV)? {
        return Ok(passphrase);
    }
    let first = prompt_secret("new recovery passphrase: ", RECOVERY_PASSPHRASE_ENV)?;
    let second = prompt_secret("confirm recovery passphrase: ", RECOVERY_PASSPHRASE_ENV)?;
    if first.expose_secret() != second.expose_secret() {
        return Err(CliError::Keys(
            "recovery passphrase confirmation did not match".to_string(),
        ));
    }
    Ok(first)
}

/// Resolve the passphrase needed to decrypt an existing recovery package.
fn resolve_recovery_passphrase() -> Result<SecretString, CliError> {
    match secret_from_env(RECOVERY_PASSPHRASE_ENV)? {
        Some(passphrase) => Ok(passphrase),
        None => prompt_secret("recovery passphrase: ", RECOVERY_PASSPHRASE_ENV),
    }
}

/// Read one non-empty UTF-8 secret from an environment variable.
fn secret_from_env(name: &str) -> Result<Option<SecretString>, CliError> {
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(SecretString::new(value))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(CliError::Keys(format!("{name} must contain valid UTF-8")))
        }
    }
}

/// Read a non-empty secret from a terminal without echoing it.
fn prompt_secret(prompt: &str, environment_name: &str) -> Result<SecretString, CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Keys(format!(
            "secret input is unavailable; set {environment_name} or run interactively"
        )));
    }
    let value = rpassword::prompt_password(prompt)
        .map_err(|error| CliError::Keys(format!("failed to read hidden input: {error}")))?;
    if value.is_empty() {
        return Err(CliError::Keys("secret input cannot be empty".to_string()));
    }
    Ok(SecretString::new(value))
}

/// Identify errors for which supplying the encrypted-storage passphrase can recover.
fn needs_storage_passphrase(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::PublisherKeychainUnavailable { .. }
            | ClientError::PublisherKeyPassphraseRequired { .. }
    )
}

#[cfg(test)]
/// Publisher-key CLI helper tests.
mod tests {
    use super::*;

    /// Build one public remote-key fixture.
    fn remote_key(public_key: &str, state: EnrolledPublisherKeyState) -> EnrolledPublisherKey {
        EnrolledPublisherKey {
            id: format!("remote-{state:?}"),
            publisher_id: "publisher-id".to_string(),
            public_key: public_key.to_string(),
            label: "device".to_string(),
            state,
            created_at: "2026-07-22T00:00:00Z".to_string(),
            revoked_at: None,
            last_used_at: None,
        }
    }

    /// Remote matching ignores revoked history and selects the active record.
    #[test]
    fn active_remote_match_ignores_revoked_history() {
        let keys = vec![
            remote_key("public-a", EnrolledPublisherKeyState::Revoked),
            remote_key("public-a", EnrolledPublisherKeyState::Active),
        ];
        assert_eq!(
            active_remote_key(&keys, "public-a").unwrap().state,
            EnrolledPublisherKeyState::Active
        );
    }

    /// Reconciliation can resolve a revoked server record by public key.
    #[test]
    fn remote_match_includes_revoked_record() {
        let keys = vec![remote_key("public-a", EnrolledPublisherKeyState::Revoked)];
        assert_eq!(
            remote_key_for_public_key(&keys, "public-a").unwrap().state,
            EnrolledPublisherKeyState::Revoked
        );
    }

    /// Client transport failures stay ambiguous while explicit 4xx responses are definitive.
    #[test]
    fn revoke_rejection_classification_preserves_ambiguous_failures() {
        let rejected = ClientError::RegistryRejected {
            url: "https://registry.example/v1/keys/id".to_string(),
            status: 400,
            message: "cannot revoke the last active publisher key".to_string(),
        };
        let transport = ClientError::RegistryHttp {
            url: "https://registry.example/v1/keys/id".to_string(),
            detail: "connection reset".to_string(),
        };
        assert!(is_definitive_revoke_rejection(&rejected));
        assert!(!is_definitive_revoke_rejection(&transport));
    }

    /// Storage fallback prompts only for the two recoverable typed errors.
    #[test]
    fn storage_passphrase_error_classification_is_narrow() {
        assert!(needs_storage_passphrase(
            &ClientError::PublisherKeychainUnavailable {
                detail: "unavailable".to_string(),
            }
        ));
        assert!(needs_storage_passphrase(
            &ClientError::PublisherKeyPassphraseRequired {
                key_id: "pk_test".to_string(),
            }
        ));
        assert!(!needs_storage_passphrase(
            &ClientError::PublisherKeyNotFound {
                key_id: "pk_test".to_string(),
            }
        ));
    }
}
