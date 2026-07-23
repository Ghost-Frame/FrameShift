//! Implementation of the `frameshift register` subcommand.
//!
//! Registers this machine's managed author signing key under a handle at the
//! registry (`POST /v1/authors`). Registration is a prerequisite for
//! `frameshift publish --server`, which signs uploads with the same key.

use clap::Args;
use frameshift_client::{identity, Client};

use crate::cmd::keys::with_key_passphrase;
use crate::util::{validate_server_url, CliError};

/// Arguments for the `register` subcommand.
#[derive(Debug, Args)]
pub struct RegisterArgs {
    /// Registry server URL.
    #[arg(long)]
    pub server: String,

    /// Handle to claim for this machine's author key.
    #[arg(long)]
    pub handle: String,

    /// Optional human-readable display name for the author.
    #[arg(long)]
    pub display_name: Option<String>,
}

/// Execute the `register` subcommand.
///
/// Loads (creating on first use) the managed author key, sends a signed
/// `POST /v1/authors`, and prints the claimed handle and its public key.
pub fn run_register(args: RegisterArgs) -> Result<(), CliError> {
    validate_server_url(&args.server)?;
    let client = Client::with_default_data_root()?;

    // Resolve and register inside one passphrase-aware operation so an
    // encrypted fallback key never needs to leak through command arguments.
    let (pubkey, _) = with_key_passphrase(|passphrase| {
        let key = client.author_signing_key_with_passphrase(passphrase)?;
        let pubkey = identity::public_key_b64(&key);
        client.register_author_with_signing_key(
            &args.server,
            &args.handle,
            args.display_name.as_deref(),
            &key,
        )?;
        Ok(pubkey)
    })?;

    println!(
        "registered handle '{}' -> {} at {}",
        args.handle, pubkey, args.server
    );
    Ok(())
}
