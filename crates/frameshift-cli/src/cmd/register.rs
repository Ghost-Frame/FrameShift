//! Implementation of the `frameshift register` subcommand.
//!
//! Registers this machine's managed author signing key under a handle at the
//! registry (`POST /v1/authors`). Registration is a prerequisite for
//! `frameshift publish --server`, which signs uploads with the same key.

use clap::Args;
use frameshift_client::Client;

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

    // Resolve the public key first so the success line can echo it even though
    // the server derives the key from the request signature itself.
    let pubkey = client.author_pubkey_b64()?;
    client.register_author(&args.server, &args.handle, args.display_name.as_deref())?;

    println!(
        "registered handle '{}' -> {} at {}",
        args.handle, pubkey, args.server
    );
    Ok(())
}
