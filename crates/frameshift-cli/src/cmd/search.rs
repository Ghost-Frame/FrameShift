//! Implementation of the `frameshift search` subcommand.
//!
//! Searches the registry's pack catalog (`GET /v1/packs`) and prints a short
//! summary line per matching pack.

use clap::Args;
use frameshift_client::{Client, RegistrySearchQuery};

use crate::util::CliError;

/// Arguments for the `search` subcommand.
#[derive(Debug, Args)]
pub struct SearchArgs {
    /// Free-text search term matched against pack name/description/tags.
    pub query: Option<String>,

    /// Restrict results to packs carrying this tag.
    #[arg(long)]
    pub tag: Option<String>,

    /// Maximum number of results to return (server-clamped).
    #[arg(long)]
    pub limit: Option<u32>,
}

/// Execute the `search` subcommand.
///
/// Prints one line per matching pack:
/// `"{name}@{latest|-}  {total_downloads} downloads  {description}"`.
/// Prints `"no packs found"` when the registry returns zero results.
pub fn run_search(args: SearchArgs) -> Result<(), CliError> {
    let client = Client::with_default_data_root()?;
    let query = RegistrySearchQuery {
        query: args.query,
        tag: args.tag,
        limit: args.limit,
        offset: None,
    };

    let results = client.search_registry(&query)?;
    if results.is_empty() {
        println!("no packs found");
        return Ok(());
    }

    for hit in results {
        let version = hit.pack.latest_version.as_deref().unwrap_or("-");
        println!(
            "{}@{}  {} downloads  {}",
            hit.pack.name, version, hit.pack.total_downloads, hit.pack.description
        );
    }

    Ok(())
}
