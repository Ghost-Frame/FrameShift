//! Implementation of the `frameshift search` subcommand.
//!
//! Searches the registry's pack catalog (`GET /v1/packs`) and prints a short
//! summary line per matching pack.

use clap::Args;
use frameshift_client::{Client, RegistrySearchQuery, RegistrySearchResult};

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
/// `"{name}@{latest|-} by {owner}  {total_downloads} downloads  {description}"`.
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
        let owner = format_owner(&hit);
        println!(
            "{}@{} by {}  {} downloads  {}",
            hit.pack.name, version, owner, hit.pack.total_downloads, hit.pack.description
        );
    }

    Ok(())
}

/// Prefer publisher attribution, then legacy handle, then a bounded raw-key label.
fn format_owner(hit: &RegistrySearchResult) -> String {
    if let Some(publisher) = &hit.publisher {
        return format!("@{}", publisher.handle);
    }
    if let Some(author) = &hit.legacy_author {
        return format!("@{}", author.handle);
    }
    let prefix: String = hit.pack.current_author.chars().take(12).collect();
    let suffix = if hit.pack.current_author.chars().count() > 12 {
        "..."
    } else {
        ""
    };
    format!("key:{prefix}{suffix}")
}

#[cfg(test)]
/// Unit tests for ownership-aware search attribution.
mod tests {
    use super::*;
    use frameshift_client::{
        RegistryLegacyAuthorSummary, RegistryPackSummary, RegistryPublisherSummary,
    };

    /// Build one search hit for attribution precedence tests.
    fn hit() -> RegistrySearchResult {
        RegistrySearchResult {
            pack: RegistryPackSummary {
                name: "demo".to_string(),
                current_author: "abcdefghijklmnop".to_string(),
                description: "demo".to_string(),
                tags: Vec::new(),
                latest_version: Some("1.0.0".to_string()),
                total_downloads: 1,
            },
            score: 1.0,
            publisher: None,
            legacy_author: None,
        }
    }

    #[test]
    /// Publisher attribution takes precedence over legacy identity.
    fn publisher_attribution_is_preferred() {
        let mut hit = hit();
        hit.publisher = Some(RegistryPublisherSummary {
            id: "publisher-id".to_string(),
            handle: "publisher".to_string(),
            display_name: "Publisher".to_string(),
        });
        hit.legacy_author = Some(RegistryLegacyAuthorSummary {
            handle: "legacy".to_string(),
            display_name: None,
        });

        assert_eq!(format_owner(&hit), "@publisher");
    }

    #[test]
    /// Legacy attribution is used when no publisher identity is present.
    fn legacy_attribution_is_the_compatibility_fallback() {
        let mut hit = hit();
        hit.legacy_author = Some(RegistryLegacyAuthorSummary {
            handle: "legacy".to_string(),
            display_name: None,
        });

        assert_eq!(format_owner(&hit), "@legacy");
    }

    #[test]
    /// Raw-key attribution remains available for older registry responses.
    fn raw_key_attribution_is_bounded() {
        assert_eq!(format_owner(&hit()), "key:abcdefghijkl...");
    }
}
