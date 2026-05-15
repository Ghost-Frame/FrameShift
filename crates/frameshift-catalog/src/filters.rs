//! Search filter and result types for pack discovery.
//!
//! [`PackSearchFilters`] is the input to
//! [`crate::backend::CatalogBackend::search_packs`]; [`PackSearchResult`] is one
//! element of the output. [`SortMode`] controls the ranking algorithm the backend
//! applies.

use crate::identity::Ed25519PublicKey;
use crate::records::PackRecord;

/// Controls how search results are ranked.
///
/// The default is `Recent` (newest packs first). Backends MUST implement a
/// deterministic tiebreaker (e.g. `name ASC`) for equal scores within any
/// sort mode so that paginated results are stable across requests.
///
/// # Serde
///
/// Serializes as a lowercase kebab-case string:
/// - `Trending` -> `"trending"`
/// - `TopRated` -> `"top-rated"`
/// - `Recent` -> `"recent"`
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SortMode {
    /// Rank by recent download velocity (trending packs first).
    Trending,

    /// Rank by total download count (most downloaded packs first).
    TopRated,

    /// Rank by publication date, newest first.
    ///
    /// This is the default when no sort mode is specified.
    #[default]
    Recent,
}

/// Filters passed to [`crate::backend::CatalogBackend::search_packs`].
///
/// All fields are optional except `sort`, `limit`, and `offset`, which have
/// sensible defaults. A search with all optional fields set to `None` returns
/// the most-recent packs paginated by `limit`/`offset`.
///
/// # Pagination
///
/// Use `limit` + `offset` for cursor-free pagination. The total result set size
/// is not returned by `search_packs`; callers may detect end-of-results by
/// receiving a response shorter than `limit`.
///
/// # Invariants
///
/// - `limit` of `0` is valid and returns an empty result (some backends may
///   return up to their internal minimum instead -- document adapter behavior).
/// - `offset` beyond the total result count returns an empty `Vec`.
/// - If both `query` and `tag` are `Some`, the backend applies both filters
///   (AND semantics, not OR).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackSearchFilters {
    /// Full-text or prefix search query matched against pack name and description.
    ///
    /// `None` means no text filter is applied.
    pub query: Option<String>,

    /// Filter results to packs that include this exact tag.
    ///
    /// `None` means no tag filter is applied.
    pub tag: Option<String>,

    /// Filter results to packs whose current owner matches this public key.
    ///
    /// `None` means no author filter is applied.
    pub author: Option<Ed25519PublicKey>,

    /// Filter results to packs tagged for a specific runtime context
    /// (e.g. `"chiasm"`, `"axon"`).
    ///
    /// `None` means no context filter is applied.
    pub target_context: Option<String>,

    /// The sort order to apply to results.
    ///
    /// Defaults to [`SortMode::Recent`].
    pub sort: SortMode,

    /// Maximum number of results to return.
    ///
    /// A value of `0` is valid. Callers SHOULD use a reasonable upper bound
    /// (e.g. 100) to avoid large result sets.
    pub limit: u32,

    /// Number of results to skip before returning matches.
    ///
    /// Used for cursor-free pagination. `0` means start from the first result.
    pub offset: u32,
}

/// Default filter set: no constraints, `SortMode::Recent`, limit 20, offset 0.
impl Default for PackSearchFilters {
    /// Returns filters with no constraints and `SortMode::Recent`.
    ///
    /// Default `limit` is 20; default `offset` is 0.
    fn default() -> Self {
        Self {
            query: None,
            tag: None,
            author: None,
            target_context: None,
            sort: SortMode::Recent,
            limit: 20,
            offset: 0,
        }
    }
}

/// A single result from [`crate::backend::CatalogBackend::search_packs`].
///
/// Pairs the matching [`PackRecord`] with a relevance score that backends use
/// to rank results. The score's scale is backend-defined; callers MUST NOT
/// compare scores across backends.
///
/// # Ordering
///
/// Results are returned in descending score order. When two results have equal
/// scores, the backend MUST apply a deterministic tiebreaker (typically
/// `name ASC`) so that paginated results are stable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackSearchResult {
    /// The matching pack record.
    pub pack: PackRecord,

    /// The backend-assigned relevance score for this result.
    ///
    /// Higher scores indicate better matches. The scale is backend-specific;
    /// do not compare scores across different backend implementations.
    pub score: f32,
}

#[cfg(test)]
/// Unit tests for search filter types and sort mode defaults.
mod tests {
    use super::*;

    #[test]
    /// SortMode::default() returns the Recent variant.
    fn sort_mode_default_is_recent() {
        assert_eq!(SortMode::default(), SortMode::Recent);
    }

    #[test]
    /// PackSearchFilters::default() has Recent sort, limit 20, offset 0.
    fn pack_search_filters_default_sort_is_recent() {
        let f = PackSearchFilters::default();
        assert_eq!(f.sort, SortMode::Recent);
        assert_eq!(f.limit, 20);
        assert_eq!(f.offset, 0);
    }

    #[test]
    /// All SortMode variants roundtrip correctly through serde JSON.
    fn sort_mode_serde_roundtrip() {
        for mode in [SortMode::Trending, SortMode::TopRated, SortMode::Recent] {
            let json = serde_json::to_string(&mode).expect("serialize");
            let back: SortMode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(mode, back);
        }
    }
}
