//! Prometheus metrics registry and collectors for the frameshift HTTP server.
//!
//! All collectors are registered in [`Metrics::new`] against a private
//! [`prometheus::Registry`]. The registry is NOT the default global registry so
//! that tests remain hermetic and multiple test instances do not collide.
//!
//! # Collectors
//!
//! | Name | Type | Labels | Purpose |
//! |---|---|---|---|
//! | `http_requests_total` | IntCounterVec | method, path_template, status | Request throughput |
//! | `http_request_duration_seconds` | HistogramVec | method, path_template | Latency distribution |
//! | `packs_published_total` | IntCounter | -- | Pack publish success count |
//! | `pack_downloads_total` | IntCounter | -- | Pack download success count |
//! | `searches_total` | IntCounter | -- | Catalog search invocations |
//!
//! # Cardinality note
//!
//! `path_template` MUST be a route template such as `/v1/packs/{name}` rather
//! than the raw request path. Recording raw paths would cause unbounded label
//! cardinality because every unique pack name or hash would create a new time
//! series. Use `axum::extract::MatchedPath` (which carries the template) when
//! recording labels.

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
};

/// All Prometheus collectors owned by this server instance.
///
/// Constructed once at startup and shared via `Arc<Metrics>` in [`crate::state::AppState`].
/// Clone is cheap because the inner prometheus types are already `Arc`-wrapped.
#[derive(Clone)]
pub struct Metrics {
    /// Private registry that holds only this server's collectors.
    ///
    /// Using a private registry (not `prometheus::default_registry()`) keeps
    /// tests hermetic -- each test that builds a `Metrics` gets its own
    /// isolated collector set with no cross-test state.
    registry: Registry,

    /// Total HTTP requests, labelled by method, path template, and status code.
    ///
    /// `path_template` carries the axum matched route (e.g. `/v1/packs/{name}`)
    /// rather than the raw path to keep cardinality bounded.
    pub http_requests_total: IntCounterVec,

    /// Histogram of per-request wall-clock latency in seconds.
    ///
    /// Labels match `http_requests_total` except no `status` label, because
    /// the duration is recorded before the full response is written.
    pub http_request_duration_seconds: HistogramVec,

    /// Number of packs successfully published via `POST /v1/packs`.
    pub packs_published_total: IntCounter,

    /// Number of successful pack byte downloads (both direct and signed-URL paths).
    pub pack_downloads_total: IntCounter,

    /// Number of catalog search invocations via `GET /v1/packs`.
    pub searches_total: IntCounter,
}

impl Metrics {
    /// Construct and register all collectors against a new private registry.
    ///
    /// # Panics
    ///
    /// Panics if any collector fails to register. This is intentional: a
    /// misconfigured registry at startup should crash fast rather than silently
    /// producing empty metrics.
    pub fn new() -> Self {
        // Private registry -- not the global prometheus default.
        let registry = Registry::new();

        // HTTP request counter: method x path_template x status.
        let http_requests_total = IntCounterVec::new(
            Opts::new(
                "http_requests_total",
                "Total number of HTTP requests processed.",
            ),
            &["method", "path_template", "status"],
        )
        .expect("http_requests_total metric creation must not fail");

        // HTTP request latency histogram: method x path_template.
        // Buckets cover 1 ms to 10 s to accommodate both fast catalog reads
        // and slower object-store uploads.
        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds.",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method", "path_template"],
        )
        .expect("http_request_duration_seconds metric creation must not fail");

        // Domain-level counters: no labels, low cardinality.
        let packs_published_total = IntCounter::new(
            "packs_published_total",
            "Total number of packs successfully published.",
        )
        .expect("packs_published_total metric creation must not fail");

        let pack_downloads_total = IntCounter::new(
            "pack_downloads_total",
            "Total number of successful pack byte downloads (direct and signed-URL).",
        )
        .expect("pack_downloads_total metric creation must not fail");

        let searches_total = IntCounter::new(
            "searches_total",
            "Total number of catalog search invocations.",
        )
        .expect("searches_total metric creation must not fail");

        // Register all collectors -- panics on duplicate or incompatible desc.
        registry
            .register(Box::new(http_requests_total.clone()))
            .expect("register http_requests_total");
        registry
            .register(Box::new(http_request_duration_seconds.clone()))
            .expect("register http_request_duration_seconds");
        registry
            .register(Box::new(packs_published_total.clone()))
            .expect("register packs_published_total");
        registry
            .register(Box::new(pack_downloads_total.clone()))
            .expect("register pack_downloads_total");
        registry
            .register(Box::new(searches_total.clone()))
            .expect("register searches_total");

        Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            packs_published_total,
            pack_downloads_total,
            searches_total,
        }
    }

    /// Encode all registered metrics as Prometheus text exposition format
    /// (content-type `text/plain; version=0.0.4`).
    ///
    /// Returns an empty string if the registry has no samples yet. Never
    /// returns an error in practice -- encoding failures are an internal bug
    /// and are surfaced as an empty string rather than propagated to callers.
    pub fn encode_text(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buf = Vec::new();
        if let Err(e) = encoder.encode(&metric_families, &mut buf) {
            // Encoding failure is a local bug; log it but don't crash the handler.
            tracing::error!(error = %e, "prometheus text encoding failed");
            return String::new();
        }
        // The TextEncoder always produces valid UTF-8 per the Prometheus spec.
        String::from_utf8(buf).unwrap_or_default()
    }
}

/// Default impl delegates to [`Metrics::new`].
impl Default for Metrics {
    /// Create a fresh [`Metrics`] instance with all collectors registered.
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry encodes to valid UTF-8 text even with no observations.
    #[test]
    fn encode_text_produces_valid_utf8_with_no_observations() {
        let metrics = Metrics::new();
        // No observations: the encoder still produces the metric header lines.
        let text = metrics.encode_text();
        // Valid UTF-8 (no panic above means it decoded fine). Labeled vec
        // collectors (http_requests_total) emit no series until a label combo is
        // observed, but the plain IntCounters always render at 0, so the metric
        // names must be present in the exposition text.
        assert!(
            text.contains("pack_downloads_total"),
            "expected always-on counter names in output; got: {text:?}"
        );
    }

    /// Incrementing a counter is reflected in the encoded output.
    #[test]
    fn counter_increment_is_visible_in_encoded_text() {
        let metrics = Metrics::new();

        // Record one search.
        metrics.searches_total.inc();

        let text = metrics.encode_text();
        // The text exposition line for searches_total must show a value of 1.
        assert!(
            text.contains("searches_total 1"),
            "expected 'searches_total 1' in encoded output; got: {text:?}"
        );
    }

    /// Incrementing `packs_published_total` three times yields 3 in output.
    #[test]
    fn packs_published_counter_accumulates() {
        let metrics = Metrics::new();
        metrics.packs_published_total.inc();
        metrics.packs_published_total.inc();
        metrics.packs_published_total.inc();
        let text = metrics.encode_text();
        assert!(
            text.contains("packs_published_total 3"),
            "expected 'packs_published_total 3'; got: {text:?}"
        );
    }
}
