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
//! | `creator_workflow_outcomes_total` | IntCounterVec | stage, outcome | Bounded account and publication workflow outcomes |
//! | `publication_moderation_snapshot_available` | IntGauge | -- | Whether queue gauges reflect a successful catalog snapshot |
//! | `publication_quarantine_submissions` | IntGauge | -- | Submissions still in initial quarantine |
//! | `publication_quarantine_oldest_age_seconds` | Gauge | -- | Age of the oldest initially quarantined submission |
//! | `publication_moderation_queue_submissions` | IntGauge | -- | Unresolved submissions awaiting review |
//! | `publication_moderation_queue_oldest_age_seconds` | Gauge | -- | Age of the oldest unresolved submission |
//! | `publication_moderation_reviewers_available` | IntGauge | -- | Distinct accounts with active review authority |
//!
//! # Cardinality note
//!
//! `path_template` MUST be a route template such as `/v1/packs/{name}` rather
//! than the raw request path. Recording raw paths would cause unbounded label
//! cardinality because every unique pack name or hash would create a new time
//! series. Use `axum::extract::MatchedPath` (which carries the template) when
//! recording labels.

use chrono::{DateTime, Utc};
use frameshift_catalog::PublicationModerationSnapshot;
use prometheus::{
    Encoder, Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts,
    Registry, TextEncoder,
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

    /// Account and publication workflow responses grouped by bounded stage and outcome.
    ///
    /// Both labels come from fixed vocabularies in the metrics middleware.
    /// User-controlled identifiers, raw paths, request IDs, and error text are
    /// never used as label values.
    pub creator_workflow_outcomes_total: IntCounterVec,

    /// Whether the publication moderation gauges reflect a successful catalog snapshot.
    pub publication_moderation_snapshot_available: IntGauge,

    /// Number of submissions still in the initial quarantine state.
    pub publication_quarantine_submissions: IntGauge,

    /// Age in seconds of the oldest initially quarantined submission.
    pub publication_quarantine_oldest_age_seconds: Gauge,

    /// Number of unresolved submissions awaiting review or requested changes.
    pub publication_moderation_queue_submissions: IntGauge,

    /// Age in seconds of the oldest unresolved moderation submission.
    pub publication_moderation_queue_oldest_age_seconds: Gauge,

    /// Distinct accounts holding at least one active moderation role.
    pub publication_moderation_reviewers_available: IntGauge,
}

/// Builds, updates, and encodes the server's private Prometheus registry.
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

        let creator_workflow_outcomes_total = IntCounterVec::new(
            Opts::new(
                "creator_workflow_outcomes_total",
                "Creator account and publication workflow responses by bounded stage and outcome.",
            ),
            &["stage", "outcome"],
        )
        .expect("creator_workflow_outcomes_total metric creation must not fail");

        let publication_moderation_snapshot_available = IntGauge::new(
            "publication_moderation_snapshot_available",
            "Whether publication moderation gauges reflect a successful catalog snapshot.",
        )
        .expect("publication_moderation_snapshot_available metric creation must not fail");
        let publication_quarantine_submissions = IntGauge::new(
            "publication_quarantine_submissions",
            "Submissions still in the initial publication quarantine state.",
        )
        .expect("publication_quarantine_submissions metric creation must not fail");
        let publication_quarantine_oldest_age_seconds = Gauge::new(
            "publication_quarantine_oldest_age_seconds",
            "Age in seconds of the oldest initially quarantined publication submission.",
        )
        .expect("publication_quarantine_oldest_age_seconds metric creation must not fail");
        let publication_moderation_queue_submissions = IntGauge::new(
            "publication_moderation_queue_submissions",
            "Unresolved publication submissions awaiting review or requested changes.",
        )
        .expect("publication_moderation_queue_submissions metric creation must not fail");
        let publication_moderation_queue_oldest_age_seconds = Gauge::new(
            "publication_moderation_queue_oldest_age_seconds",
            "Age in seconds of the oldest unresolved publication submission.",
        )
        .expect("publication_moderation_queue_oldest_age_seconds metric creation must not fail");
        let publication_moderation_reviewers_available = IntGauge::new(
            "publication_moderation_reviewers_available",
            "Distinct accounts holding an active moderator or administrator role.",
        )
        .expect("publication_moderation_reviewers_available metric creation must not fail");

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
        registry
            .register(Box::new(creator_workflow_outcomes_total.clone()))
            .expect("register creator_workflow_outcomes_total");
        registry
            .register(Box::new(publication_moderation_snapshot_available.clone()))
            .expect("register publication_moderation_snapshot_available");
        registry
            .register(Box::new(publication_quarantine_submissions.clone()))
            .expect("register publication_quarantine_submissions");
        registry
            .register(Box::new(publication_quarantine_oldest_age_seconds.clone()))
            .expect("register publication_quarantine_oldest_age_seconds");
        registry
            .register(Box::new(publication_moderation_queue_submissions.clone()))
            .expect("register publication_moderation_queue_submissions");
        registry
            .register(Box::new(
                publication_moderation_queue_oldest_age_seconds.clone(),
            ))
            .expect("register publication_moderation_queue_oldest_age_seconds");
        registry
            .register(Box::new(publication_moderation_reviewers_available.clone()))
            .expect("register publication_moderation_reviewers_available");

        Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            packs_published_total,
            pack_downloads_total,
            searches_total,
            creator_workflow_outcomes_total,
            publication_moderation_snapshot_available,
            publication_quarantine_submissions,
            publication_quarantine_oldest_age_seconds,
            publication_moderation_queue_submissions,
            publication_moderation_queue_oldest_age_seconds,
            publication_moderation_reviewers_available,
        }
    }

    /// Refresh publication moderation gauges from one bounded catalog snapshot.
    ///
    /// `None` marks the snapshot unavailable and resets every dependent gauge,
    /// so stale or unsupported data cannot masquerade as a verified queue state.
    pub fn update_publication_moderation_snapshot(
        &self,
        snapshot: Option<&PublicationModerationSnapshot>,
        observed_at: DateTime<Utc>,
    ) {
        let Some(snapshot) = snapshot else {
            self.publication_moderation_snapshot_available.set(0);
            self.publication_quarantine_submissions.set(0);
            self.publication_quarantine_oldest_age_seconds.set(0.0);
            self.publication_moderation_queue_submissions.set(0);
            self.publication_moderation_queue_oldest_age_seconds
                .set(0.0);
            self.publication_moderation_reviewers_available.set(0);
            return;
        };

        self.publication_moderation_snapshot_available.set(1);
        self.publication_quarantine_submissions
            .set(saturating_i64(snapshot.quarantined_submissions));
        self.publication_quarantine_oldest_age_seconds
            .set(age_seconds(snapshot.oldest_quarantined_at, observed_at));
        self.publication_moderation_queue_submissions
            .set(saturating_i64(snapshot.queued_submissions));
        self.publication_moderation_queue_oldest_age_seconds
            .set(age_seconds(snapshot.oldest_queued_at, observed_at));
        self.publication_moderation_reviewers_available
            .set(saturating_i64(snapshot.active_reviewers));
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

/// Convert an unsigned catalog count into Prometheus's signed gauge domain.
fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Return a non-negative age in seconds for an optional queue timestamp.
fn age_seconds(timestamp: Option<DateTime<Utc>>, observed_at: DateTime<Utc>) -> f64 {
    timestamp
        .map(|timestamp| {
            observed_at
                .signed_duration_since(timestamp)
                .num_milliseconds()
                .max(0) as f64
                / 1000.0
        })
        .unwrap_or(0.0)
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

    /// Workflow counters encode only their fixed stage and outcome labels.
    #[test]
    fn creator_workflow_counter_encodes_bounded_labels() {
        let metrics = Metrics::new();
        metrics
            .creator_workflow_outcomes_total
            .with_label_values(&["publisher_key", "client_error"])
            .inc();

        let text = metrics.encode_text();
        assert!(text.contains(
            "creator_workflow_outcomes_total{outcome=\"client_error\",stage=\"publisher_key\"} 1"
        ));
    }

    /// Moderation snapshot gauges encode exact aggregate counts and clamped ages.
    #[test]
    fn moderation_snapshot_gauges_encode_bounded_current_state() {
        let metrics = Metrics::new();
        let observed_at = DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
            .expect("fixture timestamp must parse")
            .with_timezone(&Utc);
        let snapshot = PublicationModerationSnapshot {
            quarantined_submissions: 2,
            oldest_quarantined_at: Some(observed_at - chrono::Duration::seconds(90)),
            queued_submissions: 3,
            oldest_queued_at: Some(observed_at + chrono::Duration::seconds(10)),
            active_reviewers: 1,
        };

        metrics.update_publication_moderation_snapshot(Some(&snapshot), observed_at);
        let text = metrics.encode_text();

        assert!(text.contains("publication_moderation_snapshot_available 1"));
        assert!(text.contains("publication_quarantine_submissions 2"));
        assert!(text.contains("publication_quarantine_oldest_age_seconds 90"));
        assert!(text.contains("publication_moderation_queue_submissions 3"));
        assert!(text.contains("publication_moderation_queue_oldest_age_seconds 0"));
        assert!(text.contains("publication_moderation_reviewers_available 1"));
    }

    /// An unavailable snapshot clears every dependent gauge and marks it unavailable.
    #[test]
    fn unavailable_moderation_snapshot_resets_dependent_gauges() {
        let metrics = Metrics::new();
        let observed_at = Utc::now();
        let snapshot = PublicationModerationSnapshot {
            quarantined_submissions: 2,
            oldest_quarantined_at: Some(observed_at),
            queued_submissions: 3,
            oldest_queued_at: Some(observed_at),
            active_reviewers: 1,
        };
        metrics.update_publication_moderation_snapshot(Some(&snapshot), observed_at);
        metrics.update_publication_moderation_snapshot(None, observed_at);
        let text = metrics.encode_text();

        assert!(text.contains("publication_moderation_snapshot_available 0"));
        assert!(text.contains("publication_quarantine_submissions 0"));
        assert!(text.contains("publication_moderation_queue_submissions 0"));
        assert!(text.contains("publication_moderation_reviewers_available 0"));
    }
}
