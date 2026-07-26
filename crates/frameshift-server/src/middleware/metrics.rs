//! Tower middleware that records per-request Prometheus metrics.
//!
//! [`MetricsLayer`] wraps every request passing through it and records:
//!
//! - `http_requests_total` -- incremented once per response, labelled by
//!   HTTP method, matched route template (from axum [`MatchedPath`]), and
//!   HTTP status code string.
//! - `http_request_duration_seconds` -- wall-clock latency from the moment
//!   `Service::call` is invoked to when the inner future resolves.
//! - `creator_workflow_outcomes_total` -- bounded account and publication
//!   workflow responses grouped by fixed stage and outcome vocabularies.
//!
//! # Path template strategy
//!
//! Raw request paths (e.g. `/v1/packs/my-great-persona/versions/1.2.3`)
//! would produce unbounded label cardinality. Instead the middleware reads
//! axum's [`MatchedPath`] extension, which carries the route template string
//! (`/v1/packs/{name}/versions/{version}`). When no template is available
//! (e.g. 404 for an unmatched path) the label falls back to the literal
//! string `"<unmatched>"`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use axum::extract::MatchedPath;
use axum::http::{Method, Request, StatusCode};
use tower::{Layer, Service};

use crate::metrics::Metrics;

/// Tower [`Layer`] that injects [`MetricsService`] into the middleware stack.
///
/// Constructed with a shared reference to the server [`Metrics`] so that all
/// requests update the same collectors regardless of which async task handles
/// the request.
#[derive(Clone)]
pub struct MetricsLayer {
    /// Shared collector set -- cheap Arc clone per layer invocation.
    metrics: Arc<Metrics>,
}

/// Constructs metrics layers around one shared collector set.
impl MetricsLayer {
    /// Create a new [`MetricsLayer`] that records into the given [`Metrics`].
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }
}

/// Wraps one Tower service with request metrics collection.
impl<S> Layer<S> for MetricsLayer {
    /// The wrapped service type produced by this layer.
    type Service = MetricsService<S>;

    /// Wrap `inner` with a [`MetricsService`] that records request metrics.
    fn layer(&self, inner: S) -> Self::Service {
        MetricsService {
            inner,
            metrics: Arc::clone(&self.metrics),
        }
    }
}

/// Tower [`Service`] that records `http_requests_total` and
/// `http_request_duration_seconds` for every request.
///
/// The path template is extracted from the axum [`MatchedPath`] request
/// extension, which is populated by axum's router after route matching. This
/// means the label reflects the route pattern rather than the raw URL.
#[derive(Clone)]
pub struct MetricsService<S> {
    /// The wrapped inner service (next layer or the handler itself).
    inner: S,
    /// Shared collector set.
    metrics: Arc<Metrics>,
}

/// Type alias for the boxed future returned by [`MetricsService::call`].
///
/// Boxing avoids a stable `impl Trait` associated type (not yet available on
/// trait impls) and keeps the service usable across async trait boundaries.
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Map one matched method and route template to a bounded creator workflow stage.
///
/// Every accepted path is an axum route template, never a raw request path.
/// Keeping the mapping explicit prevents user-controlled identifiers from
/// entering Prometheus labels.
fn creator_workflow_stage(method: &Method, path_template: &str) -> Option<&'static str> {
    match (method.as_str(), path_template) {
        ("GET" | "PATCH", "/v1/account") => Some("account"),
        ("POST", "/v1/publishers") | ("PATCH", "/v1/publishers/{handle}") => Some("publisher"),
        (
            "GET" | "POST",
            "/v1/publishers/{handle}/keys" | "/v1/publishers/{handle}/keys/challenge",
        )
        | ("DELETE", "/v1/publishers/{handle}/keys/{key_id}") => Some("publisher_key"),
        ("GET", "/v1/publish-intents/{id}")
        | ("POST", "/v1/publish-intents" | "/v1/publish-intents/") => Some("publication_intent"),
        ("GET", "/v1/publication-submissions/{id}")
        | ("POST", "/v1/publication-submissions" | "/v1/publication-submissions/") => {
            Some("quarantine")
        }
        ("POST", "/v1/moderation/publication-submissions/{submission_id}/promotion") => {
            Some("promotion")
        }
        (
            "GET",
            "/v1/moderation/publication-submissions/{submission_id}"
            | "/v1/moderation/publication-submissions/{submission_id}/artifact",
        )
        | ("POST", "/v1/moderation/publication-submissions/{submission_id}/decisions") => {
            Some("moderation")
        }
        (
            "GET",
            "/v1/publishers/{handle}/publication-appeals" | "/v1/admin/publication-appeals",
        )
        | (
            "POST",
            "/v1/publishers/{handle}/publication-decisions/{decision_id}/appeal"
            | "/v1/admin/publication-appeals/{appeal_id}/resolution",
        ) => Some("appeal"),
        (
            "POST",
            "/v1/publication-submissions/{id}/withdraw"
            | "/v1/admin/publishers/{publisher_id}/suspend"
            | "/v1/admin/packs/{name}/{version}/tombstone",
        ) => Some("lifecycle"),
        _ => None,
    }
}

/// Reduce an HTTP response or transport error to a bounded workflow outcome.
fn creator_workflow_outcome(status: Option<StatusCode>) -> &'static str {
    match status {
        None => "transport_error",
        Some(status) if status.is_success() => "success",
        Some(status) if status.is_client_error() => "client_error",
        Some(status) if status.is_server_error() => "server_error",
        Some(_) => "other_status",
    }
}

/// Records bounded metrics while preserving the wrapped service contract.
impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for MetricsService<S>
where
    S: Service<Request<ReqBody>, Response = axum::http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    /// Propagate the response type unchanged.
    type Response = S::Response;
    /// Propagate the error type unchanged.
    type Error = S::Error;
    /// Boxed future to avoid an `impl Trait` associated type.
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    /// Delegate readiness to the inner service.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Record latency and request count, then delegate to `inner`.
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Extract the method string before the request is consumed.
        let creator_stage = creator_workflow_stage(
            req.method(),
            req.extensions()
                .get::<MatchedPath>()
                .map_or("<unmatched>", MatchedPath::as_str),
        );
        let method = req.method().as_str().to_string();

        // Extract the matched route template from axum's extensions.
        // MatchedPath is populated by axum after routing; it is absent for
        // requests that do not match any route (404). Fall back to a fixed
        // sentinel so those requests still land in a bounded label bucket.
        let path_template = req
            .extensions()
            .get::<MatchedPath>()
            .map(|mp| mp.as_str().to_string())
            .unwrap_or_else(|| "<unmatched>".to_string());

        let metrics = Arc::clone(&self.metrics);
        let start = Instant::now();

        // Clone inner to satisfy the borrow checker when moving into the async
        // block -- the original `self.inner` was mutably borrowed by poll_ready.
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let response = inner.call(req).await;

            // Elapsed wall-clock time in fractional seconds.
            let elapsed = start.elapsed().as_secs_f64();

            // Determine the status string, or a sentinel on transport error.
            let status = match &response {
                Ok(resp) => resp.status().as_u16().to_string(),
                Err(_) => "error".to_string(),
            };

            // Record latency (no status label -- smaller cardinality).
            metrics
                .http_request_duration_seconds
                .with_label_values(&[&method, &path_template])
                .observe(elapsed);

            // Increment the request counter with the full label set.
            metrics
                .http_requests_total
                .with_label_values(&[&method, &path_template, &status])
                .inc();

            if let Some(stage) = creator_stage {
                let outcome =
                    creator_workflow_outcome(response.as_ref().ok().map(|value| value.status()));
                metrics
                    .creator_workflow_outcomes_total
                    .with_label_values(&[stage, outcome])
                    .inc();
            }

            response
        })
    }
}

#[cfg(test)]
/// Unit tests for bounded workflow classification and outcome mapping.
mod tests {
    use super::{creator_workflow_outcome, creator_workflow_stage};
    use axum::http::{Method, StatusCode};

    /// Every creator workflow route maps to its fixed stage.
    #[test]
    fn creator_routes_map_to_bounded_stages() {
        let cases = [
            (Method::GET, "/v1/account", "account"),
            (Method::PATCH, "/v1/account", "account"),
            (Method::POST, "/v1/publishers", "publisher"),
            (Method::PATCH, "/v1/publishers/{handle}", "publisher"),
            (Method::GET, "/v1/publishers/{handle}/keys", "publisher_key"),
            (
                Method::POST,
                "/v1/publishers/{handle}/keys",
                "publisher_key",
            ),
            (
                Method::POST,
                "/v1/publishers/{handle}/keys/challenge",
                "publisher_key",
            ),
            (
                Method::DELETE,
                "/v1/publishers/{handle}/keys/{key_id}",
                "publisher_key",
            ),
            (Method::POST, "/v1/publish-intents", "publication_intent"),
            (Method::POST, "/v1/publish-intents/", "publication_intent"),
            (
                Method::GET,
                "/v1/publish-intents/{id}",
                "publication_intent",
            ),
            (Method::POST, "/v1/publication-submissions", "quarantine"),
            (Method::POST, "/v1/publication-submissions/", "quarantine"),
            (
                Method::GET,
                "/v1/publication-submissions/{id}",
                "quarantine",
            ),
            (
                Method::GET,
                "/v1/moderation/publication-submissions/{submission_id}",
                "moderation",
            ),
            (
                Method::GET,
                "/v1/moderation/publication-submissions/{submission_id}/artifact",
                "moderation",
            ),
            (
                Method::POST,
                "/v1/moderation/publication-submissions/{submission_id}/decisions",
                "moderation",
            ),
            (
                Method::POST,
                "/v1/moderation/publication-submissions/{submission_id}/promotion",
                "promotion",
            ),
            (
                Method::POST,
                "/v1/publishers/{handle}/publication-decisions/{decision_id}/appeal",
                "appeal",
            ),
            (
                Method::GET,
                "/v1/publishers/{handle}/publication-appeals",
                "appeal",
            ),
            (Method::GET, "/v1/admin/publication-appeals", "appeal"),
            (
                Method::POST,
                "/v1/admin/publication-appeals/{appeal_id}/resolution",
                "appeal",
            ),
            (
                Method::POST,
                "/v1/publication-submissions/{id}/withdraw",
                "lifecycle",
            ),
            (
                Method::POST,
                "/v1/admin/publishers/{publisher_id}/suspend",
                "lifecycle",
            ),
            (
                Method::POST,
                "/v1/admin/packs/{name}/{version}/tombstone",
                "lifecycle",
            ),
        ];

        for (method, path, expected) in cases {
            assert_eq!(
                creator_workflow_stage(&method, path),
                Some(expected),
                "{method} {path}"
            );
        }
    }

    /// Public profile reads and unmatched paths do not enter creator workflow metrics.
    #[test]
    fn unrelated_routes_are_not_classified() {
        assert_eq!(
            creator_workflow_stage(&Method::GET, "/v1/publishers/{handle}"),
            None
        );
        assert_eq!(creator_workflow_stage(&Method::GET, "<unmatched>"), None);
    }

    /// Response status classes and transport failures map to fixed outcomes.
    #[test]
    fn response_statuses_map_to_bounded_outcomes() {
        assert_eq!(creator_workflow_outcome(Some(StatusCode::OK)), "success");
        assert_eq!(
            creator_workflow_outcome(Some(StatusCode::BAD_REQUEST)),
            "client_error"
        );
        assert_eq!(
            creator_workflow_outcome(Some(StatusCode::INTERNAL_SERVER_ERROR)),
            "server_error"
        );
        assert_eq!(
            creator_workflow_outcome(Some(StatusCode::FOUND)),
            "other_status"
        );
        assert_eq!(creator_workflow_outcome(None), "transport_error");
    }
}
