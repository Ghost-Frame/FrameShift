//! Tower middleware that records per-request Prometheus metrics.
//!
//! [`MetricsLayer`] wraps every request passing through it and records:
//!
//! - `http_requests_total` -- incremented once per response, labelled by
//!   HTTP method, matched route template (from axum [`MatchedPath`]), and
//!   HTTP status code string.
//! - `http_request_duration_seconds` -- wall-clock latency from the moment
//!   `Service::call` is invoked to when the inner future resolves.
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
use axum::http::Request;
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

impl MetricsLayer {
    /// Create a new [`MetricsLayer`] that records into the given [`Metrics`].
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }
}

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

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for MetricsService<S>
where
    S: Service<Request<ReqBody>, Response = axum::http::Response<ResBody>>
        + Clone
        + Send
        + 'static,
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

            response
        })
    }
}
