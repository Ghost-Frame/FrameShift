//! Tracing middleware configuration.
//!
//! Provides [`make_trace_layer`], which returns a
//! [`tower_http::trace::TraceLayer`] configured for the frameshift server.
//!
//! # Span fields
//!
//! Each HTTP request opens a span with the following fields:
//!
//! | Field | Value |
//! |---|---|
//! | `method` | HTTP method (GET, POST, ...) |
//! | `path` | Request URI path |
//! | `status` | HTTP response status code (filled on response) |
//! | `request_id` | UUID v4 from `x-request-id` (filled by request_id middleware) |
//!
//! # Privacy
//!
//! Request and response bodies are NEVER logged. Query strings are included in
//! `path` via the URI, which is intentional -- query params are not secret for
//! the read-only endpoints in this milestone. If a future endpoint carries
//! sensitive query params, the span configuration here MUST be adjusted.

use axum::http::Request;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::{Level, Span};

/// A [`tower_http::trace::MakeSpan`] that opens an `http_request` span with a
/// pre-declared `request_id` field.
///
/// `tracing` silently drops `Span::record` calls for fields that were NOT
/// declared at span creation time.  The request-ID middleware records the id
/// after the span is created, so the field MUST be declared up front (as
/// [`tracing::field::Empty`]) or the recorded value never appears in logs.
#[derive(Clone, Copy, Debug, Default)]
pub struct PersonifyMakeSpan;

impl<B> tower_http::trace::MakeSpan<B> for PersonifyMakeSpan {
    /// Open one span per HTTP request with the fields documented at the module
    /// level.  `request_id` is declared empty so the request-ID middleware can
    /// populate it via `Span::current().record("request_id", ...)`.
    fn make_span(&mut self, request: &Request<B>) -> Span {
        tracing::span!(
            Level::DEBUG,
            "http_request",
            method = %request.method(),
            path = %request.uri().path(),
            request_id = tracing::field::Empty,
            status = tracing::field::Empty,
        )
    }
}

/// Build a [`TraceLayer`] configured for the frameshift HTTP server.
///
/// Opens a `DEBUG`-level span per request via [`PersonifyMakeSpan`] (which
/// pre-declares the `request_id` and `status` fields). On response, logs at
/// `INFO` level (controlled by `DefaultOnResponse`). Request and response
/// bodies are never captured.
pub fn make_trace_layer() -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    PersonifyMakeSpan,
> {
    TraceLayer::new_for_http()
        .make_span_with(PersonifyMakeSpan)
        .on_response(DefaultOnResponse::new().level(Level::INFO))
}
