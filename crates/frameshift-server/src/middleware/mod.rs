//! HTTP middleware modules for the frameshift server.
//!
//! Middleware is applied globally in [`crate::router::app`] in the following
//! order (outermost to innermost; each layer wraps all inner layers):
//!
//! 1. `metrics` -- records `http_requests_total` and
//!    `http_request_duration_seconds` into the Prometheus registry.  Reads
//!    `MatchedPath` from request extensions for bounded-cardinality labels.
//! 2. `request_id` -- generates or forwards `x-request-id`, records it in the
//!    tracing span, and copies it to response headers.
//! 3. `tracing` -- [`tower_http::trace::TraceLayer`] that opens a span per
//!    request, enriched with the request-id from step 2.
//! 4. `compression` -- [`tower_http::compression::CompressionLayer`] for gzip.
//! 5. `body_limit` -- [`tower_http::limit::RequestBodyLimitLayer`] applying
//!    `config.max_request_bytes`.
//!
//! Payload bodies are NEVER logged by any middleware layer. Only span
//! metadata (method, path, status, latency, request-id) is captured.
//!
//! The `auth` module is applied per-route (not globally) via `route_layer` on
//! the mutating endpoints, where it buffers and verifies the Ed25519
//! signed-request envelope.

pub mod account;
pub mod auth;
pub mod metrics;
pub mod request_id;
pub mod tracing;
