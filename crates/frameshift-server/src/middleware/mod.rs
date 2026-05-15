//! HTTP middleware modules for the frameshift server.
//!
//! Middleware is applied globally in [`crate::router::app`] in the following
//! order (outermost to innermost; each layer wraps all inner layers):
//!
//! 1. `request_id` -- generates or forwards `x-request-id`, records it in the
//!    tracing span, and copies it to response headers.
//! 2. `tracing` -- [`tower_http::trace::TraceLayer`] that opens a span per
//!    request, enriched with the request-id from step 1.
//! 3. `compression` -- [`tower_http::compression::CompressionLayer`] for gzip.
//! 4. `body_limit` -- [`tower_http::limit::RequestBodyLimitLayer`] applying
//!    `config.max_request_bytes`.
//!
//! Payload bodies are NEVER logged by any middleware layer. Only span
//! metadata (method, path, status, latency, request-id) is captured.

pub mod request_id;
pub mod tracing;
