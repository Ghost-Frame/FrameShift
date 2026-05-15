//! Request-ID middleware.
//!
//! This module provides [`make_request_id`], which generates a new UUID v4
//! string for every request that does not already carry an `x-request-id`
//! header. The generated (or forwarded) ID is:
//!
//! 1. Stamped into the current [`tracing::Span`] via `Span::current().record`.
//! 2. Propagated to the response as the `x-request-id` header via
//!    [`tower_http::request_id`] plumbing.
//!
//! # Lifecycle
//!
//! ```text
//! Incoming request
//!   -> propagate_request_id (tower-http): read x-request-id or use generated id
//!   -> set_request_id (tower-http):       generate via MakeRequestId if absent
//!   -> handler                            request_id available via Extension<RequestId>
//! Response
//!   -> propagate_request_id copies id to x-request-id response header
//! ```
//!
//! The `tracing` span recording happens inside [`RequestIdGenerator::make_request_id`]
//! so the ID is available for all downstream span events.

use tower_http::request_id::{MakeRequestId, RequestId};

/// UUID v4 request-ID generator.
///
/// Implements [`MakeRequestId`] from `tower-http`. On each call, generates a
/// new UUID v4, records it in the active tracing span, and returns it as a
/// [`RequestId`] header value.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestIdGenerator;

impl MakeRequestId for RequestIdGenerator {
    /// Generate a new UUID v4 request ID for each request.
    ///
    /// The generated ID is:
    /// - Recorded into the current tracing span under the field `request_id`.
    /// - Returned as a [`RequestId`] whose header value is the UUID string.
    ///
    /// If the span field `request_id` is not present (the span was not created
    /// with that field), the `record` call is silently ignored by `tracing`.
    fn make_request_id<B>(&mut self, _request: &axum::http::Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::new_v4().to_string();
        tracing::Span::current().record("request_id", id.as_str());
        let header_value = axum::http::HeaderValue::from_str(&id).ok()?;
        Some(RequestId::new(header_value))
    }
}
