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

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use tower_http::request_id::{MakeRequestId, RequestId};

/// UUID supplied by the client before tracing middleware can synthesize one.
#[derive(Clone, Copy, Debug)]
pub struct ClientRequestId(pub Option<uuid::Uuid>);

/// Preserve a valid caller-supplied request ID before tracing fills a missing header.
pub async fn capture_client_request_id(mut request: Request, next: Next) -> Response {
    let client_request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| uuid::Uuid::parse_str(value).ok());
    request
        .extensions_mut()
        .insert(ClientRequestId(client_request_id));
    next.run(request).await
}

/// UUID v4 request-ID generator.
///
/// Implements [`MakeRequestId`] from `tower-http`. On each call, generates a
/// new UUID v4, records it in the active tracing span, and returns it as a
/// [`RequestId`] header value.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestIdGenerator;

/// Generate a tracing request ID only when the incoming request lacks one.
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
