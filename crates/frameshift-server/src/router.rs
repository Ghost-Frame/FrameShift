//! Router composition for the frameshift HTTP server.
//!
//! [`app`] assembles the full [`axum::Router`] by nesting sub-routers and
//! applying global middleware layers. The returned router has no bound state;
//! call `.with_state(state)` on the result to produce a `Router<()>` ready
//! for `axum::serve`.
//!
//! # Middleware stack
//!
//! `axum::Router::layer` wraps each new layer AROUND the existing stack, so
//! the LAST `.layer(...)` call below becomes the OUTERMOST layer at request
//! handling time. Reading the actual call order in [`app`]:
//!
//! 1. `PropagateRequestId` -- innermost; copies the generated `x-request-id`
//!    from the request extensions onto the outgoing response.
//! 2. `SetRequestId` -- generates a UUID v4 id (via [`RequestIdGenerator`])
//!    when the incoming request has no `x-request-id` header, and stamps it
//!    onto the request extensions for `PropagateRequestId` to read.
//! 3. `TraceLayer` -- opens a span per request with method, path, status,
//!    request_id; logs on response.
//! 4. `CompressionLayer` -- gzip response compression.
//! 5. `RequestBodyLimitLayer` -- caps request body size BEFORE the rest of
//!    the stack sees any bytes.
//! 6. Security response headers (`X-Content-Type-Options`, `X-Frame-Options`,
//!    `Referrer-Policy`) -- added to every response if not already present.
//! 7. Client request-ID capture -- preserves a caller UUID before tracing can
//!    synthesize a missing request ID.
//! 8. `CorsLayer` -- outermost; handles preflight `OPTIONS` requests and
//!    stamps `Access-Control-Allow-*` headers on responses. Only applied
//!    when `state.config.cors_allowed_origins` is non-empty.
//!
//! # Per-route layers
//!
//! The `download-url` mint endpoint uses its configured per-IP rate limit.
//! Signed writes and anonymous telemetry use a separate abuse rate to bound
//! nonce-cache and log-amplification pressure before handler work.
//! Account and publisher-owner routes carry a separate OIDC bearer layer when
//! the verifier is configured; public auth metadata and publisher reads remain
//! available without bearer credentials.
//!
//! The legacy mutating endpoints `POST /v1/packs` and `POST /v1/authors` carry the Ed25519
//! signed-request `route_layer` ([`crate::middleware::auth::require_signed_request`]).
//! It is applied only to those method-routers, so anonymous reads on the same
//! paths (e.g. `GET /v1/packs`) never buffer a body or require a signature.
//! Administrator lifecycle routes instead require an OIDC account and enforce
//! an active administrator role atomically in the catalog.

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::routing::post;
use axum::Router;
use frameshift_objects::PackStore;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::{PeerIpKeyExtractor, SmartIpKeyExtractor};
use tower_governor::GovernorLayer;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::mcp::mcp_router;
use crate::middleware::account::{require_account, resolve_optional_account};
use crate::middleware::auth::require_signed_request;
use crate::middleware::identity_limit::{
    enforce_account_rate_limit, enforce_signer_rate_limit, IdentityRateLimits,
};
use crate::middleware::metrics::MetricsLayer;
use crate::middleware::request_id::{capture_client_request_id, RequestIdGenerator};
use crate::middleware::tracing::make_trace_layer;
use crate::publication::{PublicationAdmissionService, PublicationPromotionService};
use crate::routes::accounts::{account_write_router, auth_config_router, publisher_read_router};
use crate::routes::admin::admin_router;
use crate::routes::authors::{authors_router, authors_write_router};
use crate::routes::downloads::{dl_router, pack_download_url_router};
use crate::routes::handles::handles_router;
use crate::routes::invite_admin::invite_admin_router;
use crate::routes::invite_requests::invite_request_router;
use crate::routes::local_auth::{local_auth_protected_router, local_auth_public_router};
use crate::routes::memory::memory_router;
use crate::routes::moderation::moderation_router;
use crate::routes::ops::ops_router;
use crate::routes::packs::{packs_router, publish_pack};
use crate::routes::publication_intents::publication_intent_router;
use crate::routes::publication_submissions::{
    publication_submission_read_router, publication_submission_write_router,
};
use crate::routes::telemetry::telemetry_router;
use crate::state::AppState;

/// Build the complete Axum router for the frameshift HTTP server.
///
/// The router is structured as follows:
///
/// ```text
/// /
///   /healthz    -- ops
///   /metrics    -- ops
///   /v1
///     /packs    -- pack read endpoints + POST publish (signed-request)
///     /authors  -- GET list (paginated) + lookup; POST register (signed-request)
///     /handles  -- handle lookup
///     /auth/config -- public OIDC capability metadata
///     /account  -- OIDC-authenticated account profile and memberships
///     /publishers -- public profiles plus OIDC-authenticated owner operations
///     /publish-intents -- OIDC-authenticated creation and account-scoped retrieval
///     /moderation/publication-submissions -- role-gated review, decisions, and promotion
///     /telemetry -- POST /selection opt-in selection telemetry sink
///     /memory   -- GET /health read-only memory backend health
///     /admin    -- account-authenticated administrator lifecycle controls
///   /mcp        -- MCP placeholder (501 for all methods)
/// ```
///
/// Global middleware (applied to all routes):
/// - Request-ID propagation and generation (UUID v4).
/// - Tracing layer with one span per HTTP request.
/// - Gzip compression.
/// - Request body size limit from `state.config.max_request_bytes`.
///
/// # Parameters
///
/// - `state` -- the fully constructed [`AppState`] to wire into the router.
///
/// # Returns
///
/// An `axum::Router` with `AppState` already wired in via `.with_state(state)`.
/// The caller passes this directly to `axum::serve`.
pub fn app(state: AppState) -> Router {
    build_app(state, None, None, None)
}

/// Build the complete router with explicit publication-quarantine admission.
///
/// The caller must supply `quarantine` as a store isolated from the public
/// object store. The admission service is constructed with `state.catalog`, so
/// authorization and atomic intent consumption share one catalog authority.
/// The same isolated store backs authenticated reviewer artifact access.
/// Keeping this separate from [`app`] prevents accidental quarantine writes or
/// reads through the standard public application surface.
pub fn app_with_publication_admission(state: AppState, quarantine: Arc<dyn PackStore>) -> Router {
    let admission = Arc::new(PublicationAdmissionService::new(
        Arc::clone(&state.catalog),
        Arc::clone(&quarantine),
    ));
    let quota = frameshift_catalog::PublishQuota {
        max_versions: (state.config.max_versions_per_author != 0)
            .then_some(state.config.max_versions_per_author),
        max_bytes: (state.config.max_bytes_per_author != 0)
            .then_some(state.config.max_bytes_per_author),
        max_total_bytes: (state.config.max_total_bytes != 0)
            .then_some(state.config.max_total_bytes),
    };
    let promotion = Arc::new(PublicationPromotionService::new(
        Arc::clone(&state.catalog),
        Arc::clone(&quarantine),
        Arc::clone(&state.objects),
        state.config.max_request_bytes,
        quota,
    ));
    build_app(state, Some(admission), Some(quarantine), Some(promotion))
}

/// Compose the complete router with optional explicit quarantine services.
fn build_app(
    state: AppState,
    publication_admission: Option<Arc<PublicationAdmissionService>>,
    quarantine_review: Option<Arc<dyn PackStore>>,
    publication_promotion: Option<Arc<PublicationPromotionService>>,
) -> Router {
    let max_body = state.config.max_request_bytes;
    let cors = build_cors_layer(&state);

    // Signed-request auth layer for mutating endpoints. Built here (not inside
    // the route modules) because it needs the live `AppState` -- the config
    // skew window and the shared replay-nonce cache -- baked into the layer.
    // `state.clone()` keeps the original `state` available for `.with_state`.
    let signed = axum::middleware::from_fn_with_state(state.clone(), require_signed_request);

    // Identity-keyed limiters complementing the per-IP governor layers. The
    // Arc is exposed through a request Extension (added as a global layer
    // below) so both the middleware fns and the authorized publisher check in
    // the publish handler share one set of token buckets.
    let identity_limits = IdentityRateLimits::from_config(&state.config);
    let signer_limit = axum::middleware::from_fn(enforce_signer_rate_limit);
    let account_limit = axum::middleware::from_fn(enforce_account_rate_limit);

    // Publish (`POST /v1/packs`) carries the signed-request layer. It is merged
    // with the anonymous read router so GET (search) and POST (publish) share
    // the `/` path with only the POST gated by auth. The signer limit is added
    // first so it runs strictly inside (after) signature verification.
    let publish = Router::new()
        .route("/", post(publish_pack))
        .route_layer(signer_limit.clone())
        .route_layer(signed.clone());
    let publish = if state.account_auth.is_some() {
        let optional_account =
            axum::middleware::from_fn_with_state(state.clone(), resolve_optional_account);
        publish.route_layer(optional_account)
    } else {
        publish
    };
    let publish = apply_ip_rate_limit(publish, &state, state.config.abuse_rate_per_min);
    let mint_router = build_mint_router(&state);
    let packs = packs_router()
        .merge(publish)
        .nest("/{name}/versions/{version}/download-url", mint_router);

    // Authors: anonymous reads merged with signed-request-gated registration.
    // Signer limit inside the signed layer, mirroring the publish router.
    let author_writes = authors_write_router()
        .route_layer(signer_limit.clone())
        .route_layer(signed.clone());
    let author_writes = apply_ip_rate_limit(author_writes, &state, state.config.abuse_rate_per_min);
    let authors = authors_router().merge(author_writes);

    let telemetry =
        apply_ip_rate_limit(telemetry_router(), &state, state.config.abuse_rate_per_min);
    let invite_requests = apply_ip_rate_limit(
        invite_request_router(),
        &state,
        state.config.abuse_rate_per_min,
    );

    let mut v1 = Router::new()
        .nest("/packs", packs)
        .nest("/authors", authors)
        .nest("/handles", handles_router())
        .nest("/auth", auth_config_router())
        .merge(invite_requests)
        .nest("/publishers", publisher_read_router())
        .nest("/telemetry", telemetry)
        .nest("/memory", memory_router());

    if state.config.first_party_auth.enabled() {
        let local_auth = apply_ip_rate_limit(
            local_auth_public_router(),
            &state,
            state.config.abuse_rate_per_min,
        );
        v1 = v1.merge(Router::new().nest("/auth", local_auth));
    }

    if state.account_auth.is_some() || state.config.first_party_auth.enabled() {
        let account_layer = axum::middleware::from_fn_with_state(state.clone(), require_account);
        let mut account_routes = account_write_router()
            .merge(Router::new().nest("/auth", local_auth_protected_router()))
            .merge(Router::new().nest("/admin", admin_router().merge(invite_admin_router())))
            .merge(Router::new().nest("/publish-intents", publication_intent_router()))
            .merge(Router::new().nest(
                "/publication-submissions",
                publication_submission_read_router(),
            ))
            .merge(Router::new().nest(
                "/moderation/publication-submissions",
                moderation_router(quarantine_review, publication_promotion),
            ));
        if let Some(admission) = publication_admission {
            let submission_writes = publication_submission_write_router(admission)
                .route_layer(signer_limit.clone())
                .route_layer(signed.clone());
            let submission_writes =
                apply_ip_rate_limit(submission_writes, &state, state.config.abuse_rate_per_min);
            account_routes = account_routes
                .merge(Router::new().nest("/publication-submissions", submission_writes));
        }
        // Account limit inside the account layer so the authenticated account
        // extension is always present when the limiter runs.
        let account_routes = account_routes
            .route_layer(account_limit)
            .route_layer(account_layer);
        v1 = v1.merge(account_routes);
    }

    let x_request_id = axum::http::HeaderName::from_static("x-request-id");

    // Static security response headers, applied if not already set by a handler.
    let hdr_xcto = SetResponseHeaderLayer::if_not_present(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    let hdr_xfo = SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    let hdr_rp = SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );

    // MetricsLayer is applied last, making it the outermost layer.  All layers
    // added to an axum Router via `.layer()` run AFTER the router has matched
    // the route and stamped MatchedPath into request extensions, so the outermost
    // position is safe and MatchedPath is always available.  (Unmatched requests
    // fall back to the "<unmatched>" label inside MetricsService.)
    let metrics_layer = MetricsLayer::new(std::sync::Arc::clone(&state.metrics));

    let mut router = Router::new()
        .merge(ops_router())
        .nest("/v1", v1)
        .nest("/dl", dl_router())
        .nest("/mcp", mcp_router())
        .layer(PropagateRequestIdLayer::new(x_request_id.clone()))
        .layer(SetRequestIdLayer::new(x_request_id, RequestIdGenerator))
        .layer(make_trace_layer())
        .layer(CompressionLayer::new())
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(hdr_xcto)
        .layer(hdr_xfo)
        .layer(hdr_rp)
        .layer(metrics_layer)
        .layer(axum::Extension(identity_limits))
        .layer(axum::middleware::from_fn(capture_client_request_id));

    if let Some(cors) = cors {
        router = router.layer(cors);
    }

    router.with_state(state)
}

/// Build the download-URL mint sub-router with its configured per-IP rate limit.
///
/// `0` disables rate limiting (escape hatch for local dev / load tests).
/// When positive, the [`GovernorLayer`] is configured with:
///
/// - period = `60 / rate_per_min` seconds (interval between token
///   replenishments)
/// - burst = `rate_per_min` (maximum tokens that can accumulate)
/// - key extractor = [`PeerIpKeyExtractor`] by default (safe against XFF
///   spoofing), or [`SmartIpKeyExtractor`] when
///   `state.config.trust_forwarded_for` is `true` (for deployments where a
///   trusted proxy rewrites XFF before requests reach this server)
///
/// The layer is applied only at the mint sub-router; it does NOT apply to
/// the verifier `/dl/{hash}` (HMAC is the gate there) or to any other
/// endpoint.
fn build_mint_router(state: &AppState) -> Router<AppState> {
    apply_ip_rate_limit(
        pack_download_url_router(),
        state,
        state.config.download_rate_per_min,
    )
}

/// Apply a per-IP governor to `router`, or return it unchanged when `rate` is zero.
fn apply_ip_rate_limit(router: Router<AppState>, state: &AppState, rate: u32) -> Router<AppState> {
    if rate == 0 {
        return router;
    }
    let burst = NonZeroU32::new(rate).expect("rate > 0 verified above");
    let period_secs = (60u64 / u64::from(rate)).max(1);
    // Build separate arms because GovernorConfigBuilder is generic over the
    // key extractor type, making a runtime branch on the same builder awkward.
    if state.config.trust_forwarded_for {
        let conf = GovernorConfigBuilder::default()
            .period(std::time::Duration::from_secs(period_secs))
            .burst_size(burst.into())
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("governor config valid (period > 0, burst > 0)");
        router.layer(GovernorLayer::new(Arc::new(conf)))
    } else {
        let conf = GovernorConfigBuilder::default()
            .period(std::time::Duration::from_secs(period_secs))
            .burst_size(burst.into())
            .key_extractor(PeerIpKeyExtractor)
            .finish()
            .expect("governor config valid (period > 0, burst > 0)");
        router.layer(GovernorLayer::new(Arc::new(conf)))
    }
}

/// Build the `CorsLayer` from `state.config.cors_allowed_origins`.
///
/// Returns `None` when the configured origin list is empty, so the router
/// does not apply any CORS layer at all (preserves prior behavior). When at
/// least one origin parses to a valid `HeaderValue`, returns a `CorsLayer`
/// configured with:
///
/// - methods: `GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`, `HEAD`
/// - allowed headers: `Authorization`, `Content-Type`, and the four
///   `X-Frameshift-*` signed-request headers
/// - exposed headers: `X-Request-Id` (lets browsers correlate logs)
/// - max age: 600 seconds (10 minute preflight cache)
///
/// Origins that fail `HeaderValue::from_str` are skipped with a `tracing::warn`,
/// but startup is not aborted -- a single typo in `CORS_ALLOWED_ORIGINS` must
/// not knock the server over.
fn build_cors_layer(state: &AppState) -> Option<CorsLayer> {
    let origins: Vec<HeaderValue> = state
        .config
        .cors_origins()
        .filter_map(|raw| match HeaderValue::from_str(raw) {
            Ok(v) => Some(v),
            Err(err) => {
                tracing::warn!(origin = raw, %err, "ignoring invalid CORS origin");
                None
            }
        })
        .collect();

    if origins.is_empty() {
        return None;
    }

    let expose: HeaderName = HeaderName::from_static("x-request-id");
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::HEAD,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("x-frameshift-pubkey"),
            HeaderName::from_static("x-frameshift-timestamp"),
            HeaderName::from_static("x-frameshift-nonce"),
            HeaderName::from_static("x-frameshift-signature"),
            HeaderName::from_static("x-request-id"),
        ])
        .expose_headers([expose])
        .max_age(std::time::Duration::from_secs(600));
    Some(if state.config.first_party_auth.enabled() {
        cors.allow_credentials(true)
    } else {
        cors
    })
}
