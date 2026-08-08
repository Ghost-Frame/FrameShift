//! Integration tests for the dedicated Cloudflare Access MCP identity boundary.

#[path = "../../../tests/mocks/mod.rs"]
mod mocks;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::account_auth::{BearerTokenVerifier, OidcAuthError, OidcVerifier, VerifiedOidcIdentity};
use crate::mcp::{
    mcp_router_with_dispatcher, McpDispatchError, McpDispatcher, McpListToolsRequest,
    McpListToolsResult, McpPrepareToolRequest, McpPreparedTool, McpTransportConfig,
    MODERN_PROTOCOL_VERSION,
};
use crate::metrics::Metrics;
use crate::{
    app, AppState, FirstPartyAuthConfig, InviteRequestConfig, McpAccessConfig, OidcConfig,
    ServerConfig,
};
use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{HeaderValue, Method, Request, StatusCode};
use axum::routing::get;
use axum::Json;
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use frameshift_catalog::AccountStatus;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Map, Value};
use tower::ServiceExt as _;
use uuid::Uuid;

use super::{require_mcp_access, McpAccessRuntime, McpAuthenticatedAccount};
use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Maximum response body read by one MCP Access integration assertion.
const TEST_RESPONSE_LIMIT: usize = 1024 * 1024;

/// Exact protected-resource challenge configured for the test application.
const EXPECTED_CHALLENGE: &str = concat!(
    "Bearer resource_metadata=\"",
    "https://mcp.frameshift.test/.well-known/oauth-authorization-server\""
);

/// Test-only RFC 8017 RSA key whose public modulus is exposed by [`rsa_jwks`].
const TEST_RSA_PRIVATE_KEY_DER_BASE64: &str = concat!(
    "MIIEowIBAAKCAQEA0DxY3ldLYLewF2uYCaK3kG0n0k9yie9X9RjopZz1o7alOYxO",
    "2RrHAQU4sezqZNxAlvqEDBnwS8Ki4uNv7+l1b2VKiIoiplzHU4efry8fEPabUiwE",
    "voayhH5CiL1EDdYqIA1O3ICKL3tO9Ra57yFsZoSMBimDq+BSL+zVIBK1Mdps91oF",
    "j30/tcgphi8nL6YpathTrXYUsny593A22OfPJtfcVyoQ36fycOUEVzsSKZNXwgQB",
    "mDVCeFqfDMn62psxI6fZeypBb5gyZR8DRmrJod8/loD+UPlsdI+qFfLMd2l+12nU",
    "O0ylYDc9pO+pBSP2ZjNcbc7z8V7a6uIT0VFZEwIDAQABAoIBABLbLBbyI66943Gz",
    "egCBXgrzf3QhYpdP95CHsWVxyaKKAvsrk+Y/8P5MKT6fW/hHI4goZjWsUaCintpZ",
    "ywSYCNzN+MpVa97RrvEG6nRUGYWRNy5hMwrHqrmprz+vl86C8qyVV+tKrnivO06h",
    "QLQBPE4qOX3DW5uARCD32rK9TvAVE907xRmBWG0wC/T0FPna9prEOS24efU4I3fh",
    "5T3/bFWOHSjXxARyvVcRj/I0uwwibeSqQ/nMIOKO0xtVn7FFYGhdgwrFOUdcLPBk",
    "kRoU74X8r9yMckcJy0+ViuGW05sSAz8DY4ypPdcA16jvPokmvwAjO/v1gniF6Rwa",
    "jAP9uLECgYEA/s9rGy86wW2Cdcolkdt+scXFm1//bxMNEYaettyTFg7DWJGFpzi5",
    "TL//CghMiXce/w26Jq30wVtACCLiwTMAPbGW7hcnBzvOwjDOjGw1Okv/jTDs9AkL",
    "ni0TmKsAFG/38RVoUCZsJ5weFJ9oZewCNZlI7h3jRXsO/vxxlxr/znECgYEA0TVB",
    "yj+K0P9I3dCy27XdCQIxailJMZ4NNbyo/QZJ4ZRiIa3VYUCp2hcCXJXzPyG6mEj0",
    "kOjpA3Ij/IR0ivO39AoACP4RKJ6/nJGDR9N04Z+sU5d/K0gpwICE05MJGU8L/oSz",
    "m1SfKMvE1z4K8NxhyMkyHs0gs1tbJ8nJiiBXKcMCgYBCP406SSI+jglANKll7apX",
    "7/J7fg78Qvi/2L9FDb4UGwyA53zXSDEtGjHl2tiDWPwvFdOTIOEksGPKeb94uZjT",
    "cWurRUu5XrxX0raw3aVNHds4S0MgA4YIvvF8XOEtbxsIjCdNx1+RQM61T+ilryG3",
    "672BYzXmp6LzepDR14wwkQKBgQC5xiUJx6spM8gs0KpC2BfTbBMdRlQsr0DjuwgE",
    "x5TLr8wERCz7E0TA2TXLqYw7P2RG3mHuXCSuXqj+D1C+IvXyyv6E/beW7oEQM1b0",
    "bR2ZTQTlpd3TPV12B6nrhuHJi5wHAyfKgzZiL7A3wmxMviZG+gJ7v4OOQU2M428I",
    "LPe5qQKBgEDW+J+bVct1KHZ/+W+hkzxDKQ2mfM+wdOyj+f8yvNY23vfvhfnOkcIl",
    "jdEG8YepKhGibG0caXdIYK/Fgyly6mDdfmSm40v+aVVQwQduSiPoRlcawrB3X78O",
    "tBb0cXERD5uQserDuTdedzEK7ijNXd22ZssjtEBoXt+A+QxenHkq"
);

/// Public RSA modulus paired with [`TEST_RSA_PRIVATE_KEY`], encoded for JWK.
const TEST_RSA_MODULUS: &str = concat!(
    "0DxY3ldLYLewF2uYCaK3kG0n0k9yie9X9RjopZz1o7alOYxO2RrHAQU4sezqZNxA",
    "lvqEDBnwS8Ki4uNv7-l1b2VKiIoiplzHU4efry8fEPabUiwEvoayhH5CiL1EDdYqI",
    "A1O3ICKL3tO9Ra57yFsZoSMBimDq-BSL-zVIBK1Mdps91oFj30_tcgphi8nL6Ypat",
    "hTrXYUsny593A22OfPJtfcVyoQ36fycOUEVzsSKZNXwgQBmDVCeFqfDMn62psxI6",
    "fZeypBb5gyZR8DRmrJod8_loD-UPlsdI-qFfLMd2l-12nUO0ylYDc9pO-pBSP2Zj",
    "Ncbc7z8V7a6uIT0VFZEw"
);

/// Stable key identifier exposed by the local JWKS fixture.
const TEST_RSA_KEY_ID: &str = "mcp-access-rs256-key";

/// Loopback JWKS server kept alive for one production-verifier test.
struct JwksFixture {
    /// Exact loopback URL serving the fixture document.
    url: String,
    /// Background server task aborted when the fixture leaves scope.
    task: tokio::task::JoinHandle<()>,
}

/// Ensure the loopback JWKS task cannot leak across integration tests.
impl Drop for JwksFixture {
    /// Stop the provider task when its owning test completes or panics.
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Deterministic assertion verifier with observable prevalidation calls.
#[derive(Clone, Default)]
struct FakeVerifier {
    /// Opaque assertion strings mapped to trusted identities or sanitized failures.
    outcomes: Arc<RwLock<HashMap<String, Result<VerifiedOidcIdentity, OidcAuthError>>>>,
    /// Number of assertions that crossed the HTTP header validation boundary.
    calls: Arc<AtomicUsize>,
}

/// Mutation and observation helpers for the assertion verifier double.
impl FakeVerifier {
    /// Register one successful stable identity for an opaque assertion.
    fn allow(&self, token: &str, subject: &str, email: Option<&str>) {
        self.outcomes.write().unwrap().insert(
            token.to_string(),
            Ok(VerifiedOidcIdentity {
                issuer: "https://team.cloudflareaccess.com".to_string(),
                subject: subject.to_string(),
                email: email.map(str::to_string),
                display_name: Some(format!("Display {subject}")),
                auth_time: None,
            }),
        );
    }

    /// Register one sanitized verifier failure for an opaque assertion.
    fn reject_with(&self, token: &str, error: OidcAuthError) {
        self.outcomes
            .write()
            .unwrap()
            .insert(token.to_string(), Err(error));
    }

    /// Return how many requests reached cryptographic verification.
    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// Header-verification behavior for MCP Access integration tests.
#[async_trait]
impl BearerTokenVerifier for FakeVerifier {
    /// Return the scripted identity or failure and record the invocation.
    async fn verify(&self, token: &str) -> Result<VerifiedOidcIdentity, OidcAuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcomes
            .read()
            .unwrap()
            .get(token)
            .cloned()
            .unwrap_or(Err(OidcAuthError::InvalidToken))
    }
}

/// Dispatcher that records only the account UUID inserted by authentication.
#[derive(Clone, Default)]
struct AccountProbeDispatcher {
    /// Account IDs observed through the server-owned MCP request context.
    observed_accounts: Arc<Mutex<Vec<Option<Uuid>>>>,
}

/// Account-context observations for both MCP protocol eras.
#[async_trait]
impl McpDispatcher for AccountProbeDispatcher {
    /// Record the authenticated account extension and return no visible tools.
    async fn list_tools(
        &self,
        request: McpListToolsRequest,
    ) -> Result<McpListToolsResult, McpDispatchError> {
        let account_id = request
            .context
            .extension::<McpAuthenticatedAccount>()
            .map(|account| account.account_id);
        self.observed_accounts.lock().unwrap().push(account_id);
        Ok(McpListToolsResult::default())
    }

    /// Return no executable tools from the context probe.
    async fn prepare_tool(
        &self,
        _request: McpPrepareToolRequest,
    ) -> Result<Option<Box<dyn McpPreparedTool>>, McpDispatchError> {
        Ok(None)
    }
}

/// Return a fully enabled, Cloudflare-pinned MCP Access configuration.
fn enabled_access_config() -> McpAccessConfig {
    McpAccessConfig {
        assertion: OidcConfig {
            enabled: true,
            issuer: "https://team.cloudflareaccess.com".to_string(),
            audience: "a1b2c3d4e5f6".to_string(),
            jwks_url: "https://team.cloudflareaccess.com/cdn-cgi/access/certs".to_string(),
            allowed_algorithms: vec!["RS256".to_string()],
            jwks_cache_ttl: Duration::from_secs(300),
            jwks_stale_ttl: Duration::from_secs(900),
            clock_skew: Duration::from_secs(30),
            fresh_auth_max_age: Duration::from_secs(300),
        },
        resource_url: "https://mcp.frameshift.test/mcp".to_string(),
        resource_metadata_url: "https://mcp.frameshift.test/.well-known/oauth-authorization-server"
            .to_string(),
    }
}

/// Build a deterministic server configuration around one MCP Access policy.
fn test_config(mcp_access: McpAccessConfig) -> Arc<ServerConfig> {
    let mut config = ServerConfig::from_env().expect("default test environment must parse");
    config.bind_addr = "127.0.0.1:0".parse().unwrap();
    config.log_level = "off".to_string();
    config.max_request_bytes = 1_048_576;
    config.max_search_limit = 100;
    config.cors_allowed_origins.clear();
    config.download_rate_per_min = 0;
    config.abuse_rate_per_min = 0;
    config.account_rate_per_min = 0;
    config.signer_rate_per_min = 0;
    config.publisher_rate_per_min = 0;
    config.trust_forwarded_for = false;
    config.oidc = OidcConfig::disabled();
    config.mcp_access = mcp_access;
    config.invite_requests = InviteRequestConfig::disabled();
    config.first_party_auth = FirstPartyAuthConfig::disabled();
    Arc::new(config)
}

/// Construct an enabled test runtime around one deterministic verifier.
fn test_runtime(verifier: FakeVerifier) -> Arc<McpAccessRuntime> {
    McpAccessRuntime::with_verifier(&enabled_access_config(), Arc::new(verifier))
        .expect("valid MCP Access policy must construct")
        .expect("enabled MCP Access policy must return a runtime")
}

/// Return the deterministic RSA public key document served by the local provider.
fn rsa_jwks() -> Value {
    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": TEST_RSA_KEY_ID,
            "alg": "RS256",
            "n": TEST_RSA_MODULUS,
            "e": "AQAB"
        }]
    })
}

/// Start an isolated loopback provider for the production JWKS fetch path.
async fn start_jwks_fixture() -> JwksFixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback JWKS listener must bind");
    let address = listener
        .local_addr()
        .expect("loopback JWKS listener must expose its address");
    let router = Router::new().route("/jwks", get(|| async { Json(rsa_jwks()) }));
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("loopback JWKS provider must serve");
    });
    JwksFixture {
        url: format!("http://{address}/jwks"),
        task,
    }
}

/// Build the real OIDC verifier with the exact Access claim policy and local JWKS I/O.
fn production_test_runtime(jwks_url: &str) -> Arc<McpAccessRuntime> {
    let access_config = enabled_access_config();
    let mut verifier_config = access_config.assertion.clone();
    verifier_config.jwks_url = jwks_url.to_string();
    let verifier = OidcVerifier::from_config(&verifier_config)
        .expect("production RS256 verifier policy must be valid")
        .expect("enabled production verifier must construct");
    McpAccessRuntime::with_verifier(&access_config, verifier)
        .expect("exact Access middleware policy must be valid")
        .expect("enabled Access middleware must construct")
}

/// Return the current Unix timestamp for deterministic registered-claim offsets.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must follow the Unix epoch")
        .as_secs()
}

/// Sign one JWT with the RSA fixture and caller-selected key identifier.
fn rsa_token(key_id: &str, claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key_id.to_string());
    let private_key = STANDARD
        .decode(TEST_RSA_PRIVATE_KEY_DER_BASE64)
        .expect("test RSA private key must decode");
    encode(&header, &claims, &EncodingKey::from_rsa_der(&private_key))
        .expect("test RSA token must encode")
}

/// Sign one deliberately disallowed HMAC JWT for algorithm-confusion coverage.
fn hmac_token(claims: Value) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(TEST_RSA_KEY_ID.to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(b"test-only-disallowed-hmac-key"),
    )
    .expect("test HMAC token must encode")
}

/// Build application state with an optional validated MCP Access runtime.
fn test_state(
    catalog: MockCatalog,
    config: Arc<ServerConfig>,
    mcp_access: Option<Arc<McpAccessRuntime>>,
) -> AppState {
    AppState {
        catalog: Arc::new(catalog),
        objects: Arc::new(MockPackStore::new()),
        runtime: None,
        memory: None,
        config,
        metrics: Arc::new(Metrics::new()),
        auth_nonces: Arc::new(crate::auth::NonceCache::new(Duration::from_secs(600))),
        account_auth: None,
        mcp_access,
    }
}

/// Build one valid legacy initialize request with an optional Access assertion.
fn legacy_initialize_request(assertion: Option<&str>) -> Request<Body> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "mcp-access-test", "version": "1.0.0" }
        }
    });
    request_with_body("/mcp", body, assertion)
}

/// Build one legacy tools/list request with an optional Access assertion.
fn legacy_list_request(assertion: Option<&str>) -> Request<Body> {
    request_with_body(
        "/mcp",
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        assertion,
    )
}

/// Build one final-era tools/list request with an optional Access assertion.
fn modern_list_request(assertion: Option<&str>) -> Request<Body> {
    let mut params = Map::new();
    params.insert(
        "_meta".to_string(),
        json!({
            "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": "mcp-access-test",
                "version": "1.0.0"
            },
            "io.modelcontextprotocol/clientCapabilities": {}
        }),
    );
    let mut request = request_with_body(
        "/mcp",
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": params}),
        assertion,
    );
    request.headers_mut().insert(
        "mcp-protocol-version",
        HeaderValue::from_static(MODERN_PROTOCOL_VERSION),
    );
    request
        .headers_mut()
        .insert("mcp-method", HeaderValue::from_static("tools/list"));
    request
}

/// Build one JSON POST and optionally attach the trusted edge assertion header.
fn request_with_body(path: &str, body: Value, assertion: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(Body::from(body.to_string()))
        .expect("test MCP request must be valid");
    if let Some(assertion) = assertion {
        request.headers_mut().insert(
            "cf-access-jwt-assertion",
            HeaderValue::from_str(assertion).expect("test assertion must be a valid header"),
        );
    }
    request
}

/// Read one bounded JSON response body.
async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), TEST_RESPONSE_LIMIT)
        .await
        .expect("test response body must be readable");
    serde_json::from_slice(&bytes).expect("test response body must be JSON")
}

/// Disabled or invalid runtime state leaves the application MCP route absent.
#[tokio::test]
async fn application_mcp_route_is_absent_without_validated_runtime() {
    let state = test_state(
        MockCatalog::new(),
        test_config(McpAccessConfig::disabled()),
        None,
    );
    for method in [Method::GET, Method::POST] {
        let request = Request::builder()
            .method(method)
            .uri("/mcp")
            .body(Body::empty())
            .unwrap();
        let response = app(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

/// Enabled configuration accepts only the exact pinned Cloudflare contract.
#[test]
fn access_configuration_is_disabled_by_default_and_rejects_unsafe_variants() {
    let verifier = Arc::new(FakeVerifier::default());
    assert!(
        McpAccessRuntime::with_verifier(&McpAccessConfig::disabled(), verifier.clone())
            .expect("disabled policy is a valid state")
            .is_none()
    );
    assert!(
        McpAccessRuntime::with_verifier(&enabled_access_config(), verifier.clone())
            .expect("exact Cloudflare policy must be valid")
            .is_some()
    );
    assert!(McpAccessRuntime::from_config(&enabled_access_config())
        .expect("production verifier must accept the exact pinned policy")
        .is_some());

    let mut invalid = Vec::new();
    let mut value = enabled_access_config();
    value.assertion.audience.clear();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.issuer = "http://team.cloudflareaccess.com".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.issuer = "https://example.test".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.issuer = "https://team.cloudflareaccess.com.evil.test".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.issuer = "https://team.cloudflareaccess.com/not-root".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.jwks_url.clear();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.jwks_url =
        "https://team.cloudflareaccess.com/.well-known/openid-configuration".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.jwks_url =
        "https://other.cloudflareaccess.com/cdn-cgi/access/certs".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.allowed_algorithms = vec!["RS256".to_string(), "ES256".to_string()];
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.allowed_algorithms = vec!["ES256".to_string()];
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.audience = " padded".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.jwks_cache_ttl = Duration::ZERO;
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.jwks_stale_ttl = Duration::from_secs(7 * 24 * 60 * 60 + 1);
    invalid.push(value);
    let mut value = enabled_access_config();
    value.assertion.clock_skew = Duration::from_secs(5 * 60 + 1);
    invalid.push(value);
    let mut value = enabled_access_config();
    value.resource_url = "https://mcp.frameshift.test/not-mcp".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.resource_url = "http://mcp.frameshift.test/mcp".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.resource_url = "https://user@mcp.frameshift.test/mcp".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.resource_url = "https://mcp.frameshift.test/mcp?tenant=attacker".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.resource_metadata_url =
        "https://other.test/.well-known/oauth-authorization-server".to_string();
    invalid.push(value);
    let mut value = enabled_access_config();
    value.resource_metadata_url = "https://mcp.frameshift.test/wrong".to_string();
    invalid.push(value);

    for invalid in invalid {
        assert!(
            McpAccessRuntime::with_verifier(&invalid, verifier.clone()).is_err(),
            "unsafe MCP Access policy must fail closed"
        );
    }
}

/// Real RS256/JWKS verification rejects every claim and key substitution before MCP dispatch.
#[tokio::test]
async fn production_rs256_verifier_enforces_access_claims_end_to_end() {
    let provider = start_jwks_fixture().await;
    let catalog = MockCatalog::new();
    let catalog_state = catalog.state.clone();
    let state = test_state(
        catalog,
        test_config(enabled_access_config()),
        Some(production_test_runtime(&provider.url)),
    );
    let router = app(state);
    let now = unix_now();
    let valid_claims = json!({
        "iss": "https://team.cloudflareaccess.com",
        "sub": "production-rs256-subject",
        "aud": "a1b2c3d4e5f6",
        "exp": now + 300,
        "nbf": now - 1,
        "email": "profile-only@example.test"
    });
    let valid = rsa_token(TEST_RSA_KEY_ID, valid_claims.clone());
    let response = router
        .clone()
        .oneshot(legacy_initialize_request(Some(&valid)))
        .await
        .expect("valid production assertion request must complete");
    assert_eq!(response.status(), StatusCode::OK);

    let invalid_tokens = [
        ("wrong algorithm", hmac_token(valid_claims.clone())),
        (
            "wrong audience",
            rsa_token(
                TEST_RSA_KEY_ID,
                json!({
                    "iss": "https://team.cloudflareaccess.com",
                    "sub": "wrong-audience-subject",
                    "aud": "attacker-audience",
                    "exp": now + 300
                }),
            ),
        ),
        (
            "expired assertion",
            rsa_token(
                TEST_RSA_KEY_ID,
                json!({
                    "iss": "https://team.cloudflareaccess.com",
                    "sub": "expired-subject",
                    "aud": "a1b2c3d4e5f6",
                    "exp": now - 300
                }),
            ),
        ),
        (
            "future not-before",
            rsa_token(
                TEST_RSA_KEY_ID,
                json!({
                    "iss": "https://team.cloudflareaccess.com",
                    "sub": "future-subject",
                    "aud": "a1b2c3d4e5f6",
                    "exp": now + 900,
                    "nbf": now + 300
                }),
            ),
        ),
        (
            "unknown key id",
            rsa_token(
                "attacker-key",
                json!({
                    "iss": "https://team.cloudflareaccess.com",
                    "sub": "unknown-key-subject",
                    "aud": "a1b2c3d4e5f6",
                    "exp": now + 300
                }),
            ),
        ),
    ];

    for (scenario, token) in invalid_tokens {
        let response = router
            .clone()
            .oneshot(legacy_initialize_request(Some(&token)))
            .await
            .expect("invalid production assertion request must complete");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{scenario} must fail closed"
        );
        assert_eq!(
            response
                .headers()
                .get("www-authenticate")
                .and_then(|value| value.to_str().ok()),
            Some(EXPECTED_CHALLENGE),
            "{scenario} must retain the fixed challenge"
        );
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "{scenario} must remain non-cacheable"
        );
    }

    let state = catalog_state.read().unwrap();
    assert_eq!(state.accounts.len(), 1);
    assert!(state.account_subjects.contains_key(&(
        "https://team.cloudflareaccess.com".to_string(),
        "production-rs256-subject".to_string()
    )));
}

/// Missing, duplicated, malformed, and oversized assertions stop before verification.
#[tokio::test]
async fn assertion_header_is_exactly_one_bounded_ascii_token() {
    let verifier = FakeVerifier::default();
    let runtime = test_runtime(verifier.clone());
    let state = test_state(
        MockCatalog::new(),
        test_config(enabled_access_config()),
        Some(runtime),
    );
    let router = app(state);

    let missing = router
        .clone()
        .oneshot(legacy_initialize_request(None))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let mut duplicate = legacy_initialize_request(None);
    duplicate
        .headers_mut()
        .append("Cf-Access-Jwt-Assertion", HeaderValue::from_static("first"));
    duplicate.headers_mut().append(
        "cf-access-jwt-assertion",
        HeaderValue::from_static("second"),
    );
    assert_eq!(
        router.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    for malformed in ["", "two parts"] {
        let request = legacy_initialize_request(Some(malformed));
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let mut horizontal_tab = legacy_initialize_request(None);
    horizontal_tab.headers_mut().insert(
        "cf-access-jwt-assertion",
        HeaderValue::from_bytes(b"tab\tvalue").expect("horizontal tab is valid header bytes"),
    );
    assert_eq!(
        router
            .clone()
            .oneshot(horizontal_tab)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let oversized = "a".repeat(16 * 1024 + 1);
    let request = legacy_initialize_request(Some(&oversized));
    assert_eq!(
        router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(verifier.call_count(), 0);

    let boundary = "b".repeat(16 * 1024);
    verifier.allow(&boundary, "boundary-subject", None);
    let request = legacy_initialize_request(Some(&boundary));
    assert_eq!(
        router.oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(verifier.call_count(), 1);
}

/// Client-controlled bearer, cookie, query, and MCP metadata never authenticate.
#[tokio::test]
async fn client_controlled_identity_fallbacks_are_ignored() {
    let verifier = FakeVerifier::default();
    verifier.allow(
        "attacker-controlled",
        "fallback-subject",
        Some("same@example.test"),
    );
    let state = test_state(
        MockCatalog::new(),
        test_config(enabled_access_config()),
        Some(test_runtime(verifier.clone())),
    );
    let router = app(state);
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "attacker-controlled",
                "version": "attacker-controlled",
                "email": "same@example.test",
                "subject": "fallback-subject"
            }
        }
    });
    let mut request = request_with_body(
        "/mcp?cf-access-jwt-assertion=attacker-controlled",
        body,
        None,
    );
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_static("Bearer attacker-controlled"),
    );
    request.headers_mut().insert(
        "cookie",
        HeaderValue::from_static("CF_Authorization=attacker-controlled"),
    );

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(verifier.call_count(), 0);
}

/// Verifier output still must match the pinned issuer and a stable nonblank subject.
#[tokio::test]
async fn verifier_output_cannot_cross_the_pinned_identity_boundary() {
    let verifier = FakeVerifier::default();
    verifier.allow("wrong-issuer", "subject-a", None);
    verifier
        .outcomes
        .write()
        .unwrap()
        .get_mut("wrong-issuer")
        .and_then(|outcome| outcome.as_mut().ok())
        .expect("scripted identity must exist")
        .issuer = "https://other.cloudflareaccess.com".to_string();
    verifier.allow("blank-subject", " ", None);
    let catalog = MockCatalog::new();
    let state_handle = catalog.state.clone();
    let state = test_state(
        catalog,
        test_config(enabled_access_config()),
        Some(test_runtime(verifier)),
    );
    let router = app(state);

    for token in ["wrong-issuer", "blank-subject"] {
        assert_eq!(
            router
                .clone()
                .oneshot(legacy_initialize_request(Some(token)))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert!(state_handle.read().unwrap().accounts.is_empty());
}

/// Authentication failures are fixed, redacted, non-cacheable, and challenge-bearing.
#[tokio::test]
async fn verifier_failures_have_fixed_status_and_challenge_semantics() {
    let verifier = FakeVerifier::default();
    verifier.reject_with("invalid", OidcAuthError::InvalidToken);
    verifier.reject_with("bad-config", OidcAuthError::InvalidConfiguration);
    verifier.reject_with("outage", OidcAuthError::ProviderUnavailable);
    let state = test_state(
        MockCatalog::new(),
        test_config(enabled_access_config()),
        Some(test_runtime(verifier)),
    );
    let router = app(state);

    for token in ["invalid", "bad-config"] {
        let response = router
            .clone()
            .oneshot(legacy_initialize_request(Some(token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get("www-authenticate")
                .and_then(|value| value.to_str().ok()),
            Some(EXPECTED_CHALLENGE)
        );
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response_json(response).await,
            json!({"error": "MCP authentication required"})
        );
    }

    let response = router
        .oneshot(legacy_initialize_request(Some("outage")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("www-authenticate").is_none());
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response_json(response).await,
        json!({"error": "service unavailable"})
    );
}

/// Exact issuer and subject identity is stable while profile email is non-authoritative.
#[tokio::test]
async fn stable_subjects_reuse_accounts_and_same_email_different_subjects_do_not_merge() {
    let verifier = FakeVerifier::default();
    verifier.allow("subject-a", "subject-a", Some("shared@example.test"));
    verifier.allow("subject-b", "subject-b", Some("shared@example.test"));
    let catalog = MockCatalog::new();
    let state_handle = catalog.state.clone();
    let state = test_state(
        catalog,
        test_config(enabled_access_config()),
        Some(test_runtime(verifier)),
    );
    let router = app(state);

    for token in ["subject-a", "subject-a", "subject-b"] {
        assert_eq!(
            router
                .clone()
                .oneshot(legacy_initialize_request(Some(token)))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    let state = state_handle.read().unwrap();
    assert_eq!(state.accounts.len(), 2);
    let first = state
        .account_subjects
        .get(&(
            "https://team.cloudflareaccess.com".to_string(),
            "subject-a".to_string(),
        ))
        .copied()
        .unwrap();
    let second = state
        .account_subjects
        .get(&(
            "https://team.cloudflareaccess.com".to_string(),
            "subject-b".to_string(),
        ))
        .copied()
        .unwrap();
    assert_ne!(first, second);
}

/// Suspended and disabled durable accounts are rejected after valid assertion verification.
#[tokio::test]
async fn inactive_account_is_forbidden() {
    let verifier = FakeVerifier::default();
    verifier.allow("active-first", "status-subject", None);
    let catalog = MockCatalog::new();
    let state_handle = catalog.state.clone();
    let state = test_state(
        catalog,
        test_config(enabled_access_config()),
        Some(test_runtime(verifier)),
    );
    let router = app(state);

    assert_eq!(
        router
            .clone()
            .oneshot(legacy_initialize_request(Some("active-first")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let account_id = *state_handle
        .read()
        .unwrap()
        .account_subjects
        .values()
        .next()
        .unwrap();
    state_handle
        .write()
        .unwrap()
        .accounts
        .get_mut(&account_id)
        .unwrap()
        .status = AccountStatus::Suspended;

    let response = router
        .oneshot(legacy_initialize_request(Some("active-first")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(response_json(response).await, json!({"error": "forbidden"}));
}

/// Both legacy and final protocol dispatch receive only the durable account UUID.
#[tokio::test]
async fn dispatcher_context_receives_authenticated_account_in_both_protocol_eras() {
    let verifier = FakeVerifier::default();
    verifier.allow("context-token", "context-subject", None);
    let catalog = MockCatalog::new();
    let state_handle = catalog.state.clone();
    let state = test_state(
        catalog,
        test_config(enabled_access_config()),
        Some(test_runtime(verifier)),
    );
    let dispatcher = Arc::new(AccountProbeDispatcher::default());
    let auth_layer = axum::middleware::from_fn_with_state(state.clone(), require_mcp_access);
    let router: Router =
        mcp_router_with_dispatcher::<AppState>(McpTransportConfig::default(), dispatcher.clone())
            .route_layer(auth_layer)
            .with_state(state);

    assert_eq!(
        router
            .clone()
            .oneshot(legacy_list_request(Some("context-token")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router
            .oneshot(modern_list_request(Some("context-token")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let expected = *state_handle
        .read()
        .unwrap()
        .account_subjects
        .values()
        .next()
        .unwrap();
    assert_eq!(
        dispatcher.observed_accounts.lock().unwrap().as_slice(),
        [Some(expected), Some(expected)]
    );
}

/// Per-account limiting runs after authentication and keys on the durable account UUID.
#[tokio::test]
async fn account_rate_limit_applies_after_access_authentication() {
    let verifier = FakeVerifier::default();
    verifier.allow("limited-token", "limited-subject", None);
    let mut config = (*test_config(enabled_access_config())).clone();
    config.account_rate_per_min = 1;
    let state = test_state(
        MockCatalog::new(),
        Arc::new(config),
        Some(test_runtime(verifier.clone())),
    );
    let router = app(state);

    assert_eq!(
        router
            .clone()
            .oneshot(legacy_initialize_request(Some("limited-token")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router
            .clone()
            .oneshot(legacy_initialize_request(Some("limited-token")))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let before = verifier.call_count();
    assert_eq!(
        router
            .oneshot(legacy_initialize_request(None))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(verifier.call_count(), before);
}
