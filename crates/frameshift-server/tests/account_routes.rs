//! Integration tests for OIDC account and publisher-owner HTTP workflows.

mod mocks;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use frameshift_catalog::{AccountStatus, Ed25519PublicKey, MembershipState};
use frameshift_server::account_auth::{BearerTokenVerifier, OidcAuthError, VerifiedOidcIdentity};
use frameshift_server::metrics::Metrics;
use frameshift_server::{app, AppState, LogFormat, OidcConfig, ServerConfig};
use http_body_util::BodyExt as _;
use secrecy::SecretString;
use serde_json::{json, Value};
use tower::ServiceExt as _;

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Deterministic bearer verifier used to isolate route authorization behavior.
#[derive(Clone)]
struct FakeVerifier {
    /// Opaque test tokens mapped to validated identities or sanitized failures.
    outcomes: Arc<RwLock<HashMap<String, Result<VerifiedOidcIdentity, OidcAuthError>>>>,
}

/// Constructors and mutation helpers for the bearer verifier test double.
impl FakeVerifier {
    /// Build a verifier with no accepted tokens.
    fn new() -> Self {
        Self {
            outcomes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a stable active identity for one opaque token.
    fn allow(&self, token: &str, subject: &str, auth_time: u64) {
        self.outcomes.write().unwrap().insert(
            token.to_string(),
            Ok(VerifiedOidcIdentity {
                issuer: "https://issuer.frameshift.test".to_string(),
                subject: subject.to_string(),
                email: Some(format!("{subject}@example.test")),
                display_name: Some(subject.to_string()),
                auth_time: Some(auth_time),
            }),
        );
    }

    /// Register a sanitized verification failure for one opaque token.
    fn reject_with(&self, token: &str, error: OidcAuthError) {
        self.outcomes
            .write()
            .unwrap()
            .insert(token.to_string(), Err(error));
    }
}

/// Bearer verification behavior for account route integration tests.
#[async_trait]
impl BearerTokenVerifier for FakeVerifier {
    /// Return the preconfigured identity or failure without parsing token bytes.
    async fn verify(&self, token: &str) -> Result<VerifiedOidcIdentity, OidcAuthError> {
        self.outcomes
            .read()
            .unwrap()
            .get(token)
            .cloned()
            .unwrap_or(Err(OidcAuthError::InvalidToken))
    }
}

/// Build a server configuration with account authentication enabled.
fn test_config() -> Arc<ServerConfig> {
    Arc::new(ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        postgres_url: SecretString::new("postgres://test".into()),
        object_store_root: PathBuf::from("/tmp"),
        log_level: "off".into(),
        log_format: LogFormat::Text,
        max_request_bytes: 1_048_576,
        max_search_limit: 100,
        shutdown_grace: Duration::from_secs(1),
        cors_allowed_origins: String::new(),
        download_secret: SecretString::new(String::new()),
        download_token_ttl: Duration::from_secs(300),
        download_max_token_ttl: Duration::from_secs(1800),
        download_rate_per_min: 0,
        abuse_rate_per_min: 0,
        metrics_bearer_token: SecretString::new(String::new()),
        publisher_pubkeys: vec!["*".to_string()],
        max_versions_per_author: 0,
        max_bytes_per_author: 0,
        max_total_bytes: 0,
        object_store_backend: "fs".to_string(),
        r2_endpoint: String::new(),
        r2_bucket: String::new(),
        r2_prefix: "objects".to_string(),
        r2_region: "auto".to_string(),
        r2_access_key_id: String::new(),
        r2_secret_access_key: SecretString::new(String::new()),
        trust_forwarded_for: false,
        signed_request_max_skew: Duration::from_secs(300),
        admin_pubkeys: Vec::new(),
        oidc: OidcConfig {
            enabled: true,
            issuer: "https://issuer.frameshift.test".to_string(),
            audience: "frameshift-api".to_string(),
            jwks_url: "https://issuer.frameshift.test/jwks".to_string(),
            allowed_algorithms: vec!["EdDSA".to_string()],
            jwks_cache_ttl: Duration::from_secs(300),
            jwks_stale_ttl: Duration::from_secs(900),
            clock_skew: Duration::from_secs(30),
            fresh_auth_max_age: Duration::from_secs(300),
        },
        memory_backend: "none".to_string(),
        memory_http_endpoint: String::new(),
        memory_http_auth: "none".to_string(),
        memory_http_timeout_secs: 30,
        memory_sqlite_path: String::new(),
    })
}

/// Build application state around shared catalog and bearer verifier doubles.
fn test_state(catalog: MockCatalog, verifier: Option<FakeVerifier>) -> AppState {
    AppState {
        catalog: Arc::new(catalog),
        objects: Arc::new(MockPackStore::new()),
        runtime: None,
        memory: None,
        config: test_config(),
        metrics: Arc::new(Metrics::new()),
        auth_nonces: Arc::new(frameshift_server::auth::NonceCache::new(
            Duration::from_secs(600),
        )),
        account_auth: verifier.map(|value| Arc::new(value) as Arc<dyn BearerTokenVerifier>),
    }
}

/// Send one JSON request through the in-process router.
async fn send(
    state: AppState,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> axum::http::Response<axum::body::Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let bytes = body.map_or_else(Vec::new, |value| serde_json::to_vec(&value).unwrap());
    if !bytes.is_empty() {
        builder = builder.header("content-type", "application/json");
    }
    app(state)
        .oneshot(builder.body(axum::body::Body::from(bytes)).unwrap())
        .await
        .unwrap()
}

/// Decode one JSON response body after its status has been asserted.
async fn response_json(response: axum::http::Response<axum::body::Body>) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Disabled auth omits protected routes while retaining public capability metadata.
#[tokio::test]
async fn disabled_auth_never_mounts_protected_routes() {
    let state = test_state(MockCatalog::new(), None);
    let config = send(state.clone(), Method::GET, "/v1/auth/config", None, None).await;
    assert_eq!(config.status(), StatusCode::OK);
    assert_eq!(response_json(config).await["enabled"], false);

    let account = send(state, Method::GET, "/v1/account", None, None).await;
    assert_eq!(account.status(), StatusCode::NOT_FOUND);
}

/// Account JIT provisioning, publisher ownership, key proof, and suspension are enforced.
#[tokio::test]
async fn account_and_publisher_security_workflow_is_enforced() {
    let now = u64::try_from(Utc::now().timestamp()).unwrap();
    let verifier = FakeVerifier::new();
    verifier.allow("owner", "owner-subject", now);
    verifier.allow("other", "other-subject", now);
    verifier.allow("stale", "owner-subject", now.saturating_sub(301));
    verifier.reject_with("outage", OidcAuthError::ProviderUnavailable);
    let catalog = MockCatalog::new();
    let state = test_state(catalog.clone(), Some(verifier));

    let missing = send(state.clone(), Method::GET, "/v1/account", None, None).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let unavailable = send(
        state.clone(),
        Method::GET,
        "/v1/account",
        Some("outage"),
        None,
    )
    .await;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

    let account = send(
        state.clone(),
        Method::GET,
        "/v1/account",
        Some("owner"),
        None,
    )
    .await;
    assert_eq!(account.status(), StatusCode::OK);
    let account_json = response_json(account).await;
    let account_id = account_json["account"]["id"].as_str().unwrap();

    let oversized_account = send(
        state.clone(),
        Method::PATCH,
        "/v1/account",
        Some("owner"),
        Some(json!({"display_name": "x".repeat(101)})),
    )
    .await;
    assert_eq!(oversized_account.status(), StatusCode::BAD_REQUEST);

    let created = send(
        state.clone(),
        Method::POST,
        "/v1/publishers",
        Some("owner"),
        Some(json!({
            "handle": "gatekeeper",
            "display_name": "Gatekeeper",
            "biography": "Verifies before release."
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let publisher = response_json(created).await;
    let publisher_id = publisher["id"].as_str().unwrap();

    let public = send(
        state.clone(),
        Method::GET,
        "/v1/publishers/gatekeeper",
        None,
        None,
    )
    .await;
    assert_eq!(public.status(), StatusCode::OK);

    let cross_account = send(
        state.clone(),
        Method::PATCH,
        "/v1/publishers/gatekeeper",
        Some("other"),
        Some(json!({"display_name": "Nope"})),
    )
    .await;
    assert_eq!(cross_account.status(), StatusCode::FORBIDDEN);

    let stale_profile_update = send(
        state.clone(),
        Method::PATCH,
        "/v1/publishers/gatekeeper",
        Some("stale"),
        Some(json!({"display_name": "Too Old"})),
    )
    .await;
    assert_eq!(stale_profile_update.status(), StatusCode::FORBIDDEN);

    let stale = send(
        state.clone(),
        Method::POST,
        "/v1/publishers/gatekeeper/keys/challenge",
        Some("stale"),
        Some(json!({"public_key": URL_SAFE_NO_PAD.encode([7_u8; 32])})),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::FORBIDDEN);

    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let public_key = Ed25519PublicKey(signing_key.verifying_key().to_bytes()).to_string();
    let challenge = send(
        state.clone(),
        Method::POST,
        "/v1/publishers/gatekeeper/keys/challenge",
        Some("owner"),
        Some(json!({"public_key": public_key})),
    )
    .await;
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge = response_json(challenge).await;
    let challenge_text = challenge["challenge"].as_str().unwrap();
    assert_eq!(
        challenge_text,
        format!("frameshift-key-enrollment:v1:{account_id}:{publisher_id}:{public_key}")
    );
    let proof_signature =
        URL_SAFE_NO_PAD.encode(signing_key.sign(challenge_text.as_bytes()).to_bytes());

    let enrolled = send(
        state.clone(),
        Method::POST,
        "/v1/publishers/gatekeeper/keys",
        Some("owner"),
        Some(json!({
            "public_key": public_key,
            "label": "primary",
            "proof_signature": proof_signature
        })),
    )
    .await;
    assert_eq!(enrolled.status(), StatusCode::OK);
    let enrolled = response_json(enrolled).await;
    let key_id = enrolled["id"].as_str().unwrap();

    let last_key = send(
        state.clone(),
        Method::DELETE,
        &format!("/v1/publishers/gatekeeper/keys/{key_id}"),
        Some("owner"),
        None,
    )
    .await;
    assert_eq!(last_key.status(), StatusCode::BAD_REQUEST);

    {
        let mut catalog_state = catalog.state.write().unwrap();
        let membership = catalog_state
            .publisher_memberships
            .values_mut()
            .next()
            .unwrap();
        membership.state = MembershipState::Revoked;
    }
    let revoked_membership = send(
        state.clone(),
        Method::PATCH,
        "/v1/publishers/gatekeeper",
        Some("owner"),
        Some(json!({"display_name": "Blocked"})),
    )
    .await;
    assert_eq!(revoked_membership.status(), StatusCode::FORBIDDEN);

    {
        let mut catalog_state = catalog.state.write().unwrap();
        let owner = catalog_state
            .accounts
            .values_mut()
            .find(|account| account.subject == "owner-subject")
            .unwrap();
        owner.status = AccountStatus::Suspended;
    }
    let suspended = send(
        state.clone(),
        Method::GET,
        "/v1/account",
        Some("owner"),
        None,
    )
    .await;
    assert_eq!(suspended.status(), StatusCode::FORBIDDEN);

    let catalog_state = catalog.state.read().unwrap();
    assert_eq!(catalog_state.accounts.len(), 2);
    assert_eq!(catalog_state.publisher_audit_events.len(), 2);
}
