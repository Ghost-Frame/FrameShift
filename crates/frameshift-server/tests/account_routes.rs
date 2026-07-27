//! Integration tests for OIDC account and publisher-owner HTTP workflows.

mod mocks;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::{Method, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use frameshift_catalog::{
    AccountInviteIntent, AccountInviteRecord, AccountInviteRequestRecord, AccountInviteStatus,
    AccountStatus, Ed25519PublicKey, MembershipState, PlatformRole, PlatformRoleRecord,
    PlatformRoleState, PublisherKeyRecord, PublisherKeyState, PublisherMembershipRecord,
    PublisherModerationStatus, PublisherProfileRecord, PublisherRole,
};
use frameshift_server::account_auth::{BearerTokenVerifier, OidcAuthError, VerifiedOidcIdentity};
use frameshift_server::metrics::Metrics;
use frameshift_server::{
    app, AppState, FirstPartyAuthConfig, InviteRequestConfig, LogFormat, OidcConfig, ServerConfig,
};
use http_body_util::BodyExt as _;
use secrecy::SecretString;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;
use uuid::Uuid;

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
    test_config_with_invites(InviteRequestConfig::disabled())
}

/// Build a server configuration with explicit invite application settings.
fn test_config_with_invites(invite_requests: InviteRequestConfig) -> Arc<ServerConfig> {
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
        account_rate_per_min: 0,
        signer_rate_per_min: 0,
        publisher_rate_per_min: 0,
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
        quarantine_object_store_backend: "disabled".to_string(),
        quarantine_object_store_root: PathBuf::from("/tmp/frameshift-quarantine-test"),
        quarantine_r2_endpoint: String::new(),
        quarantine_r2_bucket: String::new(),
        quarantine_r2_prefix: "quarantine".to_string(),
        quarantine_r2_region: "auto".to_string(),
        quarantine_r2_access_key_id: String::new(),
        quarantine_r2_secret_access_key: SecretString::new(String::new()),
        trust_forwarded_for: false,
        signed_request_max_skew: Duration::from_secs(300),
        admin_pubkeys: Vec::new(),
        publisher_ownership_reads: true,
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
        invite_requests,
        first_party_auth: frameshift_server::FirstPartyAuthConfig::disabled(),
        memory_backend: "none".to_string(),
        memory_http_endpoint: String::new(),
        memory_http_auth: "none".to_string(),
        memory_http_timeout_secs: 30,
        memory_sqlite_path: String::new(),
    })
}

/// Build a server configuration with deterministic first-party authentication enabled.
fn first_party_test_config() -> Arc<ServerConfig> {
    let mut config = (*test_config()).clone();
    config.cors_allowed_origins = "https://frameshift.test".to_string();
    config.first_party_auth = FirstPartyAuthConfig {
        password_pepper: SecretString::new("integration-test-password-pepper".to_string()),
        ..FirstPartyAuthConfig::disabled()
    };
    Arc::new(config)
}

/// Build application state around shared catalog and bearer verifier doubles.
fn test_state(catalog: MockCatalog, verifier: Option<FakeVerifier>) -> AppState {
    test_state_with_config(catalog, verifier, test_config())
}

/// Build application state around explicit server configuration.
fn test_state_with_config(
    catalog: MockCatalog,
    verifier: Option<FakeVerifier>,
    config: Arc<ServerConfig>,
) -> AppState {
    AppState {
        catalog: Arc::new(catalog),
        objects: Arc::new(MockPackStore::new()),
        runtime: None,
        memory: None,
        config,
        metrics: Arc::new(Metrics::new()),
        auth_nonces: Arc::new(frameshift_server::auth::NonceCache::new(
            Duration::from_secs(600),
        )),
        account_auth: verifier.map(|value| Arc::new(value) as Arc<dyn BearerTokenVerifier>),
    }
}

/// Start a local Turnstile Siteverify double with one deterministic outcome.
async fn spawn_turnstile_verifier(success: bool) -> String {
    let verifier = Router::new().route(
        "/",
        post(move || async move {
            Json(json!({
                "success": success,
                "hostname": "frameshift.test",
                "action": "invite_request"
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, verifier).await.unwrap();
    });
    format!("http://{address}/")
}

/// Return enabled invite settings bound to one local Siteverify double.
async fn enabled_invite_config(success: bool) -> InviteRequestConfig {
    InviteRequestConfig {
        turnstile_site_key: "1x00000000000000000000AA".to_string(),
        turnstile_secret: SecretString::new("test-secret".to_string()),
        expected_hostname: "frameshift.test".to_string(),
        verify_url: spawn_turnstile_verifier(success).await,
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

/// Send one browser request with exact Origin and optional Cookie headers.
async fn send_browser(
    state: AppState,
    method: Method,
    path: &str,
    origin: Option<&str>,
    cookie: Option<&str>,
    body: Option<Value>,
) -> axum::http::Response<axum::body::Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
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

/// Provision one test account and return its generated stable identifier.
async fn provision_account(state: AppState, token: &str) -> Uuid {
    let response = send(state, Method::GET, "/v1/account", Some(token), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    Uuid::parse_str(
        response_json(response).await["account"]["id"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

/// Seed one publisher, owner membership, and active key for an account.
fn seed_publisher(catalog: &MockCatalog, account_id: Uuid) -> (Uuid, Uuid) {
    let publisher_id = Uuid::new_v4();
    let key_id = Uuid::new_v4();
    let now = Utc::now();
    let mut state = catalog.state.write().unwrap();
    state.publishers.insert(
        publisher_id,
        PublisherProfileRecord {
            id: publisher_id,
            handle: format!("publisher-{}", &publisher_id.to_string()[..8]),
            display_name: "Intent Publisher".to_string(),
            biography: None,
            moderation_status: PublisherModerationStatus::Pending,
            created_at: now,
            updated_at: now,
        },
    );
    state.publisher_memberships.insert(
        (account_id, publisher_id),
        PublisherMembershipRecord {
            account_id,
            publisher_id,
            role: PublisherRole::Owner,
            state: MembershipState::Active,
            created_at: now,
            updated_at: now,
        },
    );
    state.publisher_keys.insert(
        key_id,
        PublisherKeyRecord {
            id: key_id,
            publisher_id,
            public_key: Ed25519PublicKey([41; 32]),
            label: "intent-test".to_string(),
            state: PublisherKeyState::Active,
            created_at: now,
            revoked_at: None,
            last_used_at: None,
        },
    );
    (publisher_id, key_id)
}

/// Seed one deterministic bootstrap invitation and return its raw token.
fn fixture_bootstrap_invite(catalog: &MockCatalog, email: &str) -> String {
    let raw_token = [7_u8; 32];
    let token = URL_SAFE_NO_PAD.encode(raw_token);
    let now = Utc::now();
    let invite = AccountInviteRecord {
        id: Uuid::new_v4(),
        request_id: None,
        normalized_email: email.to_string(),
        token_digest: Sha256::digest(raw_token).to_vec(),
        issued_by_account_id: None,
        is_bootstrap: true,
        expires_at: now + chrono::Duration::hours(1),
        consumed_at: None,
        revoked_at: None,
        created_at: now,
    };
    catalog
        .state
        .write()
        .unwrap()
        .account_invites
        .insert(invite.id, invite);
    token
}

/// Seed one pending invite application for administrator route tests.
fn fixture_invite_application(catalog: &MockCatalog, email: &str) -> Uuid {
    let now = Utc::now();
    let record = AccountInviteRequestRecord {
        id: Uuid::new_v4(),
        normalized_email: email.to_string(),
        display_name: Some("Invite Applicant".to_string()),
        intent: AccountInviteIntent::PublishPersonas,
        statement: "I publish carefully reviewed personas.".to_string(),
        status: AccountInviteStatus::Pending,
        consented_at: now,
        created_at: now,
        updated_at: now,
    };
    let id = record.id;
    catalog
        .state
        .write()
        .unwrap()
        .account_invite_requests
        .insert(email.to_string(), record);
    id
}

/// Give one active account administrator authority in the test catalog.
fn fixture_administrator(catalog: &MockCatalog, account_id: Uuid) {
    let now = Utc::now();
    catalog
        .state
        .write()
        .unwrap()
        .platform_roles
        .push(PlatformRoleRecord {
            account_id,
            role: PlatformRole::Administrator,
            state: PlatformRoleState::Active,
            assigned_by_account_id: account_id,
            created_at: now,
            updated_at: now,
        });
}

/// Construct a valid exact publication-intent request body.
fn intent_body(id: Uuid, publisher_id: Uuid, key_id: Uuid) -> Value {
    json!({
        "id": id,
        "publisher_id": publisher_id,
        "publisher_key_id": key_id,
        "archive_hash": "11".repeat(32),
        "manifest_hash": "22".repeat(32),
        "file_inventory_hash": "33".repeat(32),
        "scan_schema_version": 1
    })
}

/// Invite configuration always discloses the invite-only policy without secrets.
#[tokio::test]
async fn invite_config_discloses_invite_only_policy() {
    let response = send(
        test_state(MockCatalog::new(), None),
        Method::GET,
        "/v1/account-invite-requests",
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["registration"], "invite_only");
    assert_eq!(body["invite_requests_enabled"], false);
    assert!(body["turnstile_site_key"].is_null());
}

/// The production TCP boundary supplies peer addresses to rate-limited routes.
#[tokio::test]
async fn invite_config_works_over_tcp_with_ip_rate_limiting() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);

    let mut config = (*test_config()).clone();
    config.bind_addr = address;
    config.abuse_rate_per_min = 60;
    let state = test_state_with_config(MockCatalog::new(), None, Arc::new(config));
    let server = tokio::spawn(frameshift_server::run(state));
    let url = format!("http://{address}/v1/account-invite-requests");

    let mut response = None;
    for _attempt in 0..50 {
        match reqwest::get(&url).await {
            Ok(candidate) => {
                response = Some(candidate);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }

    let response = response.expect("server did not accept a TCP request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["registration"], "invite_only");
    drop(server);
}

/// A verified application is stored once and duplicate responses remain identical.
#[tokio::test]
async fn invite_application_is_verified_and_idempotent_by_email() {
    let catalog = MockCatalog::new();
    let config = test_config_with_invites(enabled_invite_config(true).await);
    let state = test_state_with_config(catalog.clone(), None, config);
    let body = json!({
        "email": "  Applicant@Example.Test ",
        "display_name": " Applicant ",
        "intent": "publish_personas",
        "statement": "I create security personas and want to publish them responsibly.",
        "consent": true,
        "turnstile_token": "single-use-test-token",
        "website": ""
    });

    let first = send(
        state.clone(),
        Method::POST,
        "/v1/account-invite-requests",
        None,
        Some(body.clone()),
    )
    .await;
    let second = send(
        state,
        Method::POST,
        "/v1/account-invite-requests",
        None,
        Some(body),
    )
    .await;
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    assert_eq!(response_json(first).await, response_json(second).await);

    let stored = catalog.state.read().unwrap();
    assert_eq!(stored.account_invite_requests.len(), 1);
    let application = stored
        .account_invite_requests
        .get("applicant@example.test")
        .unwrap();
    assert_eq!(application.display_name.as_deref(), Some("Applicant"));
}

/// Invite intake fails closed when anti-bot settings are absent.
#[tokio::test]
async fn invite_application_requires_configured_verification() {
    let response = send(
        test_state(MockCatalog::new(), None),
        Method::POST,
        "/v1/account-invite-requests",
        None,
        Some(json!({
            "email": "applicant@example.test",
            "intent": "other",
            "statement": "I would like to evaluate account features for my workflow.",
            "consent": true,
            "turnstile_token": "unverified-token"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// A rejected Turnstile token never reaches durable application storage.
#[tokio::test]
async fn invite_application_rejects_failed_turnstile_verification() {
    let catalog = MockCatalog::new();
    let config = test_config_with_invites(enabled_invite_config(false).await);
    let response = send(
        test_state_with_config(catalog.clone(), None, config),
        Method::POST,
        "/v1/account-invite-requests",
        None,
        Some(json!({
            "email": "applicant@example.test",
            "intent": "contribute",
            "statement": "I want to contribute careful documentation and useful personas.",
            "consent": true,
            "turnstile_token": "rejected-token"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(catalog
        .state
        .read()
        .unwrap()
        .account_invite_requests
        .is_empty());
}

/// Browser registration requires a trusted origin and produces one revocable cookie session.
#[tokio::test]
async fn invite_redemption_creates_one_browser_account_and_logout_revokes_it() {
    let catalog = MockCatalog::new();
    let invite_token = fixture_bootstrap_invite(&catalog, "member@example.test");
    let state = test_state_with_config(catalog.clone(), None, first_party_test_config());
    let registration = json!({
        "invite_token": invite_token,
        "email": " Member@Example.Test ",
        "display_name": " Member ",
        "password": "correct horse battery staple",
        "client_kind": "browser"
    });

    let untrusted = send_browser(
        state.clone(),
        Method::POST,
        "/v1/auth/register",
        None,
        None,
        Some(registration.clone()),
    )
    .await;
    assert_eq!(untrusted.status(), StatusCode::FORBIDDEN);

    let registered = send_browser(
        state.clone(),
        Method::POST,
        "/v1/auth/register",
        Some("https://frameshift.test"),
        None,
        Some(registration.clone()),
    )
    .await;
    assert_eq!(registered.status(), StatusCode::OK);
    let cookie = registered
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let registered_body = response_json(registered).await;
    assert!(registered_body["token"].is_null());
    assert_eq!(registered_body["account"]["email"], "member@example.test");

    {
        let stored = catalog.state.read().unwrap();
        assert_eq!(stored.accounts.len(), 1);
        assert_eq!(stored.account_password_credentials.len(), 1);
        assert_eq!(stored.account_sessions.len(), 1);
        assert!(stored
            .account_invites
            .values()
            .all(|invite| invite.consumed_at.is_some()));
        assert!(stored
            .account_password_credentials
            .get("member@example.test")
            .unwrap()
            .password_hash
            .starts_with("$argon2id$"));
    }

    let replayed = send_browser(
        state.clone(),
        Method::POST,
        "/v1/auth/register",
        Some("https://frameshift.test"),
        None,
        Some(registration),
    )
    .await;
    assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(catalog.state.read().unwrap().accounts.len(), 1);

    let authenticated = send_browser(
        state.clone(),
        Method::GET,
        "/v1/account",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(authenticated.status(), StatusCode::OK);

    let logged_out = send_browser(
        state.clone(),
        Method::POST,
        "/v1/auth/logout",
        Some("https://frameshift.test"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(logged_out.status(), StatusCode::OK);
    assert!(logged_out
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert!(catalog
        .state
        .read()
        .unwrap()
        .account_sessions
        .values()
        .all(|session| session.revoked_at.is_some()));

    let revoked = send_browser(state, Method::GET, "/v1/account", None, Some(&cookie), None).await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
}

/// Desktop login returns an explicit bearer token and rejects the wrong password.
#[tokio::test]
async fn desktop_password_login_uses_explicit_revocable_bearer_sessions() {
    let catalog = MockCatalog::new();
    let invite_token = fixture_bootstrap_invite(&catalog, "desktop@example.test");
    let state = test_state_with_config(catalog, None, first_party_test_config());
    let registered = send(
        state.clone(),
        Method::POST,
        "/v1/auth/register",
        None,
        Some(json!({
            "invite_token": invite_token,
            "email": "desktop@example.test",
            "password": "correct horse battery staple",
            "client_kind": "desktop"
        })),
    )
    .await;
    assert_eq!(registered.status(), StatusCode::OK);
    let initial_token = response_json(registered).await["token"]
        .as_str()
        .unwrap()
        .to_string();

    let wrong_password = send(
        state.clone(),
        Method::POST,
        "/v1/auth/login",
        None,
        Some(json!({
            "email": "desktop@example.test",
            "password": "incorrect horse battery staple",
            "client_kind": "desktop"
        })),
    )
    .await;
    assert_eq!(wrong_password.status(), StatusCode::UNAUTHORIZED);

    let logged_in = send(
        state.clone(),
        Method::POST,
        "/v1/auth/login",
        None,
        Some(json!({
            "email": " DESKTOP@example.test ",
            "password": "correct horse battery staple",
            "client_kind": "desktop"
        })),
    )
    .await;
    assert_eq!(logged_in.status(), StatusCode::OK);
    let token = response_json(logged_in).await["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(token, initial_token);
    assert_eq!(URL_SAFE_NO_PAD.decode(&token).unwrap().len(), 32);

    let authenticated = send(state, Method::GET, "/v1/account", Some(&token), None).await;
    assert_eq!(authenticated.status(), StatusCode::OK);
}

/// Mounted local authentication rejects an invalid bearer as unauthorized.
#[tokio::test]
async fn local_only_invalid_bearer_returns_unauthorized() {
    let state = test_state_with_config(MockCatalog::new(), None, first_party_test_config());
    let response = send(
        state,
        Method::GET,
        "/v1/account",
        Some("not-a-valid-session"),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Browser reviewers can preflight the PATCH operation used for state changes.
#[tokio::test]
async fn first_party_cors_allows_reviewer_patch_preflight() {
    let response = app(test_state_with_config(
        MockCatalog::new(),
        None,
        first_party_test_config(),
    ))
    .oneshot(
        Request::builder()
            .method(Method::OPTIONS)
            .uri(format!("/v1/admin/invite-requests/{}", Uuid::new_v4()))
            .header("origin", "https://frameshift.test")
            .header("access-control-request-method", "PATCH")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get("access-control-allow-methods")
        .unwrap()
        .to_str()
        .unwrap()
        .split(',')
        .any(|method| method.trim() == "PATCH"));
}

/// Only administrators can review applications and issued raw tokens are never persisted.
#[tokio::test]
async fn administrator_review_issues_one_digest_only_invitation() {
    let now = u64::try_from(Utc::now().timestamp()).unwrap();
    let verifier = FakeVerifier::new();
    verifier.allow("admin", "admin-subject", now);
    verifier.allow("member", "member-subject", now);
    let catalog = MockCatalog::new();
    let state = test_state_with_config(catalog.clone(), Some(verifier), first_party_test_config());
    let administrator_id = provision_account(state.clone(), "admin").await;
    let _member_id = provision_account(state.clone(), "member").await;
    fixture_administrator(&catalog, administrator_id);
    let application_id = fixture_invite_application(&catalog, "invitee@example.test");

    let unauthorized = send(
        state.clone(),
        Method::GET,
        "/v1/admin/invite-requests",
        Some("member"),
        None,
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::FORBIDDEN);

    let reviewing = send(
        state.clone(),
        Method::PATCH,
        &format!("/v1/admin/invite-requests/{application_id}"),
        Some("admin"),
        Some(json!({ "status": "reviewing" })),
    )
    .await;
    assert_eq!(reviewing.status(), StatusCode::OK);
    assert_eq!(response_json(reviewing).await["status"], "reviewing");

    let issued = send(
        state.clone(),
        Method::POST,
        &format!("/v1/admin/invite-requests/{application_id}/invite"),
        Some("admin"),
        None,
    )
    .await;
    assert_eq!(issued.status(), StatusCode::OK);
    let issued_body = response_json(issued).await;
    let raw_token = issued_body["token"].as_str().unwrap();
    let raw_bytes = URL_SAFE_NO_PAD.decode(raw_token).unwrap();
    assert_eq!(raw_bytes.len(), 32);
    {
        let stored = catalog.state.read().unwrap();
        assert_eq!(stored.account_invites.len(), 1);
        assert_eq!(
            stored.account_invites.values().next().unwrap().token_digest,
            Sha256::digest(raw_bytes).to_vec()
        );
        assert_eq!(
            stored
                .account_invite_requests
                .get("invitee@example.test")
                .unwrap()
                .status,
            AccountInviteStatus::Invited
        );
    }

    let duplicate = send(
        state,
        Method::POST,
        &format!("/v1/admin/invite-requests/{application_id}/invite"),
        Some("admin"),
        None,
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    assert_eq!(catalog.state.read().unwrap().account_invites.len(), 1);
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

/// Publisher creation cannot claim a handle already held by the legacy namespace.
#[tokio::test]
async fn publisher_creation_rejects_legacy_handle() {
    let now = u64::try_from(Utc::now().timestamp()).unwrap();
    let verifier = FakeVerifier::new();
    verifier.allow("owner", "namespace-owner", now);
    let catalog = MockCatalog::new();
    catalog
        .state
        .write()
        .unwrap()
        .handles
        .insert("legacy-owned".to_string(), Ed25519PublicKey([83_u8; 32]));
    let state = test_state(catalog.clone(), Some(verifier));

    let provisioned = send(
        state.clone(),
        Method::GET,
        "/v1/account",
        Some("owner"),
        None,
    )
    .await;
    assert_eq!(provisioned.status(), StatusCode::OK);
    let response = send(
        state,
        Method::POST,
        "/v1/publishers",
        Some("owner"),
        Some(json!({
            "handle": "legacy-owned",
            "display_name": "Legacy Owned"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(catalog.state.read().unwrap().publishers.is_empty());
}

/// Account views fail closed when a membership cannot resolve its publisher.
#[tokio::test]
async fn account_view_rejects_orphaned_publisher_membership() {
    let now = Utc::now();
    let verifier = FakeVerifier::new();
    verifier.allow(
        "owner",
        "orphaned-owner",
        u64::try_from(now.timestamp()).unwrap(),
    );
    let catalog = MockCatalog::new();
    let state = test_state(catalog.clone(), Some(verifier));
    let account_id = provision_account(state.clone(), "owner").await;
    let publisher_id = Uuid::new_v4();
    catalog.state.write().unwrap().publisher_memberships.insert(
        (account_id, publisher_id),
        PublisherMembershipRecord {
            account_id,
            publisher_id,
            role: PublisherRole::Owner,
            state: MembershipState::Active,
            created_at: now,
            updated_at: now,
        },
    );

    let response = send(state, Method::GET, "/v1/account", Some("owner"), None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Account authentication failures increment the bounded workflow metric.
#[tokio::test]
async fn account_auth_rejection_records_creator_workflow_outcome() {
    let state = test_state(MockCatalog::new(), Some(FakeVerifier::new()));
    let metrics = Arc::clone(&state.metrics);

    let response = send(state, Method::GET, "/v1/account", None, None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(metrics
        .encode_text()
        .contains("creator_workflow_outcomes_total{outcome=\"client_error\",stage=\"account\"} 1"));
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

    let joined_account = send(
        state.clone(),
        Method::GET,
        "/v1/account",
        Some("owner"),
        None,
    )
    .await;
    assert_eq!(joined_account.status(), StatusCode::OK);
    let joined_account = response_json(joined_account).await;
    assert_eq!(
        joined_account["memberships"][0]["publisher_id"],
        publisher_id
    );
    assert_eq!(joined_account["publishers"][0]["id"], publisher_id);
    assert_eq!(joined_account["publishers"][0]["handle"], "gatekeeper");

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

    let enrollment_body = json!({
        "public_key": public_key,
        "label": "primary",
        "proof_signature": proof_signature
    });
    let enrolled = send(
        state.clone(),
        Method::POST,
        "/v1/publishers/gatekeeper/keys",
        Some("owner"),
        Some(enrollment_body.clone()),
    )
    .await;
    assert_eq!(enrolled.status(), StatusCode::OK);
    let enrolled = response_json(enrolled).await;
    let key_id = enrolled["id"].as_str().unwrap();

    let retried = send(
        state.clone(),
        Method::POST,
        "/v1/publishers/gatekeeper/keys",
        Some("owner"),
        Some(enrollment_body),
    )
    .await;
    assert_eq!(retried.status(), StatusCode::OK);
    let retried = response_json(retried).await;
    assert_eq!(retried["id"].as_str(), Some(key_id));

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

/// Publication-intent routes are absent without auth and reject missing credentials.
#[tokio::test]
async fn publication_intent_routes_require_configured_bearer_authentication() {
    let id = Uuid::new_v4();
    let disabled = send(
        test_state(MockCatalog::new(), None),
        Method::GET,
        &format!("/v1/publish-intents/{id}"),
        None,
        None,
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::NOT_FOUND);

    let verifier = FakeVerifier::new();
    verifier.allow(
        "owner",
        "owner-subject",
        u64::try_from(Utc::now().timestamp()).unwrap(),
    );
    let enabled = test_state(MockCatalog::new(), Some(verifier));
    let missing = send(
        enabled.clone(),
        Method::GET,
        &format!("/v1/publish-intents/{id}"),
        None,
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let invalid = send(
        enabled,
        Method::GET,
        &format!("/v1/publish-intents/{id}"),
        Some("invalid"),
        None,
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
}

/// Creation binds server-owned fields and preserves exact retry semantics.
#[tokio::test]
async fn publication_intent_creation_is_bound_and_idempotent() {
    let verifier = FakeVerifier::new();
    verifier.allow(
        "owner",
        "owner-subject",
        u64::try_from(Utc::now().timestamp()).unwrap(),
    );
    let catalog = MockCatalog::new();
    let state = test_state(catalog.clone(), Some(verifier));
    let account_id = provision_account(state.clone(), "owner").await;
    let (publisher_id, key_id) = seed_publisher(&catalog, account_id);
    let id = Uuid::new_v4();
    let body = intent_body(id, publisher_id, key_id);

    let first = send(
        state.clone(),
        Method::POST,
        "/v1/publish-intents",
        Some("owner"),
        Some(body.clone()),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_json = response_json(first).await;
    assert_eq!(first_json["account_id"], account_id.to_string());
    assert!(first_json["consumed_at"].is_null());
    let created_at = first_json["created_at"].as_str().unwrap();
    let expires_at = first_json["expires_at"].as_str().unwrap();
    let ttl = expires_at
        .parse::<chrono::DateTime<Utc>>()
        .unwrap()
        .signed_duration_since(created_at.parse::<chrono::DateTime<Utc>>().unwrap());
    assert_eq!(ttl, chrono::Duration::minutes(15));

    let retry = send(
        state.clone(),
        Method::POST,
        "/v1/publish-intents",
        Some("owner"),
        Some(body.clone()),
    )
    .await;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(response_json(retry).await, first_json);

    let mut changed = body;
    changed["scan_schema_version"] = json!(2);
    let conflict = send(
        state,
        Method::POST,
        "/v1/publish-intents",
        Some("owner"),
        Some(changed),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
}

/// Retrieval returns owned intents while hiding foreign and missing identifiers.
#[tokio::test]
async fn publication_intent_retrieval_is_account_scoped() {
    let now = u64::try_from(Utc::now().timestamp()).unwrap();
    let verifier = FakeVerifier::new();
    verifier.allow("owner", "owner-subject", now);
    verifier.allow("other", "other-subject", now);
    let catalog = MockCatalog::new();
    let state = test_state(catalog.clone(), Some(verifier));
    let owner_id = provision_account(state.clone(), "owner").await;
    let _other_id = provision_account(state.clone(), "other").await;
    let (publisher_id, key_id) = seed_publisher(&catalog, owner_id);
    let id = Uuid::new_v4();
    let created = send(
        state.clone(),
        Method::POST,
        "/v1/publish-intents",
        Some("owner"),
        Some(intent_body(id, publisher_id, key_id)),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);

    let owned = send(
        state.clone(),
        Method::GET,
        &format!("/v1/publish-intents/{id}"),
        Some("owner"),
        None,
    )
    .await;
    assert_eq!(owned.status(), StatusCode::OK);
    assert_eq!(response_json(owned).await["id"], id.to_string());

    let foreign = send(
        state.clone(),
        Method::GET,
        &format!("/v1/publish-intents/{id}"),
        Some("other"),
        None,
    )
    .await;
    let foreign_status = foreign.status();
    let foreign_body = response_json(foreign).await;
    let missing = send(
        state,
        Method::GET,
        &format!("/v1/publish-intents/{}", Uuid::new_v4()),
        Some("other"),
        None,
    )
    .await;
    assert_eq!(foreign_status, StatusCode::NOT_FOUND);
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(foreign_body, response_json(missing).await);
}

/// Invalid scanner schemas and unauthorized identity bindings fail closed.
#[tokio::test]
async fn publication_intent_creation_rejects_invalid_or_unauthorized_bindings() {
    let now = u64::try_from(Utc::now().timestamp()).unwrap();
    let verifier = FakeVerifier::new();
    verifier.allow("owner", "owner-subject", now);
    verifier.allow("other", "other-subject", now);
    let catalog = MockCatalog::new();
    let state = test_state(catalog.clone(), Some(verifier));
    let owner_id = provision_account(state.clone(), "owner").await;
    let _other_id = provision_account(state.clone(), "other").await;
    let (publisher_id, key_id) = seed_publisher(&catalog, owner_id);

    let mut invalid_schema = intent_body(Uuid::new_v4(), publisher_id, key_id);
    invalid_schema["scan_schema_version"] = json!(0);
    let invalid = send(
        state.clone(),
        Method::POST,
        "/v1/publish-intents",
        Some("owner"),
        Some(invalid_schema),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let mut injected_server_fields = intent_body(Uuid::new_v4(), publisher_id, key_id);
    injected_server_fields["account_id"] = json!(owner_id);
    injected_server_fields["expires_at"] = json!("2099-01-01T00:00:00Z");
    let injected = send(
        state.clone(),
        Method::POST,
        "/v1/publish-intents",
        Some("owner"),
        Some(injected_server_fields),
    )
    .await;
    assert_eq!(injected.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let unauthorized = send(
        state,
        Method::POST,
        "/v1/publish-intents",
        Some("other"),
        Some(intent_body(Uuid::new_v4(), publisher_id, key_id)),
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::FORBIDDEN);
}

/// Send one request through a shared router so limiter state persists.
async fn send_on_router(
    router: &axum::Router,
    path: &str,
    token: &str,
) -> axum::http::Response<axum::body::Body> {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// One account exhausting its identity budget is rejected while another proceeds.
#[tokio::test]
async fn account_rate_limit_bounds_each_account_independently() {
    let now = Utc::now();
    let verifier = FakeVerifier::new();
    verifier.allow(
        "token-a",
        "rate-limit-subject-a",
        u64::try_from(now.timestamp()).unwrap(),
    );
    verifier.allow(
        "token-b",
        "rate-limit-subject-b",
        u64::try_from(now.timestamp()).unwrap(),
    );
    let mut state = test_state(MockCatalog::new(), Some(verifier));
    let mut config = (*state.config).clone();
    config.account_rate_per_min = 1;
    state.config = Arc::new(config);
    let router = app(state);

    let first = send_on_router(&router, "/v1/account", "token-a").await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = send_on_router(&router, "/v1/account", "token-a").await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let other = send_on_router(&router, "/v1/account", "token-b").await;
    assert_eq!(
        other.status(),
        StatusCode::OK,
        "an unrelated account must not be affected by another account's budget"
    );
}

/// A zero account rate disables the identity limiter entirely.
#[tokio::test]
async fn account_rate_limit_zero_disables_the_limiter() {
    let now = Utc::now();
    let verifier = FakeVerifier::new();
    verifier.allow(
        "token-a",
        "rate-limit-disabled-subject",
        u64::try_from(now.timestamp()).unwrap(),
    );
    let state = test_state(MockCatalog::new(), Some(verifier));
    let router = app(state);

    for _ in 0..5 {
        let response = send_on_router(&router, "/v1/account", "token-a").await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
