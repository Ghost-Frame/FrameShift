//! Integration tests for bearer-authenticated publication moderation routes.

mod mocks;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use frameshift_catalog::{
    AccountRecord, AccountStatus, MembershipState, PlatformRole, PlatformRoleRecord,
    PlatformRoleState, PublicationSubmissionRecord, PublicationSubmissionState,
    PublisherMembershipRecord, PublisherRole,
};
use frameshift_objects::ObjectHash;
use frameshift_publication::PublicationReport;
use frameshift_server::account_auth::{BearerTokenVerifier, OidcAuthError, VerifiedOidcIdentity};
use frameshift_server::metrics::Metrics;
use frameshift_server::{app, AppState, OidcConfig, ServerConfig};
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use tower::ServiceExt as _;
use uuid::Uuid;

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Stable issuer shared by test identities and catalog accounts.
const TEST_ISSUER: &str = "https://issuer.frameshift.test";

/// Deterministic bearer verifier backed by opaque test tokens.
#[derive(Clone)]
struct FakeVerifier {
    /// Opaque bearer tokens mapped to verified identities.
    identities: Arc<RwLock<HashMap<String, VerifiedOidcIdentity>>>,
}

/// Construction helpers for the deterministic bearer verifier.
impl FakeVerifier {
    /// Build a verifier containing every moderation test identity.
    fn new() -> Self {
        let subjects = [
            ("moderator-token", "moderator"),
            ("administrator-token", "administrator"),
            ("ordinary-token", "ordinary"),
            ("revoked-token", "revoked"),
            ("owner-token", "owner"),
        ];
        Self {
            identities: Arc::new(RwLock::new(
                subjects
                    .into_iter()
                    .map(|(token, subject)| (token.to_string(), identity(subject)))
                    .collect(),
            )),
        }
    }
}

/// Verify only bearer tokens explicitly installed in the fixture.
#[async_trait]
impl BearerTokenVerifier for FakeVerifier {
    /// Return a configured identity or a sanitized invalid-token failure.
    async fn verify(&self, token: &str) -> Result<VerifiedOidcIdentity, OidcAuthError> {
        self.identities
            .read()
            .unwrap()
            .get(token)
            .cloned()
            .ok_or(OidcAuthError::InvalidToken)
    }
}

/// Stable identities and records used across moderation route tests.
struct Fixture {
    /// Shared mutable catalog used by the in-process router.
    catalog: MockCatalog,
    /// Fully composed application state with bearer authentication enabled.
    state: AppState,
    /// Quarantined submission available for moderation.
    submission: PublicationSubmissionRecord,
    /// Active moderator account identifier.
    moderator_id: Uuid,
    /// Publisher owner who also holds a moderator role.
    owner_id: Uuid,
}

/// Build one verified identity for an exact OIDC subject.
fn identity(subject: &str) -> VerifiedOidcIdentity {
    VerifiedOidcIdentity {
        issuer: TEST_ISSUER.to_string(),
        subject: subject.to_string(),
        email: Some(format!("{subject}@example.test")),
        display_name: Some(subject.to_string()),
        auth_time: Some(Utc::now().timestamp() as u64),
    }
}

/// Build an account-auth-enabled server configuration for route tests.
fn test_config() -> Arc<ServerConfig> {
    let mut config = ServerConfig::from_env().unwrap();
    config.bind_addr = "127.0.0.1:0".parse().unwrap();
    config.log_level = "off".to_string();
    config.max_request_bytes = 1_048_576;
    config.abuse_rate_per_min = 0;
    config.download_rate_per_min = 0;
    config.oidc = OidcConfig {
        enabled: true,
        issuer: TEST_ISSUER.to_string(),
        audience: "frameshift-api".to_string(),
        jwks_url: format!("{TEST_ISSUER}/jwks"),
        allowed_algorithms: vec!["EdDSA".to_string()],
        jwks_cache_ttl: Duration::from_secs(300),
        jwks_stale_ttl: Duration::from_secs(900),
        clock_skew: Duration::from_secs(30),
        fresh_auth_max_age: Duration::from_secs(300),
    };
    Arc::new(config)
}

/// Insert one active account and its exact OIDC subject mapping.
fn seed_account(catalog: &MockCatalog, id: Uuid, subject: &str) {
    let now = Utc::now();
    let mut state = catalog.state.write().unwrap();
    state
        .account_subjects
        .insert((TEST_ISSUER.to_string(), subject.to_string()), id);
    state.accounts.insert(
        id,
        AccountRecord {
            id,
            issuer: TEST_ISSUER.to_string(),
            subject: subject.to_string(),
            email: Some(format!("{subject}@example.test")),
            display_name: Some(subject.to_string()),
            status: AccountStatus::Active,
            created_at: now,
            updated_at: now,
        },
    );
}

/// Assign one global platform role to an account.
fn seed_role(
    catalog: &MockCatalog,
    account_id: Uuid,
    role: PlatformRole,
    state: PlatformRoleState,
) {
    let now = Utc::now();
    catalog
        .state
        .write()
        .unwrap()
        .platform_roles
        .push(PlatformRoleRecord {
            account_id,
            role,
            state,
            assigned_by_account_id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
        });
}

/// Build a complete moderation fixture with authorized and denied identities.
fn fixture() -> Fixture {
    let catalog = MockCatalog::new();
    let moderator_id = Uuid::new_v4();
    let administrator_id = Uuid::new_v4();
    let ordinary_id = Uuid::new_v4();
    let revoked_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    for (id, subject) in [
        (moderator_id, "moderator"),
        (administrator_id, "administrator"),
        (ordinary_id, "ordinary"),
        (revoked_id, "revoked"),
        (owner_id, "owner"),
    ] {
        seed_account(&catalog, id, subject);
    }
    seed_role(
        &catalog,
        moderator_id,
        PlatformRole::Moderator,
        PlatformRoleState::Active,
    );
    seed_role(
        &catalog,
        administrator_id,
        PlatformRole::Administrator,
        PlatformRoleState::Active,
    );
    seed_role(
        &catalog,
        revoked_id,
        PlatformRole::Moderator,
        PlatformRoleState::Revoked,
    );
    seed_role(
        &catalog,
        owner_id,
        PlatformRole::Moderator,
        PlatformRoleState::Active,
    );

    let now = Utc::now();
    let publisher_id = Uuid::new_v4();
    let submission = PublicationSubmissionRecord {
        id: Uuid::new_v4(),
        intent_id: Uuid::new_v4(),
        account_id: owner_id,
        publisher_id,
        publisher_key_id: Uuid::new_v4(),
        archive_hash: ObjectHash::of(b"archive"),
        manifest_hash: ObjectHash::of(b"manifest"),
        file_inventory_hash: ObjectHash::of(b"inventory"),
        scan_schema_version: 1,
        scan_report: PublicationReport {
            schema_version: 1,
            valid: true,
            inventory_hash: ObjectHash::of(b"inventory").to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
        },
        state: PublicationSubmissionState::Quarantined,
        created_at: now,
        updated_at: now,
    };
    {
        let mut state = catalog.state.write().unwrap();
        state.publisher_memberships.insert(
            (owner_id, publisher_id),
            PublisherMembershipRecord {
                account_id: owner_id,
                publisher_id,
                role: PublisherRole::Owner,
                state: MembershipState::Active,
                created_at: now,
                updated_at: now,
            },
        );
        state
            .publication_submissions
            .insert(submission.id, submission.clone());
    }
    let state = AppState {
        catalog: Arc::new(catalog.clone()),
        objects: Arc::new(MockPackStore::new()),
        runtime: None,
        memory: None,
        config: test_config(),
        metrics: Arc::new(Metrics::new()),
        auth_nonces: Arc::new(frameshift_server::auth::NonceCache::new(
            Duration::from_secs(600),
        )),
        account_auth: Some(Arc::new(FakeVerifier::new())),
    };
    Fixture {
        catalog,
        state,
        submission,
        moderator_id,
        owner_id,
    }
}

/// Send one JSON request through the in-process application.
async fn send(
    state: AppState,
    method: Method,
    path: &str,
    token: Option<&str>,
    request_id: Option<&str>,
    body: Option<Value>,
) -> axum::http::Response<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if let Some(request_id) = request_id {
        builder = builder.header("x-request-id", request_id);
    }
    let bytes = body.map_or_else(Vec::new, |value| serde_json::to_vec(&value).unwrap());
    if !bytes.is_empty() {
        builder = builder.header("content-type", "application/json");
    }
    app(state)
        .oneshot(builder.body(Body::from(bytes)).unwrap())
        .await
        .unwrap()
}

/// Decode one JSON response body.
async fn response_json(response: axum::http::Response<Body>) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Build the canonical valid decision body.
fn decision_body(id: Uuid, action: &str) -> Value {
    json!({
        "id": id,
        "action": action,
        "reason_code": "review_complete",
        "private_explanation": "The artifact passed review."
    })
}

#[tokio::test]
/// Moderation routes require a valid bearer token.
async fn moderation_requires_authentication() {
    let fixture = fixture();
    let path = format!(
        "/v1/moderation/publication-submissions/{}",
        fixture.submission.id
    );
    for token in [None, Some("invalid-token")] {
        let response = send(fixture.state.clone(), Method::GET, &path, token, None, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
/// Reads fail closed for ordinary and revoked-role accounts.
async fn moderation_reads_require_active_role() {
    let fixture = fixture();
    let path = format!(
        "/v1/moderation/publication-submissions/{}",
        fixture.submission.id
    );
    for token in ["ordinary-token", "revoked-token"] {
        let response = send(
            fixture.state.clone(),
            Method::GET,
            &path,
            Some(token),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_json(response).await, json!({"error": "forbidden"}));
    }
    for token in ["moderator-token", "administrator-token"] {
        let response = send(
            fixture.state.clone(),
            Method::GET,
            &path,
            Some(token),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(response).await["id"],
            fixture.submission.id.to_string()
        );
    }
}

#[tokio::test]
/// Decisions bind actor, submission, and request identifiers outside the JSON body.
async fn moderation_decision_uses_trusted_bindings() {
    let fixture = fixture();
    let decision_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let path = format!(
        "/v1/moderation/publication-submissions/{}/decisions",
        fixture.submission.id
    );
    let response = send(
        fixture.state.clone(),
        Method::POST,
        &path,
        Some("moderator-token"),
        Some(&request_id.to_string()),
        Some(decision_body(decision_id, "approve")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["actor_account_id"], fixture.moderator_id.to_string());
    assert_eq!(body["submission_id"], fixture.submission.id.to_string());
    assert_eq!(body["request_id"], request_id.to_string());
    assert_eq!(body["to_state"], "approved");
    let state = fixture.catalog.state.read().unwrap();
    assert_eq!(
        state
            .publication_submissions
            .get(&fixture.submission.id)
            .unwrap()
            .state,
        PublicationSubmissionState::Approved
    );
}

#[tokio::test]
/// Unknown identity and replay binding fields are rejected instead of ignored.
async fn moderation_decision_rejects_binding_overrides() {
    let fixture = fixture();
    let path = format!(
        "/v1/moderation/publication-submissions/{}/decisions",
        fixture.submission.id
    );
    let mut body = decision_body(Uuid::new_v4(), "approve");
    body["actor_account_id"] = json!(fixture.owner_id);
    let response = send(
        fixture.state,
        Method::POST,
        &path,
        Some("moderator-token"),
        Some(&Uuid::new_v4().to_string()),
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
/// A globally privileged publisher owner cannot review their own submission.
async fn moderation_decision_rejects_self_review() {
    let fixture = fixture();
    let path = format!(
        "/v1/moderation/publication-submissions/{}/decisions",
        fixture.submission.id
    );
    let response = send(
        fixture.state,
        Method::POST,
        &path,
        Some("owner-token"),
        Some(&Uuid::new_v4().to_string()),
        Some(decision_body(Uuid::new_v4(), "reject")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await, json!({"error": "forbidden"}));
}

#[tokio::test]
/// Exact decision retries succeed while changed replays conflict.
async fn moderation_decision_enforces_exact_idempotency() {
    let fixture = fixture();
    let path = format!(
        "/v1/moderation/publication-submissions/{}/decisions",
        fixture.submission.id
    );
    let decision_id = Uuid::new_v4();
    let request_id = Uuid::new_v4().to_string();
    let body = decision_body(decision_id, "request_changes");
    let first = send(
        fixture.state.clone(),
        Method::POST,
        &path,
        Some("moderator-token"),
        Some(&request_id),
        Some(body.clone()),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = response_json(first).await;
    let retry = send(
        fixture.state.clone(),
        Method::POST,
        &path,
        Some("moderator-token"),
        Some(&request_id),
        Some(body),
    )
    .await;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(response_json(retry).await, first_body);

    let conflict = send(
        fixture.state,
        Method::POST,
        &path,
        Some("moderator-token"),
        Some(&request_id),
        Some(decision_body(decision_id, "reject")),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
}

#[tokio::test]
/// Malformed request IDs and missing submissions return bounded client errors.
async fn moderation_rejects_malformed_request_id_and_bounds_missing_records() {
    let fixture = fixture();
    let decision_path = format!(
        "/v1/moderation/publication-submissions/{}/decisions",
        fixture.submission.id
    );
    let malformed = send(
        fixture.state.clone(),
        Method::POST,
        &decision_path,
        Some("moderator-token"),
        Some("not-a-uuid"),
        Some(decision_body(Uuid::new_v4(), "approve")),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(malformed).await,
        json!({"error": "x-request-id must be a UUID"})
    );

    let missing_id = Uuid::new_v4();
    let missing_path = format!("/v1/moderation/publication-submissions/{missing_id}");
    let missing = send(
        fixture.state,
        Method::GET,
        &missing_path,
        Some("moderator-token"),
        None,
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing).await,
        json!({"error": "publication submission not found"})
    );
}
