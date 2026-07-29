//! Integration tests for bearer-authenticated publication moderation routes.

mod mocks;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use chrono::Utc;
use frameshift_catalog::{
    AccountRecord, AccountStatus, MembershipState, PlatformRole, PlatformRoleRecord,
    PlatformRoleState, PublicationSubmissionRecord, PublicationSubmissionState,
    PublisherMembershipRecord, PublisherModerationStatus, PublisherProfileRecord, PublisherRole,
};
use frameshift_objects::ObjectHash;
use frameshift_publication::PublicationReport;
use frameshift_server::account_auth::{BearerTokenVerifier, OidcAuthError, VerifiedOidcIdentity};
use frameshift_server::metrics::Metrics;
use frameshift_server::{app, app_with_publication_admission, AppState, OidcConfig, ServerConfig};
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
    /// Explicit quarantine-enabled router used by moderation tests.
    router: Router,
    /// Isolated in-memory quarantine store.
    quarantine: MockPackStore,
    /// Exact archive bytes bound to the submission record.
    archive_bytes: Vec<u8>,
    /// Quarantined submission available for moderation.
    submission: PublicationSubmissionRecord,
    /// Active moderator account identifier.
    moderator_id: Uuid,
    /// Active administrator account identifier.
    administrator_id: Uuid,
    /// Publisher owner who also holds a moderator role.
    owner_id: Uuid,
    /// Stable publisher handle used by owner-bound appeal routes.
    publisher_handle: String,
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
    let publisher_handle = "appeal-publisher".to_string();
    let archive_bytes = b"exact private review archive".to_vec();
    let submission = PublicationSubmissionRecord {
        id: Uuid::new_v4(),
        intent_id: Uuid::new_v4(),
        account_id: owner_id,
        publisher_id,
        publisher_key_id: Uuid::new_v4(),
        archive_hash: ObjectHash::of(&archive_bytes),
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
        state.publishers.insert(
            publisher_id,
            PublisherProfileRecord {
                id: publisher_id,
                handle: publisher_handle.clone(),
                display_name: "Appeal Publisher".to_string(),
                biography: None,
                moderation_status: PublisherModerationStatus::Approved,
                created_at: now,
                updated_at: now,
            },
        );
        state
            .publisher_handles
            .insert(publisher_handle.clone(), publisher_id);
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
    let quarantine = MockPackStore::new();
    quarantine.insert(submission.archive_hash, archive_bytes.clone());
    let router = app_with_publication_admission(state.clone(), Arc::new(quarantine.clone()));
    Fixture {
        catalog,
        state,
        router,
        quarantine,
        archive_bytes,
        submission,
        moderator_id,
        administrator_id,
        owner_id,
        publisher_handle,
    }
}

/// Send one JSON request through the in-process application.
async fn send(
    router: Router,
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
    router
        .oneshot(builder.body(Body::from(bytes)).unwrap())
        .await
        .unwrap()
}

/// Decode one JSON response body.
async fn response_json(response: axum::http::Response<Body>) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Collect one response body as exact bytes.
async fn response_bytes(response: axum::http::Response<Body>) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
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

/// Reject the fixture submission and return the immutable decision identifier.
async fn reject_for_appeal(fixture: &Fixture) -> Uuid {
    let decision_id = Uuid::new_v4();
    let path = format!(
        "/v1/moderation/publication-submissions/{}/decisions",
        fixture.submission.id
    );
    let response = send(
        fixture.router.clone(),
        Method::POST,
        &path,
        Some("moderator-token"),
        Some(&Uuid::new_v4().to_string()),
        Some(decision_body(decision_id, "reject")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    decision_id
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
        let response = send(
            fixture.router.clone(),
            Method::GET,
            &path,
            token,
            None,
            None,
        )
        .await;
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
            fixture.router.clone(),
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
            fixture.router.clone(),
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
/// Quarantine artifacts are absent from the standard application surface.
async fn moderation_artifact_requires_explicit_quarantine_wiring() {
    let fixture = fixture();
    let path = format!(
        "/v1/moderation/publication-submissions/{}/artifact",
        fixture.submission.id
    );
    let response = send(
        app(fixture.state),
        Method::GET,
        &path,
        Some("moderator-token"),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
/// Artifact reads require authentication and independent active review authority.
async fn moderation_artifact_requires_independent_reviewer() {
    let fixture = fixture();
    let path = format!(
        "/v1/moderation/publication-submissions/{}/artifact",
        fixture.submission.id
    );
    for token in [None, Some("invalid-token")] {
        let response = send(
            fixture.router.clone(),
            Method::GET,
            &path,
            token,
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for token in ["ordinary-token", "revoked-token", "owner-token"] {
        let response = send(
            fixture.router.clone(),
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
}

#[tokio::test]
/// Active reviewers receive only the catalog-bound exact archive as a private attachment.
async fn moderation_artifact_returns_verified_private_attachment() {
    for token in ["moderator-token", "administrator-token"] {
        let fixture = fixture();
        let path = format!(
            "/v1/moderation/publication-submissions/{}/artifact?hash={}",
            fixture.submission.id,
            ObjectHash::of(b"caller-selected")
        );
        let response = send(fixture.router, Method::GET, &path, Some(token), None, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/gzip");
        assert_eq!(
            response.headers()["content-disposition"],
            format!(
                "attachment; filename=\"publication-{}.tar.gz\"",
                fixture.submission.id
            )
        );
        assert_eq!(
            response.headers()["cache-control"],
            "private, no-store, max-age=0"
        );
        assert_eq!(
            response.headers()["content-length"],
            fixture.archive_bytes.len().to_string()
        );
        assert_eq!(response_bytes(response).await, fixture.archive_bytes);
    }
}

#[tokio::test]
/// Missing, substituted, and oversized quarantine objects return no artifact bytes.
async fn moderation_artifact_fails_closed_on_storage_mismatch() {
    let absent_submission = fixture();
    let absent_path = format!(
        "/v1/moderation/publication-submissions/{}/artifact",
        Uuid::new_v4()
    );
    let response = send(
        absent_submission.router,
        Method::GET,
        &absent_path,
        Some("moderator-token"),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(response).await,
        json!({"error": "publication submission not found"})
    );

    let missing = fixture();
    missing
        .quarantine
        .blobs
        .write()
        .unwrap()
        .remove(&missing.submission.archive_hash);
    let missing_path = format!(
        "/v1/moderation/publication-submissions/{}/artifact",
        missing.submission.id
    );
    let response = send(
        missing.router,
        Method::GET,
        &missing_path,
        Some("moderator-token"),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response_json(response).await,
        json!({"error": "upstream backend mismatch"})
    );

    let substituted = fixture();
    substituted.quarantine.insert(
        substituted.submission.archive_hash,
        b"substituted archive".to_vec(),
    );
    let substituted_path = format!(
        "/v1/moderation/publication-submissions/{}/artifact",
        substituted.submission.id
    );
    let response = send(
        substituted.router,
        Method::GET,
        &substituted_path,
        Some("moderator-token"),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let oversized = fixture();
    let oversized_bytes = vec![0_u8; oversized.state.config.max_request_bytes + 1];
    let oversized_hash = ObjectHash::of(&oversized_bytes);
    oversized
        .catalog
        .state
        .write()
        .unwrap()
        .publication_submissions
        .get_mut(&oversized.submission.id)
        .unwrap()
        .archive_hash = oversized_hash;
    oversized.quarantine.insert(oversized_hash, oversized_bytes);
    let oversized_path = format!(
        "/v1/moderation/publication-submissions/{}/artifact",
        oversized.submission.id
    );
    let response = send(
        oversized.router,
        Method::GET,
        &oversized_path,
        Some("moderator-token"),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
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
        fixture.router.clone(),
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
/// Decisions and promotions with no client-supplied `x-request-id` header are
/// rejected instead of silently accepting a server-generated id, which would
/// defeat substituted-retry rejection (F-10 regression).
async fn moderation_mutations_require_client_supplied_request_id() {
    let fixture = fixture();
    let decision_path = format!(
        "/v1/moderation/publication-submissions/{}/decisions",
        fixture.submission.id
    );
    let decision = send(
        fixture.router.clone(),
        Method::POST,
        &decision_path,
        Some("moderator-token"),
        None,
        Some(decision_body(Uuid::new_v4(), "approve")),
    )
    .await;
    assert_eq!(decision.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(decision).await,
        json!({"error": "x-request-id must be a UUID"})
    );

    let promotion_path = format!(
        "/v1/moderation/publication-submissions/{}/promotion",
        fixture.submission.id
    );
    let promotion = send(
        fixture.router,
        Method::POST,
        &promotion_path,
        Some("moderator-token"),
        None,
        Some(json!({ "id": Uuid::new_v4() })),
    )
    .await;
    assert_eq!(promotion.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(promotion).await,
        json!({"error": "x-request-id must be a UUID"})
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
        fixture.router,
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
        fixture.router,
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
        fixture.router.clone(),
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
        fixture.router.clone(),
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
        fixture.router,
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
        fixture.router.clone(),
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
        fixture.router,
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

#[tokio::test]
/// Owner and administrator appeal routes require a valid bearer identity.
async fn publication_appeal_routes_require_authentication() {
    let fixture = fixture();
    let owner_path = format!(
        "/v1/publishers/{}/publication-appeals",
        fixture.publisher_handle
    );
    let admin_path = "/v1/admin/publication-appeals";
    for path in [owner_path.as_str(), admin_path] {
        let response = send(fixture.router.clone(), Method::GET, path, None, None, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
/// Filing, private listing, independent overturn, and audit projection bind trusted actors.
async fn publication_appeal_round_trip_binds_trusted_context() {
    let fixture = fixture();
    let decision_id = reject_for_appeal(&fixture).await;
    let appeal_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let file_path = format!(
        "/v1/publishers/{}/publication-decisions/{decision_id}/appeal",
        fixture.publisher_handle
    );
    let filed = send(
        fixture.router.clone(),
        Method::POST,
        &file_path,
        Some("owner-token"),
        Some(&request_id.to_string()),
        Some(json!({
            "id": appeal_id,
            "statement": "The rejection relied on an outdated compatibility result."
        })),
    )
    .await;
    assert_eq!(filed.status(), StatusCode::OK);
    let filed_body = response_json(filed).await;
    assert_eq!(filed_body["id"], appeal_id.to_string());
    assert_eq!(filed_body["decision_id"], decision_id.to_string());
    assert_eq!(filed_body["actor_account_id"], fixture.owner_id.to_string());
    assert_eq!(filed_body["request_id"], request_id.to_string());

    let owner_list_path = format!(
        "/v1/publishers/{}/publication-appeals?limit=10",
        fixture.publisher_handle
    );
    let owner_list = send(
        fixture.router.clone(),
        Method::GET,
        &owner_list_path,
        Some("owner-token"),
        None,
        None,
    )
    .await;
    assert_eq!(owner_list.status(), StatusCode::OK);
    let owner_cases = response_json(owner_list).await;
    assert_eq!(owner_cases.as_array().unwrap().len(), 1);
    assert!(owner_cases[0]["resolution"].is_null());

    let resolution_id = Uuid::new_v4();
    let resolution_request_id = Uuid::new_v4();
    let resolution_path = format!("/v1/admin/publication-appeals/{appeal_id}/resolution");
    let resolved = send(
        fixture.router.clone(),
        Method::POST,
        &resolution_path,
        Some("administrator-token"),
        Some(&resolution_request_id.to_string()),
        Some(json!({
            "id": resolution_id,
            "disposition": "overturn",
            "rationale": "Independent review confirmed the compatibility evidence.",
            "separation_exception_reason": null
        })),
    )
    .await;
    assert_eq!(resolved.status(), StatusCode::OK);
    let resolved_body = response_json(resolved).await;
    assert_eq!(resolved_body["appeal_id"], appeal_id.to_string());
    assert_eq!(
        resolved_body["actor_account_id"],
        fixture.administrator_id.to_string()
    );
    assert_eq!(
        resolved_body["request_id"],
        resolution_request_id.to_string()
    );

    let admin_list = send(
        fixture.router,
        Method::GET,
        "/v1/admin/publication-appeals?limit=10",
        Some("administrator-token"),
        None,
        None,
    )
    .await;
    assert_eq!(admin_list.status(), StatusCode::OK);
    let admin_cases = response_json(admin_list).await;
    assert_eq!(
        admin_cases[0]["resolution"]["id"],
        resolution_id.to_string()
    );
    assert_eq!(
        fixture
            .catalog
            .state
            .read()
            .unwrap()
            .publication_submissions[&fixture.submission.id]
            .state,
        PublicationSubmissionState::Approved
    );
}

#[tokio::test]
/// Appeal routes deny foreign actors and reject malformed correlation or DTO fields.
async fn publication_appeal_routes_enforce_authority_and_request_contracts() {
    let fixture = fixture();
    let decision_id = reject_for_appeal(&fixture).await;
    let file_path = format!(
        "/v1/publishers/{}/publication-decisions/{decision_id}/appeal",
        fixture.publisher_handle
    );
    let body = json!({
        "id": Uuid::new_v4(),
        "statement": "Please review the evidence again."
    });

    let foreign = send(
        fixture.router.clone(),
        Method::POST,
        &file_path,
        Some("ordinary-token"),
        Some(&Uuid::new_v4().to_string()),
        Some(body.clone()),
    )
    .await;
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);

    let missing_request_id = send(
        fixture.router.clone(),
        Method::POST,
        &file_path,
        Some("owner-token"),
        None,
        Some(body.clone()),
    )
    .await;
    assert_eq!(missing_request_id.status(), StatusCode::BAD_REQUEST);

    let mut unknown_field_body = body;
    unknown_field_body["actor_account_id"] = json!(fixture.owner_id);
    let unknown_field = send(
        fixture.router.clone(),
        Method::POST,
        &file_path,
        Some("owner-token"),
        Some(&Uuid::new_v4().to_string()),
        Some(unknown_field_body),
    )
    .await;
    assert_eq!(unknown_field.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let appeal_id = Uuid::new_v4();
    let filed = send(
        fixture.router.clone(),
        Method::POST,
        &file_path,
        Some("owner-token"),
        Some(&Uuid::new_v4().to_string()),
        Some(json!({
            "id": appeal_id,
            "statement": "Please review the corrected compatibility evidence."
        })),
    )
    .await;
    assert_eq!(filed.status(), StatusCode::OK);
    let resolution_path = format!("/v1/admin/publication-appeals/{appeal_id}/resolution");
    let resolution_body = json!({
        "id": Uuid::new_v4(),
        "disposition": "uphold",
        "rationale": "The original decision remains supported.",
        "separation_exception_reason": null
    });
    let foreign_resolution = send(
        fixture.router.clone(),
        Method::POST,
        &resolution_path,
        Some("ordinary-token"),
        Some(&Uuid::new_v4().to_string()),
        Some(resolution_body.clone()),
    )
    .await;
    assert_eq!(foreign_resolution.status(), StatusCode::FORBIDDEN);
    let missing_resolution_request_id = send(
        fixture.router.clone(),
        Method::POST,
        &resolution_path,
        Some("administrator-token"),
        None,
        Some(resolution_body),
    )
    .await;
    assert_eq!(
        missing_resolution_request_id.status(),
        StatusCode::BAD_REQUEST
    );

    let partial_cursor_path = format!(
        "/v1/publishers/{}/publication-appeals?before_id={}",
        fixture.publisher_handle,
        Uuid::new_v4()
    );
    let partial_cursor = send(
        fixture.router,
        Method::GET,
        &partial_cursor_path,
        Some("owner-token"),
        None,
        None,
    )
    .await;
    assert_eq!(partial_cursor.status(), StatusCode::BAD_REQUEST);
}
