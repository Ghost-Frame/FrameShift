//! Integration tests for account-role-gated administrator lifecycle routes.

mod mocks;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use frameshift_catalog::{
    AccountRecord, AccountStatus, Ed25519PublicKey, PackRecord, PackStatus, PackVersionRecord,
    PlatformRole, PlatformRoleRecord, PlatformRoleState, PublisherModerationStatus,
    PublisherProfileRecord,
};
use frameshift_objects::ObjectHash;
use frameshift_server::account_auth::{BearerTokenVerifier, OidcAuthError, VerifiedOidcIdentity};
use frameshift_server::metrics::Metrics;
use frameshift_server::{app, AppState, OidcConfig, ServerConfig};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;
use uuid::Uuid;

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Stable issuer shared by administrator route fixtures.
const TEST_ISSUER: &str = "https://issuer.frameshift.test";

/// Deterministic opaque bearer-token verifier.
#[derive(Clone)]
struct FakeVerifier {
    /// Tokens mapped to already verified identities.
    identities: Arc<RwLock<HashMap<String, VerifiedOidcIdentity>>>,
}

/// Construction helpers for the deterministic verifier.
impl FakeVerifier {
    /// Build verifier identities for an administrator and ordinary account.
    fn new() -> Self {
        let identities = ["administrator", "ordinary"]
            .into_iter()
            .map(|subject| {
                (
                    format!("{subject}-token"),
                    VerifiedOidcIdentity {
                        issuer: TEST_ISSUER.to_string(),
                        subject: subject.to_string(),
                        email: Some(format!("{subject}@example.test")),
                        display_name: Some(subject.to_string()),
                        auth_time: Some(Utc::now().timestamp() as u64),
                    },
                )
            })
            .collect();
        Self {
            identities: Arc::new(RwLock::new(identities)),
        }
    }
}

/// Verify only tokens installed in the fixture.
#[async_trait]
impl BearerTokenVerifier for FakeVerifier {
    /// Return a configured identity or a sanitized invalid-token error.
    async fn verify(&self, token: &str) -> Result<VerifiedOidcIdentity, OidcAuthError> {
        self.identities
            .read()
            .unwrap()
            .get(token)
            .cloned()
            .ok_or(OidcAuthError::InvalidToken)
    }
}

/// Complete administrator route fixture.
struct Fixture {
    /// Shared catalog used to inspect committed lifecycle state.
    catalog: MockCatalog,
    /// Fully composed authenticated application state.
    state: AppState,
    /// Active administrator account identifier.
    administrator_id: Uuid,
    /// Ordinary account holding no platform role.
    ordinary_id: Uuid,
    /// Approved publisher available for suspension tests.
    publisher_id: Uuid,
}

/// Build account-authenticated state with one active administrator.
fn fixture() -> Fixture {
    let catalog = MockCatalog::new();
    let administrator_id = Uuid::new_v4();
    let ordinary_id = Uuid::new_v4();
    seed_account(&catalog, administrator_id, "administrator");
    seed_account(&catalog, ordinary_id, "ordinary");
    seed_role(&catalog, administrator_id, PlatformRole::Administrator);
    seed_active_release(&catalog, "my-pack", "1.0.0");
    let publisher_id = seed_publisher(&catalog, "admin-target");

    let mut config = ServerConfig::from_env().unwrap();
    config.bind_addr = "127.0.0.1:0".parse().unwrap();
    config.log_level = "off".to_string();
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
    let state = AppState {
        catalog: Arc::new(catalog.clone()),
        objects: Arc::new(MockPackStore::new()),
        runtime: None,
        memory: None,
        config: Arc::new(config),
        metrics: Arc::new(Metrics::new()),
        auth_nonces: Arc::new(frameshift_server::auth::NonceCache::new(
            Duration::from_secs(600),
        )),
        account_auth: Some(Arc::new(FakeVerifier::new())),
        mcp_access: None,
        mcp_dispatcher: None,
    };
    Fixture {
        catalog,
        state,
        administrator_id,
        ordinary_id,
        publisher_id,
    }
}

/// Insert one approved publisher profile available for administrator suspension.
fn seed_publisher(catalog: &MockCatalog, handle: &str) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let mut state = catalog.state.write().unwrap();
    state.publisher_handles.insert(handle.to_string(), id);
    state.publishers.insert(
        id,
        PublisherProfileRecord {
            id,
            handle: handle.to_string(),
            display_name: handle.to_string(),
            biography: None,
            moderation_status: PublisherModerationStatus::Approved,
            created_at: now,
            updated_at: now,
        },
    );
    id
}

/// Insert one active account and exact OIDC subject mapping.
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
            email: None,
            display_name: Some(subject.to_string()),
            status: AccountStatus::Active,
            created_at: now,
            updated_at: now,
        },
    );
}

/// Assign one active global platform role.
fn seed_role(catalog: &MockCatalog, account_id: Uuid, role: PlatformRole) {
    let now = Utc::now();
    catalog
        .state
        .write()
        .unwrap()
        .platform_roles
        .push(PlatformRoleRecord {
            account_id,
            role,
            state: PlatformRoleState::Active,
            assigned_by_account_id: account_id,
            created_at: now,
            updated_at: now,
        });
}

/// Insert one active public pack head and version.
fn seed_active_release(catalog: &MockCatalog, name: &str, version: &str) {
    let now = Utc::now();
    let author = Ed25519PublicKey([7; 32]);
    let mut state = catalog.state.write().unwrap();
    state.packs.insert(
        name.to_string(),
        PackRecord {
            name: name.to_string(),
            current_author: author,
            publisher_id: None,
            tags: Vec::new(),
            description: String::new(),
            created_at: now,
            latest_version: Some(version.to_string()),
            total_downloads: 0,
            extends: None,
        },
    );
    state.versions.insert(
        (name.to_string(), version.to_string()),
        PackVersionRecord {
            pack_name: name.to_string(),
            version: version.to_string(),
            content_hash: ObjectHash::of(b"admin lifecycle release"),
            signature: vec![0; 64],
            author_pubkey: author,
            publisher_key_id: None,
            parent_hash: None,
            capability_manifest_json: "{}".to_string(),
            schema_version: 1,
            license: "MIT".to_string(),
            published_at: now,
            status: PackStatus::Active,
            size_bytes: 32,
        },
    );
}

/// Send one JSON request through the real application router.
async fn send(
    state: AppState,
    method: Method,
    path: &str,
    token: Option<&str>,
    request_id: Option<Uuid>,
    body: Option<Value>,
) -> axum::http::Response<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if let Some(request_id) = request_id {
        builder = builder.header("x-request-id", request_id.to_string());
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

/// The administrator surface rejects requests without account authentication.
#[tokio::test]
async fn tombstone_requires_bearer_account() {
    let fixture = fixture();
    let response = send(
        fixture.state,
        Method::POST,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        None,
        Some(Uuid::new_v4()),
        Some(serde_json::json!({
            "id": Uuid::new_v4(),
            "reason": "tos-violation"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A mutation with no `x-request-id` header is rejected instead of silently
/// accepting a server-generated id, which would defeat substituted-retry
/// rejection (F-10 regression).
#[tokio::test]
async fn tombstone_and_suspend_require_client_supplied_request_id() {
    let fixture = fixture();
    let tombstone = send(
        fixture.state.clone(),
        Method::POST,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        Some("administrator-token"),
        None,
        Some(serde_json::json!({
            "id": Uuid::new_v4(),
            "reason": "tos-violation"
        })),
    )
    .await;
    assert_eq!(tombstone.status(), StatusCode::BAD_REQUEST);

    let suspend = send(
        fixture.state,
        Method::POST,
        &format!("/v1/admin/publishers/{}/suspend", fixture.publisher_id),
        Some("administrator-token"),
        None,
        Some(serde_json::json!({
            "id": Uuid::new_v4(),
            "reason_code": "policy.abuse"
        })),
    )
    .await;
    assert_eq!(suspend.status(), StatusCode::BAD_REQUEST);
}

/// An active ordinary account cannot exercise administrator lifecycle controls.
#[tokio::test]
async fn tombstone_rejects_non_administrator_account() {
    let fixture = fixture();
    let response = send(
        fixture.state,
        Method::POST,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        Some("ordinary-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({
            "id": Uuid::new_v4(),
            "reason": "tos-violation"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// An administrator tombstone commits release state and immutable evidence.
#[tokio::test]
async fn administrator_tombstone_commits_audited_transition() {
    let fixture = fixture();
    let decision_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let body = serde_json::json!({
        "id": decision_id,
        "reason": "tos-violation"
    });
    let response = send(
        fixture.state.clone(),
        Method::POST,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        Some("administrator-token"),
        Some(request_id),
        Some(body.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["action"], "tombstone_release");
    assert_eq!(
        json["actor_account_id"],
        fixture.administrator_id.to_string()
    );

    let retry = send(
        fixture.state,
        Method::POST,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        Some("administrator-token"),
        Some(request_id),
        Some(body),
    )
    .await;
    assert_eq!(retry.status(), StatusCode::OK);
    let state = fixture.catalog.state.read().unwrap();
    assert!(matches!(
        state
            .versions
            .get(&("my-pack".to_string(), "1.0.0".to_string()))
            .unwrap()
            .status,
        PackStatus::Tombstone { .. }
    ));
    assert_eq!(state.publication_lifecycle_decisions.len(), 1);
}

/// Global lifecycle evidence is visible only through the administrator audit route.
#[tokio::test]
async fn administrator_can_read_lifecycle_audit() {
    let fixture = fixture();
    let decision_id = Uuid::new_v4();
    let create = send(
        fixture.state.clone(),
        Method::POST,
        "/v1/admin/packs/my-pack/1.0.0/tombstone",
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({
            "id": decision_id,
            "reason": "dmca"
        })),
    )
    .await;
    assert_eq!(create.status(), StatusCode::OK);
    let audit = send(
        fixture.state,
        Method::GET,
        "/v1/admin/publication-decisions?limit=50",
        Some("administrator-token"),
        None,
        None,
    )
    .await;
    assert_eq!(audit.status(), StatusCode::OK);
    let json = response_json(audit).await;
    assert_eq!(json.as_array().unwrap().len(), 1);
    assert_eq!(json[0]["id"], decision_id.to_string());
}

/// An administrator can suspend an approved publisher through the account boundary.
#[tokio::test]
async fn administrator_can_suspend_publisher() {
    let fixture = fixture();
    let response = send(
        fixture.state,
        Method::POST,
        &format!("/v1/admin/publishers/{}/suspend", fixture.publisher_id),
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({
            "id": Uuid::new_v4(),
            "reason_code": "policy.abuse"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["action"], "suspend_publisher");
    assert_eq!(
        fixture
            .catalog
            .state
            .read()
            .unwrap()
            .publishers
            .get(&fixture.publisher_id)
            .unwrap()
            .moderation_status,
        PublisherModerationStatus::Suspended
    );
}

/// The role and status routes reject an account without administrator authority.
#[tokio::test]
async fn platform_role_and_status_routes_require_administrator() {
    let fixture = fixture();
    let target = fixture.administrator_id;
    let grant = send(
        fixture.state.clone(),
        Method::POST,
        &format!("/v1/admin/accounts/{target}/platform-roles"),
        Some("ordinary-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({"role": "moderator"})),
    )
    .await;
    assert_eq!(grant.status(), StatusCode::FORBIDDEN);

    let revoke = send(
        fixture.state.clone(),
        Method::DELETE,
        &format!("/v1/admin/accounts/{target}/platform-roles/administrator"),
        Some("ordinary-token"),
        Some(Uuid::new_v4()),
        None,
    )
    .await;
    assert_eq!(revoke.status(), StatusCode::FORBIDDEN);

    let status = send(
        fixture.state,
        Method::PATCH,
        &format!("/v1/admin/accounts/{target}/status"),
        Some("ordinary-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({"status": "suspended"})),
    )
    .await;
    assert_eq!(status.status(), StatusCode::FORBIDDEN);
    // The sole administrator must still hold authority after the failed calls.
    assert_eq!(
        fixture
            .catalog
            .state
            .read()
            .unwrap()
            .platform_roles
            .iter()
            .filter(|record| record.state == PlatformRoleState::Active)
            .count(),
        1
    );
}

/// An unauthorized caller cannot distinguish a missing target account.
#[tokio::test]
async fn unauthorized_role_grant_does_not_reveal_target_existence() {
    let fixture = fixture();
    let missing = Uuid::new_v4();
    let existing = send(
        fixture.state.clone(),
        Method::POST,
        &format!("/v1/admin/accounts/{}/platform-roles", fixture.ordinary_id),
        Some("ordinary-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({"role": "moderator"})),
    )
    .await;
    let absent = send(
        fixture.state,
        Method::POST,
        &format!("/v1/admin/accounts/{missing}/platform-roles"),
        Some("ordinary-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({"role": "moderator"})),
    )
    .await;
    assert_eq!(existing.status(), StatusCode::FORBIDDEN);
    assert_eq!(absent.status(), absent.status());
    assert_eq!(
        existing.status(),
        absent.status(),
        "target existence must not change the rejection an unauthorized caller sees"
    );
}

/// An administrator grants a moderator role idempotently and revokes it auditably.
#[tokio::test]
async fn administrator_grants_then_revokes_moderator_role() {
    let fixture = fixture();
    let target = fixture.ordinary_id;
    let path = format!("/v1/admin/accounts/{target}/platform-roles");

    let granted = send(
        fixture.state.clone(),
        Method::POST,
        &path,
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({"role": "moderator"})),
    )
    .await;
    assert_eq!(granted.status(), StatusCode::OK);
    let body = response_json(granted).await;
    assert_eq!(body["role"], "moderator");
    assert_eq!(body["state"], "active");
    assert_eq!(
        body["assigned_by_account_id"],
        fixture.administrator_id.to_string()
    );
    let first_created_at = body["created_at"].clone();

    // Repeating the grant must not rewrite the original assignment.
    let repeated = send(
        fixture.state.clone(),
        Method::POST,
        &path,
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({"role": "moderator"})),
    )
    .await;
    assert_eq!(repeated.status(), StatusCode::OK);
    let repeated_body = response_json(repeated).await;
    assert_eq!(repeated_body["created_at"], first_created_at);
    assert_eq!(
        fixture.catalog.state.read().unwrap().platform_roles.len(),
        2,
        "an idempotent grant must not create a second assignment row"
    );

    let revoked = send(
        fixture.state,
        Method::DELETE,
        &format!("{path}/moderator"),
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        None,
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    let revoked_body = response_json(revoked).await;
    assert_eq!(revoked_body["state"], "revoked");
    assert_eq!(
        revoked_body["created_at"], first_created_at,
        "revocation must retain the original grant time for audit"
    );
    let state = fixture.catalog.state.read().unwrap();
    assert_eq!(
        state.platform_roles.len(),
        2,
        "revocation must preserve the assignment row rather than delete it"
    );
}

/// The last active administrator can neither be revoked nor suspended.
#[tokio::test]
async fn last_administrator_authority_cannot_be_removed() {
    let fixture = fixture();
    let administrator = fixture.administrator_id;

    let revoked = send(
        fixture.state.clone(),
        Method::DELETE,
        &format!("/v1/admin/accounts/{administrator}/platform-roles/administrator"),
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        None,
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::BAD_REQUEST);

    let suspended = send(
        fixture.state.clone(),
        Method::PATCH,
        &format!("/v1/admin/accounts/{administrator}/status"),
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({"status": "suspended"})),
    )
    .await;
    assert_eq!(suspended.status(), StatusCode::BAD_REQUEST);

    // Authority must remain intact and usable after both rejections.
    let state = fixture.catalog.state.read().unwrap();
    assert!(state.platform_roles.iter().any(|record| {
        record.account_id == administrator
            && record.role == PlatformRole::Administrator
            && record.state == PlatformRoleState::Active
    }));
    assert_eq!(state.accounts[&administrator].status, AccountStatus::Active);
}

/// A second administrator makes the first administrator's role revocable.
#[tokio::test]
async fn administrator_role_is_revocable_once_coverage_exists() {
    let fixture = fixture();
    let second = fixture.ordinary_id;
    let promote = send(
        fixture.state.clone(),
        Method::POST,
        &format!("/v1/admin/accounts/{second}/platform-roles"),
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({"role": "administrator"})),
    )
    .await;
    assert_eq!(promote.status(), StatusCode::OK);

    let revoked = send(
        fixture.state,
        Method::DELETE,
        &format!(
            "/v1/admin/accounts/{}/platform-roles/administrator",
            fixture.administrator_id
        ),
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        None,
    )
    .await;
    assert_eq!(
        revoked.status(),
        StatusCode::OK,
        "revocation is permitted once another active administrator provides coverage"
    );
}

/// Suspending an account blocks its next authenticated request.
#[tokio::test]
async fn suspended_account_loses_authenticated_access() {
    let fixture = fixture();
    let target = fixture.ordinary_id;
    // Grant a role first so the account has authority to lose.
    let granted = send(
        fixture.state.clone(),
        Method::POST,
        &format!("/v1/admin/accounts/{target}/platform-roles"),
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({"role": "moderator"})),
    )
    .await;
    assert_eq!(granted.status(), StatusCode::OK);

    let suspended = send(
        fixture.state.clone(),
        Method::PATCH,
        &format!("/v1/admin/accounts/{target}/status"),
        Some("administrator-token"),
        Some(Uuid::new_v4()),
        Some(serde_json::json!({"status": "suspended"})),
    )
    .await;
    assert_eq!(suspended.status(), StatusCode::OK);
    assert_eq!(response_json(suspended).await["status"], "suspended");

    let after = send(
        fixture.state.clone(),
        Method::GET,
        "/v1/account",
        Some("ordinary-token"),
        Some(Uuid::new_v4()),
        None,
    )
    .await;
    assert_eq!(
        after.status(),
        StatusCode::FORBIDDEN,
        "a suspended account must be rejected on its next authenticated request"
    );

    // Suspension must preserve the account and its assignment history.
    let state = fixture.catalog.state.read().unwrap();
    assert!(state.accounts.contains_key(&target));
    assert!(state
        .platform_roles
        .iter()
        .any(|record| record.account_id == target));
}
