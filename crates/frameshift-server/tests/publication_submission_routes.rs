//! Integration tests for bearer-authenticated, signed quarantine submissions.

mod mocks;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use chrono::{Duration as ChronoDuration, Utc};
use ed25519_dalek::SigningKey;
use flate2::write::GzEncoder;
use flate2::Compression;
use frameshift_catalog::{
    AccountRecord, AccountStatus, MembershipState, PlatformRole, PlatformRoleRecord,
    PlatformRoleState, PublicationIntentRecord, PublicationSubmissionState, PublisherKeyRecord,
    PublisherKeyState, PublisherMembershipRecord, PublisherModerationStatus,
    PublisherProfileRecord, PublisherRole,
};
use frameshift_objects::ObjectHash;
use frameshift_pack::Pack;
use frameshift_server::account_auth::{BearerTokenVerifier, OidcAuthError, VerifiedOidcIdentity};
use frameshift_server::metrics::Metrics;
use frameshift_server::{app, app_with_publication_admission, AppState, OidcConfig, ServerConfig};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tar::Builder;
use tower::ServiceExt as _;
use uuid::Uuid;

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;
use mocks::signing::{signed_headers, SignedHeader};

/// Stable test issuer shared by verifier identities and seeded accounts.
const TEST_ISSUER: &str = "https://issuer.frameshift.test";

/// Deterministic bearer verifier for publication-submission route tests.
#[derive(Clone)]
struct FakeVerifier {
    /// Opaque tokens mapped to verified OIDC identities.
    identities: Arc<RwLock<HashMap<String, VerifiedOidcIdentity>>>,
}

/// Construction helpers for [`FakeVerifier`].
impl FakeVerifier {
    /// Build a verifier with owner and foreign-account tokens.
    fn new() -> Self {
        Self {
            identities: Arc::new(RwLock::new(HashMap::from([
                (
                    "owner-token".to_string(),
                    verified_identity("owner-subject"),
                ),
                (
                    "foreign-token".to_string(),
                    verified_identity("foreign-subject"),
                ),
            ]))),
        }
    }
}

/// OIDC verification behavior backed by deterministic token fixtures.
#[async_trait]
impl BearerTokenVerifier for FakeVerifier {
    /// Return the configured identity without parsing token bytes.
    async fn verify(&self, token: &str) -> Result<VerifiedOidcIdentity, OidcAuthError> {
        self.identities
            .read()
            .unwrap()
            .get(token)
            .cloned()
            .ok_or(OidcAuthError::InvalidToken)
    }
}

/// Complete in-process route fixture with isolated public and quarantine stores.
struct RouteFixture {
    /// Shared fake catalog used by middleware, routes, and admission.
    catalog: MockCatalog,
    /// Public download store that must remain untouched.
    public_objects: MockPackStore,
    /// Explicit non-public quarantine store.
    quarantine: MockPackStore,
    /// Router with publication admission explicitly mounted.
    router: Router,
    /// Publisher signing key enrolled on the intent.
    signing_key: SigningKey,
    /// Different key used to prove signer mismatch rejection.
    wrong_signing_key: SigningKey,
    /// Account that owns the publication intent.
    owner_account_id: Uuid,
    /// Separate account used for tenant-isolation checks.
    foreign_account_id: Uuid,
    /// Exact durable publication intent.
    intent: PublicationIntentRecord,
    /// Exact archive bytes authorized by the intent.
    archive: Vec<u8>,
}

/// Build one verified OIDC identity for a stable subject.
fn verified_identity(subject: &str) -> VerifiedOidcIdentity {
    VerifiedOidcIdentity {
        issuer: TEST_ISSUER.to_string(),
        subject: subject.to_string(),
        email: Some(format!("{subject}@example.test")),
        display_name: Some(subject.to_string()),
        auth_time: Some(Utc::now().timestamp() as u64),
    }
}

/// Build a server configuration suitable for in-process route tests.
fn test_config() -> Arc<ServerConfig> {
    let mut config = ServerConfig::from_env().unwrap();
    config.bind_addr = "127.0.0.1:0".parse().unwrap();
    config.log_level = "off".to_string();
    config.max_request_bytes = 1_048_576;
    config.abuse_rate_per_min = 0;
    config.download_rate_per_min = 0;
    config.publisher_pubkeys = vec!["*".to_string()];
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

/// Build application state over one shared fake catalog and public object store.
fn test_state(catalog: &MockCatalog, public_objects: &MockPackStore) -> AppState {
    AppState {
        catalog: Arc::new(catalog.clone()),
        objects: Arc::new(public_objects.clone()),
        runtime: None,
        memory: None,
        config: test_config(),
        metrics: Arc::new(Metrics::new()),
        auth_nonces: Arc::new(frameshift_server::auth::NonceCache::new(
            Duration::from_secs(600),
        )),
        account_auth: Some(Arc::new(FakeVerifier::new())),
    }
}

/// Write a minimal valid public pack into `directory`.
fn write_valid_pack(directory: &Path, signing_key: &SigningKey) {
    let author_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
    let manifest = format!(
        "schema_version = 1\nname = \"submission-fixture\"\n\
         author_handle = \"alice\"\nauthor_pubkey = \"{author_pubkey}\"\n\
         version = \"1.0.0\"\nlicense = \"MIT\"\n"
    );
    std::fs::write(directory.join("pack.toml"), manifest).unwrap();
    std::fs::write(directory.join("README.md"), b"# submission fixture\n").unwrap();
    let mut pack = Pack::from_dir(directory).unwrap();
    pack.sign(signing_key).unwrap();
}

/// Encode all pack files as one flat gzip-tar archive.
fn make_targz(directory: &Path) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    archive.append_dir_all(".", directory).unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

/// Seed a durable active account and its exact OIDC subject lookup.
fn seed_account(state: &mut mocks::catalog::MockState, id: Uuid, subject: &str) {
    let now = Utc::now();
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

/// Build a complete exact publication-submission route fixture.
fn route_fixture() -> RouteFixture {
    let signing_key = SigningKey::from_bytes(&[51_u8; 32]);
    let wrong_signing_key = SigningKey::from_bytes(&[52_u8; 32]);
    let source = tempfile::TempDir::new().unwrap();
    write_valid_pack(source.path(), &signing_key);
    let report = frameshift_publication::validate_directory(source.path()).unwrap();
    assert!(report.valid);
    let archive = make_targz(source.path());
    let manifest_hash = report
        .inventory
        .iter()
        .find(|entry| entry.path == "pack.toml")
        .and_then(|entry| ObjectHash::from_hex(&entry.sha256).ok())
        .unwrap();

    let catalog = MockCatalog::new();
    let public_objects = MockPackStore::new();
    let quarantine = MockPackStore::new();
    let owner_account_id = Uuid::new_v4();
    let foreign_account_id = Uuid::new_v4();
    let publisher_id = Uuid::new_v4();
    let publisher_key_id = Uuid::new_v4();
    let now = Utc::now();
    let intent = PublicationIntentRecord {
        id: Uuid::new_v4(),
        account_id: owner_account_id,
        publisher_id,
        publisher_key_id,
        archive_hash: ObjectHash::of(&archive),
        manifest_hash,
        file_inventory_hash: ObjectHash::from_hex(&report.inventory_hash).unwrap(),
        scan_schema_version: report.schema_version,
        created_at: now,
        expires_at: now + ChronoDuration::minutes(15),
        consumed_at: None,
    };
    {
        let mut state = catalog.state.write().unwrap();
        seed_account(&mut state, owner_account_id, "owner-subject");
        seed_account(&mut state, foreign_account_id, "foreign-subject");
        state
            .publisher_handles
            .insert("submission-publisher".to_string(), publisher_id);
        state.publishers.insert(
            publisher_id,
            PublisherProfileRecord {
                id: publisher_id,
                handle: "submission-publisher".to_string(),
                display_name: "Submission Publisher".to_string(),
                biography: None,
                moderation_status: PublisherModerationStatus::Pending,
                created_at: now,
                updated_at: now,
            },
        );
        state.publisher_memberships.insert(
            (owner_account_id, publisher_id),
            PublisherMembershipRecord {
                account_id: owner_account_id,
                publisher_id,
                role: PublisherRole::Owner,
                state: MembershipState::Active,
                created_at: now,
                updated_at: now,
            },
        );
        state.publisher_keys.insert(
            publisher_key_id,
            PublisherKeyRecord {
                id: publisher_key_id,
                publisher_id,
                public_key: frameshift_catalog::Ed25519PublicKey(
                    signing_key.verifying_key().to_bytes(),
                ),
                label: "submission key".to_string(),
                state: PublisherKeyState::Active,
                created_at: now,
                revoked_at: None,
                last_used_at: None,
            },
        );
        state.publication_intents.insert(intent.id, intent.clone());
        state.enforce_publication_submission_invariants = true;
    }
    let state = test_state(&catalog, &public_objects);
    let router = app_with_publication_admission(state, Arc::new(quarantine.clone()));
    RouteFixture {
        catalog,
        public_objects,
        quarantine,
        router,
        signing_key,
        wrong_signing_key,
        owner_account_id,
        foreign_account_id,
        intent,
        archive,
    }
}

/// Encode the strict submission multipart body and its content type.
fn submission_multipart(submission_id: Uuid, intent_id: Uuid, archive: &[u8]) -> (Vec<u8>, String) {
    let boundary = format!("frameshift-submission-{submission_id}");
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n\
             {submission_id}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"intent_id\"\r\n\r\n\
             {intent_id}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"archive\"; \
             filename=\"pack.tar.gz\"\r\nContent-Type: application/gzip\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(archive);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (body, format!("multipart/form-data; boundary={boundary}"))
}

/// Build one signed submission request from exact body bytes.
fn submission_request(
    token: Option<&str>,
    body: Vec<u8>,
    content_type: &str,
    headers: &[SignedHeader],
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/v1/publication-submissions")
        .header("content-type", content_type);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    for header in headers {
        builder = builder.header(header.name, &header.value);
    }
    builder.body(Body::from(body)).unwrap()
}

/// Send one freshly signed exact submission.
async fn send_submission(
    fixture: &RouteFixture,
    token: Option<&str>,
    signing_key: &SigningKey,
    submission_id: Uuid,
) -> axum::http::Response<Body> {
    let (body, content_type) =
        submission_multipart(submission_id, fixture.intent.id, &fixture.archive);
    let headers = signed_headers(signing_key, "POST", "/v1/publication-submissions", &body);
    fixture
        .router
        .clone()
        .oneshot(submission_request(token, body, &content_type, &headers))
        .await
        .unwrap()
}

/// Send one promotion request through the explicit quarantine-enabled router.
async fn send_promotion(
    fixture: &RouteFixture,
    token: &str,
    submission_id: Uuid,
    promotion_id: Uuid,
    request_id: Uuid,
) -> axum::http::Response<Body> {
    fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v1/moderation/publication-submissions/{submission_id}/promotion"
                ))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header("x-request-id", request_id.to_string())
                .body(Body::from(
                    serde_json::json!({ "id": promotion_id }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Approve one admitted submission and grant the foreign account moderation authority.
fn approve_for_foreign_moderator(fixture: &RouteFixture, submission_id: Uuid) {
    let now = Utc::now();
    let mut state = fixture.catalog.state.write().unwrap();
    state
        .publication_submissions
        .get_mut(&submission_id)
        .unwrap()
        .state = PublicationSubmissionState::Approved;
    state
        .publishers
        .get_mut(&fixture.intent.publisher_id)
        .unwrap()
        .moderation_status = PublisherModerationStatus::Approved;
    state.platform_roles.push(PlatformRoleRecord {
        account_id: fixture.foreign_account_id,
        role: PlatformRole::Moderator,
        state: PlatformRoleState::Active,
        assigned_by_account_id: fixture.owner_account_id,
        created_at: now,
        updated_at: now,
    });
}

/// Decode one JSON response body.
async fn response_json(response: axum::http::Response<Body>) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// The standard router never mounts a quarantine submission write.
#[tokio::test]
async fn standard_app_keeps_submission_route_unmounted() {
    let fixture = route_fixture();
    let state = test_state(&fixture.catalog, &fixture.public_objects);
    let response = app(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/publication-submissions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// The standard router never mounts the approved-submission promotion write.
#[tokio::test]
async fn standard_app_keeps_promotion_route_unmounted() {
    let fixture = route_fixture();
    let state = test_state(&fixture.catalog, &fixture.public_objects);
    let response = app(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v1/moderation/publication-submissions/{}/promotion",
                    Uuid::new_v4()
                ))
                .header("authorization", "Bearer foreign-token")
                .header("content-type", "application/json")
                .header("x-request-id", Uuid::new_v4().to_string())
                .body(Body::from(
                    serde_json::json!({ "id": Uuid::new_v4() }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// An active independent moderator can promote once and replay after role revocation.
#[tokio::test]
async fn promotion_route_activates_and_replays_after_role_revocation() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let admission = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        submission_id,
    )
    .await;
    assert_eq!(admission.status(), StatusCode::OK);
    approve_for_foreign_moderator(&fixture, submission_id);

    let promotion_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let first = send_promotion(
        &fixture,
        "foreign-token",
        submission_id,
        promotion_id,
        request_id,
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_json = response_json(first).await;
    assert_eq!(first_json["id"], promotion_id.to_string());

    fixture
        .catalog
        .state
        .write()
        .unwrap()
        .platform_roles
        .first_mut()
        .unwrap()
        .state = PlatformRoleState::Revoked;
    let replay = send_promotion(
        &fixture,
        "foreign-token",
        submission_id,
        promotion_id,
        request_id,
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_json(replay).await, first_json);
    assert_eq!(fixture.public_objects.blobs.read().unwrap().len(), 1);
    let state = fixture.catalog.state.read().unwrap();
    assert_eq!(state.publication_promotions.len(), 1);
    assert_eq!(state.versions.len(), 1);
}

/// An ordinary account is rejected before any public object write occurs.
#[tokio::test]
async fn promotion_route_rejects_ordinary_account_before_public_write() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let admission = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        submission_id,
    )
    .await;
    assert_eq!(admission.status(), StatusCode::OK);
    {
        let mut state = fixture.catalog.state.write().unwrap();
        state
            .publication_submissions
            .get_mut(&submission_id)
            .unwrap()
            .state = PublicationSubmissionState::Approved;
        state
            .publishers
            .get_mut(&fixture.intent.publisher_id)
            .unwrap()
            .moderation_status = PublisherModerationStatus::Approved;
    }

    let response = send_promotion(
        &fixture,
        "foreign-token",
        submission_id,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fixture.public_objects.blobs.read().unwrap().is_empty());
    let state = fixture.catalog.state.read().unwrap();
    assert!(state.publication_promotions.is_empty());
    assert!(state.versions.is_empty());
}

/// Revoked global authority is rejected before the first public object write.
#[tokio::test]
async fn promotion_route_rejects_revoked_role_before_public_write() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let admission = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        submission_id,
    )
    .await;
    assert_eq!(admission.status(), StatusCode::OK);
    approve_for_foreign_moderator(&fixture, submission_id);
    fixture
        .catalog
        .state
        .write()
        .unwrap()
        .platform_roles
        .first_mut()
        .unwrap()
        .state = PlatformRoleState::Revoked;

    let response = send_promotion(
        &fixture,
        "foreign-token",
        submission_id,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fixture.public_objects.blobs.read().unwrap().is_empty());
}

/// A globally privileged publisher owner cannot promote their own submission.
#[tokio::test]
async fn promotion_route_rejects_publisher_owner_before_public_write() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let admission = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        submission_id,
    )
    .await;
    assert_eq!(admission.status(), StatusCode::OK);
    approve_for_foreign_moderator(&fixture, submission_id);
    {
        let now = Utc::now();
        let mut state = fixture.catalog.state.write().unwrap();
        state.platform_roles.push(PlatformRoleRecord {
            account_id: fixture.owner_account_id,
            role: PlatformRole::Administrator,
            state: PlatformRoleState::Active,
            assigned_by_account_id: fixture.foreign_account_id,
            created_at: now,
            updated_at: now,
        });
    }

    let response = send_promotion(
        &fixture,
        "owner-token",
        submission_id,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fixture.public_objects.blobs.read().unwrap().is_empty());
}

/// Active administrator authority is accepted for independent promotion.
#[tokio::test]
async fn promotion_route_accepts_independent_administrator() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let admission = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        submission_id,
    )
    .await;
    assert_eq!(admission.status(), StatusCode::OK);
    approve_for_foreign_moderator(&fixture, submission_id);
    fixture
        .catalog
        .state
        .write()
        .unwrap()
        .platform_roles
        .first_mut()
        .unwrap()
        .role = PlatformRole::Administrator;

    let response = send_promotion(
        &fixture,
        "foreign-token",
        submission_id,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fixture.public_objects.blobs.read().unwrap().len(), 1);
}

/// Both bearer authentication and signed-request proof are mandatory.
#[tokio::test]
async fn submission_requires_bearer_and_valid_signed_request() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let missing_bearer = send_submission(&fixture, None, &fixture.signing_key, submission_id).await;
    assert_eq!(missing_bearer.status(), StatusCode::UNAUTHORIZED);

    let (body, content_type) =
        submission_multipart(submission_id, fixture.intent.id, &fixture.archive);
    let unsigned = fixture
        .router
        .clone()
        .oneshot(submission_request(
            Some("owner-token"),
            body,
            &content_type,
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);

    let (mut tampered_body, content_type) =
        submission_multipart(submission_id, fixture.intent.id, &fixture.archive);
    let headers = signed_headers(
        &fixture.signing_key,
        "POST",
        "/v1/publication-submissions",
        &tampered_body,
    );
    tampered_body.push(b'x');
    let invalid_signature = fixture
        .router
        .clone()
        .oneshot(submission_request(
            Some("owner-token"),
            tampered_body,
            &content_type,
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(invalid_signature.status(), StatusCode::UNAUTHORIZED);
    assert!(fixture.quarantine.blobs.read().unwrap().is_empty());
}

/// A valid signature from the wrong key cannot consume the intent.
#[tokio::test]
async fn submission_rejects_signer_key_mismatch() {
    let fixture = route_fixture();
    let response = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.wrong_signing_key,
        Uuid::new_v4(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fixture.quarantine.blobs.read().unwrap().is_empty());
}

/// Foreign accounts cannot discover or consume another account's intent.
#[tokio::test]
async fn submission_hides_foreign_intent() {
    let fixture = route_fixture();
    let response = send_submission(
        &fixture,
        Some("foreign-token"),
        &fixture.signing_key,
        Uuid::new_v4(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(response).await["error"],
        "publication intent not found"
    );
    assert!(fixture.quarantine.blobs.read().unwrap().is_empty());
}

/// Exact retries return one quarantined record and never touch public storage.
#[tokio::test]
async fn exact_submission_retry_is_idempotent_and_quarantine_only() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let first = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        submission_id,
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_json = response_json(first).await;
    assert_eq!(first_json["id"], submission_id.to_string());
    assert_eq!(first_json["state"], "quarantined");

    let retry = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        submission_id,
    )
    .await;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(response_json(retry).await, first_json);
    assert_eq!(fixture.quarantine.blobs.read().unwrap().len(), 1);
    assert!(fixture.public_objects.blobs.read().unwrap().is_empty());
    let state = fixture.catalog.state.read().unwrap();
    assert_eq!(state.publication_submissions.len(), 1);
    assert!(state
        .publication_intents
        .get(&fixture.intent.id)
        .unwrap()
        .consumed_at
        .is_some());
}

/// A consumed intent cannot be rebound to a different submission identifier.
#[tokio::test]
async fn consumed_intent_rejects_different_submission_id() {
    let fixture = route_fixture();
    let first = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        Uuid::new_v4(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let conflicting = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        Uuid::new_v4(),
    )
    .await;
    assert_eq!(conflicting.status(), StatusCode::CONFLICT);
    assert_eq!(
        fixture
            .catalog
            .state
            .read()
            .unwrap()
            .publication_submissions
            .len(),
        1
    );
}

/// Reusing the exact signed-request nonce is rejected before handler work.
#[tokio::test]
async fn submission_rejects_replayed_signed_request_nonce() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let (body, content_type) =
        submission_multipart(submission_id, fixture.intent.id, &fixture.archive);
    let headers = signed_headers(
        &fixture.signing_key,
        "POST",
        "/v1/publication-submissions",
        &body,
    );
    let first = fixture
        .router
        .clone()
        .oneshot(submission_request(
            Some("owner-token"),
            body.clone(),
            &content_type,
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let replay = fixture
        .router
        .clone()
        .oneshot(submission_request(
            Some("owner-token"),
            body,
            &content_type,
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

/// An already-expired unconsumed intent fails before quarantine mutation.
#[tokio::test]
async fn submission_rejects_expired_intent_before_quarantine() {
    let fixture = route_fixture();
    fixture
        .catalog
        .state
        .write()
        .unwrap()
        .publication_intents
        .get_mut(&fixture.intent.id)
        .unwrap()
        .expires_at = Utc::now() - ChronoDuration::seconds(1);
    let response = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        Uuid::new_v4(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fixture.quarantine.blobs.read().unwrap().is_empty());
}

/// Submission reads are owner-only and hide foreign records like missing ones.
#[tokio::test]
async fn submission_get_is_account_scoped() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let created = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        submission_id,
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);

    let owner = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/publication-submissions/{submission_id}"))
                .header("authorization", "Bearer owner-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(owner.status(), StatusCode::OK);

    let foreign = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/publication-submissions/{submission_id}"))
                .header("authorization", "Bearer foreign-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let missing = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/publication-submissions/{}", Uuid::new_v4()))
                .header("authorization", "Bearer foreign-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_json(foreign).await, response_json(missing).await);
    assert_ne!(fixture.owner_account_id, fixture.foreign_account_id);
}

/// A withdrawal with no client-supplied `x-request-id` header is rejected
/// instead of silently accepting a server-generated id, which would defeat
/// substituted-retry rejection (F-10 regression).
#[tokio::test]
async fn submission_withdrawal_requires_client_supplied_request_id() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let created = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        submission_id,
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let lifecycle_router = app(test_state(&fixture.catalog, &fixture.public_objects));
    let response = lifecycle_router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v1/publication-submissions/{submission_id}/withdraw"
                ))
                .header("authorization", "Bearer owner-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "id": Uuid::new_v4(),
                        "reason_code": "owner.cancelled"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await["error"],
        "x-request-id must be a UUID"
    );
}

/// Owner withdrawal is account-bound, header-bound, atomic, and exactly retryable.
#[tokio::test]
async fn submission_withdrawal_enforces_owner_and_idempotency() {
    let fixture = route_fixture();
    let submission_id = Uuid::new_v4();
    let created = send_submission(
        &fixture,
        Some("owner-token"),
        &fixture.signing_key,
        submission_id,
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let lifecycle_router = app(test_state(&fixture.catalog, &fixture.public_objects));
    let decision_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let path = format!("/v1/publication-submissions/{submission_id}/withdraw");
    let body = serde_json::json!({
        "id": decision_id,
        "reason_code": "owner.cancelled"
    })
    .to_string();

    let foreign = lifecycle_router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&path)
                .header("authorization", "Bearer foreign-token")
                .header("content-type", "application/json")
                .header("x-request-id", Uuid::new_v4().to_string())
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);

    let owner = lifecycle_router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&path)
                .header("authorization", "Bearer owner-token")
                .header("content-type", "application/json")
                .header("x-request-id", request_id.to_string())
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(owner.status(), StatusCode::OK);
    assert_eq!(response_json(owner).await["action"], "withdraw_submission");
    assert_eq!(
        fixture
            .catalog
            .state
            .read()
            .unwrap()
            .publication_submissions
            .get(&submission_id)
            .unwrap()
            .state,
        PublicationSubmissionState::Withdrawn
    );

    let retry = lifecycle_router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header("authorization", "Bearer owner-token")
                .header("content-type", "application/json")
                .header("x-request-id", request_id.to_string())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(
        fixture
            .catalog
            .state
            .read()
            .unwrap()
            .publication_lifecycle_decisions
            .len(),
        1
    );
    let audit = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/publishers/submission-publisher/publication-decisions?limit=50")
                .header("authorization", "Bearer owner-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(audit.status(), StatusCode::OK);
    let audit_json = response_json(audit).await;
    assert_eq!(audit_json.as_array().unwrap().len(), 1);
    assert_eq!(audit_json[0]["id"], decision_id.to_string());
}
