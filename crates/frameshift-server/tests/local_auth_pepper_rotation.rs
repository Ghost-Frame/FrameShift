//! Integration test for first-party password pepper rotation (F-05).
//!
//! Kept in its own test binary rather than alongside the other
//! password-hashing integration tests in `account_routes.rs`:
//! `routes::local_auth` bounds concurrent Argon2 work with a small
//! process-wide static semaphore (`PASSWORD_WORK_SLOTS`), and `cargo test`
//! runs every `tests/*.rs` file as its own process. Isolating this test's
//! extra register/login Argon2 calls in a separate process keeps it from
//! competing with (and destabilizing) unrelated password tests under
//! parallel `cargo test` execution.

mod mocks;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use frameshift_catalog::AccountInviteRecord;
use frameshift_server::metrics::Metrics;
use frameshift_server::{app, AppState, FirstPartyAuthConfig, ServerConfig};
use secrecy::SecretString;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;
use uuid::Uuid;

use mocks::catalog::MockCatalog;
use mocks::objects::MockPackStore;

/// Build a server configuration with first-party auth enabled under `pepper`
/// at `pepper_version`, retaining `previous` as the historical pepper set.
fn test_config(pepper: &str, pepper_version: i16, previous: Vec<(i16, &str)>) -> Arc<ServerConfig> {
    let mut config = ServerConfig::from_env().unwrap();
    config.bind_addr = "127.0.0.1:0".parse().unwrap();
    config.log_level = "off".to_string();
    config.cors_allowed_origins = "https://frameshift.test".to_string();
    config.abuse_rate_per_min = 0;
    config.download_rate_per_min = 0;
    config.first_party_auth = FirstPartyAuthConfig {
        password_pepper: SecretString::new(pepper.to_string()),
        pepper_version,
        mfa_encryption_key: SecretString::new(URL_SAFE_NO_PAD.encode([23_u8; 32])),
        native_authorization_url: "https://frameshift.test/account/".to_string(),
        previous_peppers: previous
            .into_iter()
            .map(|(version, secret)| (version, SecretString::new(secret.to_string())))
            .collect(),
        ..FirstPartyAuthConfig::disabled()
    };
    Arc::new(config)
}

/// Build application state around one shared catalog and explicit config.
fn test_state(catalog: MockCatalog, config: Arc<ServerConfig>) -> AppState {
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
        account_auth: None,
        mcp_access: None,
    }
}

/// Seed one bootstrap invitation redeemable by `email` and return its token.
fn seed_invite(catalog: &MockCatalog, email: &str) -> String {
    let raw_token = [7_u8; 32];
    let token = URL_SAFE_NO_PAD.encode(raw_token);
    let now = Utc::now();
    let id = Uuid::new_v4();
    catalog.state.write().unwrap().account_invites.insert(
        id,
        AccountInviteRecord {
            id,
            request_id: None,
            normalized_email: email.to_string(),
            token_digest: Sha256::digest(raw_token).to_vec(),
            issued_by_account_id: None,
            is_bootstrap: true,
            expires_at: now + chrono::Duration::hours(1),
            consumed_at: None,
            revoked_at: None,
            created_at: now,
        },
    );
    token
}

/// Send one JSON request through the in-process router.
async fn send(
    state: AppState,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> axum::http::Response<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    builder = builder.header("origin", "https://frameshift.test");
    let bytes = body.map_or_else(Vec::new, |value| serde_json::to_vec(&value).unwrap());
    if !bytes.is_empty() {
        builder = builder.header("content-type", "application/json");
    }
    app(state)
        .oneshot(builder.body(Body::from(bytes)).unwrap())
        .await
        .unwrap()
}

/// A credential verified under a retained old pepper is rehashed with the
/// current pepper before login succeeds.
///
/// The persisted upgrade must preserve the password-change timestamp and let
/// later logins succeed after the historical pepper is removed. Before that
/// upgrade, omitting the required historical pepper must fail closed.
#[tokio::test]
async fn login_verifies_credential_hashed_under_a_rotated_out_pepper() {
    let catalog = MockCatalog::new();
    let invite_token = seed_invite(&catalog, "rotated@example.test");
    let v1_pepper = "integration-test-pepper-v1";
    let state_under_v1 = test_state(catalog.clone(), test_config(v1_pepper, 1, vec![]));

    let registered = send(
        state_under_v1,
        Method::POST,
        "/v1/auth/register",
        Some(json!({
            "invite_token": invite_token,
            "email": "rotated@example.test",
            "password": "correct horse battery staple",
            "client_kind": "browser"
        })),
    )
    .await;
    assert_eq!(registered.status(), StatusCode::OK);
    let original_credential = catalog
        .state
        .read()
        .unwrap()
        .account_password_credentials
        .get("rotated@example.test")
        .unwrap()
        .clone();
    assert_eq!(original_credential.pepper_version, 1);

    let state_without_history_before_rehash = test_state(
        catalog.clone(),
        test_config("integration-test-pepper-v2", 2, vec![]),
    );
    let login_without_history_before_rehash = send(
        state_without_history_before_rehash,
        Method::POST,
        "/v1/auth/login",
        Some(json!({
            "email": "rotated@example.test",
            "password": "correct horse battery staple",
            "client_kind": "browser"
        })),
    )
    .await;
    assert_eq!(
        login_without_history_before_rehash.status(),
        StatusCode::UNAUTHORIZED,
        "dropping the historical pepper before rehash must fail closed"
    );

    // Rotate to pepper version 2, retaining version 1's secret as the only
    // previous pepper.
    let state_under_v2 = test_state(
        catalog.clone(),
        test_config("integration-test-pepper-v2", 2, vec![(1, v1_pepper)]),
    );
    let login = send(
        state_under_v2,
        Method::POST,
        "/v1/auth/login",
        Some(json!({
            "email": "rotated@example.test",
            "password": "correct horse battery staple",
            "client_kind": "browser"
        })),
    )
    .await;
    assert_eq!(
        login.status(),
        StatusCode::OK,
        "a credential hashed under the retained previous pepper must still verify"
    );

    let rehashed_credential = catalog
        .state
        .read()
        .unwrap()
        .account_password_credentials
        .get("rotated@example.test")
        .unwrap()
        .clone();
    assert_eq!(rehashed_credential.pepper_version, 2);
    assert_ne!(
        rehashed_credential.password_hash,
        original_credential.password_hash
    );
    assert_eq!(
        rehashed_credential.password_changed_at,
        original_credential.password_changed_at
    );
    assert!(rehashed_credential.updated_at >= original_credential.updated_at);

    // The durable rehash removes the old pepper from subsequent login's
    // dependency chain.
    let state_without_history = test_state(
        catalog,
        test_config("integration-test-pepper-v2", 2, vec![]),
    );
    let login_without_history = send(
        state_without_history,
        Method::POST,
        "/v1/auth/login",
        Some(json!({
            "email": "rotated@example.test",
            "password": "correct horse battery staple",
            "client_kind": "browser"
        })),
    )
    .await;
    assert_eq!(
        login_without_history.status(),
        StatusCode::OK,
        "the persisted current-pepper hash must work without historical peppers"
    );
}
