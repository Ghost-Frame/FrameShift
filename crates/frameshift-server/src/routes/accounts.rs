//! OIDC account, publisher profile, and publisher signing-key HTTP routes.

use std::str::FromStr;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, patch, post};
use axum::{Extension, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use frameshift_catalog::{
    AccountRecord, CatalogError, Ed25519PublicKey, MembershipState, PublisherAuditEventRecord,
    PublisherKeyRecord, PublisherKeyState, PublisherMembershipRecord, PublisherModerationStatus,
    PublisherProfileRecord, PublisherRole,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::middleware::account::AuthenticatedAccount;
use crate::state::AppState;

/// Public OIDC bootstrap metadata returned to clients.
#[derive(Debug, Serialize)]
pub struct AuthConfigResponse {
    /// Whether account routes are configured and mounted.
    pub enabled: bool,
    /// Configured OIDC issuer when enabled.
    pub issuer: Option<String>,
    /// Configured resource audience when enabled.
    pub audience: Option<String>,
}

/// Current account response including publisher memberships.
#[derive(Debug, Serialize)]
pub struct AccountResponse {
    /// Durable account record.
    pub account: AccountRecord,
    /// Publisher memberships held by the account.
    pub memberships: Vec<PublisherMembershipRecord>,
}

/// Mutable account profile input.
#[derive(Debug, Deserialize)]
pub struct UpdateAccountRequest {
    /// Replacement email metadata when supplied.
    pub email: Option<String>,
    /// Replacement display name when supplied.
    pub display_name: Option<String>,
}

/// Publisher profile creation input.
#[derive(Debug, Deserialize)]
pub struct CreatePublisherRequest {
    /// Unique lowercase public handle.
    pub handle: String,
    /// Public display name.
    pub display_name: String,
    /// Optional public biography.
    pub biography: Option<String>,
}

/// Mutable publisher profile input.
#[derive(Debug, Deserialize)]
pub struct UpdatePublisherRequest {
    /// Replacement public display name.
    pub display_name: String,
    /// Replacement biography when supplied.
    pub biography: Option<String>,
    /// Whether an existing biography should be cleared.
    #[serde(default)]
    pub clear_biography: bool,
}

/// Signing-key enrollment input with Ed25519 proof of possession.
#[derive(Debug, Deserialize)]
pub struct EnrollPublisherKeyRequest {
    /// Base64url-no-pad Ed25519 public key.
    pub public_key: String,
    /// User-visible key label.
    pub label: String,
    /// Base64url-no-pad signature over the enrollment challenge.
    pub proof_signature: String,
}

/// Publisher signing-key challenge request.
#[derive(Debug, Deserialize)]
pub struct PublisherKeyChallengeRequest {
    /// Base64url-no-pad Ed25519 public key that will prove possession.
    pub public_key: String,
}

/// Account-bound key enrollment challenge and its freshness deadline.
#[derive(Debug, Serialize)]
pub struct PublisherKeyChallengeResponse {
    /// Exact bytes the proposed publisher key must sign.
    pub challenge: String,
    /// Unix timestamp after which fresh authentication is required again.
    pub expires_at: u64,
}

/// Build the public authentication bootstrap router.
pub fn auth_config_router() -> Router<AppState> {
    Router::new().route("/config", get(get_auth_config))
}

/// Build public publisher profile read routes.
pub fn publisher_read_router() -> Router<AppState> {
    Router::new().route("/{handle}", get(get_publisher))
}

/// Build routes that require validated OIDC account middleware.
pub fn account_write_router() -> Router<AppState> {
    Router::new()
        .route("/account", get(get_account).patch(update_account))
        .route("/publishers", post(create_publisher))
        .route("/publishers/{handle}", patch(update_publisher))
        .route(
            "/publishers/{handle}/keys",
            get(list_publisher_keys).post(enroll_publisher_key),
        )
        .route(
            "/publishers/{handle}/keys/challenge",
            post(create_publisher_key_challenge),
        )
        .route(
            "/publishers/{handle}/keys/{key_id}",
            delete(revoke_publisher_key),
        )
}

/// Return the account-bound challenge for a proposed publisher key.
async fn create_publisher_key_challenge(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(handle): Path<String>,
    Json(request): Json<PublisherKeyChallengeRequest>,
) -> Result<Json<PublisherKeyChallengeResponse>, AppError> {
    require_fresh_auth(&state, &auth)?;
    let profile = require_owner(&state, &auth, &handle).await?;
    let public_key = Ed25519PublicKey::from_str(&request.public_key)
        .map_err(|_| AppError::BadRequest("invalid publisher public key".to_string()))?;
    let auth_time = auth
        .auth_time
        .ok_or_else(|| AppError::Forbidden("fresh authentication required".to_string()))?;
    Ok(Json(PublisherKeyChallengeResponse {
        challenge: enrollment_challenge(&auth.account.id, &profile.id, &public_key),
        expires_at: auth_time.saturating_add(state.config.oidc.fresh_auth_max_age.as_secs()),
    }))
}

/// Return non-secret OIDC client bootstrap configuration.
async fn get_auth_config(State(state): State<AppState>) -> Json<AuthConfigResponse> {
    let enabled = state.account_auth.is_some();
    Json(AuthConfigResponse {
        enabled,
        issuer: enabled.then(|| state.config.oidc.issuer.clone()),
        audience: enabled.then(|| state.config.oidc.audience.clone()),
    })
}

/// Return the authenticated account and its publisher memberships.
async fn get_account(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
) -> Result<Json<AccountResponse>, AppError> {
    let memberships = state
        .catalog
        .list_account_memberships(auth.account.id)
        .await
        .map_err(|error| AppError::from_catalog(error, "publisher membership"))?;
    Ok(Json(AccountResponse {
        account: auth.account,
        memberships,
    }))
}

/// Update mutable profile metadata for the authenticated account.
async fn update_account(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Json(request): Json<UpdateAccountRequest>,
) -> Result<Json<AccountRecord>, AppError> {
    let email = request.email.as_deref().or(auth.account.email.as_deref());
    let display_name = request
        .display_name
        .as_deref()
        .or(auth.account.display_name.as_deref());
    let updated = state
        .catalog
        .update_account_profile(auth.account.id, email, display_name)
        .await
        .map_err(|error| AppError::from_catalog(error, "account"))?;
    Ok(Json(updated))
}

/// Create a pending publisher profile owned by the authenticated account.
async fn create_publisher(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    headers: HeaderMap,
    Json(request): Json<CreatePublisherRequest>,
) -> Result<Json<PublisherProfileRecord>, AppError> {
    let now = Utc::now();
    let profile = PublisherProfileRecord {
        id: Uuid::new_v4(),
        handle: request.handle,
        display_name: request.display_name,
        biography: request.biography,
        moderation_status: PublisherModerationStatus::Pending,
        created_at: now,
        updated_at: now,
    };
    let owner = PublisherMembershipRecord {
        account_id: auth.account.id,
        publisher_id: profile.id,
        role: PublisherRole::Owner,
        state: MembershipState::Active,
        created_at: now,
        updated_at: now,
    };
    state
        .catalog
        .create_publisher(profile.clone(), owner)
        .await
        .map_err(|error| AppError::from_catalog(error, "publisher"))?;
    append_audit(
        &state,
        &auth,
        profile.id,
        "publisher.created",
        None,
        request_id(&headers),
    )
    .await?;
    Ok(Json(profile))
}

/// Return one public publisher profile by normalized handle.
async fn get_publisher(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Json<PublisherProfileRecord>, AppError> {
    state
        .catalog
        .get_publisher_by_handle(&handle)
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "publisher"))
}

/// Update a publisher profile after active-owner authorization.
async fn update_publisher(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdatePublisherRequest>,
) -> Result<Json<PublisherProfileRecord>, AppError> {
    let profile = require_owner(&state, &auth, &handle).await?;
    let biography = if request.clear_biography {
        None
    } else {
        request
            .biography
            .as_deref()
            .or(profile.biography.as_deref())
    };
    let updated = state
        .catalog
        .update_publisher_profile(profile.id, &request.display_name, biography)
        .await
        .map_err(|error| AppError::from_catalog(error, "publisher"))?;
    append_audit(
        &state,
        &auth,
        profile.id,
        "publisher.updated",
        None,
        request_id(&headers),
    )
    .await?;
    Ok(Json(updated))
}

/// List enrolled publisher keys after active-owner authorization.
async fn list_publisher_keys(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(handle): Path<String>,
) -> Result<Json<Vec<PublisherKeyRecord>>, AppError> {
    let profile = require_owner(&state, &auth, &handle).await?;
    state
        .catalog
        .list_publisher_keys(profile.id)
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "publisher key"))
}

/// Enroll a publisher key after fresh authentication and proof of possession.
async fn enroll_publisher_key(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    Json(request): Json<EnrollPublisherKeyRequest>,
) -> Result<Json<PublisherKeyRecord>, AppError> {
    require_fresh_auth(&state, &auth)?;
    let profile = require_owner(&state, &auth, &handle).await?;
    let public_key = Ed25519PublicKey::from_str(&request.public_key)
        .map_err(|_| AppError::BadRequest("invalid publisher public key".to_string()))?;
    verify_enrollment_proof(
        &auth.account.id,
        &profile.id,
        &public_key,
        &request.proof_signature,
    )?;
    let record = PublisherKeyRecord {
        id: Uuid::new_v4(),
        publisher_id: profile.id,
        public_key,
        label: request.label,
        state: PublisherKeyState::Active,
        created_at: Utc::now(),
        revoked_at: None,
        last_used_at: None,
    };
    state
        .catalog
        .create_publisher_key(record.clone())
        .await
        .map_err(|error| AppError::from_catalog(error, "publisher key"))?;
    append_audit(
        &state,
        &auth,
        profile.id,
        "publisher.key.enrolled",
        Some(record.id),
        request_id(&headers),
    )
    .await?;
    Ok(Json(record))
}

/// Revoke a non-last publisher key after fresh account authentication.
async fn revoke_publisher_key(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path((handle, key_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<PublisherKeyRecord>, AppError> {
    require_fresh_auth(&state, &auth)?;
    let profile = require_owner(&state, &auth, &handle).await?;
    let record = state
        .catalog
        .revoke_publisher_key(profile.id, key_id, Utc::now())
        .await
        .map_err(|error| AppError::from_catalog(error, "publisher key"))?;
    append_audit(
        &state,
        &auth,
        profile.id,
        "publisher.key.revoked",
        Some(record.id),
        request_id(&headers),
    )
    .await?;
    Ok(Json(record))
}

/// Resolve a publisher and require an active owner membership for the account.
async fn require_owner(
    state: &AppState,
    auth: &AuthenticatedAccount,
    handle: &str,
) -> Result<PublisherProfileRecord, AppError> {
    let profile = state
        .catalog
        .get_publisher_by_handle(handle)
        .await
        .map_err(|error| AppError::from_catalog(error, "publisher"))?;
    let membership = state
        .catalog
        .get_publisher_membership(auth.account.id, profile.id)
        .await
        .map_err(|error| match error {
            CatalogError::NotFound { .. } => {
                AppError::Forbidden("publisher ownership required".to_string())
            }
            other => AppError::from_catalog(other, "publisher membership"),
        })?;
    if membership.role != PublisherRole::Owner || membership.state != MembershipState::Active {
        return Err(AppError::Forbidden(
            "active publisher ownership required".to_string(),
        ));
    }
    Ok(profile)
}

/// Require a recent provider authentication timestamp for a sensitive operation.
fn require_fresh_auth(state: &AppState, auth: &AuthenticatedAccount) -> Result<(), AppError> {
    let auth_time = auth
        .auth_time
        .ok_or_else(|| AppError::Forbidden("fresh authentication required".to_string()))?;
    let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
    let skew = state.config.oidc.clock_skew.as_secs();
    if auth_time > now.saturating_add(skew)
        || now.saturating_sub(auth_time) > state.config.oidc.fresh_auth_max_age.as_secs()
    {
        return Err(AppError::Forbidden(
            "fresh authentication required".to_string(),
        ));
    }
    Ok(())
}

/// Verify the enrolled key signed its deterministic account-bound challenge.
fn verify_enrollment_proof(
    account_id: &Uuid,
    publisher_id: &Uuid,
    public_key: &Ed25519PublicKey,
    encoded_signature: &str,
) -> Result<(), AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| AppError::BadRequest("invalid proof signature".to_string()))?;
    let signature = Signature::from_slice(&bytes)
        .map_err(|_| AppError::BadRequest("invalid proof signature".to_string()))?;
    let verifier = VerifyingKey::from_bytes(&public_key.0)
        .map_err(|_| AppError::BadRequest("invalid publisher public key".to_string()))?;
    let challenge = enrollment_challenge(account_id, publisher_id, public_key);
    verifier
        .verify(challenge.as_bytes(), &signature)
        .map_err(|_| AppError::Forbidden("key proof of possession failed".to_string()))
}

/// Build the canonical account-bound key enrollment challenge.
fn enrollment_challenge(
    account_id: &Uuid,
    publisher_id: &Uuid,
    public_key: &Ed25519PublicKey,
) -> String {
    format!("frameshift-key-enrollment:v1:{account_id}:{publisher_id}:{public_key}")
}

/// Parse the generated request identifier for audit correlation when present.
fn request_id(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
}

/// Append one sanitized account-driven publisher audit event.
async fn append_audit(
    state: &AppState,
    auth: &AuthenticatedAccount,
    publisher_id: Uuid,
    action: &str,
    target_key_id: Option<Uuid>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    state
        .catalog
        .append_publisher_audit_event(PublisherAuditEventRecord {
            id: Uuid::new_v4(),
            actor_account_id: Some(auth.account.id),
            publisher_id,
            action: action.to_string(),
            target_key_id,
            target_version: None,
            request_id,
            created_at: Utc::now(),
            metadata: serde_json::json!({}),
        })
        .await
        .map_err(|error| AppError::from_catalog(error, "publisher audit"))
}
