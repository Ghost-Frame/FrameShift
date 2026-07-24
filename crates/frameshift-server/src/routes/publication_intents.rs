//! Authenticated HTTP routes for creating and retrieving publication intents.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use chrono::{Duration, Utc};
use frameshift_catalog::{CatalogError, ObjectHash, PublicationIntentRecord};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::middleware::account::AuthenticatedAccount;
use crate::state::AppState;

/// Lifetime assigned by the server to each newly created publication intent.
const PUBLICATION_INTENT_TTL_SECONDS: i64 = 15 * 60;

/// Client-controlled fields that bind one idempotent publication intent.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePublicationIntentRequest {
    /// Stable caller-generated identifier used as the idempotency key.
    pub id: Uuid,
    /// Publisher under which the artifact will be submitted.
    pub publisher_id: Uuid,
    /// Active publisher key that will sign the eventual submission.
    pub publisher_key_id: Uuid,
    /// SHA-256 digest of the exact archive bytes.
    pub archive_hash: ObjectHash,
    /// SHA-256 digest of the canonical manifest bytes.
    pub manifest_hash: ObjectHash,
    /// SHA-256 digest of the normalized file inventory.
    pub file_inventory_hash: ObjectHash,
    /// Positive version of the scanner contract used for the inventory.
    pub scan_schema_version: u32,
}

/// Build publication-intent routes protected by the account middleware.
pub fn publication_intent_router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_publication_intent))
        .route("/{id}", get(get_publication_intent))
}

/// Create or idempotently retrieve one exact account-bound publication intent.
async fn create_publication_intent(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Json(request): Json<CreatePublicationIntentRequest>,
) -> Result<Json<PublicationIntentRecord>, AppError> {
    if request.scan_schema_version == 0 {
        return Err(AppError::BadRequest(
            "scan_schema_version must be positive".to_string(),
        ));
    }
    match state.catalog.get_publication_intent(request.id).await {
        Ok(existing) => return existing_intent_response(existing, &auth, &request),
        Err(CatalogError::NotFound { .. }) => {}
        Err(error) => return Err(AppError::from_catalog(error, "publication intent")),
    }

    let created_at = Utc::now();
    let record = PublicationIntentRecord {
        id: request.id,
        account_id: auth.account.id,
        publisher_id: request.publisher_id,
        publisher_key_id: request.publisher_key_id,
        archive_hash: request.archive_hash,
        manifest_hash: request.manifest_hash,
        file_inventory_hash: request.file_inventory_hash,
        scan_schema_version: request.scan_schema_version,
        created_at,
        expires_at: created_at + Duration::seconds(PUBLICATION_INTENT_TTL_SECONDS),
        consumed_at: None,
    };
    match state.catalog.create_publication_intent(record).await {
        Ok(created) => Ok(Json(created)),
        Err(CatalogError::Conflict { .. }) => {
            let existing = state
                .catalog
                .get_publication_intent(request.id)
                .await
                .map_err(|error| AppError::from_catalog(error, "publication intent"))?;
            existing_intent_response(existing, &auth, &request)
        }
        Err(error) => Err(AppError::from_catalog(error, "publication intent")),
    }
}

/// Retrieve one publication intent only for the authenticated owning account.
async fn get_publication_intent(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(id): Path<Uuid>,
) -> Result<Json<PublicationIntentRecord>, AppError> {
    let record = match state.catalog.get_publication_intent(id).await {
        Ok(record) => record,
        Err(CatalogError::NotFound { .. }) => return Err(publication_intent_not_found()),
        Err(error) => return Err(AppError::from_catalog(error, "publication intent")),
    };
    if record.account_id != auth.account.id {
        return Err(publication_intent_not_found());
    }
    Ok(Json(record))
}

/// Return the fixed response shared by missing and foreign-account intent reads.
fn publication_intent_not_found() -> AppError {
    AppError::NotFound("publication intent not found".to_string())
}

/// Return an exact retry or reject reuse of an intent identifier for different input.
fn existing_intent_response(
    existing: PublicationIntentRecord,
    auth: &AuthenticatedAccount,
    request: &CreatePublicationIntentRequest,
) -> Result<Json<PublicationIntentRecord>, AppError> {
    let exact_retry = existing.account_id == auth.account.id
        && existing.publisher_id == request.publisher_id
        && existing.publisher_key_id == request.publisher_key_id
        && existing.archive_hash == request.archive_hash
        && existing.manifest_hash == request.manifest_hash
        && existing.file_inventory_hash == request.file_inventory_hash
        && existing.scan_schema_version == request.scan_schema_version;
    if exact_retry {
        Ok(Json(existing))
    } else {
        Err(AppError::Conflict(format!(
            "publication_intent conflict: {}",
            request.id
        )))
    }
}
