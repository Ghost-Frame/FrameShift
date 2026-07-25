//! Authenticated HTTP routes for admitting exact publication archives to quarantine.

use std::sync::Arc;

use axum::extract::{Multipart, Path, State};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use chrono::Utc;
use frameshift_catalog::{
    CatalogError, PublicationIntentClaim, PublicationIntentRecord, PublicationSubmissionRecord,
    PublisherKeyState,
};
use uuid::Uuid;

use crate::auth::VerifiedSigner;
use crate::error::AppError;
use crate::middleware::account::AuthenticatedAccount;
use crate::publication::{PublicationAdmissionError, PublicationAdmissionService};
use crate::state::AppState;

/// Parsed client-controlled fields for one publication submission.
struct SubmissionMultipart {
    /// Stable caller-generated submission identifier and idempotency key.
    id: Uuid,
    /// Durable publication intent authorizing the exact archive.
    intent_id: Uuid,
    /// Exact gzip-tar archive bytes covered by the signed request.
    archive: Vec<u8>,
}

/// Build account-scoped publication-submission read routes.
pub fn publication_submission_read_router() -> Router<AppState> {
    Router::new().route("/{id}", get(get_publication_submission))
}

/// Build publication-submission writes over one explicit quarantine service.
pub fn publication_submission_write_router(
    admission: Arc<PublicationAdmissionService>,
) -> Router<AppState> {
    Router::new()
        .route("/", post(create_publication_submission))
        .layer(Extension(admission))
}

/// Admit an exact signed archive to quarantine under its durable intent.
async fn create_publication_submission(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Extension(signer): Extension<VerifiedSigner>,
    Extension(admission): Extension<Arc<PublicationAdmissionService>>,
    multipart: Multipart,
) -> Result<Json<PublicationSubmissionRecord>, AppError> {
    let request = parse_submission_multipart(multipart).await?;
    let intent = load_owned_intent(&state, request.intent_id, auth.account.id).await?;
    if intent.consumed_at.is_none() && intent.expires_at <= Utc::now() {
        return Err(AppError::Forbidden(
            "publication intent is no longer active".to_string(),
        ));
    }
    authorize_intent_signer(&state, &intent, signer).await?;
    let claim = publication_intent_claim(&intent);
    admission
        .admit(request.id, claim, request.archive)
        .await
        .map(Json)
        .map_err(map_admission_error)
}

/// Retrieve one quarantined submission only for its authenticated account.
async fn get_publication_submission(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(id): Path<Uuid>,
) -> Result<Json<PublicationSubmissionRecord>, AppError> {
    let record = match state.catalog.get_publication_submission(id).await {
        Ok(record) => record,
        Err(CatalogError::NotFound { .. }) => return Err(publication_submission_not_found()),
        Err(error) => return Err(AppError::from_catalog(error, "publication submission")),
    };
    if record.account_id != auth.account.id {
        return Err(publication_submission_not_found());
    }
    Ok(Json(record))
}

/// Parse the strict three-field multipart publication-submission contract.
async fn parse_submission_multipart(
    mut multipart: Multipart,
) -> Result<SubmissionMultipart, AppError> {
    let mut id = None;
    let mut intent_id = None;
    let mut archive = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| invalid_multipart())?
    {
        let name = field.name().ok_or_else(invalid_multipart)?.to_string();
        match name.as_str() {
            "id" => {
                reject_duplicate(id.is_some(), "id")?;
                let value = field.text().await.map_err(|_| invalid_multipart())?;
                id = Some(
                    Uuid::parse_str(&value)
                        .map_err(|_| AppError::BadRequest("id must be a UUID".to_string()))?,
                );
            }
            "intent_id" => {
                reject_duplicate(intent_id.is_some(), "intent_id")?;
                let value = field.text().await.map_err(|_| invalid_multipart())?;
                intent_id =
                    Some(Uuid::parse_str(&value).map_err(|_| {
                        AppError::BadRequest("intent_id must be a UUID".to_string())
                    })?);
            }
            "archive" => {
                reject_duplicate(archive.is_some(), "archive")?;
                archive = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|_| invalid_multipart())?
                        .to_vec(),
                );
            }
            _ => {
                return Err(AppError::BadRequest(
                    "unknown publication submission field".to_string(),
                ));
            }
        }
    }
    Ok(SubmissionMultipart {
        id: id.ok_or_else(|| missing_field("id"))?,
        intent_id: intent_id.ok_or_else(|| missing_field("intent_id"))?,
        archive: archive.ok_or_else(|| missing_field("archive"))?,
    })
}

/// Load an intent without revealing whether a foreign account owns it.
async fn load_owned_intent(
    state: &AppState,
    intent_id: Uuid,
    account_id: Uuid,
) -> Result<PublicationIntentRecord, AppError> {
    let intent = match state.catalog.get_publication_intent(intent_id).await {
        Ok(intent) => intent,
        Err(CatalogError::NotFound { .. }) => return Err(publication_intent_not_found()),
        Err(error) => return Err(AppError::from_catalog(error, "publication intent")),
    };
    if intent.account_id != account_id {
        return Err(publication_intent_not_found());
    }
    Ok(intent)
}

/// Require the verified request signer to be the intent's active publisher key.
async fn authorize_intent_signer(
    state: &AppState,
    intent: &PublicationIntentRecord,
    signer: VerifiedSigner,
) -> Result<(), AppError> {
    let key = match state
        .catalog
        .get_publisher_key(intent.publisher_key_id)
        .await
    {
        Ok(key) => key,
        Err(CatalogError::NotFound { .. }) | Err(CatalogError::Unauthorized { .. }) => {
            return Err(AppError::Forbidden(
                "publication submission signer is not authorized".to_string(),
            ));
        }
        Err(error) => return Err(AppError::from_catalog(error, "publisher key")),
    };
    if key.publisher_id != intent.publisher_id
        || key.state != PublisherKeyState::Active
        || key.public_key != signer.pubkey
    {
        return Err(AppError::Forbidden(
            "publication submission signer is not authorized".to_string(),
        ));
    }
    Ok(())
}

/// Copy every durable intent binding into the atomic admission claim.
fn publication_intent_claim(intent: &PublicationIntentRecord) -> PublicationIntentClaim {
    PublicationIntentClaim {
        id: intent.id,
        account_id: intent.account_id,
        publisher_id: intent.publisher_id,
        publisher_key_id: intent.publisher_key_id,
        archive_hash: intent.archive_hash,
        manifest_hash: intent.manifest_hash,
        file_inventory_hash: intent.file_inventory_hash,
        scan_schema_version: intent.scan_schema_version,
    }
}

/// Map admission failures to bounded public HTTP errors.
fn map_admission_error(error: PublicationAdmissionError) -> AppError {
    match error {
        PublicationAdmissionError::ArchiveHashMismatch => {
            AppError::BadRequest("publication archive does not match intent".to_string())
        }
        PublicationAdmissionError::InvalidArchive(_) => {
            AppError::BadRequest("invalid publication archive".to_string())
        }
        PublicationAdmissionError::Validation { codes } => {
            AppError::BadRequest(format!("publication validation failed: {codes}"))
        }
        PublicationAdmissionError::IntentMismatch { field } => {
            AppError::BadRequest(format!("publication {field} does not match intent"))
        }
        PublicationAdmissionError::Catalog(error) => {
            AppError::from_catalog(error, "publication submission")
        }
        PublicationAdmissionError::Quarantine(error) => {
            tracing::error!(%error, "publication quarantine write failed");
            AppError::Internal("publication quarantine write failed".to_string())
        }
        PublicationAdmissionError::Internal(error) => {
            tracing::error!(%error, "publication inspection failed");
            AppError::Internal("publication inspection failed".to_string())
        }
    }
}

/// Reject one duplicate multipart field with a stable public diagnostic.
fn reject_duplicate(duplicate: bool, field: &'static str) -> Result<(), AppError> {
    if duplicate {
        Err(AppError::BadRequest(format!(
            "duplicate publication submission field: {field}"
        )))
    } else {
        Ok(())
    }
}

/// Return the fixed malformed-multipart response.
fn invalid_multipart() -> AppError {
    AppError::BadRequest("invalid publication submission multipart body".to_string())
}

/// Return the fixed missing-field response.
fn missing_field(field: &'static str) -> AppError {
    AppError::BadRequest(format!("missing publication submission field: {field}"))
}

/// Return the fixed response shared by missing and foreign-account intents.
fn publication_intent_not_found() -> AppError {
    AppError::NotFound("publication intent not found".to_string())
}

/// Return the fixed response shared by missing and foreign-account submissions.
fn publication_submission_not_found() -> AppError {
    AppError::NotFound("publication submission not found".to_string())
}
