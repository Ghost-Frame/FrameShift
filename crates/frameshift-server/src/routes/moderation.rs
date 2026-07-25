//! Authenticated HTTP routes for reviewing quarantined publication submissions.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use frameshift_catalog::{
    CatalogError, MembershipState, PlatformRole, PlatformRoleState, PublicationModerationAction,
    PublicationModerationDecisionRecord, PublicationModerationDecisionRequest,
    PublicationSubmissionRecord, PublisherRole,
};
use frameshift_objects::{ObjectHash, PackStore};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::middleware::account::AuthenticatedAccount;
use crate::state::AppState;

/// Caller-controlled fields accepted for one publication moderation decision.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModeratePublicationRequest {
    /// Stable caller-generated decision identifier.
    id: Uuid,
    /// Review action to apply to the path-bound submission.
    action: PublicationModerationAction,
    /// Stable bounded private reason code.
    reason_code: String,
    /// Optional bounded private explanation for the publisher.
    private_explanation: Option<String>,
}

/// Build role-gated publication moderation routes.
///
/// Artifact access is mounted only when the caller supplies the isolated
/// quarantine store used by publication admission.
pub fn moderation_router(quarantine: Option<Arc<dyn PackStore>>) -> Router<AppState> {
    let router = Router::new()
        .route("/{submission_id}", get(get_moderation_submission))
        .route(
            "/{submission_id}/decisions",
            post(create_moderation_decision),
        );
    if let Some(quarantine) = quarantine {
        router.merge(
            Router::new()
                .route("/{submission_id}/artifact", get(get_moderation_artifact))
                .layer(Extension(quarantine)),
        )
    } else {
        router
    }
}

/// Retrieve one submission only after proving active global review authority.
async fn get_moderation_submission(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(submission_id): Path<Uuid>,
) -> Result<Json<PublicationSubmissionRecord>, AppError> {
    require_moderation_role(&state, auth.account.id).await?;
    state
        .catalog
        .get_publication_submission(submission_id)
        .await
        .map(Json)
        .map_err(map_moderation_submission_error)
}

/// Return one exact quarantine archive to an independently authorized reviewer.
async fn get_moderation_artifact(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Extension(quarantine): Extension<Arc<dyn PackStore>>,
    Path(submission_id): Path<Uuid>,
) -> Result<Response, AppError> {
    require_moderation_role(&state, auth.account.id).await?;
    let submission = state
        .catalog
        .get_publication_submission(submission_id)
        .await
        .map_err(map_moderation_submission_error)?;
    require_independent_reviewer(&state, auth.account.id, submission.publisher_id).await?;

    let bytes = quarantine
        .get(&submission.archive_hash)
        .await
        .map_err(|error| AppError::from_objects(error, "publication quarantine"))?;
    if bytes.len() > state.config.max_request_bytes
        || ObjectHash::of(&bytes) != submission.archive_hash
    {
        return Err(AppError::BadGateway(
            "publication quarantine artifact failed integrity bounds".to_string(),
        ));
    }

    Response::builder()
        .header(header::CONTENT_TYPE, "application/gzip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"publication-{submission_id}.tar.gz\""),
        )
        .header(header::CONTENT_LENGTH, bytes.len())
        .header(header::CACHE_CONTROL, "private, no-store, max-age=0")
        .body(Body::from(bytes))
        .map_err(|error| AppError::Internal(format!("artifact response construction: {error}")))
}

/// Apply one path-, identity-, and request-header-bound moderation decision.
async fn create_moderation_decision(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(submission_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<ModeratePublicationRequest>,
) -> Result<Json<PublicationModerationDecisionRecord>, AppError> {
    let request = PublicationModerationDecisionRequest {
        id: body.id,
        submission_id,
        actor_account_id: auth.account.id,
        action: body.action,
        reason_code: body.reason_code,
        private_explanation: body.private_explanation,
        request_id: request_id(&headers)?,
    };
    state
        .catalog
        .moderate_publication_submission(request)
        .await
        .map(Json)
        .map_err(map_moderation_submission_error)
}

/// Require an active moderator or administrator assignment for one account.
async fn require_moderation_role(state: &AppState, account_id: Uuid) -> Result<(), AppError> {
    let authorized = state
        .catalog
        .list_account_platform_roles(account_id)
        .await
        .map_err(|error| AppError::from_catalog(error, "platform role"))?
        .into_iter()
        .any(|record| {
            record.state == PlatformRoleState::Active
                && matches!(
                    record.role,
                    PlatformRole::Moderator | PlatformRole::Administrator
                )
        });
    if authorized {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "active moderation role required".to_string(),
        ))
    }
}

/// Reject active publisher owners from accessing their own review artifact.
async fn require_independent_reviewer(
    state: &AppState,
    account_id: Uuid,
    publisher_id: Uuid,
) -> Result<(), AppError> {
    match state
        .catalog
        .get_publisher_membership(account_id, publisher_id)
        .await
    {
        Ok(membership)
            if membership.role == PublisherRole::Owner
                && membership.state == MembershipState::Active =>
        {
            Err(AppError::Forbidden(
                "publisher owners cannot review their own artifacts".to_string(),
            ))
        }
        Ok(_) | Err(CatalogError::NotFound { .. }) => Ok(()),
        Err(error) => Err(AppError::from_catalog(error, "publisher membership")),
    }
}

/// Parse the mandatory request correlation header as a stable UUID.
fn request_id(headers: &HeaderMap) -> Result<Uuid, AppError> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| AppError::BadRequest("x-request-id must be a UUID".to_string()))
}

/// Map moderation catalog failures without exposing raw submission identifiers.
fn map_moderation_submission_error(error: CatalogError) -> AppError {
    match error {
        CatalogError::NotFound { .. } => {
            AppError::NotFound("publication submission not found".to_string())
        }
        other => AppError::from_catalog(other, "publication moderation"),
    }
}
