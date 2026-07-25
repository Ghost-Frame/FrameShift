//! Authenticated HTTP routes for reviewing quarantined publication submissions.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use frameshift_catalog::{
    CatalogError, PlatformRole, PlatformRoleState, PublicationModerationAction,
    PublicationModerationDecisionRecord, PublicationModerationDecisionRequest,
    PublicationSubmissionRecord,
};
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
pub fn moderation_router() -> Router<AppState> {
    Router::new()
        .route("/{submission_id}", get(get_moderation_submission))
        .route(
            "/{submission_id}/decisions",
            post(create_moderation_decision),
        )
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
