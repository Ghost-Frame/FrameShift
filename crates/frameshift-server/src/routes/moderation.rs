//! Authenticated HTTP routes for reviewing quarantined publication submissions.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use frameshift_catalog::{
    CatalogError, MembershipState, PlatformRole, PlatformRoleState, PublicationModerationAction,
    PublicationModerationDecisionRecord, PublicationModerationDecisionRequest,
    PublicationPromotionRecord, PublicationSubmissionRecord, PublisherRole,
};
use frameshift_objects::{ObjectHash, PackStore};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::middleware::account::AuthenticatedAccount;
use crate::middleware::request_id::ClientRequestId;
use crate::publication::{PublicationPromotionError, PublicationPromotionService};
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

/// Caller-controlled identity for one approved-submission promotion.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotePublicationRequest {
    /// Stable caller-generated promotion identifier.
    id: Uuid,
}

/// Build role-gated publication moderation routes.
///
/// Artifact access is mounted only when the caller supplies the isolated
/// quarantine store used by publication admission.
pub fn moderation_router(
    quarantine: Option<Arc<dyn PackStore>>,
    promotion: Option<Arc<PublicationPromotionService>>,
) -> Router<AppState> {
    let router = Router::new()
        .route("/{submission_id}", get(get_moderation_submission))
        .route(
            "/{submission_id}/decisions",
            post(create_moderation_decision),
        );
    let router = if let Some(quarantine) = quarantine {
        router.merge(
            Router::new()
                .route("/{submission_id}/artifact", get(get_moderation_artifact))
                .layer(Extension(quarantine)),
        )
    } else {
        router
    };
    if let Some(promotion) = promotion {
        router.merge(
            Router::new()
                .route("/{submission_id}/promotion", post(promote_publication))
                .layer(Extension(promotion)),
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
    Extension(client_request_id): Extension<ClientRequestId>,
    Path(submission_id): Path<Uuid>,
    Json(body): Json<ModeratePublicationRequest>,
) -> Result<Json<PublicationModerationDecisionRecord>, AppError> {
    let request = PublicationModerationDecisionRequest {
        id: body.id,
        submission_id,
        actor_account_id: auth.account.id,
        action: body.action,
        reason_code: body.reason_code,
        private_explanation: body.private_explanation,
        request_id: required_client_request_id(client_request_id)?,
    };
    state
        .catalog
        .moderate_publication_submission(request)
        .await
        .map(Json)
        .map_err(map_moderation_submission_error)
}

/// Promote one path-bound approved submission using only server-verified bytes.
async fn promote_publication(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Extension(promotion): Extension<Arc<PublicationPromotionService>>,
    Extension(client_request_id): Extension<ClientRequestId>,
    Path(submission_id): Path<Uuid>,
    Json(body): Json<PromotePublicationRequest>,
) -> Result<Json<PublicationPromotionRecord>, AppError> {
    let submission = state
        .catalog
        .get_publication_submission(submission_id)
        .await
        .map_err(map_moderation_submission_error)?;
    if submission.state != frameshift_catalog::PublicationSubmissionState::Promoted {
        require_moderation_role(&state, auth.account.id).await?;
        require_independent_reviewer(&state, auth.account.id, submission.publisher_id).await?;
    }
    promotion
        .promote(
            body.id,
            submission_id,
            auth.account.id,
            required_client_request_id(client_request_id)?,
        )
        .await
        .map(Json)
        .map_err(map_publication_promotion_error)
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

/// Require a valid request UUID that was present before tracing middleware ran.
///
/// The synthesized id [`tower_http::request_id::SetRequestIdLayer`] would
/// otherwise stamp onto a request with no client-supplied header must never
/// be treated as if the caller had provided it -- that would defeat
/// substituted-retry rejection for these idempotent mutations (F-10).
fn required_client_request_id(client_request_id: ClientRequestId) -> Result<Uuid, AppError> {
    client_request_id
        .0
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

/// Map promotion failures without exposing private archive or catalog details.
fn map_publication_promotion_error(error: PublicationPromotionError) -> AppError {
    match error {
        PublicationPromotionError::Catalog(error) => map_moderation_submission_error(error),
        PublicationPromotionError::NotApproved => {
            AppError::Conflict("publication submission is not approved".to_string())
        }
        PublicationPromotionError::Quarantine(_)
        | PublicationPromotionError::Integrity
        | PublicationPromotionError::Verification(_)
        | PublicationPromotionError::ReportMismatch => {
            AppError::BadGateway("publication quarantine artifact failed verification".to_string())
        }
        PublicationPromotionError::Manifest(field) => {
            AppError::BadRequest(format!("publication manifest {field} is invalid"))
        }
        PublicationPromotionError::PublicStore(_) => {
            AppError::ServiceUnavailable("public object storage is unavailable".to_string())
        }
    }
}
