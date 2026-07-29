//! Account-authenticated administrator publication lifecycle endpoints.

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, patch, post};
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use frameshift_catalog::{
    AccountRecord, AccountStatus, AccountStatusChangeRequest, PlatformRole,
    PlatformRoleAssignmentRequest, PlatformRoleRecord, PlatformRoleRevocationRequest,
    PublicationAppealCaseRecord, PublicationAppealCursor, PublicationAppealDisposition,
    PublicationAppealResolutionRecord, PublicationAppealResolutionRequest,
    PublicationLifecycleCursor, PublicationLifecycleDecisionRecord, PublicationTombstoneRequest,
    PublisherSuspensionRequest, TombstoneReason,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::middleware::account::AuthenticatedAccount;
use crate::middleware::request_id::ClientRequestId;
use crate::routes::packs::{validate_pack_name, validate_pack_version};
use crate::state::AppState;

/// Build account-authenticated administrator lifecycle routes.
pub fn admin_router() -> Router<AppState> {
    Router::new()
        .route(
            "/packs/{name}/{version}/tombstone",
            post(tombstone_pack_route),
        )
        .route(
            "/publishers/{publisher_id}/suspend",
            post(suspend_publisher_route),
        )
        .route(
            "/publication-decisions",
            get(list_publication_decisions_route),
        )
        .route("/publication-appeals", get(list_publication_appeals_route))
        .route(
            "/publication-appeals/{appeal_id}/resolution",
            post(resolve_publication_appeal_route),
        )
        .route(
            "/accounts/{account_id}/platform-roles",
            post(assign_platform_role_route),
        )
        .route(
            "/accounts/{account_id}/platform-roles/{role}",
            delete(revoke_platform_role_route),
        )
        .route(
            "/accounts/{account_id}/status",
            patch(set_account_status_route),
        )
}

/// Caller-controlled fields for one administrator release tombstone.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TombstoneRequestBody {
    /// Stable caller-generated lifecycle decision identifier.
    id: Uuid,
    /// Bounded public tombstone reason.
    reason: TombstoneReason,
}

/// Caller-controlled fields for one administrator publisher suspension.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuspendPublisherRequestBody {
    /// Stable caller-generated lifecycle decision identifier.
    id: Uuid,
    /// Stable bounded private reason code.
    reason_code: String,
}

/// Query parameters for deterministic lifecycle audit pagination.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationDecisionQuery {
    /// Timestamp component of the exclusive keyset cursor.
    before_created_at: Option<DateTime<Utc>>,
    /// Identifier component of the exclusive keyset cursor.
    before_id: Option<Uuid>,
    /// Bounded result count, defaulting to fifty.
    limit: Option<u32>,
}

/// Caller-controlled field for one administrator platform-role grant.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignPlatformRoleRequestBody {
    /// Global authority being granted to the target account.
    role: PlatformRole,
}

/// Caller-controlled field for one administrator account status transition.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetAccountStatusRequestBody {
    /// Status the target account must hold after the transition.
    status: AccountStatus,
}

/// Caller-controlled fields for one administrator appeal resolution.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvePublicationAppealRequestBody {
    /// Stable caller-generated resolution identifier.
    id: Uuid,
    /// Final appeal disposition.
    disposition: PublicationAppealDisposition,
    /// Bounded private rationale for the disposition.
    rationale: String,
    /// Required reason only for unavoidable sole-administrator self-resolution.
    separation_exception_reason: Option<String>,
}

/// Tombstone one active release under atomic account administrator authority.
async fn tombstone_pack_route(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Extension(client_request_id): Extension<ClientRequestId>,
    Path((name, version)): Path<(String, String)>,
    Json(body): Json<TombstoneRequestBody>,
) -> Result<Json<PublicationLifecycleDecisionRecord>, AppError> {
    validate_pack_name(&name)?;
    validate_pack_version(&version)?;
    state
        .catalog
        .tombstone_publication_release(PublicationTombstoneRequest {
            id: body.id,
            pack_name: name,
            version,
            actor_account_id: auth.account.id,
            reason: body.reason,
            request_id: required_client_request_id(client_request_id)?,
        })
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "publication tombstone"))
}

/// Suspend one publisher under atomic account administrator authority.
async fn suspend_publisher_route(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Extension(client_request_id): Extension<ClientRequestId>,
    Path(publisher_id): Path<Uuid>,
    Json(body): Json<SuspendPublisherRequestBody>,
) -> Result<Json<PublicationLifecycleDecisionRecord>, AppError> {
    state
        .catalog
        .suspend_publisher(PublisherSuspensionRequest {
            id: body.id,
            publisher_id,
            actor_account_id: auth.account.id,
            reason_code: body.reason_code,
            request_id: required_client_request_id(client_request_id)?,
        })
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "publisher suspension"))
}

/// List global immutable lifecycle evidence for an active administrator.
async fn list_publication_decisions_route(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Query(query): Query<PublicationDecisionQuery>,
) -> Result<Json<Vec<PublicationLifecycleDecisionRecord>>, AppError> {
    state
        .catalog
        .list_administrator_lifecycle_decisions(
            auth.account.id,
            lifecycle_cursor(query.before_created_at, query.before_id)?,
            query.limit.unwrap_or(50),
        )
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "publication lifecycle audit"))
}

/// Resolve one appeal under atomic administrator and separation enforcement.
async fn resolve_publication_appeal_route(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Extension(client_request_id): Extension<ClientRequestId>,
    Path(appeal_id): Path<Uuid>,
    Json(body): Json<ResolvePublicationAppealRequestBody>,
) -> Result<Json<PublicationAppealResolutionRecord>, AppError> {
    state
        .catalog
        .resolve_publication_appeal(PublicationAppealResolutionRequest {
            id: body.id,
            appeal_id,
            actor_account_id: auth.account.id,
            disposition: body.disposition,
            rationale: body.rationale,
            separation_exception_reason: body.separation_exception_reason,
            request_id: required_client_request_id(client_request_id)?,
        })
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "publication appeal resolution"))
}

/// Grant one platform role under atomic account administrator authority.
///
/// The catalog verifies the actor's active administrator authority before it
/// looks at the target account, so an unauthorized caller receives the same
/// fixed `403` whether or not the target exists.
async fn assign_platform_role_route(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(account_id): Path<Uuid>,
    Json(body): Json<AssignPlatformRoleRequestBody>,
) -> Result<Json<PlatformRoleRecord>, AppError> {
    state
        .catalog
        .assign_account_platform_role(PlatformRoleAssignmentRequest {
            account_id,
            role: body.role,
            actor_account_id: auth.account.id,
        })
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "platform role"))
}

/// Revoke one platform role under atomic account administrator authority.
///
/// The assignment is retained in the revoked state, and revoking the last
/// active administrator is rejected.
async fn revoke_platform_role_route(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path((account_id, role)): Path<(Uuid, PlatformRole)>,
) -> Result<Json<PlatformRoleRecord>, AppError> {
    state
        .catalog
        .revoke_account_platform_role(PlatformRoleRevocationRequest {
            account_id,
            role,
            actor_account_id: auth.account.id,
        })
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "platform role"))
}

/// Transition one account's status under atomic account administrator authority.
///
/// Suspending or disabling an account takes effect on that account's next
/// request, because the account middleware rejects any non-active account.
async fn set_account_status_route(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(account_id): Path<Uuid>,
    Json(body): Json<SetAccountStatusRequestBody>,
) -> Result<Json<AccountRecord>, AppError> {
    state
        .catalog
        .set_account_status(AccountStatusChangeRequest {
            account_id,
            status: body.status,
            actor_account_id: auth.account.id,
        })
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "account status"))
}

/// List global private appeal cases for an active administrator.
async fn list_publication_appeals_route(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Query(query): Query<PublicationDecisionQuery>,
) -> Result<Json<Vec<PublicationAppealCaseRecord>>, AppError> {
    let before = match (query.before_created_at, query.before_id) {
        (None, None) => None,
        (Some(created_at), Some(id)) => Some(PublicationAppealCursor { created_at, id }),
        _ => {
            return Err(AppError::BadRequest(
                "before_created_at and before_id must be supplied together".to_string(),
            ));
        }
    };
    state
        .catalog
        .list_administrator_publication_appeals(auth.account.id, before, query.limit.unwrap_or(50))
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "publication appeal"))
}

/// Require both components of a keyset cursor or neither component.
fn lifecycle_cursor(
    created_at: Option<DateTime<Utc>>,
    id: Option<Uuid>,
) -> Result<Option<PublicationLifecycleCursor>, AppError> {
    match (created_at, id) {
        (None, None) => Ok(None),
        (Some(created_at), Some(id)) => Ok(Some(PublicationLifecycleCursor { created_at, id })),
        _ => Err(AppError::BadRequest(
            "before_created_at and before_id must be supplied together".to_string(),
        )),
    }
}

/// Require a valid request UUID that was present before tracing middleware ran.
fn required_client_request_id(client_request_id: ClientRequestId) -> Result<Uuid, AppError> {
    client_request_id
        .0
        .ok_or_else(|| AppError::BadRequest("x-request-id must be a UUID".to_string()))
}
