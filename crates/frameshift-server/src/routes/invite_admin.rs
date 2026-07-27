//! Administrator invite-application review and one-time invitation issuance.

use axum::extract::{Path, Query, State};
use axum::routing::{get, patch, post};
use axum::{Extension, Json, Router};
use chrono::{Duration, Utc};
use frameshift_catalog::{
    AccountInviteIssueRequest, AccountInviteRecord, AccountInviteRequestRecord,
    AccountInviteReviewRequest, AccountInviteStatus,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::middleware::account::AuthenticatedAccount;
use crate::routes::local_auth::generate_token;
use crate::state::AppState;

/// Administrator queue query with optional status filtering.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteQueueQuery {
    /// Optional review state filter.
    pub status: Option<AccountInviteStatus>,
    /// Bounded result count.
    pub limit: Option<u32>,
}

/// Administrator-requested non-issued review state.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewInviteRequest {
    /// New pending, reviewing, or declined state.
    pub status: AccountInviteStatus,
}

/// One-time invitation response shown only to the issuing administrator.
#[derive(Debug, Serialize)]
pub struct IssuedInviteResponse {
    /// Durable invitation metadata.
    pub invite: AccountInviteRecord,
    /// Raw invitation token returned once and never persisted.
    pub token: String,
}

/// Build administrator invite review and issuance routes.
pub fn invite_admin_router() -> Router<AppState> {
    Router::new()
        .route("/invite-requests", get(list_invite_requests))
        .route(
            "/invite-requests/{request_id}",
            patch(review_invite_request),
        )
        .route("/invite-requests/{request_id}/invite", post(issue_invite))
}

/// List invite applications after backend administrator authorization.
async fn list_invite_requests(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Query(query): Query<InviteQueueQuery>,
) -> Result<Json<Vec<AccountInviteRequestRecord>>, AppError> {
    state
        .catalog
        .list_account_invite_requests(auth.account.id, query.status, query.limit.unwrap_or(50))
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "account invite request"))
}

/// Transition one application between non-issued review states.
async fn review_invite_request(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(request_id): Path<Uuid>,
    Json(request): Json<ReviewInviteRequest>,
) -> Result<Json<AccountInviteRequestRecord>, AppError> {
    state
        .catalog
        .review_account_invite_request(AccountInviteReviewRequest {
            request_id,
            status: request.status,
            actor_account_id: auth.account.id,
        })
        .await
        .map(Json)
        .map_err(|error| AppError::from_catalog(error, "account invite request"))
}

/// Generate and issue one invitation whose raw token is returned exactly once.
async fn issue_invite(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(request_id): Path<Uuid>,
) -> Result<Json<IssuedInviteResponse>, AppError> {
    let (token, token_digest) = generate_token();
    let created_at = Utc::now();
    let ttl = Duration::from_std(state.config.first_party_auth.invite_ttl)
        .map_err(|_| AppError::Internal("invite duration is invalid".to_string()))?;
    let invite = state
        .catalog
        .issue_account_invite(AccountInviteIssueRequest {
            id: Uuid::new_v4(),
            request_id,
            token_digest,
            actor_account_id: auth.account.id,
            expires_at: created_at + ttl,
            created_at,
        })
        .await
        .map_err(|error| AppError::from_catalog(error, "account invite"))?;
    Ok(Json(IssuedInviteResponse { invite, token }))
}
