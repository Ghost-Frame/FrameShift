//! Public application intake for invite-only first-party account registration.

use std::sync::LazyLock;

use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use frameshift_catalog::{AccountInviteIntent, AccountInviteRequestRecord, AccountInviteStatus};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::state::AppState;

/// Turnstile action bound to the invite application widget and verifier.
const TURNSTILE_ACTION: &str = "invite_request";
/// Maximum normalized email byte length accepted by the account schema.
const MAX_EMAIL_BYTES: usize = 320;
/// Maximum optional applicant display-name length.
const MAX_DISPLAY_NAME_CHARS: usize = 100;
/// Minimum application statement length needed for useful review.
const MIN_STATEMENT_CHARS: usize = 40;
/// Maximum application statement length accepted by the intake.
const MAX_STATEMENT_CHARS: usize = 2_000;
/// Maximum Cloudflare Turnstile token length.
const MAX_TURNSTILE_TOKEN_CHARS: usize = 2_048;
/// Tight request body limit for the small invite application schema.
const MAX_INVITE_REQUEST_BYTES: usize = 16 * 1024;

/// Shared outbound client for bounded Turnstile verification requests.
static TURNSTILE_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("static Turnstile client configuration is valid")
});

/// Browser-submitted fields for one invite application.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInviteRequest {
    /// Applicant email used for future invite contact.
    pub email: String,
    /// Optional applicant display name.
    pub display_name: Option<String>,
    /// Applicant-selected reason for requesting an invite.
    pub intent: AccountInviteIntent,
    /// Bounded private statement supplied to reviewers.
    pub statement: String,
    /// Explicit consent to store the application and contact the applicant.
    pub consent: bool,
    /// Single-use Turnstile token issued for this form action.
    pub turnstile_token: String,
    /// Hidden bot-trap field that must remain blank.
    #[serde(default)]
    pub website: String,
}

/// Non-secret capability metadata for the invite application form.
#[derive(Debug, Serialize)]
pub struct InviteRequestConfigResponse {
    /// Stable registration policy exposed to every client.
    pub registration: &'static str,
    /// Whether the backend can currently accept protected applications.
    pub invite_requests_enabled: bool,
    /// Public Turnstile site key when intake is enabled.
    pub turnstile_site_key: Option<String>,
}

/// Generic response shared by new, duplicate, and bot-trap submissions.
#[derive(Debug, Serialize)]
pub struct InviteRequestAcceptedResponse {
    /// Enumeration-resistant acknowledgement shown by the marketplace.
    pub message: &'static str,
}

/// Turnstile Siteverify input sent only to Cloudflare.
#[derive(Debug, Serialize)]
struct TurnstileVerifyRequest<'a> {
    /// Secret verifier key.
    secret: &'a str,
    /// Single-use browser token.
    response: &'a str,
}

/// Fields required from a successful Turnstile Siteverify response.
#[derive(Debug, Deserialize)]
struct TurnstileVerifyResponse {
    /// Whether Cloudflare accepted the supplied token.
    success: bool,
    /// Hostname on which the widget solved the challenge.
    hostname: Option<String>,
    /// Widget action bound into the issued token.
    action: Option<String>,
}

/// Build the public invite application routes.
pub fn invite_request_router() -> Router<AppState> {
    Router::new()
        .route(
            "/account-invite-requests",
            get(get_invite_request_config).post(create_invite_request),
        )
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_INVITE_REQUEST_BYTES,
        ))
}

/// Return invite-only registration policy and public widget configuration.
async fn get_invite_request_config(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<InviteRequestConfigResponse> {
    let enabled = state.config.invite_requests.enabled();
    Json(InviteRequestConfigResponse {
        registration: "invite_only",
        invite_requests_enabled: enabled,
        turnstile_site_key: enabled
            .then(|| state.config.invite_requests.turnstile_site_key.clone()),
    })
}

/// Validate, verify, and durably store one invite application.
async fn create_invite_request(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(request): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<InviteRequestAcceptedResponse>), AppError> {
    if !request.website.trim().is_empty() {
        return Ok(accepted_response());
    }

    let normalized_email = normalize_email(&request.email)?;
    let display_name = normalize_optional_display_name(request.display_name)?;
    let statement = normalize_statement(&request.statement)?;
    if !request.consent {
        return Err(AppError::BadRequest(
            "application consent is required".to_string(),
        ));
    }
    validate_turnstile_token(&request.turnstile_token)?;
    verify_turnstile(&state, &request.turnstile_token).await?;

    let now = Utc::now();
    state
        .catalog
        .create_account_invite_request(AccountInviteRequestRecord {
            id: Uuid::new_v4(),
            normalized_email,
            display_name,
            intent: request.intent,
            statement,
            status: AccountInviteStatus::Pending,
            consented_at: now,
            created_at: now,
            updated_at: now,
        })
        .await
        .map_err(|error| AppError::from_catalog(error, "account invite request"))?;

    Ok(accepted_response())
}

/// Build the enumeration-resistant accepted response.
fn accepted_response() -> (StatusCode, Json<InviteRequestAcceptedResponse>) {
    (
        StatusCode::ACCEPTED,
        Json(InviteRequestAcceptedResponse {
            message: "Application received. We will email you if an invite becomes available.",
        }),
    )
}

/// Normalize and minimally validate one applicant email.
fn normalize_email(raw: &str) -> Result<String, AppError> {
    let normalized = raw.trim().to_lowercase();
    let valid_length = !normalized.is_empty() && normalized.len() <= MAX_EMAIL_BYTES;
    let valid_shape = normalized.matches('@').count() == 1
        && normalized
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty());
    let safe_chars =
        !normalized.chars().any(char::is_whitespace) && !normalized.chars().any(char::is_control);
    if !valid_length || !valid_shape || !safe_chars {
        return Err(AppError::BadRequest(
            "a valid email address is required".to_string(),
        ));
    }
    Ok(normalized)
}

/// Trim and bound an optional applicant display name.
fn normalize_optional_display_name(raw: Option<String>) -> Result<Option<String>, AppError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let normalized = raw.trim().to_string();
    if normalized.is_empty() {
        return Ok(None);
    }
    if normalized.chars().count() > MAX_DISPLAY_NAME_CHARS
        || normalized.chars().any(char::is_control)
    {
        return Err(AppError::BadRequest(
            "display name is too long or contains invalid characters".to_string(),
        ));
    }
    Ok(Some(normalized))
}

/// Trim and bound the private application statement.
fn normalize_statement(raw: &str) -> Result<String, AppError> {
    let normalized = raw.trim().to_string();
    let length = normalized.chars().count();
    if !(MIN_STATEMENT_CHARS..=MAX_STATEMENT_CHARS).contains(&length)
        || normalized.chars().any(char::is_control)
    {
        return Err(AppError::BadRequest(format!(
            "statement must be between {MIN_STATEMENT_CHARS} and {MAX_STATEMENT_CHARS} characters"
        )));
    }
    Ok(normalized)
}

/// Reject empty or oversized Turnstile tokens before any outbound request.
fn validate_turnstile_token(token: &str) -> Result<(), AppError> {
    let length = token.chars().count();
    if length == 0 || length > MAX_TURNSTILE_TOKEN_CHARS {
        return Err(AppError::BadRequest(
            "anti-bot verification is required".to_string(),
        ));
    }
    Ok(())
}

/// Verify the single-use anti-bot token and bind it to this form and hostname.
async fn verify_turnstile(state: &AppState, token: &str) -> Result<(), AppError> {
    let config = &state.config.invite_requests;
    if !config.enabled() {
        return Err(AppError::ServiceUnavailable(
            "invite application verification is not configured".to_string(),
        ));
    }

    let response = TURNSTILE_CLIENT
        .post(&config.verify_url)
        .json(&TurnstileVerifyRequest {
            secret: config.turnstile_secret.expose_secret(),
            response: token,
        })
        .send()
        .await
        .map_err(|error| {
            AppError::ServiceUnavailable(format!("Turnstile request failed: {error}"))
        })?;
    if !response.status().is_success() {
        return Err(AppError::ServiceUnavailable(format!(
            "Turnstile returned HTTP {}",
            response.status()
        )));
    }
    let verification = response
        .json::<TurnstileVerifyResponse>()
        .await
        .map_err(|error| {
            AppError::ServiceUnavailable(format!("Turnstile response was invalid: {error}"))
        })?;
    let hostname_matches =
        verification.hostname.as_deref() == Some(config.expected_hostname.as_str());
    let action_matches = verification.action.as_deref() == Some(TURNSTILE_ACTION);
    if !verification.success || !hostname_matches || !action_matches {
        return Err(AppError::Forbidden(
            "invite application anti-bot verification failed".to_string(),
        ));
    }
    Ok(())
}
