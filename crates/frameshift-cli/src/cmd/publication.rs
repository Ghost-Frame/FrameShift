//! Human-reviewed Creator Studio publication commands.
//!
//! Review and submission bind one exact artifact before quarantine admission.
//! Owner lifecycle commands then expose withdrawal, immutable decision evidence,
//! and appeals without weakening the authenticated server boundary.

use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;
use frameshift_catalog::{
    MembershipState, ObjectHash, PublicationAppealCursor, PublicationLifecycleCursor, PublisherRole,
};
use frameshift_client::account::{self, AccountView};
use frameshift_client::identity::public_key_b64;
use frameshift_client::publication::{
    create_publication_intent, file_publication_appeal, get_publication_submission,
    list_publication_appeals, list_publication_decisions, prepare_publication, submit_publication,
    withdraw_publication_submission,
};
use frameshift_client::{
    Client, EnrolledPublisherKey, EnrolledPublisherKeyState, PublicationReviewBinding,
};
use frameshift_studio::{DraftReviewReport, Studio};
use secrecy::SecretString;
use uuid::Uuid;

use crate::cmd::keys::{resolve_access_token, with_key_passphrase};
use crate::util::{validate_server_url, CliError};

/// Arguments for the `publication` command group.
#[derive(Debug, Args)]
pub struct PublicationArgs {
    /// Publication operation to execute.
    #[command(subcommand)]
    pub command: PublicationCommand,
}

/// Supported Creator Studio publication operations.
#[derive(Debug, Subcommand)]
pub enum PublicationCommand {
    /// Display the exact artifact and publisher binding that submission must confirm.
    Review {
        /// Creator Studio draft identifier.
        #[arg(long)]
        draft: String,
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Account-owned publisher handle.
        #[arg(long)]
        publisher: String,
    },
    /// Confirm and submit one exact reviewed artifact to quarantine.
    Submit {
        /// Creator Studio draft identifier.
        #[arg(long)]
        draft: String,
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Account-owned publisher handle.
        #[arg(long)]
        publisher: String,
        /// Exact archive hash displayed by `publication review`.
        #[arg(long)]
        confirm_archive_hash: ObjectHash,
        /// Exact publisher UUID displayed by `publication review`.
        #[arg(long)]
        confirm_publisher_id: Uuid,
        /// Exact publisher-key UUID displayed by `publication review`.
        #[arg(long)]
        confirm_publisher_key_id: Uuid,
        /// Stable intent UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        intent_id: Option<Uuid>,
        /// Stable submission UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        submission_id: Option<Uuid>,
    },
    /// Retrieve the current state of one account-owned quarantined submission.
    Status {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Stable submission UUID returned by the submission command.
        #[arg(long)]
        submission_id: Uuid,
    },
    /// Withdraw one eligible account-owned submission before publication.
    Withdraw {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Stable submission UUID returned by the submission command.
        #[arg(long)]
        submission_id: Uuid,
        /// Stable 1-64 character private reason code.
        #[arg(long)]
        reason_code: String,
        /// Stable decision UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        decision_id: Option<Uuid>,
        /// Stable request UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    /// List immutable lifecycle decisions for one owned publisher profile.
    Decisions {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Account-owned publisher handle.
        #[arg(long)]
        publisher: String,
        /// RFC 3339 timestamp from the final record of the preceding page.
        #[arg(long, requires = "before_id")]
        before_created_at: Option<DateTime<Utc>>,
        /// UUID from the final record of the preceding page.
        #[arg(long, requires = "before_created_at")]
        before_id: Option<Uuid>,
        /// Number of newest-first records to return.
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
    },
    /// File one appeal against an adverse moderation decision.
    Appeal {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Account-owned publisher handle.
        #[arg(long)]
        publisher: String,
        /// Adverse moderation decision UUID.
        #[arg(long)]
        decision_id: Uuid,
        /// Private appeal statement of at most 4000 characters.
        #[arg(long)]
        statement: String,
        /// Stable appeal UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        appeal_id: Option<Uuid>,
        /// Stable request UUID to reuse after an ambiguous network failure.
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    /// List private appeal cases for one owned publisher profile.
    Appeals {
        /// Registry base URL.
        #[arg(long)]
        server: String,
        /// Account-owned publisher handle.
        #[arg(long)]
        publisher: String,
        /// RFC 3339 timestamp from the final record of the preceding page.
        #[arg(long, requires = "before_id")]
        before_created_at: Option<DateTime<Utc>>,
        /// UUID from the final record of the preceding page.
        #[arg(long, requires = "before_created_at")]
        before_id: Option<Uuid>,
        /// Number of newest-first appeal cases to return.
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
    },
}

/// One exact review report paired with the key that produced its artifact.
struct ResolvedPublication {
    /// Selected local signing key loaded through secure key storage.
    signing_key: SigningKey,
    /// Path-free manifest, inventory, artifact, publisher, and key review data.
    review: DraftReviewReport,
}

/// Execute one human-reviewed publication operation.
pub fn run_publication(args: PublicationArgs) -> Result<(), CliError> {
    match args.command {
        PublicationCommand::Review {
            draft,
            server,
            publisher,
        } => review(&draft, &server, &publisher),
        PublicationCommand::Submit {
            draft,
            server,
            publisher,
            confirm_archive_hash,
            confirm_publisher_id,
            confirm_publisher_key_id,
            intent_id,
            submission_id,
        } => submit(
            &draft,
            &server,
            &publisher,
            confirm_archive_hash,
            confirm_publisher_id,
            confirm_publisher_key_id,
            intent_id,
            submission_id,
        ),
        PublicationCommand::Status {
            server,
            submission_id,
        } => status(&server, submission_id),
        PublicationCommand::Withdraw {
            server,
            submission_id,
            reason_code,
            decision_id,
            request_id,
        } => withdraw(
            &server,
            submission_id,
            &reason_code,
            decision_id,
            request_id,
        ),
        PublicationCommand::Decisions {
            server,
            publisher,
            before_created_at,
            before_id,
            limit,
        } => decisions(
            &server,
            &publisher,
            publication_lifecycle_cursor(before_created_at, before_id)?,
            limit,
        ),
        PublicationCommand::Appeal {
            server,
            publisher,
            decision_id,
            statement,
            appeal_id,
            request_id,
        } => appeal(
            &server,
            &publisher,
            decision_id,
            &statement,
            appeal_id,
            request_id,
        ),
        PublicationCommand::Appeals {
            server,
            publisher,
            before_created_at,
            before_id,
            limit,
        } => appeals(
            &server,
            &publisher,
            publication_appeal_cursor(before_created_at, before_id)?,
            limit,
        ),
    }
}

/// Prepare and print one path-free final review report without recording approval.
fn review(draft: &str, server: &str, publisher: &str) -> Result<(), CliError> {
    validate_server_url(server)?;
    let client = Client::with_default_data_root()?;
    let token = resolve_access_token(server)?;
    let studio = open_studio(&client)?;
    let resolved = resolve_publication(&client, &studio, draft, server, publisher, &token)?;
    println!("{}", serde_json::to_string_pretty(&resolved.review)?);
    Ok(())
}

/// Confirm, persist, and submit one exact reviewed draft to quarantine.
#[allow(clippy::too_many_arguments)]
fn submit(
    draft: &str,
    server: &str,
    publisher: &str,
    confirm_archive_hash: ObjectHash,
    confirm_publisher_id: Uuid,
    confirm_publisher_key_id: Uuid,
    intent_id: Option<Uuid>,
    submission_id: Option<Uuid>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let client = Client::with_default_data_root()?;
    let token = resolve_access_token(server)?;
    let studio = open_studio(&client)?;
    let resolved = resolve_publication(&client, &studio, draft, server, publisher, &token)?;
    let binding = resolved.review.binding;
    confirm_binding(
        binding,
        confirm_archive_hash,
        confirm_publisher_id,
        confirm_publisher_key_id,
    )?;

    studio
        .confirm_review(draft, binding)
        .map_err(publication_draft_error)?;
    studio
        .confirm_submission_intent(draft, binding)
        .map_err(publication_draft_error)?;
    let snapshot = studio
        .snapshot_for_submission(draft, binding)
        .map_err(publication_draft_error)?;
    let prepared = prepare_publication(&snapshot, &resolved.signing_key)?;
    if prepared.binding() != binding.artifact {
        return Err(CliError::Publish(
            "publication draft changed after confirmation".to_string(),
        ));
    }

    let intent_id = intent_id.unwrap_or_else(Uuid::new_v4);
    let submission_id = submission_id.unwrap_or_else(Uuid::new_v4);
    create_publication_intent(server, &token, intent_id, binding, &prepared).map_err(|error| {
        retryable_transport_error(
            "publication intent creation",
            error,
            intent_id,
            submission_id,
        )
    })?;
    let submission = submit_publication(
        server,
        &token,
        &resolved.signing_key,
        submission_id,
        intent_id,
        &prepared,
    )
    .map_err(|error| {
        retryable_transport_error("publication submission", error, intent_id, submission_id)
    })?;
    println!("{}", serde_json::to_string_pretty(&submission)?);
    Ok(())
}

/// Print the account-scoped state of one quarantined submission.
fn status(server: &str, submission_id: Uuid) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let submission = get_publication_submission(server, &token, submission_id)?;
    println!("{}", serde_json::to_string_pretty(&submission)?);
    Ok(())
}

/// Withdraw one eligible non-public submission while preserving retry identifiers.
fn withdraw(
    server: &str,
    submission_id: Uuid,
    reason_code: &str,
    decision_id: Option<Uuid>,
    request_id: Option<Uuid>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let decision_id = decision_id.unwrap_or_else(Uuid::new_v4);
    let request_id = request_id.unwrap_or_else(Uuid::new_v4);
    let decision = withdraw_publication_submission(
        server,
        &token,
        submission_id,
        decision_id,
        request_id,
        reason_code,
    )
    .map_err(|error| {
        retryable_owner_mutation_error(
            "publication withdrawal",
            error,
            "decision-id",
            decision_id,
            request_id,
        )
    })?;
    println!("{}", serde_json::to_string_pretty(&decision)?);
    Ok(())
}

/// Print one bounded newest-first page of publisher lifecycle decisions.
fn decisions(
    server: &str,
    publisher: &str,
    before: Option<PublicationLifecycleCursor>,
    limit: u32,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let records = list_publication_decisions(server, &token, publisher, before, limit)
        .map_err(|error| publication_transport_error("publication decision listing", error))?;
    println!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}

/// File one appeal while preserving both retry identifiers in any failure.
fn appeal(
    server: &str,
    publisher: &str,
    decision_id: Uuid,
    statement: &str,
    appeal_id: Option<Uuid>,
    request_id: Option<Uuid>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let appeal_id = appeal_id.unwrap_or_else(Uuid::new_v4);
    let request_id = request_id.unwrap_or_else(Uuid::new_v4);
    let record = file_publication_appeal(
        server,
        &token,
        publisher,
        decision_id,
        appeal_id,
        request_id,
        statement,
    )
    .map_err(|error| {
        retryable_owner_mutation_error(
            "publication appeal",
            error,
            "appeal-id",
            appeal_id,
            request_id,
        )
    })?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

/// Print one bounded newest-first page of publisher appeal cases.
fn appeals(
    server: &str,
    publisher: &str,
    before: Option<PublicationAppealCursor>,
    limit: u32,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let records = list_publication_appeals(server, &token, publisher, before, limit)
        .map_err(|error| publication_transport_error("publication appeal listing", error))?;
    println!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}

/// Construct a lifecycle cursor after Clap has enforced the paired flags.
fn publication_lifecycle_cursor(
    created_at: Option<DateTime<Utc>>,
    id: Option<Uuid>,
) -> Result<Option<PublicationLifecycleCursor>, CliError> {
    match (created_at, id) {
        (None, None) => Ok(None),
        (Some(created_at), Some(id)) => Ok(Some(PublicationLifecycleCursor { created_at, id })),
        _ => Err(CliError::Publish(
            "--before-created-at and --before-id must be supplied together".to_string(),
        )),
    }
}

/// Construct an appeal cursor after Clap has enforced the paired flags.
fn publication_appeal_cursor(
    created_at: Option<DateTime<Utc>>,
    id: Option<Uuid>,
) -> Result<Option<PublicationAppealCursor>, CliError> {
    match (created_at, id) {
        (None, None) => Ok(None),
        (Some(created_at), Some(id)) => Ok(Some(PublicationAppealCursor { created_at, id })),
        _ => Err(CliError::Publish(
            "--before-created-at and --before-id must be supplied together".to_string(),
        )),
    }
}

/// Open the canonical Creator Studio draft store below the managed data root.
fn open_studio(client: &Client) -> Result<Studio, CliError> {
    Studio::open(client.data_root().join("studio").join("drafts")).map_err(publication_draft_error)
}

/// Recompute one exact artifact and resolve its authenticated publisher authority.
fn resolve_publication(
    client: &Client,
    studio: &Studio,
    draft: &str,
    server: &str,
    publisher: &str,
    token: &SecretString,
) -> Result<ResolvedPublication, CliError> {
    let draft_status = studio.status(draft).map_err(publication_draft_error)?;
    let snapshot = studio
        .snapshot_for_review(draft, &draft_status.publication.inventory_hash)
        .map_err(publication_draft_error)?;
    let (signing_key, _) =
        with_key_passphrase(|passphrase| client.author_signing_key_with_passphrase(passphrase))?;
    let prepared = prepare_publication(&snapshot, &signing_key)?;

    let account = account::get_account(server, token)?;
    let publisher_id = resolve_owned_publisher(&account, publisher)?;
    let keys = client.list_publisher_keys(server, publisher, token)?;
    let publisher_key_id =
        resolve_active_remote_key(&keys, &public_key_b64(&signing_key), publisher_id)?;
    let binding = PublicationReviewBinding {
        artifact: prepared.binding(),
        publisher_id,
        publisher_key_id,
    };
    let review = studio
        .review_report(draft, binding)
        .map_err(publication_draft_error)?;
    require_manifest_publisher(&review.manifest.author_handle, publisher)?;
    Ok(ResolvedPublication {
        signing_key,
        review,
    })
}

/// Require signed manifest attribution to match the selected account-owned publisher.
fn require_manifest_publisher(author_handle: &str, publisher: &str) -> Result<(), CliError> {
    if author_handle == publisher {
        return Ok(());
    }
    Err(CliError::Publish(format!(
        "draft author handle {author_handle} does not match selected publisher {publisher}"
    )))
}

/// Resolve one active owner membership and its aligned publisher profile.
fn resolve_owned_publisher(view: &AccountView, handle: &str) -> Result<Uuid, CliError> {
    let mut profiles = view
        .publishers
        .iter()
        .filter(|profile| profile.handle == handle);
    let profile = profiles.next().ok_or_else(|| {
        CliError::Publish(format!(
            "authenticated account does not own publisher {handle}"
        ))
    })?;
    if profiles.next().is_some() {
        return Err(CliError::Publish(format!(
            "registry returned duplicate publisher handle {handle}"
        )));
    }
    let owns_profile = view.memberships.iter().any(|membership| {
        membership.publisher_id == profile.id
            && membership.role == PublisherRole::Owner
            && membership.state == MembershipState::Active
    });
    if !owns_profile {
        return Err(CliError::Publish(format!(
            "authenticated account does not actively own publisher {handle}"
        )));
    }
    Ok(profile.id)
}

/// Resolve the unique active remote key matching the selected local public key.
fn resolve_active_remote_key(
    keys: &[EnrolledPublisherKey],
    public_key: &str,
    publisher_id: Uuid,
) -> Result<Uuid, CliError> {
    let mut found = None;
    for key in keys.iter().filter(|key| {
        key.public_key == public_key && key.state == EnrolledPublisherKeyState::Active
    }) {
        let remote_publisher_id = Uuid::parse_str(&key.publisher_id).map_err(|_| {
            CliError::Publish("registry returned an invalid publisher-key owner UUID".to_string())
        })?;
        if remote_publisher_id != publisher_id {
            return Err(CliError::Publish(
                "registry returned the selected key under a different publisher".to_string(),
            ));
        }
        let remote_key_id = Uuid::parse_str(&key.id).map_err(|_| {
            CliError::Publish("registry returned an invalid publisher-key UUID".to_string())
        })?;
        if found.replace(remote_key_id).is_some() {
            return Err(CliError::Publish(
                "multiple active enrolled keys match the selected local key".to_string(),
            ));
        }
    }
    found.ok_or_else(|| {
        CliError::Publish(
            "no active enrolled publisher key matches the selected local key".to_string(),
        )
    })
}

/// Require every explicit confirmation to match the freshly prepared binding.
fn confirm_binding(
    binding: PublicationReviewBinding,
    archive_hash: ObjectHash,
    publisher_id: Uuid,
    publisher_key_id: Uuid,
) -> Result<(), CliError> {
    if archive_hash != binding.artifact.archive_hash {
        return Err(CliError::Publish(
            "confirmed archive hash does not match the current reviewed artifact".to_string(),
        ));
    }
    if publisher_id != binding.publisher_id {
        return Err(CliError::Publish(
            "confirmed publisher UUID does not match the current publisher".to_string(),
        ));
    }
    if publisher_key_id != binding.publisher_key_id {
        return Err(CliError::Publish(
            "confirmed publisher-key UUID does not match the current signing key".to_string(),
        ));
    }
    Ok(())
}

/// Preserve idempotency identifiers in errors so ambiguous requests can be retried exactly.
fn retryable_transport_error(
    stage: &str,
    error: frameshift_client::ClientError,
    intent_id: Uuid,
    submission_id: Uuid,
) -> CliError {
    CliError::Publish(format!(
        "{stage} failed: {error}; retry with --intent-id {intent_id} --submission-id {submission_id}"
    ))
}

/// Preserve owner-mutation idempotency identifiers in an actionable retry command.
fn retryable_owner_mutation_error(
    stage: &str,
    error: frameshift_client::ClientError,
    operation_id_flag: &str,
    operation_id: Uuid,
    request_id: Uuid,
) -> CliError {
    CliError::Publish(format!(
        "{stage} failed: {error}; retry with --{operation_id_flag} {operation_id} --request-id {request_id}"
    ))
}

/// Wrap one read-only publication transport failure with its failed operation.
fn publication_transport_error(stage: &str, error: frameshift_client::ClientError) -> CliError {
    CliError::Publish(format!("{stage} failed: {error}"))
}

/// Map Creator Studio failures into the publication command's public error surface.
fn publication_draft_error(error: frameshift_studio::StudioError) -> CliError {
    CliError::Publish(format!("publication draft error: {error}"))
}

#[cfg(test)]
/// Publication command policy regression tests.
mod tests {
    use super::*;

    /// Build an authenticated owner view from its public wire representation.
    fn owner_view() -> AccountView {
        serde_json::from_value(serde_json::json!({
            "account": {
                "id": "00000000-0000-0000-0000-000000000001",
                "issuer": "https://issuer.example",
                "subject": "subject-1",
                "email": null,
                "display_name": "Alice",
                "status": "active",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            },
            "memberships": [{
                "account_id": "00000000-0000-0000-0000-000000000001",
                "publisher_id": "00000000-0000-0000-0000-000000000002",
                "role": "owner",
                "state": "active",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            }],
            "publishers": [{
                "id": "00000000-0000-0000-0000-000000000002",
                "handle": "alice",
                "display_name": "Alice",
                "biography": null,
                "moderation_status": "pending",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            }]
        }))
        .expect("valid account fixture")
    }

    /// Build one exact review binding with stable test identifiers.
    fn review_binding() -> PublicationReviewBinding {
        PublicationReviewBinding {
            artifact: frameshift_client::PublicationBinding {
                archive_hash: ObjectHash::from_bytes([1_u8; 32]),
                manifest_hash: ObjectHash::from_bytes([2_u8; 32]),
                file_inventory_hash: ObjectHash::from_bytes([3_u8; 32]),
                scan_schema_version: 1,
            },
            publisher_id: Uuid::from_u128(2),
            publisher_key_id: Uuid::from_u128(3),
        }
    }

    /// Publisher resolution requires an exact handle and active owner membership.
    #[test]
    fn resolves_only_active_owned_publisher() {
        let view = owner_view();
        assert_eq!(
            resolve_owned_publisher(&view, "alice").unwrap(),
            Uuid::from_u128(2)
        );
        assert!(resolve_owned_publisher(&view, "mallory").is_err());

        let mut revoked = view;
        revoked.memberships[0].state = MembershipState::Revoked;
        assert!(resolve_owned_publisher(&revoked, "alice").is_err());
    }

    /// Remote-key resolution binds the selected public key to the same publisher UUID.
    #[test]
    fn resolves_only_matching_active_remote_key() {
        let keys = vec![EnrolledPublisherKey {
            id: Uuid::from_u128(3).to_string(),
            publisher_id: Uuid::from_u128(2).to_string(),
            public_key: "selected-public-key".to_string(),
            label: "laptop".to_string(),
            state: EnrolledPublisherKeyState::Active,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            revoked_at: None,
            last_used_at: None,
        }];
        assert_eq!(
            resolve_active_remote_key(&keys, "selected-public-key", Uuid::from_u128(2)).unwrap(),
            Uuid::from_u128(3)
        );
        assert!(resolve_active_remote_key(&keys, "another-key", Uuid::from_u128(2)).is_err());
        assert!(
            resolve_active_remote_key(&keys, "selected-public-key", Uuid::from_u128(4)).is_err()
        );
    }

    /// Confirmation succeeds only when all three human-reviewed identifiers match.
    #[test]
    fn confirmation_rejects_each_substitution() {
        let binding = review_binding();
        assert!(confirm_binding(
            binding,
            binding.artifact.archive_hash,
            binding.publisher_id,
            binding.publisher_key_id
        )
        .is_ok());
        assert!(confirm_binding(
            binding,
            ObjectHash::from_bytes([9_u8; 32]),
            binding.publisher_id,
            binding.publisher_key_id
        )
        .is_err());
        assert!(confirm_binding(
            binding,
            binding.artifact.archive_hash,
            Uuid::from_u128(9),
            binding.publisher_key_id
        )
        .is_err());
        assert!(confirm_binding(
            binding,
            binding.artifact.archive_hash,
            binding.publisher_id,
            Uuid::from_u128(9)
        )
        .is_err());
    }

    /// Signed manifest attribution cannot name a publisher other than the selected owner profile.
    #[test]
    fn manifest_handle_must_match_selected_publisher() {
        assert!(require_manifest_publisher("alice", "alice").is_ok());
        assert!(require_manifest_publisher("mallory", "alice").is_err());
    }

    /// Owner mutation failures retain both UUID flags required for an exact retry.
    #[test]
    fn owner_mutation_error_preserves_retry_ids() {
        let operation_id = Uuid::from_u128(20);
        let request_id = Uuid::from_u128(21);
        let error = retryable_owner_mutation_error(
            "publication appeal",
            frameshift_client::ClientError::RegistryHttp {
                url: "https://registry.example".to_string(),
                detail: "connection closed".to_string(),
            },
            "appeal-id",
            operation_id,
            request_id,
        );
        let message = error.to_string();
        assert!(message.contains(&format!("--appeal-id {operation_id}")));
        assert!(message.contains(&format!("--request-id {request_id}")));
    }

    /// Programmatic callers cannot construct a partial keyset cursor.
    #[test]
    fn cursor_construction_rejects_partial_components() {
        assert!(publication_lifecycle_cursor(None, Some(Uuid::from_u128(1))).is_err());
        assert!(publication_appeal_cursor(None, Some(Uuid::from_u128(1))).is_err());
    }
}
