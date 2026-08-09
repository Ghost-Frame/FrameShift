//! Diesel table! macro declarations for the frameshift catalog schema.
//!
//! Column names and types here MUST match the complete ordered migration
//! history under `migrations/`.
//!
//! # Type mapping
//!
//! | Postgres type | Diesel type | Rust type |
//! |---|---|---|
//! | `BYTEA` | `diesel::sql_types::Binary` | `Vec<u8>` |
//! | `TEXT` | `diesel::sql_types::Text` | `String` |
//! | `TEXT[]` | `diesel::sql_types::Array<Text>` | `Vec<String>` |
//! | `JSONB` | `diesel::sql_types::Jsonb` | `serde_json::Value` |
//! | `TIMESTAMPTZ` | `diesel::sql_types::Timestamptz` | `DateTime<Utc>` |
//! | `BIGINT` | `diesel::sql_types::BigInt` | `i64` |
//! | `INTEGER` | `diesel::sql_types::Integer` | `i32` |
//! | `SMALLINT` | `diesel::sql_types::SmallInt` | `i16` |
//! | `UUID` | `diesel::sql_types::Uuid` | `uuid::Uuid` |

// Diesel's table! macro generates dead_code for columns not referenced in
// every query file; suppress the lint workspace-wide to keep CI green.
#![allow(dead_code)]

diesel::table! {
    /// OIDC-backed FrameShift accounts keyed by an internal UUID.
    accounts (id) {
        /// Internal stable account identifier.
        id -> Uuid,
        /// Canonical OIDC issuer URL.
        issuer -> Text,
        /// Issuer-scoped OIDC subject.
        subject -> Text,
        /// Optional profile email.
        email -> Nullable<Text>,
        /// Optional account display name.
        display_name -> Nullable<Text>,
        /// Account lifecycle state.
        status -> Text,
        /// Account creation timestamp.
        created_at -> Timestamptz,
        /// Most recent account update timestamp.
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    /// Optional first-party password credentials linked to stable accounts.
    account_password_credentials (account_id) {
        /// Account authenticated by the credential.
        account_id -> Uuid,
        /// Normalized unique email used for first-party sign-in.
        normalized_email -> Text,
        /// Argon2id PHC string containing the salt and cost parameters.
        password_hash -> Text,
        /// Application password-record schema version.
        password_version -> SmallInt,
        /// External credential-broker pepper version.
        pepper_version -> SmallInt,
        /// Successful email-verification timestamp.
        email_verified_at -> Nullable<Timestamptz>,
        /// Credential creation timestamp.
        created_at -> Timestamptz,
        /// Most recent password-change timestamp.
        password_changed_at -> Timestamptz,
        /// Most recent credential-record update timestamp.
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    /// Revocable sessions storing only SHA-256 digests of opaque tokens.
    account_sessions (id) {
        /// Stable session identifier.
        id -> Uuid,
        /// Account authenticated by the session.
        account_id -> Uuid,
        /// SHA-256 digest of the random session token.
        token_digest -> Binary,
        /// Client class receiving the session.
        client_kind -> Text,
        /// Session creation timestamp.
        created_at -> Timestamptz,
        /// Most recent authenticated-use timestamp.
        last_seen_at -> Timestamptz,
        /// Exclusive expiry of the current short-lived access token.
        access_expires_at -> Timestamptz,
        /// Sliding inactivity expiry timestamp.
        idle_expires_at -> Timestamptz,
        /// Non-extendable session expiry timestamp.
        absolute_expires_at -> Timestamptz,
        /// Most recent second-factor verification inherited by the session.
        mfa_verified_at -> Nullable<Timestamptz>,
        /// Explicit revocation timestamp.
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    /// Append-only refresh-token generations for revocable session families.
    account_session_refresh_tokens (id) {
        /// Stable refresh-generation identifier.
        id -> Uuid,
        /// Session family owning this generation.
        session_id -> Uuid,
        /// Monotonically increasing family generation.
        generation -> BigInt,
        /// SHA-256 digest of the random refresh token.
        token_digest -> Binary,
        /// Refresh-token creation timestamp.
        created_at -> Timestamptz,
        /// Exclusive refresh-token expiry timestamp.
        expires_at -> Timestamptz,
        /// Successful consumption or replay-observation timestamp.
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    /// Encrypted TOTP authenticator metadata and replay fence.
    account_mfa_authenticators (id) {
        /// Stable authenticator identifier.
        id -> Uuid,
        /// Account owning this authenticator.
        account_id -> Uuid,
        /// Pending, active, or disabled lifecycle state.
        state -> Text,
        /// Opaque authenticated ciphertext containing the TOTP seed.
        secret_ciphertext -> Binary,
        /// Random 192-bit XChaCha20-Poly1305 nonce.
        secret_nonce -> Binary,
        /// Deployment-managed encryption-key version.
        secret_key_version -> SmallInt,
        /// Exclusive deadline for confirming a pending enrollment.
        pending_expires_at -> Nullable<Timestamptz>,
        /// Greatest successfully consumed TOTP timestep.
        last_used_timestep -> Nullable<BigInt>,
        /// Authenticator metadata creation timestamp.
        created_at -> Timestamptz,
        /// Successful enrollment activation timestamp.
        activated_at -> Nullable<Timestamptz>,
        /// Authenticator disable timestamp.
        disabled_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    /// Digest-only high-entropy recovery codes bound to one authenticator.
    account_mfa_recovery_codes (id) {
        /// Stable recovery-code identifier.
        id -> Uuid,
        /// Authenticator that issued the recovery code.
        authenticator_id -> Uuid,
        /// SHA-256 digest of the random recovery code.
        code_digest -> Binary,
        /// Recovery-code creation timestamp.
        created_at -> Timestamptz,
        /// Successful one-time consumption timestamp.
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    /// Digest-only password-bound challenges for MFA login completion.
    account_mfa_login_challenges (id) {
        /// Stable challenge identifier.
        id -> Uuid,
        /// Account that passed the first factor.
        account_id -> Uuid,
        /// SHA-256 digest of the random challenge token.
        token_digest -> Binary,
        /// Browser, desktop, or CLI client binding.
        client_kind -> Text,
        /// Challenge creation timestamp.
        created_at -> Timestamptz,
        /// Exclusive challenge-completion deadline.
        expires_at -> Timestamptz,
        /// Successful one-time completion timestamp.
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    /// Digest-only authorization codes bound to native S256 requests.
    account_native_authorization_codes (id) {
        /// Stable authorization-code identifier.
        id -> Uuid,
        /// Browser-authenticated account authorizing the native client.
        account_id -> Uuid,
        /// SHA-256 digest of the random authorization code.
        token_digest -> Binary,
        /// Desktop or CLI client binding.
        client_kind -> Text,
        /// Exact IP-literal loopback redirect URI string.
        redirect_uri -> Text,
        /// Decoded 32-byte S256 PKCE challenge.
        pkce_challenge -> Binary,
        /// MFA assurance inherited from the browser session.
        mfa_verified_at -> Nullable<Timestamptz>,
        /// Authorization-code creation timestamp.
        created_at -> Timestamptz,
        /// Exclusive authorization-code exchange deadline.
        expires_at -> Timestamptz,
        /// Successful one-time exchange timestamp.
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    /// Append-only sanitized first-party authentication audit events.
    account_auth_audit_events (id) {
        /// Stable event identifier.
        id -> Uuid,
        /// Stable authentication event class.
        event_kind -> Text,
        /// Stable success or rejection outcome.
        outcome -> Text,
        /// Optional affected account identifier.
        account_id -> Nullable<Uuid>,
        /// Optional affected session-family identifier.
        session_id -> Nullable<Uuid>,
        /// Optional browser, desktop, or CLI client class.
        client_kind -> Nullable<Text>,
        /// Optional keyed canonical-identifier digest.
        identifier_tag -> Nullable<Binary>,
        /// Optional keyed canonical-network digest.
        network_tag -> Nullable<Binary>,
        /// Optional bounded static reason code.
        reason_code -> Nullable<Text>,
        /// Event creation timestamp.
        created_at -> Timestamptz,
    }
}

diesel::table! {
    /// Single-use password-reset capabilities stored only as SHA-256 digests.
    account_password_recovery_tokens (id) {
        /// Stable internal recovery-token identifier.
        id -> Uuid,
        /// Local account authorized by the token.
        account_id -> Uuid,
        /// SHA-256 digest of the raw bearer token.
        token_digest -> Binary,
        /// Token creation timestamp.
        created_at -> Timestamptz,
        /// Exclusive token-consumption deadline.
        expires_at -> Timestamptz,
        /// Successful one-time consumption timestamp.
        consumed_at -> Nullable<Timestamptz>,
        /// Explicit supersession or revocation timestamp.
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    /// Per-account serialization lock and remote persona-state revision fence.
    account_persona_state (account_id) {
        /// Stable authenticated account identifier.
        account_id -> Uuid,
        /// Latest committed fresh mutation sequence.
        revision -> BigInt,
        /// Timestamp of the latest committed fresh mutation.
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    /// Exact verified public persona versions attached to one account.
    account_persona_installations (account_id, pack_name, version) {
        /// Account that owns the installation.
        account_id -> Uuid,
        /// Canonical public pack name.
        pack_name -> Text,
        /// Exact immutable public version string.
        version -> Text,
        /// Raw 32-byte SHA-256 archive content hash.
        content_hash -> Binary,
        /// Timestamp of the first successful account attachment.
        installed_at -> Timestamptz,
    }
}

diesel::table! {
    /// Single account-level active persona bound to an exact installation.
    account_active_personas (account_id) {
        /// Account that owns the active selection.
        account_id -> Uuid,
        /// Exact installed root pack name.
        pack_name -> Text,
        /// Exact installed root version.
        version -> Text,
        /// Raw 32-byte SHA-256 archive content hash.
        content_hash -> Binary,
        /// Timestamp of the latest successful selection.
        selected_at -> Timestamptz,
    }
}

diesel::table! {
    /// Bounded global-only integer selection preferences for one account.
    account_persona_preferences (account_id, pack_name) {
        /// Account that owns the preference.
        account_id -> Uuid,
        /// Installed active pack name receiving the preference.
        pack_name -> Text,
        /// Exact signed selection bias in milli-units.
        bias_millis -> SmallInt,
        /// Number of mutations incorporated into this preference.
        mutation_count -> BigInt,
        /// Timestamp of the latest preference mutation.
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    /// Append-only idempotency evidence for account persona mutations.
    account_persona_operations (account_id, operation_id) {
        /// Account that owns the operation.
        account_id -> Uuid,
        /// Caller-selected non-nil idempotency identifier.
        operation_id -> Uuid,
        /// Account revision committed by this fresh mutation.
        sequence -> BigInt,
        /// Exact bounded mutation tool name.
        tool_name -> Text,
        /// Canonical request-hashing schema version.
        request_schema_version -> Integer,
        /// Raw 32-byte SHA-256 canonical request hash.
        request_hash -> Binary,
        /// Bounded typed receipt whose non-secret fields are enforced in Rust.
        receipt -> Jsonb,
        /// Timestamp at which the operation committed.
        created_at -> Timestamptz,
    }
}

diesel::table! {
    /// Exact authenticated account growth bound to an installed persona.
    account_persona_growth_entries (account_id, entry_id) {
        /// Account-scoped half of the tenant-composite entry identity.
        account_id -> Uuid,
        /// Caller-selected non-nil growth entry identifier.
        entry_id -> Uuid,
        /// Exact installed pack name receiving the growth.
        pack_name -> Text,
        /// Exact installed version receiving the growth.
        version -> Text,
        /// Raw 32-byte SHA-256 installed archive hash.
        content_hash -> Binary,
        /// Positive monotonic account/persona sequence.
        sequence -> BigInt,
        /// Exact structurally admitted UTF-8 growth text.
        text -> Text,
        /// Raw 32-byte SHA-256 hash of the exact text bytes.
        text_hash -> Binary,
        /// Timestamp at which the growth mutation committed.
        created_at -> Timestamptz,
        /// Idempotency operation that created the entry.
        operation_id -> Uuid,
    }
}

diesel::table! {
    /// Encrypted recovery deliveries leased to background workers.
    account_password_recovery_outbox (id) {
        /// Stable outbox identifier and provider idempotency key.
        id -> Uuid,
        /// Local account receiving the recovery-related message.
        account_id -> Uuid,
        /// Stable reset or password-changed delivery purpose.
        kind -> Text,
        /// Lowercase, trimmed destination email.
        recipient -> Text,
        /// Opaque authenticated ciphertext containing the message payload.
        ciphertext -> Binary,
        /// Random 192-bit XChaCha20-Poly1305 nonce.
        nonce -> Binary,
        /// Deployment-managed encryption-key version.
        key_version -> SmallInt,
        /// Number of leases issued for this delivery.
        attempt_count -> Integer,
        /// Most recent lease-acquisition timestamp.
        last_attempt_at -> Nullable<Timestamptz>,
        /// UUID fencing the currently active worker lease.
        claim_id -> Nullable<Uuid>,
        /// Timestamp at which the current worker lease began.
        claimed_at -> Nullable<Timestamptz>,
        /// Earliest timestamp at which an unclaimed worker may acquire the row.
        next_attempt_at -> Timestamptz,
        /// Exclusive deadline after which the delivery must not be sent.
        expires_at -> Timestamptz,
        /// Successful provider acknowledgement timestamp.
        sent_at -> Nullable<Timestamptz>,
        /// Bounded provider-assigned message identifier.
        provider_message_id -> Nullable<Text>,
        /// Permanent failure timestamp.
        failed_at -> Nullable<Timestamptz>,
        /// Bounded static diagnostic code from the latest failed attempt.
        last_error_code -> Nullable<Text>,
        /// Outbox row creation timestamp.
        created_at -> Timestamptz,
    }
}

diesel::table! {
    /// Public artifact publisher profiles.
    publisher_profiles (id) {
        /// Internal stable publisher identifier.
        id -> Uuid,
        /// Unique normalized public handle.
        handle -> Text,
        /// Public display name.
        display_name -> Text,
        /// Optional public biography.
        biography -> Nullable<Text>,
        /// Publisher moderation state.
        moderation_status -> Text,
        /// Profile creation timestamp.
        created_at -> Timestamptz,
        /// Most recent profile update timestamp.
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    /// Account roles within publisher profiles.
    publisher_memberships (account_id, publisher_id) {
        /// Account holding the role.
        account_id -> Uuid,
        /// Publisher receiving the member.
        publisher_id -> Uuid,
        /// Authorization role.
        role -> Text,
        /// Membership lifecycle state.
        state -> Text,
        /// Membership creation timestamp.
        created_at -> Timestamptz,
        /// Most recent membership update timestamp.
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    /// Public Ed25519 keys enrolled to publishers.
    publisher_keys (id) {
        /// Internal stable key identifier.
        id -> Uuid,
        /// Publisher owning the key.
        publisher_id -> Uuid,
        /// Raw 32-byte Ed25519 public key.
        public_key -> Binary,
        /// User-visible key label.
        label -> Text,
        /// Key lifecycle state.
        state -> Text,
        /// Key enrollment timestamp.
        created_at -> Timestamptz,
        /// Key revocation timestamp.
        revoked_at -> Nullable<Timestamptz>,
        /// Most recent successful use timestamp.
        last_used_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    /// Immutable audit events for publisher security operations.
    publisher_audit_events (id) {
        /// Internal stable event identifier.
        id -> Uuid,
        /// Optional account responsible for the event.
        actor_account_id -> Nullable<Uuid>,
        /// Publisher affected by the event.
        publisher_id -> Uuid,
        /// Stable action name.
        action -> Text,
        /// Optional affected publisher key.
        target_key_id -> Nullable<Uuid>,
        /// Optional affected pack version.
        target_version -> Nullable<Text>,
        /// Optional request correlation identifier.
        request_id -> Nullable<Uuid>,
        /// Event timestamp.
        created_at -> Timestamptz,
        /// Sanitized structured metadata.
        metadata -> Jsonb,
    }
}

diesel::table! {
    /// Exact, expiring authorization envelopes for publication submissions.
    publication_intents (id) {
        /// Stable intent identifier and idempotency key.
        id -> Uuid,
        /// Account that created the intent.
        account_id -> Uuid,
        /// Publisher receiving the future submission.
        publisher_id -> Uuid,
        /// Publisher key authorizing the future submission.
        publisher_key_id -> Uuid,
        /// SHA-256 digest of the exact archive bytes.
        archive_hash -> Binary,
        /// SHA-256 digest of the canonical manifest bytes.
        manifest_hash -> Binary,
        /// SHA-256 digest of the normalized file inventory.
        file_inventory_hash -> Binary,
        /// Positive scanner contract version.
        scan_schema_version -> Integer,
        /// Intent creation timestamp.
        created_at -> Timestamptz,
        /// Exclusive intent expiry timestamp.
        expires_at -> Timestamptz,
        /// Successful one-time consumption timestamp.
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    /// Applications for access to invite-only first-party account registration.
    account_invite_requests (id) {
        /// Stable internal application identifier.
        id -> Uuid,
        /// Lowercase, trimmed applicant email.
        normalized_email -> Text,
        /// Optional applicant name retained for review.
        display_name -> Nullable<Text>,
        /// Applicant-selected reason for requesting access.
        intent -> Text,
        /// Bounded private application statement.
        statement -> Text,
        /// Current review lifecycle state.
        status -> Text,
        /// Time when the applicant accepted the contact terms.
        consented_at -> Timestamptz,
        /// Initial application timestamp.
        created_at -> Timestamptz,
        /// Most recent application update timestamp.
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    /// One-time invitations storing only SHA-256 digests of opaque tokens.
    account_invites (id) {
        /// Stable internal invitation identifier.
        id -> Uuid,
        /// Application approved by this invitation.
        request_id -> Nullable<Uuid>,
        /// Lowercase, trimmed email authorized to redeem the invitation.
        normalized_email -> Text,
        /// SHA-256 digest of the random invitation token.
        token_digest -> Binary,
        /// Administrator that issued the invitation.
        issued_by_account_id -> Nullable<Uuid>,
        /// Whether the invitation was inserted out of band for initial bootstrap.
        is_bootstrap -> Bool,
        /// Exclusive invitation expiry timestamp.
        expires_at -> Timestamptz,
        /// Successful one-time consumption timestamp.
        consumed_at -> Nullable<Timestamptz>,
        /// Explicit revocation timestamp.
        revoked_at -> Nullable<Timestamptz>,
        /// Invitation creation timestamp.
        created_at -> Timestamptz,
    }
}

diesel::table! {
    /// Global moderation authority assigned independently of publisher ownership.
    account_platform_roles (account_id, role) {
        /// Account receiving the global authority.
        account_id -> Uuid,
        /// Assigned global role.
        role -> Text,
        /// Assignment lifecycle state.
        state -> Text,
        /// Account that assigned the role.
        assigned_by_account_id -> Uuid,
        /// Assignment creation timestamp.
        created_at -> Timestamptz,
        /// Most recent assignment update timestamp.
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    /// Immutable evidence linking approved submissions to public catalog versions.
    publication_promotions (id) {
        /// Stable promotion identifier.
        id -> Uuid,
        /// Submission activated by this promotion.
        submission_id -> Uuid,
        /// Account that exercised promotion authority.
        actor_account_id -> Uuid,
        /// Public pack name.
        pack_name -> Text,
        /// Public semantic version.
        version -> Text,
        /// Raw 32-byte public object hash.
        content_hash -> Binary,
        /// Stable request correlation identifier.
        request_id -> Uuid,
        /// Promotion commit timestamp.
        created_at -> Timestamptz,
    }
}

diesel::table! {
    /// Immutable owner and administrator publication lifecycle controls.
    publication_lifecycle_decisions (id) {
        /// Stable lifecycle-decision identifier.
        id -> Uuid,
        /// Stable control action.
        action -> Text,
        /// Authenticated account that exercised authority.
        actor_account_id -> Uuid,
        /// Affected publisher when linked to current ownership.
        publisher_id -> Nullable<Uuid>,
        /// Affected non-public submission for withdrawals.
        submission_id -> Nullable<Uuid>,
        /// Affected public pack for release tombstones.
        pack_name -> Nullable<Text>,
        /// Affected public semantic version for release tombstones.
        version -> Nullable<Text>,
        /// Stable state observed before the control.
        from_state -> Text,
        /// Stable state committed by the control.
        to_state -> Text,
        /// Bounded reason code or public tombstone category.
        reason_code -> Text,
        /// Stable request identifier used to reject replay substitution.
        request_id -> Uuid,
        /// Decision commit timestamp.
        created_at -> Timestamptz,
    }
}

diesel::table! {
    /// Artifacts admitted only to the internal publication quarantine boundary.
    publication_submissions (id) {
        /// Stable submission identifier and idempotency key.
        id -> Uuid,
        /// One-time intent consumed by the submission.
        intent_id -> Uuid,
        /// Account that presented the artifact.
        account_id -> Uuid,
        /// Publisher receiving the future reviewed artifact.
        publisher_id -> Uuid,
        /// Publisher key that authorized the artifact.
        publisher_key_id -> Uuid,
        /// SHA-256 digest of the exact archive bytes.
        archive_hash -> Binary,
        /// SHA-256 digest of the canonical manifest bytes.
        manifest_hash -> Binary,
        /// SHA-256 digest of the normalized file inventory.
        file_inventory_hash -> Binary,
        /// Positive server scanner contract version.
        scan_schema_version -> Integer,
        /// Typed server validation report serialized as JSON.
        scan_report -> Jsonb,
        /// Non-public lifecycle state.
        state -> Text,
        /// Submission creation timestamp.
        created_at -> Timestamptz,
        /// Most recent lifecycle update timestamp.
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    /// Immutable review decisions for quarantined publication submissions.
    publication_moderation_decisions (id) {
        /// Stable decision identifier and idempotency key.
        id -> Uuid,
        /// Submission receiving the decision.
        submission_id -> Uuid,
        /// Account that exercised moderation authority.
        actor_account_id -> Uuid,
        /// Review action applied to the submission.
        action -> Text,
        /// Submission state observed before the decision.
        from_state -> Text,
        /// Submission state committed by the decision.
        to_state -> Text,
        /// Stable private reason code.
        reason_code -> Text,
        /// Optional private explanation for the publisher.
        private_explanation -> Nullable<Text>,
        /// Stable request identifier used for replay detection.
        request_id -> Uuid,
        /// Decision commit timestamp.
        created_at -> Timestamptz,
    }
}

diesel::table! {
    /// Immutable publisher-owner appeals bound to adverse moderation decisions.
    publication_appeals (id) {
        /// Stable appeal identifier.
        id -> Uuid,
        /// Immutable moderation decision being appealed.
        decision_id -> Uuid,
        /// Submission bound to the original moderation decision.
        submission_id -> Uuid,
        /// Publisher that owns the submission.
        publisher_id -> Uuid,
        /// Authenticated owner that filed the appeal.
        actor_account_id -> Uuid,
        /// Bounded private appeal statement.
        statement -> Text,
        /// Stable request identifier used for replay detection.
        request_id -> Uuid,
        /// Appeal filing timestamp.
        created_at -> Timestamptz,
    }
}

diesel::table! {
    /// Immutable administrator resolutions for publication appeals.
    publication_appeal_resolutions (id) {
        /// Stable resolution identifier.
        id -> Uuid,
        /// Appeal resolved by this record.
        appeal_id -> Uuid,
        /// Authenticated administrator that resolved the appeal.
        actor_account_id -> Uuid,
        /// Final disposition string.
        disposition -> Text,
        /// Bounded private resolution rationale.
        rationale -> Text,
        /// Audited reason for unavoidable sole-administrator self-resolution.
        separation_exception_reason -> Nullable<Text>,
        /// Stable request identifier used for replay detection.
        request_id -> Uuid,
        /// Resolution commit timestamp.
        created_at -> Timestamptz,
    }
}

diesel::table! {
    /// The `authors` table stores one row per registered Ed25519 keypair.
    ///
    /// Primary key: `pubkey` (raw 32-byte BYTEA).
    /// `handle` has a UNIQUE constraint enforced at the DB level.
    authors (pubkey) {
        /// Raw 32-byte Ed25519 public key; primary identifier for all author operations.
        pubkey -> Binary,
        /// Unique human-readable handle (e.g. "alice"). Case-sensitive.
        handle -> Text,
        /// Optional display name; NULL when the author did not supply one.
        display_name -> Nullable<Text>,
        /// UTC timestamp when the author was first registered.
        created_at -> Timestamptz,
        /// JSON array of OAuth links: [{provider, subject, linked_at}, ...].
        oauth_links -> Jsonb,
    }
}

diesel::table! {
    /// Shared replay protection for signed HTTP requests.
    signed_request_nonces (pubkey, nonce) {
        /// Raw 32-byte Ed25519 public key that signed the request.
        pubkey -> Binary,
        /// Caller-generated request nonce.
        nonce -> Text,
        /// Time after which the nonce can no longer accompany a valid request.
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    /// The `packs` table stores the mutable "head" record for each named pack.
    ///
    /// Primary key: `name` (TEXT).
    /// `current_author` references `authors(pubkey)`.
    packs (name) {
        /// Globally unique pack name.
        name -> Text,
        /// Raw 32-byte Ed25519 pubkey of the current pack owner.
        current_author -> Binary,
        /// Nullable publisher owner during the compatibility migration.
        publisher_id -> Nullable<Uuid>,
        /// Tag array for search and discovery.
        tags -> Array<Text>,
        /// Short human-readable description.
        description -> Text,
        /// UTC timestamp when the pack was first created.
        created_at -> Timestamptz,
        /// Semver string of the most-recently published version; NULL until first publish.
        latest_version -> Nullable<Text>,
        /// Cumulative download count; monotonically increasing.
        total_downloads -> BigInt,
        /// Base persona pack name from the manifest `extends` field; NULL for root packs.
        extends -> Nullable<Text>,
    }
}

diesel::table! {
    /// The `pack_versions` table stores immutable version history.
    ///
    /// Primary key: `(pack_name, version)`.
    /// `pack_name` references `packs(name)`, `author_pubkey` references `authors(pubkey)`.
    pack_versions (pack_name, version) {
        /// Parent pack name.
        pack_name -> Text,
        /// Semver version string.
        version -> Text,
        /// Raw 32-byte SHA-256 content hash of the pack artifact.
        content_hash -> Binary,
        /// Raw 64-byte Ed25519 signature over the canonical pack content.
        signature -> Binary,
        /// Raw 32-byte Ed25519 pubkey of the publishing author.
        author_pubkey -> Binary,
        /// Nullable enrolled publisher key during the compatibility migration.
        publisher_key_id -> Nullable<Uuid>,
        /// Raw 32-byte SHA-256 hash of the previous version; NULL for first version.
        parent_hash -> Nullable<Binary>,
        /// JSON capability manifest (schema defined by pack runtime).
        capability_manifest_json -> Jsonb,
        /// Integer identifying the pack schema format used at publication time.
        schema_version -> Integer,
        /// SPDX license identifier.
        license -> Text,
        /// UTC timestamp when this version was published.
        published_at -> Timestamptz,
        /// JSON status: {"kind":"active"} or tombstone object.
        status -> Jsonb,
        /// Size of the pack artifact in bytes.
        size_bytes -> BigInt,
    }
}

diesel::table! {
    /// The `handles` table maps handle strings to their current owner pubkeys.
    ///
    /// Primary key: `handle` (TEXT).
    /// `pubkey` references `authors(pubkey)`.
    handles (handle) {
        /// The handle string.
        handle -> Text,
        /// Raw 32-byte Ed25519 pubkey of the current owner.
        pubkey -> Binary,
        /// UTC timestamp of the most recent ownership update.
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    /// The `pack_downloads` table records individual download events for trending.
    ///
    /// Primary key: `id` (bigserial surrogate).
    /// No FK to `packs` -- see migration comment for rationale.
    pack_downloads (id) {
        /// Surrogate primary key; auto-incremented.
        id -> Int8,
        /// Name of the pack that was downloaded.
        pack_name -> Text,
        /// Semver version string that was downloaded.
        version -> Text,
        /// UTC timestamp of the download event.
        downloaded_at -> Timestamptz,
    }
}

// Allow Diesel join inference between packs and authors.
diesel::joinable!(packs -> authors (current_author));
// Allow Diesel join inference between packs and publisher profiles.
diesel::joinable!(packs -> publisher_profiles (publisher_id));
// Allow Diesel join inference between pack_versions and packs.
diesel::joinable!(pack_versions -> packs (pack_name));
// Allow Diesel join inference between pack_versions and authors via author_pubkey.
diesel::joinable!(pack_versions -> authors (author_pubkey));
// Allow Diesel join inference between pack versions and publisher keys.
diesel::joinable!(pack_versions -> publisher_keys (publisher_key_id));
// Allow Diesel join inference between handles and authors.
diesel::joinable!(handles -> authors (pubkey));
// Allow Diesel join inference for publisher memberships.
diesel::joinable!(publisher_memberships -> accounts (account_id));
diesel::joinable!(publisher_memberships -> publisher_profiles (publisher_id));
// Allow Diesel join inference for first-party credentials and sessions.
diesel::joinable!(account_password_credentials -> accounts (account_id));
diesel::joinable!(account_sessions -> accounts (account_id));
// Allow Diesel join inference for the account persona-state owner row.
diesel::joinable!(account_persona_state -> accounts (account_id));
// Allow Diesel join inference for mutable account persona-state projections.
diesel::joinable!(account_persona_installations -> account_persona_state (account_id));
diesel::joinable!(account_persona_preferences -> account_persona_state (account_id));
diesel::joinable!(account_persona_operations -> account_persona_state (account_id));
// Recovery rows are anchored to the first-party credential primary key.
diesel::joinable!(account_password_recovery_tokens -> account_password_credentials (account_id));
diesel::joinable!(account_password_recovery_outbox -> account_password_credentials (account_id));
// Account invitation joins are written explicitly where both optional foreign keys are needed.
diesel::joinable!(account_invites -> account_invite_requests (request_id));
// Allow Diesel join inference for publisher keys.
diesel::joinable!(publisher_keys -> publisher_profiles (publisher_id));
// Allow Diesel join inference for audit events.
diesel::joinable!(publisher_audit_events -> accounts (actor_account_id));
diesel::joinable!(publisher_audit_events -> publisher_profiles (publisher_id));
diesel::joinable!(publisher_audit_events -> publisher_keys (target_key_id));
diesel::joinable!(publication_submissions -> publication_intents (intent_id));
diesel::joinable!(account_platform_roles -> accounts (account_id));
diesel::joinable!(publication_moderation_decisions -> accounts (actor_account_id));
diesel::joinable!(publication_moderation_decisions -> publication_submissions (submission_id));
// Allow Diesel join inference for private appeal evidence.
diesel::joinable!(publication_appeals -> accounts (actor_account_id));
diesel::joinable!(publication_appeals -> publication_moderation_decisions (decision_id));
diesel::joinable!(publication_appeals -> publication_submissions (submission_id));
diesel::joinable!(publication_appeals -> publisher_profiles (publisher_id));
diesel::joinable!(publication_appeal_resolutions -> accounts (actor_account_id));
diesel::joinable!(publication_appeal_resolutions -> publication_appeals (appeal_id));
// Allow Diesel join inference from immutable promotions to their submissions.
diesel::joinable!(publication_promotions -> publication_submissions (submission_id));
// Allow Diesel join inference from lifecycle decisions to authenticated actors.
diesel::joinable!(publication_lifecycle_decisions -> accounts (actor_account_id));

diesel::allow_tables_to_appear_in_same_query!(
    authors,
    packs,
    pack_versions,
    handles,
    pack_downloads,
    signed_request_nonces,
    accounts,
    account_password_credentials,
    account_sessions,
    account_session_refresh_tokens,
    account_mfa_authenticators,
    account_mfa_recovery_codes,
    account_mfa_login_challenges,
    account_native_authorization_codes,
    account_auth_audit_events,
    account_persona_state,
    account_persona_installations,
    account_active_personas,
    account_persona_preferences,
    account_persona_operations,
    account_persona_growth_entries,
    account_password_recovery_tokens,
    account_password_recovery_outbox,
    account_invite_requests,
    account_invites,
    account_platform_roles,
    publisher_profiles,
    publisher_memberships,
    publisher_keys,
    publisher_audit_events,
    publication_intents,
    publication_submissions,
    publication_moderation_decisions,
    publication_appeals,
    publication_appeal_resolutions,
    publication_promotions,
    publication_lifecycle_decisions,
);
