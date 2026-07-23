//! Diesel table! macro declarations for the frameshift catalog schema.
//!
//! Column names and types here MUST match the schema defined in
//! `migrations/2026-05-13-000000_initial_schema/up.sql`.
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
// Allow Diesel join inference for publisher keys.
diesel::joinable!(publisher_keys -> publisher_profiles (publisher_id));
// Allow Diesel join inference for audit events.
diesel::joinable!(publisher_audit_events -> accounts (actor_account_id));
diesel::joinable!(publisher_audit_events -> publisher_profiles (publisher_id));
diesel::joinable!(publisher_audit_events -> publisher_keys (target_key_id));

diesel::allow_tables_to_appear_in_same_query!(
    authors,
    packs,
    pack_versions,
    handles,
    pack_downloads,
    signed_request_nonces,
    accounts,
    publisher_profiles,
    publisher_memberships,
    publisher_keys,
    publisher_audit_events,
);
