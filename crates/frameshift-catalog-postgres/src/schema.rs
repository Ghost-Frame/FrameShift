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
    /// The `packs` table stores the mutable "head" record for each named pack.
    ///
    /// Primary key: `name` (TEXT).
    /// `current_author` references `authors(pubkey)`.
    packs (name) {
        /// Globally unique pack name.
        name -> Text,
        /// Raw 32-byte Ed25519 pubkey of the current pack owner.
        current_author -> Binary,
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

// Allow Diesel join inference between packs and authors.
diesel::joinable!(packs -> authors (current_author));
// Allow Diesel join inference between pack_versions and packs.
diesel::joinable!(pack_versions -> packs (pack_name));
// Allow Diesel join inference between pack_versions and authors via author_pubkey.
diesel::joinable!(pack_versions -> authors (author_pubkey));
// Allow Diesel join inference between handles and authors.
diesel::joinable!(handles -> authors (pubkey));

diesel::allow_tables_to_appear_in_same_query!(authors, packs, pack_versions, handles,);
