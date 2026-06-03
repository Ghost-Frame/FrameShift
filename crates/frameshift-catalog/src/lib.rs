//! # frameshift-catalog
//!
//! Canonical async trait and types for the frameshift persona marketplace catalog.
//!
//! This crate defines the public contract that catalog backends must implement.
//! It contains no database code, no async runtime initialization, and no HTTP
//! routing -- only trait definitions, record types, filters, and error types.
//!
//! ## Structure
//!
//! - [`backend`] -- the [`backend::CatalogBackend`] async trait (14 methods).
//! - [`error`] -- [`error::CatalogError`] and [`error::HealthStatus`].
//! - [`identity`] -- [`identity::Ed25519PublicKey`] newtype. [`ObjectHash`] is
//!   re-exported from `frameshift-pack` (the workspace canonical type).
//! - [`records`] -- [`records::AuthorRecord`], [`records::PackRecord`],
//!   [`records::PackVersionRecord`], [`records::OauthLink`].
//! - [`status`] -- [`status::PackStatus`], [`status::TombstoneReason`],
//!   [`status::TombstoneRecord`].
//! - [`filters`] -- [`filters::PackSearchFilters`], [`filters::SortMode`],
//!   [`filters::PackSearchResult`].
//!
//! ## Adapter crates
//!
//! The Postgres adapter lives in `frameshift-catalog-postgres` and implements
//! `CatalogBackend` using Diesel + async connection pooling. Other backends
//! (in-memory, SQLite) follow the same pattern.

pub mod backend;
pub mod error;
pub mod filters;
pub mod identity;
pub mod records;
pub mod status;

/// Internal serde helper modules used by record types.
pub(crate) mod serde_helpers {
    /// Serialize/deserialize `Vec<u8>` as a base64url-no-padding string.
    pub mod bytes_as_b64 {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use serde::{Deserialize, Deserializer, Serializer};

        /// Serialize a byte slice as base64url no-padding string.
        pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
        }

        /// Deserialize a base64url no-padding string into `Vec<u8>`.
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            let encoded = String::deserialize(d)?;
            URL_SAFE_NO_PAD
                .decode(&encoded)
                .map_err(serde::de::Error::custom)
        }
    }
}

// Top-level re-exports for the most commonly used types.
pub use backend::CatalogBackend;
pub use error::{CatalogError, HealthStatus};
pub use filters::{PackSearchFilters, PackSearchResult, SortMode};
pub use frameshift_pack::ObjectHash;
pub use identity::Ed25519PublicKey;
pub use records::{
    AuthorRecord, OauthLink, PackRecord, PackVersionRecord, TelemetryKind, TelemetrySignal,
};
pub use status::{PackStatus, TombstoneReason, TombstoneRecord};
