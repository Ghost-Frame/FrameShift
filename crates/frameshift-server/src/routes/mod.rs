//! Route modules for the frameshift HTTP server.
//!
//! Each sub-module corresponds to a logical grouping of endpoints:
//!
//! - [`packs`] -- `GET /v1/packs*` read endpoints.
//! - [`authors`] -- `GET /v1/authors` paginated listing and
//!   `GET /v1/authors/{pubkey}` lookup.
//! - [`handles`] -- `GET /v1/handles/{handle}` lookup.
//! - [`ops`] -- `GET /healthz` and `GET /metrics` operational endpoints.
//! - [`telemetry`] -- `POST /v1/telemetry/selection` opt-in selection telemetry sink.
//! - [`memory`] -- `GET /v1/memory/health` read-only memory backend health.
//! - [`invite_requests`] -- public invite-only account application intake.
//! - [`local_auth`] -- invite redemption, password login, and session logout.
//! - [`mfa`] -- TOTP enrollment and password-bound challenge completion.
//! - [`native_auth`] -- loopback-only native authorization-code brokering.
//! - [`invite_admin`] -- administrator review and one-time invitation issuance.
//! - [`publication_intents`] -- authenticated creation and account-scoped retrieval.
//! - [`publication_submissions`] -- signed quarantine admission and account-scoped retrieval.
//! - [`moderation`] -- authenticated, role-gated publication review.
//! - [`admin`] -- `POST /v1/admin/packs/{name}/{version}/tombstone` and other
//!   allowlist-gated operator endpoints.

pub mod accounts;
pub mod admin;
pub mod authors;
pub mod downloads;
pub mod handles;
pub mod invite_admin;
pub mod invite_requests;
pub mod local_auth;
pub mod memory;
pub mod mfa;
pub mod moderation;
pub mod native_auth;
pub mod ops;
pub mod packs;
pub mod publication_intents;
pub mod publication_submissions;
pub mod telemetry;
