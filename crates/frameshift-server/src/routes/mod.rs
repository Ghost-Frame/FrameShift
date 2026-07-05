//! Route modules for the frameshift HTTP server.
//!
//! Each sub-module corresponds to a logical grouping of endpoints:
//!
//! - [`packs`] -- `GET /v1/packs*` read endpoints.
//! - [`authors`] -- `GET /v1/authors/{pubkey}` lookup.
//! - [`handles`] -- `GET /v1/handles/{handle}` lookup.
//! - [`ops`] -- `GET /healthz` and `GET /metrics` operational endpoints.
//! - [`telemetry`] -- `POST /v1/telemetry/selection` opt-in selection telemetry sink.
//! - [`memory`] -- `GET /v1/memory/health` read-only memory backend health.

pub mod authors;
pub mod downloads;
pub mod handles;
pub mod memory;
pub mod ops;
pub mod packs;
pub mod telemetry;
