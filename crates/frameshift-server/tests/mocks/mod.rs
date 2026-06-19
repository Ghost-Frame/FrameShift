//! Test mock backend implementations.
//!
//! - [`catalog`] -- [`catalog::MockCatalog`] implements [`CatalogBackend`].
//! - [`objects`] -- [`objects::MockPackStore`] implements [`PackStore`].
//! - [`signing`] -- Ed25519 signed-request header helpers for write endpoints.
//!
//! These mocks require no Postgres instance and no filesystem; all state is
//! held in-memory behind `Arc<RwLock<...>>`.

pub mod catalog;
pub mod objects;
pub mod signing;
