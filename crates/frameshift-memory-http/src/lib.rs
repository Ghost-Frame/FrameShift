//! # frameshift-memory-http
//!
//! HTTP-backed implementation of the [`frameshift_memory::MemoryAdapter`] trait.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use std::time::Duration;
//! use frameshift_memory_http::{HttpAdapter, HttpAdapterConfig, HttpAuth};
//! use secrecy::SecretString;
//! use url::Url;
//!
//! let config = HttpAdapterConfig {
//!     endpoint: Url::parse("http://localhost:8080/v1/").unwrap(),
//!     auth: HttpAuth::Bearer(SecretString::new("my-token".into())),
//!     timeout: Duration::from_secs(30),
//!     user_agent: "my-app/1.0".into(),
//! };
//! let adapter = HttpAdapter::new(config).expect("adapter construction failed");
//! ```
//!
//! ## Wire Contract
//!
//! See `docs/WIRE.md` for the full HTTP contract including request/response
//! shapes, serialization rules, retry policy, and authentication details.

pub mod adapter;
pub(crate) mod dto;
pub(crate) mod retry;

pub use adapter::{HttpAdapter, HttpAdapterConfig, HttpAuth};

#[cfg(test)]
mod tests;
