//! Filesystem-backed content-addressed [`PackStore`] adapter for the frameshift
//! workspace.
//!
//! # Overview
//!
//! This crate provides [`FsPackStore`], which implements the
//! [`frameshift_objects::PackStore`] async trait by storing objects in a
//! two-level sharded directory tree:
//!
//! ```text
//! {root}/
//!   {aa}/        <- first byte of hash, two lowercase hex digits
//!     {bb}/      <- second byte of hash, two lowercase hex digits
//!       {hex}    <- 64-char lowercase hex filename; file content = raw bytes
//! ```
//!
//! Writes are atomic (POSIX `rename(2)` within the same shard directory).
//! Optional verify-on-read and quota enforcement are controlled by
//! [`FsPackStoreConfig`].
//!
//! # Quick start
//!
//! ```rust,ignore
//! use frameshift_objects_fs::{FsPackStore, FsPackStoreConfig};
//! use frameshift_objects::{PackStore, ObjectHash};
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = FsPackStoreConfig {
//!         root: PathBuf::from("/var/lib/frameshift/objects"),
//!         verify_on_read: true,
//!         max_bytes: Some(10 * 1024 * 1024 * 1024), // 10 GiB
//!         fsync_on_put: true,
//!     };
//!     let store = FsPackStore::new(config).await.unwrap();
//!     let data = b"hello, frameshift";
//!     let hash = ObjectHash::of(data);
//!     store.put(&hash, data).await.unwrap();
//!     let back = store.get(&hash).await.unwrap();
//!     assert_eq!(back, data);
//! }
//! ```
//!
//! # Crate modules
//!
//! - [`store`] -- [`FsPackStore`] and the [`PackStore`] impl.
//! - [`path`] -- hash-to-sharded-path resolution.
//! - [`quota`] -- [`QuotaCounter`], the lock-free byte-total tracker.

mod path;
mod quota;
mod store;

pub use quota::QuotaCounter;
pub use store::{FsPackStore, FsPackStoreConfig};
