//! Library surface for `frameshift-daemon`.
//!
//! Re-exports all internal modules so that integration tests and other crates
//! can reach the protocol, handler, socket, and watcher logic without
//! depending on the binary entry point.

/// Error types used throughout the daemon.
pub mod error;

/// JSON-RPC method dispatch.
pub mod handler;

/// Orchestrator evaluation hook for the file-watch loop.
pub mod orchestrator;

/// JSON-RPC 2.0 wire types and serialization helpers.
pub mod protocol;

/// Unix socket server loop.
pub mod socket;

/// Notify-based file watcher bridge.
pub mod watcher;
