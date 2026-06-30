//! Minimal MCP stdio server for Frameshift.
//!
//! Exposes the protocol, tool dispatch, and error types as a library so
//! that unit tests can exercise them without spawning a full binary.

/// MCP server error types.
pub mod error;
/// Prompt definitions and dispatch logic (`prompts/list`, `prompts/get`).
pub mod prompts;
/// JSON-RPC 2.0 protocol types and response helpers.
pub mod protocol;
/// Tool definitions and dispatch logic (`tools/list`, `tools/call`).
pub mod tools;
