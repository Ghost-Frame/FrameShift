# Slice 001: Wire least-capability MCP dispatcher state through startup and router with fail-closed two-option gating.

- **spec:** `spec_7116f5c0`

## Components

- AppState optional dispatcher
- startup dispatcher construction
- router tuple gate
- AppState test literal updates
- MCP route mount matrix

## Hard-won conditions

- No Cargo command has run
- Shared CloudPersonaMcpDispatcher export is still expected from another agent
- Only assigned source and existing server test files are edited

## Decision: Independent optional capabilities with tuple gate

- **why:** Add a separate optional dispatcher to AppState, mount only through if let (Some(access), Some(dispatcher)), and construct the dispatcher beside validated access configuration using narrow trait-object coercions.
- **alternative:** Bundle access and dispatcher in one composite option -- rejected: Exceeds assigned API contract and file ownership.; Requires broader changes to callers and likely shared MCP modules.; Conflicts with explicit AppState field requested by root.
- **trust:** not independently verified
