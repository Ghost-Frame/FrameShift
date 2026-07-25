# Slice 001: Provide a secure, durable local Creator Studio foundation that lets tools create, import, inspect, edit, review, and prepare persona-pack drafts without exposing arbitrary filesystem access or accepting stale review state.

- **spec:** `spec_02633aea`

## Components

- frameshift-studio versioned draft store with atomic metadata and content lifecycle
- hardened blank creation and filesystem import with hidden staging and exact inventory validation
- inventory-hash-bound review and submission intent with mutation invalidation
- six local MCP draft tools rooted beneath the configured FrameShift data directory
- shared publication limits and allowed-public-path API
- restart, traversal, symlink, stale-hash, recovery, and MCP workflow tests

## Hard-won conditions

- All draft paths remain portable relative paths accepted by publication validation
- Draft creation and import become visible only after complete atomic publication
- Review and submission intent are current only for the exact deterministic inventory hash
- Any content mutation invalidates prior review and submission intent before modifying content
- MCP responses do not disclose server-side absolute draft paths
- Workspace formatting, tests, and clippy with warnings denied pass

## Decision: Dedicated frameshift-studio crate

- **why:** Create a reusable domain crate for draft lifecycle, persistence, validation, review, and import; MCP consumes it now and other clients can reuse it later.
- **alternative:** frameshift-client module -- rejected: Conflates unpublished authoring state with installed runtime state; Makes desktop and MCP depend on a broader client surface
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
