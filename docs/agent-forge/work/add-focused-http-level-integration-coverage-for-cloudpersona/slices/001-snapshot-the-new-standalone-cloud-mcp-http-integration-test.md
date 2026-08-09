# Slice 001: Snapshot the new standalone cloud MCP HTTP integration test before adversarial static review.

- **spec:** `spec_076fece0`

## Components

- crates/frameshift-server/tests/mcp_cloud_tools.rs

## Hard-won conditions

- No Cargo or Docker commands were run.
- Only the owned new integration-test file is included.

## Decision: Stateful contract fake plus signed archive fixtures

- **why:** Reuse the existing in-memory catalog and object store, add one tenant-aware AccountPersonaStateBackend fake that persists operations and captures requests, build real signed raw and typed archives, and drive all assertions through the modern HTTP MCP router.
- **alternative:** Scripted per-test persona-state stubs -- rejected: Duplicates all 13 trait methods across scenarios; Makes replay and sequential install/list/use/grow/prefs coverage brittle; Weakens evidence that account state evolves coherently
- **trust:** not independently verified
