# Slice 001: Record the clean C1 tip before Unit C2 edits.

- **spec:** `spec_c3c9be83`

## Components

- publication renderer API
- cloud MCP dispatcher
- startup/router wiring
- focused tests

## Hard-won conditions

- feature worktree clean
- HEAD synced to origin/feat/remote-mcp-connectors

## Decision: Renderer-owned authenticated output

- **why:** Extend frameshift-publication with a render result containing final text and cloned exact selected VerifiedPackProvenance values. Keep the existing text-only function as a compatibility wrapper.
- **alternative:** Store persona-state backend and build dispatcher in router -- rejected: Leaks a broad mutation backend into general request state; Router takes on service construction; Still requires fixture churn
- **trust:** not independently verified
