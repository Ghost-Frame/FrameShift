# Slice 001: Capture the clean Phase 5C8 base and the thin role-gated HTTP adapter decision before edits.

- **spec:** `spec_906de55f`

## Components

- frameshift-server moderation router
- account middleware integration
- server moderation route tests
- shared server MockCatalog moderation behavior

## Hard-won conditions

- branch starts at main 909d9e0
- actor identity comes only from AuthenticatedAccount
- submission identity comes only from the path
- request replay identity comes only from x-request-id
- queue, artifact access, promotion, appeals, deployment, and gate changes are out of scope

## Decision: Thin role-gated HTTP adapter

- **why:** Add a moderation router that checks active global role for reads, derives all security identities from middleware/path/request header, and calls the transactional catalog decision method.
- **alternative:** Combined queue, artifact, decision, and promotion API -- rejected: Large public contract; Harder security review; Mixes database and object-store authorization; Higher regression risk
- **trust:** not independently verified
