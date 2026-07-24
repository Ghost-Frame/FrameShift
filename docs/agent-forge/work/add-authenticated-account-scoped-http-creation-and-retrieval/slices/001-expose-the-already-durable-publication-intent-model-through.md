# Slice 001: Expose the already-durable publication-intent model through a tenant-safe HTTP boundary without widening into submission or moderation policy.

- **spec:** `spec_8703570f`

## Components

- publication-intent route module
- authenticated router composition
- in-memory catalog test behavior
- account route integration tests

## Hard-won conditions

- OIDC routes remain unmounted when authentication is disabled
- foreign intent reads do not disclose existence
- submission and moderation remain out of scope
- Phase 1 remains active and unchanged
- PublicationIntentRecord creation compares server timestamps in the Postgres adapter, so an HTTP layer that owns timestamps cannot replay the same record byte-for-byte. Safe HTTP idempotency requires returning an existing same-account record when all client-controlled binding fields match, including conflict recovery for concurrent creates. (FrameShift Phase 5C4 publication-intent POST route)

## Decision: Dedicated bearer-protected route module over CatalogBackend

- **why:** Add a small publication_intents route module, mount it inside the existing account-auth conditional, construct server-owned records, and enforce account-scoped GET in the handler.
- **alternative:** Fold intent handlers into accounts.rs -- rejected: Mixes publication workflow with identity/profile concerns; Makes the already large accounts module harder to review; Less obvious future submission boundary
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
