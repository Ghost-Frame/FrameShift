# Slice 001: Make publication lifecycle authority explicit, atomic, and auditable without deleting historical catalog or object evidence.

- **spec:** `spec_bec8687a`

## Components

- catalog lifecycle records and backend contract
- PostgreSQL atomic lifecycle transitions and immutable evidence
- account-authenticated owner and administrator routes
- stable scoped audit pagination
- real-Postgres concurrency, revocation, visibility, and immutability tests
- public administrator documentation

## Hard-won conditions

- No physical catalog or object deletion
- Legacy signed-key administrator allowlist cannot authorize lifecycle routes
- Exact retries are field-for-field and substitution-safe
- Owner audit is publisher-scoped; global audit requires active administrator role
- All exact CI commands, all 52 real-Postgres integration tests, security audit, strict Clippy, formatting, and declaration comments pass

## Decision: Unified typed lifecycle-decision table with three atomic catalog operations

- **why:** Add one immutable publication_lifecycle_decisions table with constrained action-specific targets and bound prior/resulting states. Implement withdrawal, publisher suspension, and release tombstone as distinct catalog methods sharing retry/audit helpers. Replace the legacy HTTP allowlist tombstone route with account-authenticated administrator routes, while retaining the low-level legacy tombstone backend method only for adapter compatibility. Expose bounded publisher-scoped lifecycle decision reads to active owners and administrators.
- **alternative:** Separate withdrawal, suspension, and tombstone evidence tables -- rejected: Three migrations/table models and repeated retry logic; Unified ordering and pagination require a union; More surface area for inconsistent idempotency
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
