# Slice 002: Record the completed approval-boundary implementation before adversarial review and verification.

- **spec:** `spec_72642433`

## Components

- PostgresCatalog publication intent admission
- PostgresCatalog publication submission admission
- Postgres integration coverage for pending, suspended, rejected, approved, and retry states

## Hard-won conditions

- Access gate remains enabled
- No production data or schema is mutated
- No Cargo invocation has run for this commit before final verification
- Resolved both Phase 5C7 blockers by inspecting current PostgresCatalog ordering. D4 approval must be checked at intent creation and rechecked at both standalone consumption and atomic submission creation because publisher status can change between transitions. Exact completed submission retries remain idempotent because existing submission resolution intentionally precedes authorization predicates; publisher suspension blocks only new transitions. (create_publication_intent, consume_publication_intent, and create_publication_submission in crates/frameshift-catalog-postgres/src/backend.rs)

## Decision: Catalog-level transactional predicates

- **why:** Check locked publisher status during intent creation and add approved-publisher EXISTS predicates to both intent consumption and atomic submission creation.
- **alternative:** PostgreSQL trigger -- rejected: Opaque Diesel error mapping; Harder idempotency semantics; Duplicates catalog authorization policy in SQL; More complex migration and testing
- **trust:** not independently verified
