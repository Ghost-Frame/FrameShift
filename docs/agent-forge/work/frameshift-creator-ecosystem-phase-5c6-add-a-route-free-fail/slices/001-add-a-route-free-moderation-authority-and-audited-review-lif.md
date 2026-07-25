# Slice 001: Add a route-free moderation authority and audited review lifecycle implementing the settled D4 launch policy.

- **spec:** `spec_f50ba3ae`

## Components

- frameshift-catalog moderation contracts
- PostgreSQL role and moderation persistence
- transactional authorization and review decisions
- focused PostgreSQL integration tests

## Hard-won conditions

- Start from origin/main 68f8fa473e85fc301a2749d220e249b83fe0bac6
- No HTTP routes, public promotion, appeals, auto-promotion, production wiring, deployment, access-gate changes, or Phase 1 retirement
- Approved remains non-public
- All moderation authorization and evidence persistence fail closed
- On origin/main 68f8fa4, publication submissions are created transactionally in PostgreSQL, have a database CHECK restricting state to quarantined, and CatalogBackend defaults unsupported submission operations to fail closed. The trait's general auth note delegates identity to HTTP, but moderation needs catalog-level transactional authorization to bind role, self-review exclusion, state transition, and immutable decision evidence. (Resolved the two blocking design unknowns before implementation.)

## Decision: Catalog-level transactional policy operation

- **why:** Add durable platform-role and moderation-event records plus one CatalogBackend operation whose PostgreSQL implementation locks the submission, verifies the active actor and role, excludes active publisher owners, validates the transition, inserts immutable evidence, and updates state in one transaction.
- **alternative:** Database trigger or stored procedure policy -- rejected: Policy becomes harder to type-check and review in Rust; Error mapping and idempotent replay become opaque; Less portable for external backends; More difficult focused testing and evolution
- **trust:** not independently verified
