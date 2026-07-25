# Slice 002: Define additive global moderation roles, review actions, immutable decision evidence, non-public submission states, and fail-closed backend contracts.

- **spec:** `spec_f50ba3ae`

## Components

- frameshift-catalog records
- CatalogBackend moderation methods
- top-level type exports

## Hard-won conditions

- Approved is explicitly non-public
- Unsupported backends return no roles and deny moderation
- Publisher ownership remains distinct from global authority
- On origin/main 68f8fa4, publication submissions are created transactionally in PostgreSQL, have a database CHECK restricting state to quarantined, and CatalogBackend defaults unsupported submission operations to fail closed. The trait's general auth note delegates identity to HTTP, but moderation needs catalog-level transactional authorization to bind role, self-review exclusion, state transition, and immutable decision evidence. (Resolved the two blocking design unknowns before implementation.)

## Decision: Catalog-level transactional policy operation

- **why:** Add durable platform-role and moderation-event records plus one CatalogBackend operation whose PostgreSQL implementation locks the submission, verifies the active actor and role, excludes active publisher owners, validates the transition, inserts immutable evidence, and updates state in one transaction.
- **alternative:** Database trigger or stored procedure policy -- rejected: Policy becomes harder to type-check and review in Rust; Error mapping and idempotent replay become opaque; Less portable for external backends; More difficult focused testing and evolution
- **trust:** not independently verified
