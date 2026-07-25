# Slice 003: Persist global role assignments and authorize non-public review transitions with immutable decision evidence in one PostgreSQL transaction.

- **spec:** `spec_f50ba3ae`

## Components

- expand-only moderation migration
- Diesel schema and row mappings
- PostgresCatalog role lookup
- transactional moderation operation
- adversarial Postgres integration tests

## Hard-won conditions

- Active moderator or administrator account required
- Active owners cannot review their publisher
- Only quarantined or needs-review states transition
- Approved remains non-public
- Identical decision and request IDs are idempotent; conflicting reuse fails
- Database insertion failure rolls back state
- On origin/main 68f8fa4, publication submissions are created transactionally in PostgreSQL, have a database CHECK restricting state to quarantined, and CatalogBackend defaults unsupported submission operations to fail closed. The trait's general auth note delegates identity to HTTP, but moderation needs catalog-level transactional authorization to bind role, self-review exclusion, state transition, and immutable decision evidence. (Resolved the two blocking design unknowns before implementation.)

## Decision: Catalog-level transactional policy operation

- **why:** Add durable platform-role and moderation-event records plus one CatalogBackend operation whose PostgreSQL implementation locks the submission, verifies the active actor and role, excludes active publisher owners, validates the transition, inserts immutable evidence, and updates state in one transaction.
- **alternative:** Database trigger or stored procedure policy -- rejected: Policy becomes harder to type-check and review in Rust; Error mapping and idempotent replay become opaque; Less portable for external backends; More difficult focused testing and evolution
- **trust:** not independently verified
