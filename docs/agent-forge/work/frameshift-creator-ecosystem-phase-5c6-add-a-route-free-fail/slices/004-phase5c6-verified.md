# Slice 004: phase5c6-verified

- **spec:** `spec_f50ba3ae`

## Components

- catalog moderation contracts
- PostgreSQL migration and persistence
- transactional moderation policy
- focused integration tests

## Hard-won conditions

- approved remains non-public
- no owner self-review
- unauthorized probes fail closed
- decision evidence rejects update and delete
- all five moderation tests pass
- On origin/main 68f8fa4, publication submissions are created transactionally in PostgreSQL, have a database CHECK restricting state to quarantined, and CatalogBackend defaults unsupported submission operations to fail closed. The trait's general auth note delegates identity to HTTP, but moderation needs catalog-level transactional authorization to bind role, self-review exclusion, state transition, and immutable decision evidence. (Resolved the two blocking design unknowns before implementation.)

## Decision: Catalog-level transactional policy operation

- **why:** Add durable platform-role and moderation-event records plus one CatalogBackend operation whose PostgreSQL implementation locks the submission, verifies the active actor and role, excludes active publisher owners, validates the transition, inserts immutable evidence, and updates state in one transaction.
- **alternative:** Database trigger or stored procedure policy -- rejected: Policy becomes harder to type-check and review in Rust; Error mapping and idempotent replay become opaque; Less portable for external backends; More difficult focused testing and evolution
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
