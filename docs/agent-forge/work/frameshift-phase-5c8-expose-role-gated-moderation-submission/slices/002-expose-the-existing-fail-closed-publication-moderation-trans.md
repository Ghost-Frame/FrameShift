# Slice 002: Expose the existing fail-closed publication moderation transaction through a thin authenticated HTTP adapter without expanding into queueing, artifact access, promotion, or access-gate changes.

- **spec:** `spec_906de55f`

## Components

- frameshift-server moderation router
- account-authenticated router composition
- shared server MockCatalog moderation behavior
- focused moderation route integration tests

## Hard-won conditions

- actor identity is derived only from AuthenticatedAccount
- submission identity is derived only from the URL path
- replay identity is derived only from a strict UUID x-request-id header
- unknown body fields are rejected
- GET requires an active moderator or administrator role before lookup
- POST delegates authorization and mutation to CatalogBackend::moderate_publication_submission
- cargo test --locked -p frameshift-server --test moderation_routes passed 7 of 7 tests

## Decision: Thin role-gated HTTP adapter

- **why:** Add a moderation router that checks active global role for reads, derives all security identities from middleware/path/request header, and calls the transactional catalog decision method.
- **alternative:** Combined queue, artifact, decision, and promotion API -- rejected: Large public contract; Harder security review; Mixes database and object-store authorization; Higher regression risk
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
