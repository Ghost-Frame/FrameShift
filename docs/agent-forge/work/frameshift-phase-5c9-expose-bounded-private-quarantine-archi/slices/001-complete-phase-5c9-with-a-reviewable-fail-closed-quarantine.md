# Slice 001: Complete Phase 5C9 with a reviewable, fail-closed quarantine artifact boundary that preserves exact bytes without making quarantine public.

- **spec:** `spec_0cf37182`

## Components

- conditional quarantine-enabled router composition
- authenticated moderation artifact handler
- active global role and independent-review authorization
- catalog-bound object identity
- response size and SHA-256 verification
- private attachment headers
- focused and full server integration tests

## Hard-won conditions

- Base is origin/main 6995cf02c66afa4b10a59c367f28e9d2319c730b
- The standard app does not mount quarantine artifact access
- The explicit application builder supplies the same isolated store to admission and review
- Actor identity comes only from bearer authentication
- Submission identity comes only from the path and object identity only from the catalog record
- Active publisher owners fail self-review even when globally privileged
- Oversized, missing, and substituted objects fail without returning bytes
- Focused tests pass 11/11 and the full frameshift-server suite passes
- Focused Clippy and formatting pass
- The website access gate and production state remain unchanged

## Decision: Conditional direct quarantine route

- **why:** Pass the explicit quarantine PackStore into moderation_router only in app_with_publication_admission; the handler performs role, self-review, catalog hash, size, and content verification before returning bytes.
- **alternative:** Publication review service -- rejected: Duplicates admission service ownership; More declarations and wiring for one read operation; Risks coupling later promotion authority to review reads
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
