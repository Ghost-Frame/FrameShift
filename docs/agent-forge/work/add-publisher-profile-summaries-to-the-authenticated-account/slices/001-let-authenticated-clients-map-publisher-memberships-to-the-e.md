# Slice 001: Let authenticated clients map publisher memberships to the exact handles required by owner-only publisher operations without manual handle entry.

- **spec:** `spec_04cbf196`

## Components

- frameshift-server account response
- frameshift-client backward-compatible account DTO
- account route regression tests

## Hard-won conditions

- No bearer token or private key material enters response bodies.
- Older servers remain readable by the new client through serde default.
- Local format, Clippy, embeddings, workspace tests, focused tests, and audit pass.
- Local Postgres integration could not run because Docker is absent and remains a hosted CI merge requirement.

## Decision: Add publisher profiles to account response

- **why:** Server resolves each membership UUID and returns additive publisher records; clients default the field for older servers.
- **alternative:** Add public lookup by publisher UUID -- rejected: Extra endpoint and N client round trips; Exposes an internal identifier lookup surface solely for joining
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
