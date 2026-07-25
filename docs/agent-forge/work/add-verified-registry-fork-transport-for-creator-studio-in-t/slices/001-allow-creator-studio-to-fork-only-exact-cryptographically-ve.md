# Slice 001: Allow Creator Studio to fork only exact, cryptographically verified, explicitly forkable registry releases while preserving immutable attribution and license.

- **spec:** `spec_2455b79b`

## Components

- frameshift-client registry verifier
- frameshift-studio atomic fork import
- frameshift-mcp draft creation schema and dispatch
- registry and Studio regression tests

## Hard-won conditions

- No draft is published on transport, authorization, identity, or validation failure
- The signed manifest author key equals the Ed25519 key that verified the signature
- The source manifest explicitly sets forkable=true
- Fork provenance binds source name, exact semver, and raw archive SHA-256
- The derived pack name differs from the source and retains the source license

## Decision: Client-owned verified fetch plus atomic Studio fork import

- **why:** Refactor the client registry installer around an internal owned verified-pack result. Install caches it; the new client fork API passes its temporary root and exact ForkOrigin to Studio, which stages, rewrites, validates, and atomically publishes.
- **alternative:** Move registry transport into a new lower-level crate -- rejected: Large public workspace expansion for one slice; Duplicates or moves trust-pin ownership; Higher compatibility and review surface
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
