# Slice 001: Implement first-party browser and native authentication server flows with rotating sessions, MFA, strict browser origin checks, and exact PKCE binding.

- **spec:** `spec_3b5fc63e`

## Components

- first-party auth configuration and token primitives
- browser registration, login, refresh, logout
- MFA enrollment, activation, challenge, disable
- native browser authorization-code broker
- authentication middleware and protected route gating
- catalog test double and integration tests

## Hard-won conditions

- focused stale MFA replacement test passes
- focused browser refresh replay test passes
- focused native PKCE single-use test passes

## Decision: Extend existing local-auth boundary

- **why:** Keep cryptographic validation, DTOs, cookies, and route orchestration in local_auth/account middleware, delegating every state transition and transaction-bound success audit to CatalogBackend.
- **alternative:** Create a new auth service abstraction -- rejected: Duplicates catalog abstractions; More declarations and wiring; Higher merge/conflict risk under concurrent contract edits
- **trust:** not independently verified
