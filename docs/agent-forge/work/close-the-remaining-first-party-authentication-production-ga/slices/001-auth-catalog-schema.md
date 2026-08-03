# Slice 001: auth-catalog-schema

- **spec:** `spec_c1cbb2ec`

## Components

- auth catalog migration

## Hard-won conditions

- No raw secret columns
- Refresh history append-only
- Audit rows immutable
- Down migration refuses destructive rollback

## Decision: Opaque access and rotating refresh family plus TOTP and browser-brokered PKCE

- **why:** Add short-lived digest-only access tokens, a separate refresh-token history/family with atomic rotation and replay revocation, encrypted TOTP plus one-time recovery codes, durable sanitized audit rows, pre-work admission limiters, and one-time browser authorization codes bound to S256 PKCE and IP-literal loopback redirects.
- **alternative:** Stored-procedure state machine -- rejected: Business contracts hidden from Rust types; Harder test/refactor surface; More SQL procedural complexity
- **trust:** not independently verified
