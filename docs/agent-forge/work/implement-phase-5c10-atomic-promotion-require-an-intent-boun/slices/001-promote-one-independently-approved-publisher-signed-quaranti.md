# Slice 001: Promote one independently approved, publisher-signed quarantine archive into public object storage and the active catalog without allowing authorization drift, identifier substitution, duplicate activation, or partial catalog commits.

- **spec:** `spec_df9e25e8`

## Components

- frameshift-catalog promotion contract and records
- Postgres immutable promotion evidence and transactional activation
- server archive re-verification and public object write
- independent moderator or administrator HTTP route
- signed submission admission hardening
- focused service, route, and Postgres concurrency tests
- public API compatibility policy

## Hard-won conditions

- Only Approved submissions can activate a first version
- The archive hash, pack identity, semantic version, actor, promotion ID, and request ID remain exactly bound
- Authorization is checked before the first public write
- Publisher owners cannot promote their own submissions
- Catalog failure preserves Approved state and creates no active version
- Exact retries remain idempotent after later role or key revocation
- The standard router exposes no submission or promotion write

## Decision: Intent-bound signed archive plus shared catalog transaction helper

- **why:** Require signature.sig inside the exact archive already bound by archive_hash; verify it during admission and promotion. Factor existing Postgres pack registration into a connection-scoped helper, then add a promotion transaction that registers the version, updates metadata, appends immutable promotion evidence, and transitions approved to promoted.
- **alternative:** Persist detached signature on publication_submissions -- rejected: Existing submissions become unpromotable or require unsafe evidence mutation; Adds schema and domain optionality solely for detached metadata; Intent archive hash does not bind the detached signature bytes
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
