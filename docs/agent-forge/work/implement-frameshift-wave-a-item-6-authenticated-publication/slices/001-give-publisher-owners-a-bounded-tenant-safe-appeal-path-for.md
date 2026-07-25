# Slice 001: Give publisher owners a bounded, tenant-safe appeal path for adverse moderation decisions and give administrators an immutable, independently reviewed resolution workflow without weakening quarantine or publication controls.

- **spec:** `spec_8cee3b7a`

## Components

- catalog appeal records and fail-closed trait methods
- expand-only immutable PostgreSQL appeal schema
- atomic filing, resolution, listing, and reviewer separation
- owner and administrator HTTP routes
- client request-ID capture and browser CORS support
- real Postgres and HTTP integration tests
- public API documentation

## Hard-won conditions

- Base commit is the verified Phase 5 lifecycle merge 5cdcd6a473d982f6b3e373581e12b619364ca842
- The access gate remains enabled and is outside this change
- One appeal is allowed per request_changes or reject decision within an inclusive 30-day database-clock window
- Overturn approves only the exact unchanged submission; uphold preserves state
- Exact completed retries survive later authority revocation while substitutions conflict
- Formatting, workspace Clippy, embeddings compilation, workspace tests, all 56 Postgres integration tests, and RustSec audit pass

## Decision: Dedicated appeals aggregate plus append-only events

- **why:** Create an immutable appeal record keyed one-to-one to the original moderation decision and an immutable one-to-one resolution record containing the disposition, rationale, actor, request binding, and any required separation exception. Expose additive catalog methods and authenticated owner/admin routes.
- **alternative:** Encode appeals only as lifecycle events; rejected because one-per-decision and one-resolution invariants become harder to enforce structurally, typed authorization and query behavior are less clear, and event metadata risks becoming an unvalidated public contract.
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
