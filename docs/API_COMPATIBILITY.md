# FrameShift API compatibility and migration policy

FrameShift evolves public HTTP, catalog, CLI JSON, and serialized record contracts
without silently invalidating released clients or historical artifact evidence.

## Compatibility window

- Additive optional response fields are compatible within the current major API
  version. Clients must ignore fields they do not understand.
- Existing fields retain their meaning and serialization until a documented major
  version boundary or an announced compatibility deadline, whichever is later.
- New required request fields use a new endpoint, explicit protocol version, or a
  negotiated capability. They are not added silently to an existing request shape.
- Enum expansion is treated as potentially breaking unless the consumer contract
  already defines unknown-value handling.
- Authentication requirements may tighten only with a route version change or a
  published transition window. A route never falls back to weaker authentication
  when configuration or validation fails.

## Database changes

Production schema changes follow expand, backfill, dual-read or dual-write, and
contract stages:

1. Expand with nullable columns, new tables, constraints, and indexes that preserve
   existing reads and writes.
2. Backfill through a separately reviewed and restartable operation with verified
   backups and reconciliation counts.
3. Prefer the new representation while retaining the legacy fallback for the
   documented compatibility window.
4. Contract only after released clients no longer require the legacy path and a
   rollback no longer depends on it.

Destructive schema operations, historical signer rewrites, and silent ownership
reassignment are prohibited. Down migrations are development rollback aids, not a
production data-erasure procedure.

## Account and publisher migration

OIDC account identity is keyed by `(issuer, subject)`. Email is mutable metadata and
never an ownership key. Publisher profiles and enrolled publisher keys are additive
to the legacy author-key model. During migration:

- `packs.current_author` and `pack_versions.author_pubkey` remain populated and keep
  their established meaning.
- `packs.publisher_id` and `pack_versions.publisher_key_id` remain nullable until a
  reviewed backfill links every eligible record.
- New readers may prefer publisher identity when present and must retain the legacy
  fallback until the compatibility window closes.
- Key revocation blocks future authorization but never invalidates or erases the
  signer bytes stored on historical versions.

## Release evidence

Every public contract change must include focused tests, generated implementation
evidence under `docs/agent-forge/`, and a destination-aware sensitive-content review.
The release note must identify additive fields, deprecated fields, the compatibility
deadline when applicable, and the tested rollback path.
