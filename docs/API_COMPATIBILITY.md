# FrameShift API compatibility and migration policy

FrameShift evolves public HTTP, catalog, CLI JSON, and serialized record contracts
without silently invalidating released clients or historical artifact evidence.
These guarantees apply to wire formats and stored data. The Rust crates are
pre-1.0 and follow Cargo semver: additive fields on public Rust structs can require
downstream source changes even when their serialized JSON form remains backward
compatible. New `CatalogBackend` lookup methods provide fail-closed defaults so
existing third-party backend implementations continue to compile.

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
- New readers prefer publisher identity when present. Legacy author fallback is
  allowed only when the corresponding publisher or publisher-key link is absent.
- With ownership enrichment enabled, a present link is authoritative. A missing
  publisher, missing publisher key, publisher mismatch, or signer-key mismatch is
  an internal consistency failure and never triggers a legacy downgrade.
- Key revocation blocks future authorization but never invalidates or erases the
  signer bytes stored on historical versions.
- When a migrated publisher and legacy author share a handle, authenticated
  publisher ownership takes precedence for new writes. Failure of publisher
  authentication never falls back to the legacy handle.

### Additive HTTP fields

Ownership-aware reads keep every existing pack and version field at its original
JSON location. They add these optional objects:

- Pack and search responses may add `publisher` with `id`, `handle`, and
  `display_name`.
- Pack and search responses may add `legacy_author` with `handle` and
  `display_name` only when no publisher is linked.
- Version responses may add `publisher`, `publisher_key` with `id` and `state`,
  and `legacy_author` when that historical version has no publisher-key link.
- Successful account-backed publish responses may add `publisher` and
  `publisher_key`.

Released v0.10 clients continue to browse, install, and verify because they ignore
unknown response fields and still verify the retained `author_pubkey`, signature,
and content hash. `PUBLISHER_OWNERSHIP_READS=false` disables read enrichment and
restores the exact legacy JSON response shape without changing stored ownership
links or signer evidence.

New clients pin both the stable publisher UUID and the exact first-observed signer
key. Publisher UUID continuity does not by itself authorize a new signer. Until a
future wire contract carries a cryptographic rotation proof rooted in the pinned
key, an unseen publisher key retains the existing key-change warning instead of
silently replacing the signer pin.

### Compatibility duration

No legacy-field retirement date is scheduled. The legacy `current_author`,
`author_pubkey`, and related response fields remain throughout v1. They cannot be
removed before both a v2 contract boundary and a separately published retirement
deadline. No minimum duration has been approved in this phase. Removing them
requires new restore and rollback evidence and is not part of the ownership
backfill.

### Backfill safety and rollback

The ownership backfill is an operator action, not a server startup migration. It
uses a separately reviewed private manifest containing stable publisher UUIDs,
publisher-key UUIDs, exact Ed25519 key bytes, immutable pack names, and expected
census totals. Handles are review labels and never ownership identifiers.

`POSTGRES_URL` must be injected into the operator process by the approved secret
manager. Do not paste it into shell history. The positional manifest is private
operator data and must be stored at a restricted path. Dry-run is the default:

```bash
cargo run -p frameshift-catalog-postgres \
  --bin frameshift-ownership-backfill -- /secure/path/ownership-manifest.json
```

Before production apply:

1. Create a backup and prove that restoring it reproduces the pre-migration
   database.
2. Disable and drain both publisher and legacy publication traffic, then verify
   that no publish requests remain in flight. The transaction lock is a second
   migration boundary, not a substitute for operational quiescence.
3. Run the operator in dry-run mode. Review its manifest digest, exact total pack
   and version census, deterministic per-publisher key, pack, and version counts,
   and every rejection.
4. Apply only the exact digest emitted by the reviewed dry-run:

   ```bash
   cargo run -p frameshift-catalog-postgres \
     --bin frameshift-ownership-backfill -- \
     /secure/path/ownership-manifest.json \
     --apply --confirm-manifest-sha256 <reviewed-dry-run-digest>
   ```

   The transaction locks the ownership tables, rejects incomplete or ambiguous
   mappings, validates existing profiles, memberships, keys, signer bytes,
   content hashes, and legacy handle provenance, and updates only nullable
   ownership identifiers. Migration audit rows use a null `actor_account_id`
   because the operator CLI is not authenticated as a publisher owner; the exact
   manifest digest and stable audit UUID provide the operator evidence.
5. Rerun the default dry-run. It must report every row as already linked, all
   applied counts as zero, and no changed signer bytes, signatures, content hashes,
   or parent hashes.
6. Re-enable publication traffic only after reconciliation succeeds.

Application rollback sets `PUBLISHER_OWNERSHIP_READS=false` or rolls back the
application release. It does not run a down migration, clear linked identifiers,
rewrite history, or delete publisher records. Database restoration is reserved for
a failed apply and uses the restore procedure proven before the transaction.

## Release evidence

Every public contract change must include focused tests, generated implementation
evidence under `docs/agent-forge/`, and a destination-aware sensitive-content review.
The release note must identify additive fields, deprecated fields, the compatibility
deadline when applicable, and the tested rollback path.
