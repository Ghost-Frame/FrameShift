# Backup, Restore, and Incident Response

This page defines the evidence a FrameShift operator should require from backup,
isolated restoration, and security response. It does not define a private
deployment topology or authorize changes to a live service.

Live recovery, destructive retention, and deletion require exact target
authorization, a tested recovery path, and the applicable operator safety
process. Do not treat this page as authorization to erase or overwrite data.

## Recovery model

The registry has three distinct state groups:

1. PostgreSQL stores catalog, account, ownership, publication, moderation, and
   audit records.
2. The public object store contains released content-addressed pack archives.
3. The quarantine object store contains non-public submitted archives.

The public and quarantine stores are separate trust zones. A backup or restore
that combines their locations is invalid. FrameShift startup rejects equal
filesystem roots and equal normalized R2 endpoint, bucket, and prefix
combinations when quarantine publication is enabled.

## Current database inventory

A complete database backup includes the migration ledger and every current
application table:

| Family | Tables |
|---|---|
| Catalog | `authors`, `handles`, `packs`, `pack_versions`, `pack_downloads` |
| Request replay defense | `signed_request_nonces` |
| Accounts and ownership | `accounts`, `publisher_profiles`, `publisher_memberships`, `publisher_keys`, `publisher_audit_events` |
| Publication admission | `publication_intents`, `publication_submissions` |
| Moderation | `account_platform_roles`, `publication_moderation_decisions` |
| Promotion and lifecycle | `publication_promotions`, `publication_lifecycle_decisions` |
| Appeals | `publication_appeals`, `publication_appeal_resolutions` |

Do not select only the tables that currently contain rows. Empty tables,
constraints, indexes, and the migration ledger are part of the recovery
contract.

## Backup evidence

Capture a coordinated recovery set while account, publication, moderation, and
legacy publication writes are disabled and drained:

1. Record the application version, migration head, database identity, public
   object location identity, and quarantine object location identity.
2. Produce a database backup with schema, data, constraints, indexes, and the
   migration ledger.
3. Produce separate public and quarantine object snapshots or immutable copies.
   Do not use a synchronization mode that deletes destination objects.
4. Record row counts for every table in the inventory above.
5. Record separate object counts, total bytes, and a stable inventory digest for
   each object store.
6. Record the active pack census by pack name, semantic version, content hash,
   signer key, signature, parent hash, status, and size.
7. Record the publication census by submission state and include intent,
   decision, promotion, lifecycle, appeal, and appeal-resolution counts.
8. Protect the recovery set on a different failure domain and record its access
   controls and retention policy in private operator records.

The backup is not proven by successful creation. It becomes usable evidence only
after an isolated restore passes the checks below.

## Isolated restoration proof

Use new, empty recovery targets that cannot receive live traffic:

1. Restore PostgreSQL into a new database and restore public and quarantine
   objects into distinct new locations.
2. Configure a restore-only FrameShift instance with those locations. Keep it
   off public routing and prevent all publication writes during verification.
3. Confirm the restored migration head and exact per-table row counts match the
   backup record.
4. Confirm public and quarantine object counts, total bytes, and inventory
   digests match their separate backup records.
5. Recompute every restored public archive hash and compare it with
   `pack_versions.content_hash`. Confirm recorded sizes, signatures, signer
   bytes, parent hashes, and lifecycle status are unchanged.
6. Recompute each quarantined archive hash and compare it with its bound
   publication submission. Confirm no quarantined object appears in the public
   location unless a matching immutable promotion record and active catalog
   version exist.
7. Exercise anonymous catalog browsing, archive download, signature
   verification, installation, and activation against the restore-only
   instance.
8. Exercise authenticated account, moderation, and lifecycle reads only with an
   explicitly approved non-production identity. Never copy a bearer token into
   a command transcript or recovery record.
9. Verify lifecycle decisions, moderation decisions, promotions, appeals, and
   publisher audit records remain queryable and retain their original actor and
   request bindings.
10. Save the restore inventory and test results beside the backup record.

`GET /healthz` is useful during this test, but it always returns HTTP `200`.
Inspect the response fields, and do not accept health alone as restoration
proof.

The ownership backfill has additional dry-run, manifest digest, census, and
rollback requirements in
[`docs/API_COMPATIBILITY.md`](https://github.com/Ghost-Frame/FrameShift/blob/main/docs/API_COMPATIBILITY.md).

## Incident priorities

For every incident:

1. Preserve logs, audit rows, database state, and both object stores.
2. Stop the narrowest write path that can worsen the incident.
3. Record the first observed time, affected identities and artifacts, current
   application version, and configuration mode without recording secrets.
4. Establish scope from immutable identifiers and content hashes, not display
   names or handles alone.
5. Make recovery changes only after a clean backup and isolated restoration
   path are available.
6. Verify anonymous reads and previously valid installs after containment.
7. Record every operator action and the evidence used to end containment.

### Compromised OIDC issuer

1. Set `OIDC_ENABLED=false` and
   `QUARANTINE_OBJECT_STORE_BACKEND=disabled`, then restart through the approved
   deployment process.
2. Verify account, publisher-management, publication-intent, submission,
   moderation, promotion, appeal, and administrator routes are unmounted.
3. Preserve issuer metadata, JWKS observations, affected token times, and server
   authentication logs without storing tokens.
4. Revoke or rotate compromised issuer material at the issuer. Do not weaken
   issuer, audience, algorithm, or fresh-auth validation to restore access.
5. Re-enable OIDC first in an isolated or gated environment. Verify discovery,
   key rotation, audience rejection, stale-token rejection, login, refresh, and
   logout before restoring account-backed routes.

Anonymous catalog reads and existing pack installation remain separate from the
OIDC account surface and should be verified during containment.

### Compromised publisher key

1. Revoke the exact publisher key through an authenticated owner workflow. If
   account authority is also in doubt, suspend the publisher through the
   administrator lifecycle control.
2. Verify the revoked key cannot create a publication intent, submit an archive,
   use the legacy publisher write path, or promote a pending submission.
3. Find affected versions and submissions by stable publisher and key
   identifiers. Do not rely on the current handle.
4. Preserve already released bytes and audit evidence. Tombstone an affected
   released version through the administrator route when it must no longer be
   offered; do not delete or rewrite its object.
5. Enroll a distinct replacement key using fresh account authentication. Verify
   the old key remains revoked and the audit history shows both actions.

### Malicious or substituted artifact

1. Stop new submission and promotion writes by disabling the quarantine-backed
   publication surface.
2. Identify the exact archive by content hash, pack name, version, submission,
   and promotion record.
3. Preserve both the public and quarantine copies, catalog rows, scan report,
   moderation decisions, and request bindings.
4. Tombstone an affected active version through the administrator lifecycle
   route. Never replace bytes beneath an existing content hash or rewrite a
   signature to fit different bytes.
5. Re-run archive validation and compare the public bytes with the exact
   quarantine archive bound to the promotion. Treat any mismatch as a separate
   database/object divergence incident.
6. Resume publication only after the failure path is reproduced, the affected
   scope is known, and hostile-archive and substitution tests pass.

### Moderator misuse

1. Revoke the affected platform role with
   `DELETE /v1/admin/accounts/{account_id}/platform-roles/{role}` as another
   active administrator. Revocation retains the assignment as auditable
   history. If the account itself is compromised rather than merely misused,
   also suspend it with `PATCH /v1/admin/accounts/{account_id}/status`. Neither
   call can remove the last active administrator, so promote a replacement
   administrator first when containing the only one.
2. Disable promotion writes if the role change cannot be enforced immediately.
3. Query moderation decisions, promotions, lifecycle actions, and appeal
   resolutions by actor account and time window.
4. Keep original decisions immutable. Use appeal, superseding lifecycle action,
   publisher suspension, or tombstone controls as appropriate instead of
   rewriting audit rows.
5. Require an independent administrator to review containment and restoration
   of moderation authority.

If no authorized moderator is available, submissions remain quarantined. An
operator outage is never a reason to auto-approve.

### Database and object-store mismatch

1. Stop publication, promotion, tombstone, and ownership migration writes.
2. Preserve the current database and both object locations before attempting
   repair.
3. Compare catalog content hashes and sizes with public objects, and compare
   submission archive hashes with quarantine objects.
4. Restore a missing or damaged object only from a verified recovery set whose
   bytes reproduce the recorded hash. Never change catalog hashes or signatures
   to match unexpected bytes.
5. If a trustworthy object cannot be recovered, keep the affected version
   unavailable and use the audited lifecycle controls. Do not fabricate a
   replacement under the same version.
6. Run the complete isolated restoration proof before returning the repaired
   system to service.

## Retention boundary

FrameShift does not currently publish a universal retention duration for
accounts, publisher evidence, quarantine archives, or audit records. Supporter
billing is also disabled, so there is no live billing-webhook recovery surface
to document.

Do not create a destructive retention job from assumptions. Retention and
account-closure policy require a separate product decision, legal review where
applicable, exact recovery evidence, and destructive-action review.

## Related guidance

- [[Operations and Observability]]
- [[Publishing and Moderation]]
- [[Accounts and Publisher Identity]]
- [[Trust and Security]]
- [[Security Reporting and Known Limits]]
