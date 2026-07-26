> **Review priority:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved. The criteria were exercised, so read the decisions below for judgment rather than for correctness.

# Record: Add source-verified sanitized public Wiki backup, restore, and incident response runbooks for the current FrameShift account, ownership, publication, moderation, and separated object-store model.

- **spec:** `spec_d4a443ed`
- **type:** docs

## Acceptance criteria

- Document a non-destructive backup inventory covering every current PostgreSQL migration family plus public and quarantine object stores.
- Document an isolated restoration proof that verifies database census, object hashes, account and publication records, anonymous reads, and quarantine/public separation before any live recovery.
- Add bounded incident runbooks for compromised OIDC issuer, compromised publisher key, malicious artifact, moderator misuse, and database/object mismatch.
- State fail-closed controls and exact rollback boundaries from current source without inventing private topology, credentials, hosts, retention periods, or deployment authority.
- Keep destructive retention and live recovery explicitly outside the public procedure without separate PEVP and target authorization.
- Update canonical Wiki navigation and source mapping, pass Wiki validation, content screening, Agent-Forge completion checks, and git diff checks.

## Edge cases

- Supporter billing remains disabled, so no nonexistent billing webhook runbook is presented as live.
- Quarantine and public object locations must never be collapsed during backup or restore.
- An object-only or database-only restore is not accepted as complete.
- A successful health endpoint alone is not accepted as restoration proof.
- No example may contain private hostnames, bucket names, credentials, or broad destructive commands.

## Interface contract

```text
Add a canonical public Wiki operator page only. Do not change runtime behavior, production state, marketplace, website, desktop, deployment, access policy, or retention jobs.
```

## Decision: One sanitized evidence-contract page

- **why:** Document source-backed invariants, isolated restore acceptance, and bounded incident checklists without private topology.
- **alternative:** Provider-specific executable scripts -- rejected: Would encode deployment assumptions; Could create destructive or credential-handling risk; Cannot prove production compatibility from this repo
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

## Verification evidence

- `scripts/wiki-docs.sh validate` -- passed
- `git diff --check` -- passed
- Destination-aware private-topology and secret-marker scan -- passed
- Destructive-command example scan -- passed
