> **Review priority:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved. The criteria were exercised, so read the decisions below for judgment rather than for correctness.

# Record: Add source-verified public Wiki guides for FrameShift core account sessions, publisher identity and device-key management, Creator Studio drafts, exact-file review, safe publishing, moderation, version lifecycle, appeals, and tombstones.

- **spec:** `spec_6f17bd06`
- **type:** docs

## Acceptance criteria

- Account guidance distinguishes anonymous local/runtime use from account-required publisher ownership and registry mutation, and accurately documents the current OIDC CLI session boundary.
- Publisher guidance accurately explains stable publisher identity, owner membership, enrolled local signing keys, key selection/enrollment/rotation/revocation/recovery, and immutable historical signer evidence.
- Creator Studio guidance covers private central-store drafts, import/create/read/write/status/preview behavior, deterministic validation, exact public inventory, mutation invalidation, and the MCP human-review boundary.
- Publishing guidance documents local validation and snapshotting, account plus active-key authorization, hash-bound review and submission intent, quarantine/moderation states, immutable versions, withdrawal, appeal, and tombstone behavior only where current public code supports it.
- Canonical Wiki navigation and SOURCES include every new page; wiki validation, link/public-content screening, command help checks, and staged diff checks pass.
- Changes merge through the core repository with all required hosted checks passing, then sync to the public GitHub Wiki and pass a fresh-clone byte-for-byte check.

## Edge cases

- Accounts remain optional for anonymous browsing, installing, activating, Automate, MCP, and local creation.
- Legacy author-handle registration remains distinct from account-backed publisher ownership.
- Private key material and bearer tokens never enter prompts, MCP payloads, or public documentation examples.
- A revoked signing key remains historical evidence but cannot authorize a new publication.
- Draft mutation invalidates prior review and submission intent before changing content.
- MCP cannot confirm final human review or submission intent.
- Moderation and appeals wording must distinguish publisher-owner and administrator actions without exposing operator-only infrastructure.
- Do not document planned billing, private packs, desktop UI details, or production configuration as current behavior.

## Interface contract

```text
The public Wiki describes only user-visible behavior verified in the current public core source. Canonical Markdown remains under docs/wiki; the public Wiki is a synchronized publication target, not an independent source. No website or desktop implementation files are changed.
```

## Decision: Three lifecycle-oriented pages

- **why:** Use separate pages for account/publisher identity, Creator Studio drafting/review, and publishing/moderation, linked in lifecycle order.
- **alternative:** One comprehensive creator guide -- rejected: Blurs authority boundaries; Harder to scan and maintain; Likely duplicates CLI reference
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

## Verification evidence

- `bash -lc 'scripts/wiki-docs.sh validate'` -- passed
- `git diff --check` plus the prohibited Unicode punctuation scan -- passed
- `bash -lc 'rg -q "\\[\\[Creator Studio\\]\\]" docs/wiki/_Sidebar.md && rg -q "Accounts-and-Publisher-Identity.md" docs/wiki/SOURCES.md && rg -q "Publishing-and-Moderation.md" docs/wiki/SOURCES.md'` -- passed
