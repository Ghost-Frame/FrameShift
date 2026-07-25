> **Review priority:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved. The criteria were exercised, so read the decisions below for judgment rather than for correctness.

# Record: Connect an exactly reviewed Creator Studio draft to the existing authenticated publication-intent and quarantine-submission APIs without exposing private keys, bearer tokens, local paths, or an agent-triggerable publish action.

- **spec:** `spec_b92dddb4`
- **type:** feature

## Acceptance criteria

- A draft snapshot is refused unless validation, review, and local submission intent are current for the exact caller-presented inventory hash.
- Snapshot bytes are reopened without following symlinks and rehashed against the validated inventory before leaving the draft store.
- Preparing the same reviewed snapshot with the same Ed25519 key produces byte-identical gzip-tar archives and identical archive, manifest, and inventory hashes.
- The signed archive contains the exact validated public inventory plus a 64-byte signature.sig that verifies over the canonical pack hash.
- Intent creation sends only the exact archive, manifest, inventory, scanner schema, publisher, and key bindings under bearer authentication.
- Submission sends the exact prepared archive with caller-provided idempotency IDs, bearer authentication, and the existing signed-request envelope.
- Account-scoped submission retrieval exposes typed moderation state without local paths, credentials, signing keys, or archive bytes.
- No MCP tool can implicitly publish or receive a bearer token or private signing key.
- Focused tests cover stale review, source substitution, deterministic preparation, request contracts, redaction, and retry-safe IDs.
- Workspace formatting, tests, clippy with denied warnings, and public outbound scans pass.

## Edge cases

- Draft content changes between validation and snapshot reads.
- A symlink replaces a reviewed file or content directory entry.
- pack.toml is absent, malformed, local-unsigned, or declares a different public key than the selected signer.
- The server rejects an expired or mismatched intent, revoked key, foreign publisher, replayed signed request, or reused ID with different bytes.
- The account session or local signing key becomes unavailable before submission.
- A transport failure occurs after server intent creation or submission persistence.
- Registry base URL contains userinfo, query, or fragment data.
- Server response bodies exceed the existing bounded decoder limit.

## Interface contract

```text
frameshift-studio returns an immutable, path-free snapshot only when review and local submission intent are current for the caller-presented inventory hash. frameshift-client deterministically signs and archives that snapshot, exposes public hash metadata for final review, creates or retrieves a caller-ID-bound server intent with a SecretString bearer token, submits the exact archive under a signed request plus bearer authentication, and retrieves account-scoped submission status. Private archive bytes and signing material are never Debug-printed or serialized.
```

## Decision: Path-free Studio snapshot plus dedicated client publication module

- **why:** Freeze only a current reviewed, intent-confirmed draft into an opaque snapshot, then let frameshift-client deterministically sign/archive it and perform explicit authenticated intent, submission, and status operations.
- **alternative:** Put network publishing inside frameshift-studio -- rejected: Couples local draft storage to secrets and networking; Makes accidental or implicit publication easier; Harder to reuse safely across native clients
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

## Verification evidence

- `cargo fmt --all -- --check` -- passed
- `cargo test --target-dir ../../build-cache/frameshift-target --workspace` -- passed
- `cargo clippy --target-dir ../../build-cache/frameshift-target --workspace --all-targets -- -D warnings` -- passed
