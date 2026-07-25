> **Review priority:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved. The criteria were exercised, so read the decisions below for judgment rather than for correctness.

# Record: Add deterministic, path-free Creator Studio preview rendering for every supported agent target and expose it through a read-only local MCP draft tool.

- **spec:** `spec_1b124fbf`
- **type:** feature

## Acceptance criteria

- Studio preview loads only the exact current managed draft inventory and never returns an absolute local path.
- Preview refuses drafts without valid typed persona source using stable path-free errors.
- Every source file is reopened without following symlinks, bounded, and rehashed against the current validation inventory before rendering.
- Preview renders Claude, Codex, Gemini, and Generic targets deterministically and labels each target with its install filename.
- Each rendered target includes a SHA-256 digest over its exact UTF-8 bytes, and repeated previews of unchanged content are byte-identical.
- The preview response binds its renders to the current draft revision, inventory hash, and shared publication validation report.
- A read-only frameshift_draft_preview MCP tool returns the typed preview without adding any publication or credential capability.
- Tests cover all target identities, deterministic hashes, target differences, missing or invalid typed source, path redaction, and source substitution failure.
- Workspace format, tests, clippy with denied warnings, RustSec audit, and hosted PostgreSQL integration pass.

## Edge cases

- persona.toml is missing, malformed, oversized, or replaced by a symlink.
- Optional rules.toml, skills.toml, or patterns.toml changes between validation and preview reads.
- A draft is publication-invalid for reasons unrelated to typed source but its structured preview is still renderable.
- Codex and Generic share an install filename but produce different content.
- Rendered output contains long strings or Unicode and must hash exact UTF-8 bytes.
- An MCP caller attempts to infer or elicit the managed draft root from an error.

## Interface contract

```text
frameshift-studio exposes a read-only DraftPreview containing the draft revision, exact current inventory hash and validation report, plus four deterministic TargetPreview values with target ID, install filename, content, and content hash. Preview is constructed from nofollow bounded copies of the exact managed typed source and exposes no filesystem path. frameshift-mcp adds one read-only frameshift_draft_preview tool returning that value; it cannot confirm review, submit, publish, access credentials, or mutate a draft.
```

## Decision: Verified temporary source snapshot in frameshift-studio

- **why:** Copy only the validated typed source files through existing bounded nofollow reads into a private temporary directory, load with frameshift-source, render all targets, then revalidate the managed draft before returning a path-free result.
- **alternative:** Render directly from managed draft directory -- rejected: Loader metadata reads can follow symlinks; Validation-to-render race can mix revisions; Source errors can embed private paths
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

## Verification evidence

- `cargo fmt --all -- --check` -- passed
- `cargo test --target-dir ../../build-cache/frameshift-target --workspace` -- passed
- `cargo clippy --target-dir ../../build-cache/frameshift-target --workspace --all-targets -- -D warnings` -- passed
