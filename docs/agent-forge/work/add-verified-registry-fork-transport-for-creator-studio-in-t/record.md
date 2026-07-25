> **Review priority:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved. The criteria were exercised, so read the decisions below for judgment rather than for correctness.

# Record: Add verified registry fork transport for Creator Studio in the core frameshift repository.

- **spec:** `spec_2455b79b`
- **type:** feature

## Acceptance criteria

- An exact name and semantic version are fetched from the configured registry without resolving mutable latest aliases.
- The raw downloaded gzip-tar bytes must match the immutable registry content_hash before extraction.
- The extracted pack signature must verify against the registry version record Ed25519 key before any draft becomes visible.
- The signed source manifest must explicitly set forkable=true; license text alone never grants fork permission.
- Studio atomically copies only the validated public inventory, excludes signature material, preserves the source license, rewrites target name/version/author identity, and records exact source name/version/raw archive hash in forked_from.
- Failure at any validation, transport, permission, rewrite, or publication boundary leaves no draft directory.
- MCP exposes a bounded backward-compatible fork creation mode with exact source version and target identity fields.
- Tests cover happy path, non-forkable source, archive hash mismatch, signature mismatch, identity mismatch, safe copying, attribution/license preservation, and atomic failure.
- Formatting, focused tests, workspace tests, Clippy with warnings denied, audit, comment checks, and leak-screened Agent-Forge review pass.

## Edge cases

- Registry record name or version differs from the exact requested resource.
- Archive is oversized, malformed, nested, path-traversing, symlinked, or contains too many entries.
- Registry signature is absent, malformed, or valid for a different key.
- Source manifest is legacy and omits forkable, which must default to false.
- Source contains signature.sig, private-looking files, or non-public paths; only publication inventory may cross into the draft.
- Source has persona.toml identity fields that must be rewritten consistently with pack.toml.
- Target identity equals source identity and would violate the fork provenance contract.
- Draft ID already exists or the source changes during copy.

## Interface contract

```text
Client owns exact immutable registry transport and cryptographic verification, then invokes Studio with a verified extracted directory plus exact ForkOrigin. Studio owns bounded target identity validation and atomic public-inventory rewrite. MCP accepts template_mode=fork with a nested bounded fork object containing source_name, source_version, target name/version/author_handle/author_pubkey/forkable. Existing create/import/blank/guided requests retain their behavior.
```

## Decision: Client-owned verified fetch plus atomic Studio fork import

- **why:** Refactor the client registry installer around an internal owned verified-pack result. Install caches it; the new client fork API passes its temporary root and exact ForkOrigin to Studio, which stages, rewrites, validates, and atomically publishes.
- **alternative:** Move registry transport into a new lower-level crate -- rejected: Large public workspace expansion for one slice; Duplicates or moves trust-pin ownership; Higher compatibility and review surface
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

## Verification evidence

- `cargo test -p frameshift-studio -p frameshift-client -p frameshift-mcp --target-dir ../../build-cache/frameshift-target` -- failed
- `cargo test -p frameshift-studio -p frameshift-client -p frameshift-mcp --target-dir ../../build-cache/frameshift-target` -- passed
