# Pack Format

Persona packs are content-addressed, signed archives designed for deterministic distribution.

## Structure

A runtime-complete pack can be a directory containing one `pack.toml`:

```
my-persona/
  pack.toml       # Manifest plus inline typed source
```

The same typed schema may be split into `persona.toml`, `rules.toml`, `skills.toml`, and `patterns.toml`. Freeform Markdown bodies also remain supported. Inline source is marked by a top-level `[voice]` table; a `pack.toml` without `[voice]` is metadata-only.

## Pack manifest schema

```toml
schema_version = 1
name = "my-persona"
author_handle = "ghost-frame"
author_pubkey = "local-unsigned"   # local-path installs only
version = "0.1.0"
license = "Elastic-2.0"

# Optional: parent version for upgrade chains
parent_hash = "sha256:..."

# Optional: composition
extends = "base-persona@^1"
mixin = ["company-style@2.x", "safety-overlay@1.x"]

# Optional: capability declaration
[capability_manifest]
required_tools = ["Read", "Edit", "Write", "Bash", "Grep", "Glob"]
network_egress = false
filesystem_scope = "project-only"    # "none", "project-only", "home", "system"
memory_required = "none"             # "none", "soft", "hard"
memory_required_ops = []             # "store", "search", "recall", "list", "forget", "health"
env_vars_read = []
primary_intents = ["implementation"]
anti_keywords = ["frontend", "css"]

# Optional: target requirements
[requires]
targets = ["assistant", "coder"]

# Optional: user-provided tokens
[tokens_required.favorite_motto]
type = "string"
prompt = "What is your favorite motto?"
optional = true

# Optional: conformance baseline for upgrade gating
[conformance_baseline]
score = 0.92
bundle_hash = "sha256:..."
```

## Inline typed source

Manifest fields and typed behavior share the same document. The loader reads each schema view independently, so fields owned by the manifest, persona, rules, skills, and patterns do not need wrapper tables.

```toml
[voice]
tone = "precise and evidence-driven"

[[voice.questions]]
text = "Which layer owns this truth?"

[[rule]]
id = "single-authority"
layer = "L1"
text = "Give each mutable transition exactly one authoritative owner."
```

An inline pack renders directly to every supported target. If `[voice]` is present but malformed, installation fails instead of falling back to Markdown.

## Content addressing

Pack contents are hashed deterministically:

1. Recursive directory walk with files sorted by NFC-normalized path.
2. For each file, concatenate `path\0length\0bytes\0` (null-byte separated).
3. SHA-256 of the full concatenated byte stream.
4. The `signature.sig` file is excluded from the hash calculation.

Identical contents always produce the same hash, regardless of filesystem ordering, OS, or platform.

### Size limits

| Limit | Value |
|---|---|
| Maximum total pack size | 5 MB |
| Maximum file count | 50 |
| Maximum single file size | 1 MB |

## Signing

Packs are signed with Ed25519:

```toml
author_handle = "ghost-frame"
author_pubkey = "<64-lowercase-hex-characters>"
```

The signature covers the canonical hash. The signature is stored in `signature.sig` (64 bytes raw) and is verified against the declared public key.

Unsigned local packs use `author_pubkey = "local-unsigned"`. The sentinel is valid for local-path installation but is rejected at publication and registry trust boundaries.

## Cache layout

Installed packs live in the content-addressed cache:

```
$XDG_DATA_HOME/frameshift/cache/<sha256-hex>/
```

Multiple projects can share the same cached pack. The cache is a flat directory keyed by hash.

## Lockfile

Each project tracks installed packs in `lock.toml`:

```toml
[[persona]]
name = "cryptographic"
version = "0.1.0"
hash = "sha256:<hex>"
author_handle = "ghost-frame"
author_pubkey = "<64-lowercase-hex-characters>"
```

The lockfile records the exact version, hash, and author identity. `frameshift sync` reconciles the lockfile with the cache.

## Garbage collection

```bash
frameshift gc
```

Removes cache entries not referenced by any project's lockfile. Safe to run at any time.

## Object store

On the marketplace server, pack archives are stored in a content-addressed object store via the `PackStore` trait:

- **Filesystem backend** -- Two-level sharded directory tree (`aa/bb/<64-char-hex>`). Atomic writes via temp file + rename. Optional quota enforcement. Optional verify-on-read for corruption detection.
- **Cloudflare R2 backend** -- S3-compatible. Flat key layout (no sharding). Configured via standard AWS SDK environment variables.

Both backends enforce verify-on-write: the SHA-256 of the stored bytes must match the declared hash.
