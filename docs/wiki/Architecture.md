# Architecture

Frameshift is a Rust workspace of 28 packages organized in layers. Each layer has a clear role, and crates within a layer depend only on lower layers.

## Simplified layer diagram

```
                          ┌─────────────────┐
                          │  frameshift-cli  │  (binary)
                          │  frameshift-mcp  │  (binary)
                          │  frameshift-seed │  (binary)
                          └────────┬────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
     ┌────────▼────────┐  ┌───────▼────────┐   ┌───────▼────────┐
     │ frameshift-daemon│  │frameshift-server│  │ frameshift-     │
     │ (background IPC) │  │ (HTTP API)     │   │ runtime         │
     └────────┬────────┘  └───────┬────────┘   └───────┬────────┘
              │                    │                     │
    ┌─────────┴──────────┐  ┌─────┴──────────┐  ┌──────┴──────────┐
    │frameshift-          │  │frameshift-      │  │frameshift-vault │
    │orchestrator         │  │catalog-postgres │  │frameshift-vault-│
    │(automate mode)      │  │frameshift-      │  │local            │
    │                     │  │objects-fs       │  │frameshift-      │
    │                     │  │frameshift-      │  │template         │
    │                     │  │objects-r2       │  │frameshift-memory│
    └─────────┬──────────┘  └─────┬──────────┘  │-http / -sqlite  │
              │                    │              └──────┬──────────┘
    ┌─────────▼──────────┐  ┌─────▼──────────┐         │
    │frameshift-compose   │  │frameshift-     │  ┌──────▼──────────┐
    │(persona composition)│  │catalog (trait) │  │frameshift-memory│
    └─────────┬──────────┘  │frameshift-     │  │(adapter trait)  │
              │              │objects (trait) │  │frameshift-vault │
    ┌─────────▼──────────┐  └─────┬──────────┘  │(vault trait)    │
    │frameshift-source    │        │              └─────────────────┘
    │(TOML schema,        │        │
    │ render, diff, patch)│        │
    └─────────┬──────────┘        │
              │                    │
    ┌─────────▼────────────────────▼──────────┐
    │           frameshift-pack                │
    │  (content addressing, signing, manifest) │
    └──────────────────────────────────────────┘
```

## Crate reference

### Foundation

| Crate | Role |
|---|---|
| `frameshift-pack` | Content addressing (SHA-256 canonical hash), Ed25519 signing, pack manifest schema, capability manifests, object hash type. Every other crate depends on this. |

### Persona source and composition

| Crate | Role |
|---|---|
| `frameshift-source` | Structured TOML persona schema (`persona.toml`, `rules.toml`, `skills.toml`, `patterns.toml`). Rendering to per-target markdown, semantic diffing, typed patch operations, content validation, security audit. Load safety limits: 1 MiB per file, 500 rules, 200 skills, 500 patterns. |
| `frameshift-compose` | Resolves `extends` (base persona) and `mixin` overlays. Deterministic layer merge with conflict detection. SD6 L1 override protection: mixins cannot override L1 rules from the base. |
| `frameshift-template` | Token placeholders (`{{name}}`) and section overlays (`<!-- section:id -->`) for persona templates. Validation, manifest-driven rendering. |

### Core engine

| Crate | Role |
|---|---|
| `frameshift-client` | Install, activate, sync, render, garbage collect. Manages the central store, lockfile, and cache. Infrastructure overlay injection. Legacy migration. Render targets: claude to CLAUDE.md, codex to AGENTS.md, gemini to GEMINI.md, generic to AGENTS.md. |
| `frameshift-growth` | Dual-format growth log: append to `growth.md` (legacy markdown) or `growth.jsonl` (structured JSONL). Summarization with Jaccard deduplication. Migration between formats. |
| `frameshift-capabilities` | Runtime capability sandbox. Filters tool access against pack manifests. Tracks usage and reports unused/undeclared capability invocations. |
| `frameshift-conformance` | Test bundle schema, runner trait, multi-strategy scoring (substring, regex, JSON shape, custom caller), and upgrade regression gate. |
| `frameshift-publication` | Deterministic, fail-closed validation for public persona directories. Produces versioned reports and a stable inventory hash for exact-artifact review. |
| `frameshift-studio` | Secure local Creator Studio draft lifecycle. Keeps private metadata outside publishable content and invalidates review or submission intent after mutations. |

### Orchestration

| Crate | Role |
|---|---|
| `frameshift-orchestrator` | Automate mode: context sensing (language detection, framework markers, task tokenization with domain cluster expansion), intent classification (10 categories), four-component persona ranking (language F1, IDF-weighted lexical, intent relatedness, capability heuristic), hysteresis switch controller (z-score + gap tests + debounce), preference learning with time decay, audit logging. |
| `frameshift-embed-candle` | Optional local semantic embeddings for persona selection. Pins the model revision and degrades to lexical ranking when the model or cache is unavailable. |
| `frameshift-daemon` | Background daemon with JSON-RPC 2.0 IPC over Unix socket. File watcher drives orchestrator evaluation on project changes. Methods: project_id, install, activate, sync, gc, grow.append, shutdown. |

### Memory

| Crate | Role |
|---|---|
| `frameshift-memory` | `MemoryAdapter` async trait: store, search, recall, list, forget, health. Memory struct with id, text, tags, metadata, timestamps. Filter support for tags, time ranges, metadata. |
| `frameshift-memory-http` | HTTP-backed adapter for external memory services. Bearer token auth, configurable timeout. |
| `frameshift-memory-sqlite-fts` | SQLite FTS5 adapter for local full-text search. WAL mode, BM25 ranking, tag intersection filtering, time-range queries. |

### Vault and secrets

| Crate | Role |
|---|---|
| `frameshift-vault` | `VaultBackend` trait and canonical TOML schema. Sections: identity (keypair_pub, handle), auth (methods, unlock), preferences (runtime_mode, publish_intent, recovery), memory (backend, endpoint, auth), variables (arbitrary key-value secrets), overlays (per-agent text blocks keyed by "agent.slot"). |
| `frameshift-vault-local` | Filesystem backend using age encryption with scrypt passphrase recipients. Atomic writes via temp-file-and-rename. Plaintext zeroized in memory via the `zeroize` crate. File permissions 0o600. |

### Runtime

| Crate | Role |
|---|---|
| `frameshift-runtime` | Loads vault, template, and memory into a single renderable unit. Validates all tokens and sections at load time against the template manifest. Checks required tokens exist in vault. `render()` is infallible after `load()` succeeds. |

### Marketplace and distribution

| Crate | Role |
|---|---|
| `frameshift-catalog` | `CatalogBackend` async trait. Author management, pack publishing, search, version resolution, tombstoning. |
| `frameshift-catalog-postgres` | PostgreSQL implementation via diesel-async + bb8 pooling. Embedded migrations. |
| `frameshift-objects` | `PackStore` async trait. Content-addressed put/get/delete/list with verify-on-write (SHA-256 of bytes must match declared hash). |
| `frameshift-objects-fs` | Filesystem backend. Two-level sharded directory tree (`aa/bb/hash`), atomic rename, optional quota counter (atomic u64), optional verify-on-read, fsync-on-put for durability. |
| `frameshift-objects-r2` | Cloudflare R2 (S3-compatible) backend. Flat key layout (no sharding needed). |
| `frameshift-server` | Axum HTTP API. Routes cover pack discovery and download, accounts and publishers, publication intents and submissions, moderation and administration, health, and metrics. Legacy author and pack publication routes remain available. Middleware includes request IDs, tracing, compression, body limits, CORS, and rate limiting. |
| `frameshift-seed` | One-shot seeder binary for bulk-ingesting persona directories into catalog and object store. |

### Entry points (binaries)

| Crate | Role |
|---|---|
| `frameshift-cli` | CLI dispatch via clap. Persona name validation rejects path traversal and symlink escapes. Its 26 top-level commands cover accounts, persona lifecycle, source authoring, conformance, publishing, selection, Automate, configuration, and vault operations. |
| `frameshift-mcp` | Local stdio MCP server with sixteen tools and three prompts for persona runtime and bounded Creator Studio draft operations. Supports MCP revisions 2025-11-25, 2025-06-18, and 2024-11-05. |

## Design patterns

- **Adapter pattern.** Pluggable backends via async traits: `CatalogBackend`, `PackStore`, `MemoryAdapter`, `VaultBackend`. Swap implementations without touching consumers.
- **Content addressing.** Canonical SHA-256 hashes enable deduplication, integrity verification, and cache sharing across projects.
- **Local-first.** All persona state lives on your machine. Growth logs never leave your environment. The marketplace is optional.
- **Infallible render.** `Runtime::load()` validates everything upfront so `Runtime::render()` cannot fail.
- **Deterministic composition.** Base -> mixins -> root, always in declared order, with conflict detection at install time.
- **Verify-on-write.** Object stores re-hash bytes before persisting and reject mismatches. Idempotent puts: storing the same content twice is a no-op.
- **Path safety.** CLI validates persona names against traversal attacks and detects symlinks escaping the data root.
