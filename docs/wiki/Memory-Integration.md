# Memory Integration

Personas can declare a memory requirement in their pack manifest. The runtime validates it at load time and satisfies it through a pluggable adapter trait.

## Declaring memory requirements

In `pack.toml`:

```toml
[capability_manifest]
memory_required = "soft"        # "none" (default), "soft", or "hard"
memory_required_ops = ["search", "recall"]
```

- `"none"` -- Persona does not use memory.
- `"soft"` -- Persona benefits from memory but works without it.
- `"hard"` -- Persona will not activate without a configured memory backend.

Valid operations: `store`, `search`, `recall`, `list`, `forget`, `health`.

## MemoryAdapter trait

The `frameshift-memory` crate defines the adapter contract:

```rust
#[async_trait]
pub trait MemoryAdapter: Send + Sync {
    async fn store(&self, text: &str, tags: &[String], metadata: Metadata) -> Result<MemoryId>;
    async fn search(&self, query: &str, k: usize, filters: Filters) -> Result<Vec<Memory>>;
    async fn recall(&self, id: MemoryId) -> Result<Memory>;
    async fn list(&self, limit: usize, offset: usize) -> Result<Vec<Memory>>;
    async fn forget(&self, id: MemoryId) -> Result<()>;
    async fn health(&self) -> Result<HealthStatus>;
}
```

The `Memory` struct: id, text, tags, metadata, created_at, updated_at. The `Filters` struct supports tags, time ranges (after/before), and metadata key-value matching.

## Available backends

### HTTP adapter (`frameshift-memory-http`)

Connects to any memory service that implements the Frameshift memory API. Configuration is provided through the vault:

- Endpoint URL
- Bearer token authentication
- Configurable timeout and retry policy

### SQLite FTS adapter (`frameshift-memory-sqlite-fts`)

Local full-text search backed by SQLite with FTS5. No external services required.

Features:

- FTS5 full-text search with BM25 ranking
- Tag intersection filtering
- Time-range queries
- Metadata filtering
- WAL journal mode for concurrent access
- Auto-schema migration

## How the runtime validates memory

The `frameshift-runtime` crate checks memory requirements at load time (`Runtime::load()`), not at render time:

1. Read the persona's `CapabilityManifest`.
2. If `memory_required = "hard"` and no memory adapter is configured, fail with `MemoryUnconfigured`.
3. If `memory_required = "soft"` and no adapter is available, proceed without memory.
4. If `memory_required = "none"`, skip the check.

Because all validation happens during `load()`, `render()` is infallible -- it cannot fail at runtime.
