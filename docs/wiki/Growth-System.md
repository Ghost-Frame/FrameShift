# Growth System

Growth is how personas learn locally. Each installed persona accumulates a log of observations -- things learned, mistakes caught, patterns discovered -- that persists across sessions.

## How it works

1. On session start, the agent reads the growth log.
2. During the session, the agent appends observations as they emerge.
3. On the next session, the new observations are available as context.

Growth is local-only. It never leaves your machine. It never flows upstream to the marketplace.

## Dual storage format

Growth supports two formats. Both can coexist for the same persona.

### JSONL (current)

Structured entries in `growth.jsonl`, one JSON object per line:

```
$XDG_DATA_HOME/frameshift/projects/<project-id>/personas/<name>/growth.jsonl
```

Each `GrowthEntry` carries:

| Field | Type | Description |
|---|---|---|
| `ts` | string | RFC 3339 timestamp |
| `session` | string | Session identifier |
| `project_id` | string | Hashed project ID |
| `persona` | string | Persona name |
| `auto_selected` | bool | Whether the persona was auto-selected by automate mode |
| `task` | string | Task context |
| `intent` | string | Intent classification |
| `text` | string | The observation |
| `scope` | string | `"project"` or `"global"` |

### Markdown (legacy)

Freeform entries in `growth.md` with timestamped markers:

```markdown
---
<!-- growth: 2026-05-25T10:30:00Z -->

The observation text goes here.
```

Legacy growth files are migrated to JSONL via `frameshift migrate`.

## Scopes

Growth entries have two scopes:

- **Project-scope** -- Stored per-project. "This codebase uses thiserror 2.x, not 1.x." Path: `projects/<pid>/personas/<name>/growth.jsonl`.
- **Global-scope** -- Stored per-persona across all projects. "Always check the migration order before running diesel." Path: `personas/<name>/growth.jsonl` (at the data root, not inside a project).

## Summarization

The engine summarizes recent growth using deduplication and selection:

1. **Jaccard deduplication.** If two entries have a Jaccard token overlap greater than 0.5, they are considered duplicates and the older one is dropped.
2. **Per-intent selection.** For each intent category, the most recent entry is kept.
3. **Cap.** At most 10 entries are returned in a summary.

This keeps the growth context concise and avoids repeating near-identical observations.

## CLI

```bash
# Append a growth entry:
frameshift grow append rust "orphan rules prevent implementing foreign traits on foreign types"
```

## Growth vs. memory

| | Growth | Memory |
|---|---|---|
| **Scope** | Per-persona, per-project (or global) | Cross-persona, cross-project |
| **Storage** | Local JSONL (or legacy markdown) | Pluggable backend (HTTP, SQLite FTS) |
| **Visibility** | Only the persona that wrote it | Any persona that searches for it |
| **Persistence** | Always local | Depends on backend |
| **Purpose** | Session-to-session learning | Long-term knowledge retrieval |

Growth is the persona's private notebook. Memory is the shared knowledge base.
