<p align="center">
  <img src="personas/assets/banner.png" alt="Frameshift" width="100%" />
</p>

# Frameshift (WIP)

A persona engine for AI coding agents. Install behavioral identities as versioned packs, activate them per-project, and let the engine pick the right one for the task.

**Status:** The CLI, pack system, orchestrator, and watch daemon work. The marketplace server and web frontend do not -- both are under active development. You can clone this repo and use the personas today via the CLI.

Personas are not instruction lists. They are complete behavioral frames -- identity, rules, skills, operating posture -- that survive long sessions, surprising inputs, and the slow drift that turns careful agents into sloppy ones around turn 200. Same model, different frame.

## Quickstart

```bash
# Install + activate + render in one shot:
frameshift use cryptographic --from ./personas

# Or step by step:
frameshift install cryptographic@0.1.0 --from-path ./personas/cryptographic
frameshift activate cryptographic
```

## Automate mode

Automate mode picks the persona for you. The engine classifies your task, scores every installed persona against the project context, and switches when the domain shifts.

```bash
# Turn on for this project:
frameshift automate on

# With a sensitivity dial (0.0 = stable, 1.0 = responsive):
frameshift automate on --sensitivity 0.7

# Check current state:
frameshift automate status
```

The selection pipeline scores four components: language overlap (how well the persona's language set matches your project), lexical match (IDF-weighted task token hits against persona keywords), intent alignment (10-category task classification), and capability fit. Scores blend into a ranked list with confidence values.

### Intent classification

The engine classifies task descriptions into one of ten intents: Implementation, Debugging, Review, Security, Writing, Ops, Testing, Refactoring, Performance, and Design. Personas declare which intents they handle best. A persona built for debugging scores higher when the task looks like debugging.

### Selection output

```bash
# Table format (default):
frameshift select --task "debug a rust compilation error" --library ~/.local/share/frameshift/personas

# Structured JSON for programmatic consumption or LLM reranking:
frameshift select --task "debug a rust compilation error" --library ~/.local/share/frameshift/personas --format json
```

JSON output includes the full context snapshot (detected languages, frameworks, inferred intent), per-candidate component scores, matched tokens, and rationale. Host LLMs can rerank using this data.

### Feedback loop

When the engine picks wrong, record the override. The engine adjusts per-persona bias for future selections, with optional intent context and time decay.

```bash
frameshift feedback --auto-pick web-designer --chosen rust --intent debugging
```

## How it works

Personas distribute as signed packs -- content-addressed tarballs with Ed25519 signatures and capability manifests. The CLI installs them into a central store outside your project tree. Your repo never gets persona files.

All state lives in `$XDG_DATA_HOME/frameshift/`:

```
cache/<sha256>/                               # Content-addressed pack cache
projects/<project-id>/
  config.toml                                 # Declared dependencies
  lock.toml                                   # Exact versions, hashes, author pubkeys
  active                                      # Currently active persona name
  personas/<name>/
    source/                                   # Pack contents (AGENTS.md + pack.toml)
    rendered/{claude,codex,gemini,generic}/    # Per-agent rendered output
    growth.jsonl                              # Structured growth log (JSONL)
  orchestrator/                               # Automate mode, preferences, audit log
```

Project ID is `sha256(realpath(project_root))`. Your project tree is never written to.

## Persona source format

A persona is a directory with two files:

```
personas/<name>/
  AGENTS.md     # Persona body: identity, rules, frame, skills, growth integration
  pack.toml     # Manifest: name, version, license, author, capabilities
```

Example `pack.toml`:

```toml
schema_version = 1
name = "cryptographic"
version = "0.1.0"
author_handle = "ghost-frame"
author_pubkey = "ed25519:<hex>"
license = "Elastic-2.0"

[capability_manifest]
required_tools = ["Read", "Edit", "Write", "Bash"]
network_egress = false
primary_intents = ["implementation", "security"]
anti_keywords = ["frontend", "css", "react"]
```

`primary_intents` declares which task categories the persona handles best. `anti_keywords` lists tokens that should repel the selection engine away from this persona. Both fields are optional.

`AGENTS.md` is freeform markdown. Structure follows the behavioral-architecture pattern described in `personas/README.md`.

A typed-source format (structured TOML with semantic diffs and patch operations) lives in the `frameshift-source` crate as the next-generation persona representation.

## Growth

Growth is local. Each persona accumulates structured learning entries as JSONL -- things learned, mistakes caught, patterns discovered. Entries carry session attribution, task context, and intent classification.

```bash
frameshift grow append rust "orphan rules prevent implementing foreign traits on foreign types"
```

Growth entries have two scopes. Project-scope entries stay with one project. Global-scope entries apply everywhere. The engine summarizes recent growth by deduplicating near-identical entries and picking the most recent per intent category.

Legacy `growth.md` files migrate to JSONL with `migrate_growth_md`.

## Memory

Personas can declare a memory requirement in their pack manifest. The runtime satisfies it through a pluggable adapter trait with backends for HTTP APIs and local SQLite. Any knowledge system that exposes store/search/recall endpoints works -- [Kleos](https://github.com/Ghost-Frame/Kleos) is the reference integration.

## CLI

```
frameshift install <name@version> [--from-path <dir>]   Install a persona pack
frameshift activate <name>                               Set active persona for this project
frameshift use <name> --from <library>                   Install + activate + print rendered output
frameshift select [--task TEXT] [--library DIR]           Rank personas by score/confidence/rationale
           [--format table|json]
frameshift automate on [--sensitivity 0.0-1.0]           Enable automate mode
frameshift automate off                                  Disable automate mode
frameshift automate status                               Print mode, sensitivity, active persona
frameshift automate lock|unlock                          Pin/unpin current persona
frameshift feedback --chosen <name> [--auto-pick <name>] Record a selection override
           [--intent <intent>] [--reason <text>]
frameshift grow append <persona> <text>                  Append to a persona's growth log
frameshift prefs [show|reset]                            View or reset preference biases
frameshift sync                                          Reconcile store with lockfile
frameshift migrate                                       Move legacy files into central store
frameshift gc                                            Remove unreferenced cache entries
frameshift diff <a> <b>                                  Semantic diff between two personas
frameshift render <persona>                              Render persona source to markdown
frameshift verify <persona>                              Run conformance checks
frameshift publish <persona>                             Publish a persona pack
frameshift project-id                                    Print hashed project ID
```

## What this repo contains

- `crates/` -- Rust workspace: CLI, client engine, pack tooling, composition, conformance, catalog, memory, vault, object storage, HTTP server, MCP server, watch daemon, orchestrator, growth
- `personas/` -- pack manifests for the persona library

## Building

```bash
cargo build
cargo test
```

### Running from source

```bash
cargo run -p frameshift-cli -- use cryptographic --from ./personas
cargo run -p frameshift-cli -- select --task "optimize a hot loop" --format json
```

## Configuration

### Server

| Variable | Default | Purpose |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:3000` | HTTP bind address |
| `POSTGRES_URL` | `""` | PostgreSQL connection URL |
| `OBJECT_STORE_ROOT` | `/tmp/frameshift-objects` | Filesystem object store root |
| `LOG_LEVEL` | `info` | Log filter |
| `LOG_FORMAT` | `text` | `text` or `json` |
| `MAX_REQUEST_BYTES` | `1048576` | Max request body size |
| `MAX_SEARCH_LIMIT` | `200` | Max search `limit` |
| `SHUTDOWN_GRACE` | `30` | Grace period in seconds |

## License

Elastic License 2.0. See [LICENSE](LICENSE) for details.

### Commercial licensing

The Elastic License 2.0 prohibits offering Frameshift to third parties as a
hosted or managed service. To sell, host, or distribute Frameshift on your own
platform, contact us for a commercial license: support@syntheos.dev.
