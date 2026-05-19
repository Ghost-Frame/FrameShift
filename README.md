<p align="center">
  <img src="personas/assets/banner.png" alt="Frameshift" width="100%" />
</p>

# Frameshift

A runtime and marketplace for versioned, composable behavioral personas for AI coding agents.

Personas are not instruction lists. They are complete behavioral identities -- typed source (structured TOML) that renders to per-agent markdown (Claude, Codex, Gemini). A persona survives long sessions, surprising inputs, and the slow drift that turns careful operators into sloppy ones around turn 200.

## What this repo contains

- `crates/` -- Rust workspace (20 crates): CLI, client engine, pack tooling, composition, conformance, catalog, memory, vault, object storage, HTTP server
- `personas/` -- pack manifests for the persona library (see the [deep product writeup](personas/README.md))

## How it works

Personas distribute as signed packs -- content-addressed tarballs with Ed25519 signatures and capability manifests. The CLI installs them into a central store outside your project tree. Your repo never gets persona files.

```bash
frameshift install cryptographic@0.3.1
frameshift activate cryptographic
```

All state lives in `$XDG_DATA_HOME/frameshift/`:

```
cache/<sha256>/                          # Content-addressed pack cache
projects/<project-id>/
  config.toml                            # Declared dependencies
  lock.toml                              # Exact versions, hashes, author pubkeys
  active                                 # Currently active persona
  personas/<name>/
    source/                              # Pack contents (TOML + markdown)
    rendered/{claude,codex,gemini,generic}/   # Per-agent rendered output
    growth.md                            # Local-only, append-only
```

Project ID is `sha256(realpath(project_root))`. Your project tree is never written to.

## Persona source format

Personas are structured TOML, not freeform markdown. Markdown is a render target.

```toml
# persona.toml
schema_version = 1
name = "cryptographic"
voice = "citation-driven, careful, willing to say I don't know"

[anchor.l2]
text = "You are working on cryptographic primitives, verifying not inventing"

[[default_questions]]
question = "Which specification or RFC governs this code?"
```

```toml
# rules.toml
[[rule]]
id = "no-rolling-crypto"
layer = "L1"
text = "Never roll a new cryptographic primitive when an audited implementation exists."
```

```toml
# skills.toml
[[skill]]
id = "test-driven-development"
invoke_when = "All cryptographic implementations -- tests BEFORE code"
```

Patch operations replace hand-editing. Semantic diffs show typed changes between versions, not text diffs.

## Growth

Growth is local. A single append-only file per installed persona, stored in the central store. Sessions deposit findings -- things learned, mistakes caught, patterns discovered. Future sessions read them back. Growth never flows upstream -- it stays on your machine, in your project context.

A persona is not static. It remembers what happened last time.

## CLI

```
frameshift install <name@version>            # Install a persona pack
frameshift install <name@version> --from-path <dir>  # Install from local directory
frameshift activate <name>                   # Set active persona for this project
frameshift sync                              # Reconcile central store with lockfile
frameshift gc                                # Remove unreferenced cache entries
frameshift project-id                        # Print hashed project ID
```

## Building

```bash
cargo build
cargo test
```

### Running from source

```bash
cargo run -p frameshift-cli -- project-id
cargo run -p frameshift-cli -- install cryptographic@0.1.0 --from-path personas/cryptographic
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

AGPL-3.0. See [LICENSE](LICENSE) for details.

## Further reading

- [Persona deep dive and product writeup](personas/README.md)
