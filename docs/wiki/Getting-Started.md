# Getting Started

## Prerequisites

- Rust toolchain (edition 2021)
- A coding agent that reads AGENTS.md, CLAUDE.md, or GEMINI.md (Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, Cline, opencode, Goose)

## Build from source

```bash
git clone https://github.com/Ghost-Frame/FrameShift.git
cd FrameShift
cargo build --release
```

The CLI binary lands at `target/release/frameshift-cli`.

## Install and activate a persona

The fastest path is `frameshift use`, which installs, activates, and prints the rendered persona in one call:

```bash
frameshift use cryptographic --from ./personas
```

Or step by step:

```bash
# Install from a local directory:
frameshift install cryptographic@0.1.0 --from-path ./personas/cryptographic

# Activate it for the current project:
frameshift activate cryptographic
```

## What happens on install

1. The CLI reads the persona's `pack.toml` manifest.
2. It computes a deterministic SHA-256 hash of the pack contents. The canonical hash walks all files sorted by NFC-normalized path and hashes `path\0length\0bytes\0` for each entry. The `signature.sig` file is excluded from the hash.
3. It copies the pack into the content-addressed cache at `$XDG_DATA_HOME/frameshift/cache/<hash>/`.
4. It records the persona in the project's `lock.toml` with the exact version, hash, and author public key.
5. It renders the persona source into per-agent markdown under `rendered/{claude,codex,gemini,generic}/`. Each target gets output optimized for that agent's conventions:
   - **claude** -- Renders to `CLAUDE.md`. Full output including design notes and safety layer.
   - **codex** -- Renders to `AGENTS.md`. Omits design notes and safety layer.
   - **gemini** -- Renders to `GEMINI.md`. Omits design notes.
   - **generic** -- Renders to `AGENTS.md`. Full output (same as Claude).

Your project tree is never written to. All state lives under `$XDG_DATA_HOME/frameshift/`.

## Infrastructure overlay

If `$XDG_CONFIG_HOME/frameshift/infrastructure.md` exists, its contents are prepended to every rendered persona under a `## Persona Context` header with the active persona name. This lets you inject machine-specific context (paths, credentials references, server aliases) without modifying persona source.

## Verify the installation

```bash
# Print the hashed project ID:
frameshift project-id

# Check what's installed:
frameshift sync
```

## Run from source (without installing the binary)

```bash
cargo run -p frameshift-cli -- use cryptographic --from ./personas
cargo run -p frameshift-cli -- select --task "optimize a hot loop" --format json
```

## Next steps

- [[Automate Mode]] -- Let the engine pick personas automatically
- [[CLI Reference]] -- Full command reference
- [[Writing Personas]] -- Create your own
