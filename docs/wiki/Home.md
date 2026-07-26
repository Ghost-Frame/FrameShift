# Frameshift

**Same model. Different frame.**

Frameshift is a persona engine for AI coding agents. It packages complete behavioral identities -- not instruction lists -- as versioned, signed, composable packs that you install per-project and switch on demand.

A persona survives long sessions, surprising inputs, and the slow drift that turns careful agents into sloppy ones around turn 200.

## Quick links

- [[Getting Started]] -- Install and activate your first persona
- [[How It Works]] -- Pack system, content addressing, rendering pipeline
- [[Automate Mode]] -- Let the engine pick the right persona for the task
- [[Persona Catalog]] -- All 37 available personas
- [[Architecture]] -- Crate map and dependency graph
- [[Writing Personas]] -- Author your own persona packs
- [[CLI Reference]] -- Every command and flag
- [[MCP Server]] -- Agent integration via Model Context Protocol
- [[Memory Integration]] -- Pluggable memory backends
- [[Growth System]] -- Local learning that persists across sessions
- [[Pack Format]] -- Content-addressed signed tarballs
- [[Composition]] -- Extend and mix personas
- [[Conformance]] -- Test bundles and upgrade regression gates
- [[Configuration]] -- Server, daemon, and environment variables

## What Frameshift is not

Frameshift is not a prompt template library. Templates drift under pressure because they encode priorities as ranked lists. Frameshift encodes identity as a coherent stance using Schubert's L1/L2/L3 behavioral architecture, which survives context erosion where ranked lists collapse.

Frameshift is not a model fine-tune. It works with any agent that reads AGENTS.md, CLAUDE.md, or GEMINI.md -- Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, Cline, opencode, Goose, and others. Same model, different frame.

## License

The runtime, engine, and tooling are licensed under [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license). Persona content in `personas/` is open source.
