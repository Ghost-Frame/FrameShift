# Documentation Sources

The Markdown in this directory is the reviewed source for the public
[Frameshift Wiki](https://github.com/Ghost-Frame/FrameShift/wiki). GitHub renders
the Wiki from its associated Git repository, but public edits begin here so they
receive the same review and validation as product changes.

The initial source set preserves every page from public Wiki commit
`017548e6b07e5df47053c031b30f3974ea0f6d38`. The wording of two destructive
command examples in `Writing-Personas.md` was made descriptive during import;
the product claims and all other content were preserved.

## Source map

| Page | Primary evidence |
|---|---|
| `Home.md` | `README.md`, workspace manifest, public license files |
| `Getting-Started.md` | `crates/frameshift-cli/src`, `crates/frameshift-client/src` |
| `How-It-Works.md` | `crates/frameshift-pack/src`, `crates/frameshift-source/src` |
| `CLI-Reference.md` | `crates/frameshift-cli/src/main.rs` and command modules |
| `Automate-Mode.md` | `crates/frameshift-orchestrator/src`, CLI automate commands |
| `MCP-Server.md` | `crates/frameshift-mcp/src` |
| `Configuration.md` | server, daemon, client, and vault configuration types |
| `Persona-Catalog.md` | public persona manifests and capability declarations |
| `Writing-Personas.md` | `crates/frameshift-source/src`, `crates/frameshift-pack/src` |
| `Creator-Studio.md` | `crates/frameshift-studio/src`, MCP draft tools, and publication bindings |
| `Accounts-and-Publisher-Identity.md` | account session, publisher membership, and local and remote key lifecycle code |
| `Publishing-and-Moderation.md` | Studio submission snapshots, publication client, catalog states, and moderation routes |
| `Composition.md` | `crates/frameshift-compose/src` |
| `Pack-Format.md` | `crates/frameshift-pack/src` |
| `Conformance.md` | `crates/frameshift-conformance/src` |
| `Growth-System.md` | `crates/frameshift-growth/src` |
| `Memory-Integration.md` | `crates/frameshift-memory*/src` |
| `Architecture.md` | workspace manifest and public crate entry points |
| `Operations-and-Observability.md` | server metrics registry, metrics middleware, operational routes, and ownership backfill contract |
| `Trust-and-Security.md` | pack, registry, client, capability, publication, and Studio trust boundaries |
| `Local-Data-and-Privacy.md` | client state model, session store, selection telemetry, vault, and CLI data operations |
| `Security-Reporting-and-Known-Limits.md` | repository security policy, release workflow, and public artifact notices |
| `Troubleshooting.md` | CLI handlers, client errors, MCP runtime, and validation failures |
| `_Sidebar.md` | Canonical page inventory in this directory |
| `_Footer.md` | Public repository identity |
| `SOURCES.md` | This documentation supply-chain contract |

## Validation

Run:

```bash
scripts/wiki-docs.sh validate
```

The validator checks page naming, navigation coverage, prose Wiki links,
source-map coverage, and public-content guardrails. It ignores Wiki-like TOML
syntax inside fenced code blocks.

## Publishing contract

Publication is deliberately separate from validation. To prepare an update:

1. Merge the reviewed core documentation change.
2. Clone `https://github.com/Ghost-Frame/FrameShift.wiki.git` into a clean
   temporary directory.
3. Run `scripts/wiki-docs.sh stage /path/to/clean/wiki/checkout`.
4. Review the staged Wiki diff.
5. Commit and push through an explicitly authorized GitHub identity.
6. Run `scripts/wiki-docs.sh check /path/to/wiki/checkout` and inspect the public
   Wiki.

The staging command refuses a dirty checkout, an unexpected remote, or any
remote Markdown page that is not represented here. It never commits, pushes,
or deletes a page.
