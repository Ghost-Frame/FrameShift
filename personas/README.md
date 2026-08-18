<p align="center">
  <img src="assets/banner.png" alt="Frameshift" width="100%" />
</p>

# Frameshift

**Same model. Different frame.**

Activate the cryptographer and you get a spec-anchored operator who refuses to invent primitives. Switch to systems and you get a paranoid engineer who state-checks before touching anything and has a rollback ready. Switch to writer and you get a technical editor who deletes a sentence before adding one. Same model. Different frame.

Each frame is a complete behavioral identity. Not a list of instructions. A coherent stance that survives long sessions, surprising inputs, and the slow drift that turns careful operators into sloppy ones around turn 200.

## What Frameshift is

A marketplace and runtime for versioned, composable behavioral personas for AI coding agents.

- **Public packs.** Each catalog entry is defined by its public `pack.toml`. A runtime-complete one-file pack carries typed persona fields alongside its identity, selection signals, and capability manifest.
- **Portable renders.** Typed source compiles to Claude, Codex, Gemini, and generic Markdown without requiring a separate `AGENTS.md` beside the public pack.
- **Signed distribution.** Registry releases are content-addressed, Ed25519-signed archives with deterministic canonicalization.
- **Composition.** Packs can extend a base or mix in overlays. Rule collisions and protected L1 overrides are checked during composition.
- **Local state.** The CLI manages a central store outside the project tree and keeps growth local to each installed persona.

## Persona source format

A public persona can be complete with one file:

```
personas/<name>/
  pack.toml     # Manifest, selection signals, capabilities, and typed behavior
```

`pack.toml` is independently decoded as the signed pack manifest and as typed persona source. A top-level `[voice]` table marks inline runtime source; `[[rule]]`, `[[skill]]`, `[[pattern]]`, anchors, and evaluation hooks use the same schemas as split typed-source files.

```toml
schema_version = 1
name = "mmo-simulation-engineer"
version = "0.1.0"
author_handle = "ghost-frame"
author_pubkey = "local-unsigned"
license = "Elastic-2.0"

[capability_manifest]
required_tools = ["Read", "Edit", "Write", "Bash"]
filesystem_scope = "project-only"
network_egress = false

[voice]
tone = "systems-minded and exact about ownership"

[[rule]]
id = "single-authority"
layer = "L1"
text = "Give every mutable state transition exactly one authoritative owner."
```

Metadata-only manifests omit `[voice]` and remain catalog entries rather than installable runtime personas. Split typed source and freeform Markdown packs remain supported for compatibility.

## Installation

```bash
# Install the public one-file pack directly from this checkout.
frameshift install mmo-simulation-engineer@0.1.0 \
  --from-path ./personas/mmo-simulation-engineer
frameshift activate mmo-simulation-engineer
```

All state lives in `$XDG_DATA_HOME/frameshift/`:

```
cache/<sha256>/                   # Content-addressed pack cache, shared across projects
projects/<project-id>/
  lock.toml                       # Installed personas, versions, hashes
  active                          # Currently active persona
  personas/<name>/
    source/                       # Exact installed pack contents
    rendered/{claude,codex,gemini,generic}/
    growth.md                     # Local-only, append-only
  orchestrator/                   # Per-project automate mode + audit state
```

Project ID is `sha256(realpath(project_root))`. Your project tree is never written to.

## Pack format

Registry releases archive the public pack contents, canonicalize them, hash them with SHA-256, and sign them with Ed25519. Inline packs need only `pack.toml`; split typed-source and Markdown packs archive their additional public files. `local-unsigned` is accepted only for local-path installs and is replaced by a real author key before registry publication.

## Composition

Personas can extend a base and mix in overlays:

```toml
extends = "base-persona@^1"
mixin = ["company-style@2.x", "safety-overlay@1.x"]
```

Resolution order: base -> mixins (in order) -> root persona. Conflicting rule IDs surface at install time and require explicit overrides.

## Frames

| Frame | What wakes up |
|---|---|
| `accessibility-engineer/` | Accessibility engineer. Equivalent task completion across keyboard, screen reader, zoom, contrast, and motion contexts |
| `agents/` | Agent designer. Personas, growth, supervision, multi-agent loops |
| `api-integrator/` | API glue engineer. REST, GraphQL, webhooks, OAuth, rate limits, idempotency keys |
| `architecture/` | Skeptical architect. Stress-tests proposals before they cost anything to fix |
| `bots/` | Discord bot personality engineer. Character fidelity across thousands of turns |
| `commit-curator/` | Git commit hygienist. Splits diffs into logical commits, writes clear messages |
| `creative/` | Creative coder. Aesthetic judgment over convention |
| `cryptographic/` | Cryptographer. Spec-anchored, constant-time aware, never invents primitives |
| `daily-planner/` | Morning ritual. Synthesizes loose ends into a focused plan for today |
| `data/` | Data engineer. Idempotent, observable, recoverable pipelines |
| `database/` | Database engineer. Schema design, query optimization, migrations, indexing strategy |
| `dep-updater/` | Dependency updater. Reads changelogs, runs tests, evaluates breakage risk |
| `desktop/` | Desktop and TUI engineer. Tauri, ratatui, wgpu, native feel over web-wrapper convenience |
| `devops/` | Deployment engineer. Staged rollouts, named rollback paths, fleet-wide awareness |
| `devtools/` | Tooling builder. Developer experience as the product |
| `embedded/` | Embedded engineer. ESP32, RP2040, STM32, no_std Rust, resource-constrained and real-time |
| `frontend/` | Frontend engineer. SvelteKit, Astro, Tailwind, no component library sludge |
| `gatekeeper/` | Paranoid gatekeeper. Classifies before it lets anything cross the public boundary |
| `go-engineer/` | Go engineer. Stdlib-first, table tests, context propagation, errors-as-values |
| `google-workspace-administrator/` | Google Workspace administrator. Proves tenant identity, minimizes authority, preserves data and recovery, and verifies live service outcomes |
| `incident-commander/` | Incident commander. Stabilizes user impact, preserves evidence, coordinates owners, and verifies recovery |
| `issue-triager/` | Issue triage. Labels, priorities, dedup, needs-info detection |
| `journal-keeper/` | Daily and weekly logger. Captures what was learned, done, pending, stuck |
| `kleos-archaeologist/` | Memory archaeologist. Mines accumulated memory for patterns and forgotten decisions |
| `lab/` | Experimenter. Speed over polish, findings over artifacts |
| `memory/` | Memory architect. Vector search, embedding pipelines, recall fidelity over latency |
| `mobile-dev/` | Mobile developer. iOS, Android, React Native, Flutter, native feel where it matters |
| `mmo-simulation-engineer/` | MMO simulation engineer. Keeps authoritative gameplay deterministic across servers, clients, persistence, and headless worlds |
| `orchestrator/` | Task decomposer. Dispatches subagents in parallel, supervises, integrates results |
| `performance/` | Performance analyst. Profiles before optimizing, benchmarks before claiming |
| `pr-author/` | PR author. Descriptions, reviewer selection, draft management, follow-up tracking |
| `product-strategist/` | Product strategist. Evidence-backed problem framing, prioritization, scope, and measurable outcomes |
| `python-engineer/` | Python engineer. uv, ruff, pyright, async where it earns its keep |
| `research/` | Source-grounded researcher. Refuses to paraphrase from training-data memory |
| `reviewer/` | Code reviewer. Five lenses: correctness, security, performance, style, documentation |
| `rust/` | Rust engineer. Idiomatic, clippy-strict, no unwraps in library code |
| `security/` | Security analyst. Opsec-first, classifies by noise level |
| `systems/` | Operator with steady hands. State-check first, change second, verify third |
| `testing/` | QA engineer. Finds the test that matters |
| `typescript-engineer/` | TypeScript engineer. Strict tsconfig, zod at the boundary, ESM modules |
| `unreal/` | Unreal developer. Blueprint plus C++ hybrid. Verifies API names before using them |
| `visual-director/` | Visual director. Semantic clarity, coherent art direction, deliberate variation, critique, and asset QA |
| `writer/` | Technical editor. Every sentence earns its place |

## Why frames beat instruction lists

Most agent prompts read like ranked priority lists. These drift fast. Under pressure -- long sessions, surprising inputs, multi-step debugging -- the model treats lower-ranked items as optional, then irrelevant.

Schubert's behavioral architecture work (SFP-2, the L1/L2/L3 distinction) found that identity held as a coherent stance survives that pressure where ranked lists collapse. **"You are an operator who treats production as inherited code, prefers reversible changes, narrates state, and has a rollback ready"** survives a 400-turn session. *"1. Check state. 2. Be careful. 3. Have a rollback"* does not.

Every frame is built on that L2 anchor:

- **L2 semantic framing.** Identity as coherent stance. The first sentence names who the operator is, not what they do.
- **Cascade anchors.** Re-anchor at top, middle, and end. Drift propagates upward through context; redundancy at multiple positions beats thoroughness at one.
- **L1 hard constraints.** Never-do rules with reasoning attached. Scar tissue from real incidents.
- **Forced classification.** Each frame declares a judgment axis. The agent classifies before acting. The classification is the design pressure.
- **Self-evaluation hooks.** Checklist before non-trivial actions.
- **Growth.** Frame is read-only. Growth log is append-only. Next session reads both.

## Growth

Growth is local. A single append-only file per installed persona, stored in the central store. Sessions deposit findings. Future sessions read them back. Growth never flows upstream -- it stays on your machine, in your project context.

## References

- Schubert, J. (2026). *AIReason LLM Behavioral Architecture.* https://doi.org/10.5281/zenodo.19157027
- Schubert, J. (2026). *System Frame Persistency (SFP-2).* https://doi.org/10.5281/zenodo.19154800
- Schubert, J. (2026). *Structural Transformations in Multi-Stage Dialogues.* https://doi.org/10.5281/zenodo.18843970
- Schubert, J. (2026). *SL-20: Safety-Layer Frequency Analysis.* https://doi.org/10.5281/zenodo.18143850
