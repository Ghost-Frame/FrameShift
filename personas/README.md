<p align="center">
  <img src="assets/banner.png" alt="Frameshift" width="100%" />
</p>

# Frameshift

**Same model. Different frame.**

Activate the cryptographer and you get a spec-anchored operator who refuses to invent primitives. Switch to systems and you get a paranoid engineer who state-checks before touching anything and has a rollback ready. Switch to writer and you get a technical editor who deletes a sentence before adding one. Same model. Different frame.

Each frame is a complete behavioral identity. Not a list of instructions. A coherent stance that survives long sessions, surprising inputs, and the slow drift that turns careful operators into sloppy ones around turn 200.

## What Frameshift is

A marketplace and runtime for versioned, composable behavioral personas for AI coding agents.

- **Freeform AGENTS.md format.** Each persona is `AGENTS.md` plus a `pack.toml` manifest. AGENTS.md is the canonical body; the engine composes per-agent rendered output (Claude, Codex, Gemini, generic) at activation time by prepending a host-side overlay and a persona header.
- **CLI.** `frameshift use`, `install`, `activate`, `select`, `automate`, `sync`, `gc`. Manages a central store outside your project tree. Your repo never gets persona files.
- **Signed packs.** Content-addressed, Ed25519-signed tarballs. Deterministic canonicalization for reproducible hashes.
- **Composition.** Extend a base persona, mix in overlays. Conflict detection at install time.
- **Marketplace server.** Catalog, version resolution, distribution.
- **Typed-source path (next).** A structured TOML format with semantic diffs and patch operations (`frameshift rule add`, `frameshift skill remove`) lives in the `frameshift-source` crate as the next-generation persona representation; the live install path uses freeform AGENTS.md.

## Persona source format

A persona is a directory containing two files:

```
personas/<name>/
  AGENTS.md     # Persona body: identity, rules, frame, skills, growth integration
  pack.toml     # Manifest: name, version, license, author, capability manifest
```

`AGENTS.md` is freeform markdown structured around the L1/L2/L3 behavioral-architecture pattern (see "Why frames beat instruction lists" below). The renderer prepends a per-host overlay and a persona header, then writes one file per target under `rendered/{claude,codex,gemini,generic}/`.

The `pack.toml` manifest declares identity, version, license, signing key, and the capability manifest:

```toml
schema_version = 1
name = "cryptographic"
version = "0.1.0"
author_handle = "ghost-frame"
author_pubkey = "ed25519:<hex>"
license = "Elastic-2.0"

[capability_manifest]
required_tools = ["Read", "Edit", "Write", "Bash"]
filesystem_scope = "project-only"
network_egress = false
```

## Installation

```bash
# Install + activate + print rendered persona in one call:
frameshift use cryptographic --from ./personas

# Or, split:
frameshift install cryptographic@0.1.0 --from-path ./personas/cryptographic
frameshift activate cryptographic
```

All state lives in `$XDG_DATA_HOME/frameshift/`:

```
cache/<sha256>/                   # Content-addressed pack cache, shared across projects
projects/<project-id>/
  lock.toml                       # Installed personas, versions, hashes
  active                          # Currently active persona
  personas/<name>/
    source/                       # Pack contents (AGENTS.md + pack.toml)
    rendered/{claude,codex,gemini,generic}/
    growth.md                     # Local-only, append-only
  orchestrator/                   # Per-project automate mode + audit state
```

Project ID is `sha256(realpath(project_root))`. Your project tree is never written to.

## Pack format

Each persona distributes as a signed pack -- a tarball of `AGENTS.md` plus `pack.toml`:

```toml
# pack.toml
schema_version = 1
name = "cryptographic"
version = "0.1.0"
author_handle = "ghost-frame"
author_pubkey = "ed25519:<hex>"
license = "Elastic-2.0"

[capability_manifest]
required_tools = ["Read", "Edit", "Bash"]
filesystem_scope = "project-only"
network_egress = false

[conformance_baseline]
score = 0.92
bundle_hash = "sha256:..."
```

Packs are tarballs, canonicalized via recursive dir walk with unicode normalization, SHA256-hashed, Ed25519-signed. The capability manifest declares what tools and access the persona needs. The conformance baseline gates upgrades -- a newer version must meet the score floor.

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
| `issue-triager/` | Issue triage. Labels, priorities, dedup, needs-info detection |
| `journal-keeper/` | Daily and weekly logger. Captures what was learned, done, pending, stuck |
| `kleos-archaeologist/` | Memory archaeologist. Mines accumulated memory for patterns and forgotten decisions |
| `lab/` | Experimenter. Speed over polish, findings over artifacts |
| `memory/` | Memory architect. Vector search, embedding pipelines, recall fidelity over latency |
| `mobile-dev/` | Mobile developer. iOS, Android, React Native, Flutter, native feel where it matters |
| `orchestrator/` | Task decomposer. Dispatches subagents in parallel, supervises, integrates results |
| `performance/` | Performance analyst. Profiles before optimizing, benchmarks before claiming |
| `pr-author/` | PR author. Descriptions, reviewer selection, draft management, follow-up tracking |
| `python-engineer/` | Python engineer. uv, ruff, pyright, async where it earns its keep |
| `research/` | Source-grounded researcher. Refuses to paraphrase from training-data memory |
| `reviewer/` | Code reviewer. Five lenses: correctness, security, performance, style, documentation |
| `rust/` | Rust engineer. Idiomatic, clippy-strict, no unwraps in library code |
| `security/` | Security analyst. Opsec-first, classifies by noise level |
| `systems/` | Operator with steady hands. State-check first, change second, verify third |
| `testing/` | QA engineer. Finds the test that matters |
| `typescript-engineer/` | TypeScript engineer. Strict tsconfig, zod at the boundary, ESM modules |
| `unreal/` | Unreal developer. Blueprint plus C++ hybrid. Verifies API names before using them |
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
