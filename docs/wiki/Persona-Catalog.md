# Persona Catalog

41 personas ship with Frameshift. Each is backed by a `pack.toml` manifest declaring identity, capabilities, and behavioral scope.

## Domain engineering

| Persona | What wakes up |
|---|---|
| `rust/` | Rust engineer. Idiomatic, clippy-strict, no unwraps in library code |
| `go-engineer/` | Go engineer. Stdlib-first, table tests, context propagation, errors-as-values |
| `typescript-engineer/` | TypeScript engineer. Strict tsconfig, zod at the boundary, ESM modules |
| `python-engineer/` | Python engineer. uv, ruff, pyright, async where it earns its keep |
| `embedded/` | Embedded engineer. ESP32, RP2040, STM32, no_std Rust, resource-constrained and real-time |
| `frontend/` | Frontend engineer. SvelteKit, Astro, Tailwind, no component library sludge |
| `mobile-dev/` | Mobile developer. iOS, Android, React Native, Flutter, native feel where it matters |
| `desktop/` | Desktop and TUI engineer. Tauri, ratatui, wgpu, native feel over web-wrapper convenience |
| `database/` | Database engineer. Schema design, query optimization, migrations, indexing strategy |
| `data/` | Data engineer. Idempotent, observable, recoverable pipelines |
| `unreal/` | Unreal developer. Blueprint plus C++ hybrid. Verifies API names before using them |
| `cryptographic/` | Cryptographer. Spec-anchored, constant-time aware, never invents primitives |
| `bots/` | Discord bot personality engineer. Character fidelity across thousands of turns |
| `accessibility-engineer/` | Accessibility engineer. Inclusive interaction, semantic structure, assistive-technology compatibility |

## Architecture and design

| Persona | What wakes up |
|---|---|
| `architecture/` | Skeptical architect. Stress-tests proposals before they cost anything to fix |
| `agents/` | Agent designer. Personas, growth, supervision, multi-agent loops |
| `memory/` | Memory architect. Vector search, embedding pipelines, recall fidelity over latency |
| `creative/` | Creative coder. Aesthetic judgment over convention |
| `api-integrator/` | API glue engineer. REST, GraphQL, webhooks, OAuth, rate limits, idempotency keys |
| `product-strategist/` | Product strategist. Converts evidence and constraints into coherent product decisions |
| `visual-director/` | Visual director. Art direction, visual systems, composition, and collection coherence |

## Operations and security

| Persona | What wakes up |
|---|---|
| `systems/` | Operator with steady hands. State-check first, change second, verify third |
| `devops/` | Deployment engineer. Staged rollouts, named rollback paths, fleet-wide awareness |
| `security/` | Security analyst. Opsec-first, classifies by noise level |
| `gatekeeper/` | Paranoid gatekeeper. Classifies before it lets anything cross the public boundary |
| `performance/` | Performance analyst. Profiles before optimizing, benchmarks before claiming |
| `incident-commander/` | Incident commander. Establishes control, coordinates responders, and protects recovery |

## Developer workflow

| Persona | What wakes up |
|---|---|
| `commit-curator/` | Git commit hygienist. Splits diffs into logical commits, writes clear messages |
| `pr-author/` | PR author. Descriptions, reviewer selection, draft management, follow-up tracking |
| `reviewer/` | Code reviewer. Five lenses: correctness, security, performance, style, documentation |
| `testing/` | QA engineer. Finds the test that matters |
| `dep-updater/` | Dependency updater. Reads changelogs, runs tests, evaluates breakage risk |
| `issue-triager/` | Issue triage. Labels, priorities, dedup, needs-info detection |
| `devtools/` | Tooling builder. Developer experience as the product |

## Research and writing

| Persona | What wakes up |
|---|---|
| `research/` | Source-grounded researcher. Refuses to paraphrase from training-data memory |
| `writer/` | Technical editor. Every sentence earns its place |
| `lab/` | Experimenter. Speed over polish, findings over artifacts |

## Planning and reflection

| Persona | What wakes up |
|---|---|
| `daily-planner/` | Morning ritual. Synthesizes loose ends into a focused plan for today |
| `journal-keeper/` | Daily and weekly logger. Captures what was learned, done, pending, stuck |
| `orchestrator/` | Task decomposer. Dispatches subagents in parallel, supervises, integrates results |
| `kleos-archaeologist/` | Memory archaeologist. Mines accumulated memory for patterns and forgotten decisions |

## Capability summary

Most personas require only `Read`, `Edit`, `Write`, `Bash`, `Grep`, `Glob` with `filesystem_scope = "project-only"` and `network_egress = false`.

Exceptions:

| Persona | Capability difference |
|---|---|
| `api-integrator/` | `network_egress = true` |
| `incident-commander/` | `network_egress = true`; `memory_required = "soft"` (search, store) |
| `product-strategist/` | `network_egress = true`; `memory_required = "soft"` (search, store) |
| `visual-director/` | `network_egress = true`; `memory_required = "soft"` (search, store) |
| `security/` | `filesystem_scope = "system"` |
| `orchestrator/` | `filesystem_scope = "system"` |
| `daily-planner/` | `memory_required = "soft"` (search, recall) |
| `journal-keeper/` | `memory_required = "soft"` (store) |
| `kleos-archaeologist/` | `memory_required = "hard"` (search, recall, context) |
