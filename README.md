# custom-agents

**A different Claude Code persona in every directory.**

`cd cryptographic/` and you get a spec-anchored cryptographer who refuses to invent primitives. `cd systems/` and you get a paranoid operator who state-checks before touching anything and has a rollback ready. `cd writer/` and you get a technical editor who deletes a sentence before adding one. Same model. Different operator.

Each subdirectory is a self-contained behavioral identity that Claude Code loads on session start. The point is not to give the model more rules. It is to anchor it in a coherent identity that survives long sessions, surprising inputs, and the slow drift that turns careful operators into sloppy ones around turn 200.

## How it works

Claude Code auto-loads `AGENTS.md` from the working directory. Launch from `systems/` and the systems engineer wakes up. Launch from `cryptographic/` and the cryptographer wakes up. The directory is the trigger.

Each context follows the same three-file template:

```
<context>/
  AGENTS.md   # The persona. Loaded on session start.
  GROWTH.md   # Running observations log. Appended during sessions.
  sync.sh     # Validation wrapper (expects an external helper).
```

`GROWTH.md` is where sessions deposit findings ("don't trust this library's docs, read the tests instead") and where future sessions read them back. The persona file is the soul. The growth log is the memory.

## Why semantic framing beats ranked lists

Most agent prompts read like ordered priority lists: "First do X. Then Y. Most importantly Z." These drift fast. Under pressure -- long sessions, surprising inputs, multi-step debugging -- the model starts treating the lower-ranked items as optional, then irrelevant.

Schubert's behavioral architecture work (SFP-2, the L1/L2/L3 distinction) found that personas held as a coherent identity hold up under that pressure where ranked lists collapse. **"You are an operator who treats production as inherited code, prefers reversible changes, narrates state, and has a rollback ready"** survives a 400-turn session. *"1. Check state. 2. Be careful. 3. Have a rollback"* does not.

Every persona here is built on that L2 anchor. Cascade anchors at top, middle, and end of each file fight upward-propagating drift. L1 hard constraints encode scar tissue from real recoveries. Forced classification axes (blast radius, capability tier, deployment risk) make the agent declare its judgment before acting -- the act of classifying is the design pressure.

## Contexts

| Directory | The operator you wake up |
|---|---|
| `agents/` | Agent designer. Personas, growth, supervision, multi-agent loops |
| `architecture/` | Skeptical architect. Stress-tests proposals before they cost anything to fix |
| `bots/` | Discord bot personality engineer. Character fidelity across thousands of turns |
| `creative/` | Creative coder. Aesthetic judgment over convention |
| `cryptographic/` | Cryptographer. Spec-anchored, constant-time aware, never invents primitives |
| `data/` | Data engineer. Idempotent, observable, recoverable pipelines |
| `desktop/` | Desktop and TUI engineer. Tauri, ratatui, wgpu, native feel over web-wrapper convenience |
| `devops/` | Deployment engineer. Staged rollouts, named rollback paths, fleet-wide awareness |
| `devtools/` | Tooling builder. Developer experience as the product |
| `frontend/` | Frontend engineer. SvelteKit, Astro, Tailwind, no component library sludge |
| `gatekeeper/` | Paranoid gatekeeper. Classifies before it lets anything cross the public boundary |
| `lab/` | Experimenter. Speed over polish, findings over artifacts |
| `memory/` | Memory architect. Vector search, embedding pipelines, recall fidelity over latency |
| `performance/` | Performance analyst. Profiles before optimizing, benchmarks before claiming |
| `research/` | Source-grounded researcher. Refuses to paraphrase from training-data memory |
| `reviewer/` | Code reviewer. Five lenses: correctness, security, performance, style, documentation |
| `rust/` | Rust engineer. Idiomatic, clippy-strict, no unwraps in library code |
| `security/` | Security analyst. Opsec-first, classifies by noise level |
| `systems/` | Operator with steady hands. State-check first, change second, verify third |
| `testing/` | QA engineer. Finds the test that matters |
| `unreal/` | Unreal developer. Blueprint plus C++ hybrid. Verifies API names before using them |
| `writer/` | Technical editor. Every sentence earns its place |

## The toolkit

Six patterns repeat across every persona:

- **L2 semantic framing.** Identity as coherent stance, not ranked priorities. The first sentence of every persona names who the agent is, not what it does.
- **Cascade anchors.** Re-anchor at top, middle, and end. Drift propagates upward through context, so redundancy at the start, middle, and end of the file matters more than thoroughness.
- **L1 hard constraints.** Never-do rules with the reasoning attached. Scar tissue from real incidents. These survive context erosion better than soft guidance.
- **Forced classification.** Each context declares an axis (LOCAL/SERVICE/HOST/FLEET/GLOBAL for systems, AUTONOMOUS/ASSISTED/CONSTRAINED/TOY for agents, ON-CHARACTER/DRIFTING/OFF-CHARACTER/BROKEN for bots). The agent must classify before acting. The classification is the design pressure.
- **Self-evaluation hooks.** Each persona ends with a short checklist run before non-trivial actions.
- **Growth integration.** The persona is read-only at session start. The growth log is append-only during the session. Next session reads both.

## Adopting it

Pick the contexts that match your work. Drop them into your repo. Tune the L1 rules to your own scar tissue -- every team has its "we tried this once and it took three days to recover" list. The framework is the structure. The content is yours.

The `sync.sh` wrappers source an external validation helper not bundled here. If you have your own validator, point `AGENT_CONFIG_DIR` at it. Otherwise ignore them; the persona files are the substantive content.

## References

The L1/L2/L3 framing, cascade anchors, and Safety-Layer Frequency work draw from Schubert:

- *AIReason LLM Behavioral Architecture.* https://doi.org/10.5281/zenodo.19157027
- *System Frame Persistency (SFP-2).* https://doi.org/10.5281/zenodo.19154800
- *Structural Transformations in Multi-Stage Dialogues -- Runport.* https://doi.org/10.5281/zenodo.18843970
- *SL-20 -- Safety-Layer Frequency Analysis.* https://doi.org/10.5281/zenodo.18143850
