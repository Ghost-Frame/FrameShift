# Automate Mode

Automate mode lets the engine pick the right persona for the task. It classifies your work, scores every installed persona, and switches when the domain shifts.

## Enable automate mode

```bash
# Turn on for the current project:
frameshift automate on

# With a sensitivity dial (0.0 = stable, 1.0 = responsive):
frameshift automate on --sensitivity 0.7

# Check current state:
frameshift automate status

# Pin the current persona (prevent switching):
frameshift automate lock

# Release the pin:
frameshift automate unlock

# Turn off:
frameshift automate off
```

## State machine

The switch controller has four states:

| State | Behavior |
|---|---|
| **Off** | Automate mode disabled. No evaluation. |
| **Armed** | Mode enabled, awaiting first selection or re-evaluation. Accepts top candidate immediately. |
| **Active** | A persona is in use with a recorded confidence score. Switches only if the challenger clears hysteresis thresholds. |
| **Locked** | User explicitly pinned a persona. Auto-switching completely suppressed. |

Transitions:
- `automate on` -- Off to Armed
- Top candidate selected -- Armed to Active
- `automate lock` -- Any state to Locked
- `automate unlock` -- Locked to Armed
- `automate off` -- Any state to Off

## How selection works

The selection pipeline scores four components for each installed persona:

### 1. Language overlap

F1 harmonic mean of precision and recall over the persona's declared language set and the languages detected in your project. Specialist personas (few declared languages, tight match) score higher than generalists.

Language detection walks the project directory (max 2000 files, depth 6, skipping `.git`/`target`/`node_modules`) and maps file extensions to languages.

### 2. Lexical match

IDF-weighted token matching between the task description and persona keywords. Rare tokens (those appearing in fewer persona keyword lists) contribute more weight, so discriminating terms matter most.

Anti-keywords (declared in `pack.toml`) score negatively. The penalty is proportional to the fraction of task tokens that match anti-keywords, scaled by 0.5.

Task tokens are expanded via domain clusters before matching. For example, "debug" expands to include: debugging, error, crash, panic, backtrace, stacktrace, fix, trace, segfault, coredump.

### 3. Intent alignment

The engine classifies the task into one of ten intents: Implementation, Debugging, Review, Security, Writing, Ops, Testing, Refactoring, Performance, Design.

Classification uses trigger-word matching. Each intent has a static set of trigger tokens (e.g., Debugging: debug, error, crash, panic, backtrace, fix, bug).

Intent score is 1.0 for exact match, 0.5 for related pairs (Debugging-Implementation, Debugging-Testing, Review-Security, Implementation-Refactoring), 0.3 for weak adjacency (Testing-Performance, Writing-Design), and 0.0 for unrelated.

### 4. Capability fit

Simple heuristic: no required tools AND no network egress scores 1.0. One of the two scores 0.5. Both required scores 0.0. Simpler personas get a slight advantage.

### Score blending

Components blend with configurable weights:

```
score = 0.30 * language
      + 0.25 * lexical
      + 0.30 * intent
      + 0.15 * capability
      + preference_bias
```

Preference bias is additive, clamped to [-0.2, +0.2], and decays at 1% per day (floor multiplier 0.3).

Confidence for the top candidate is 50% absolute score + 50% margin over the runner-up.

## Switch controller (hysteresis)

When the controller is in the Active state, it does not switch to a new persona just because it scored higher. The controller applies two statistical tests:

1. **Z-score test.** Is the challenger's score a statistical outlier above the mean? The z-threshold ranges from 0.3 (sensitive) to 1.0 (stable) based on the sensitivity dial.
2. **Gap test.** Is the normalized gap between the challenger and the runner-up large enough to be meaningful? The minimum gap fraction ranges from 0.03 (sensitive) to 0.15 (stable).

If both tests pass (clear winner), the switch happens immediately. If only the gap test passes, the controller enters a debounce phase -- the challenger must hold the top position for multiple consecutive evaluations before switching. Debounce ticks range from 0 (sensitive) to 3 (stable).

Sensitivity mapping:

| Sensitivity | Z-threshold | Debounce ticks | Min gap fraction |
|---|---|---|---|
| 0.0 (stable) | 1.0 | 3 | 0.15 |
| 0.5 (balanced) | 0.65 | 2 | 0.09 |
| 1.0 (responsive) | 0.3 | 0 | 0.03 |

## Context sensing

The engine scans the project to build a context signal:

- **Languages:** File-extension survey weighted by frequency
- **Frameworks:** Marker file detection (Cargo.toml, package.json, go.mod, etc.)
- **Task tokens:** Tokenized, lowercased, deduplicated, expanded via domain clusters
- **Inferred intent:** Classified from task tokens

A `prose` pseudo-language is injected when the task mentions writing-related terms (docs, documentation, changelog, tutorial, etc.).

## Feedback loop

When the engine picks wrong, record the override:

```bash
frameshift feedback --auto-pick web-designer --chosen rust --intent debugging
```

The engine bumps the chosen persona by +0.05 and decays the auto-pick by -0.03. Per-intent biases are tracked separately when intent context is provided. Biases decay at 1% per day with a floor of 0.3 (they never fully disappear).

## Audit log

Every persona transition is logged to `orchestrator/automate-audit.jsonl` as JSON lines:

```json
{"timestamp":"2026-05-25T10:30:00Z","from":"web-designer","to":"rust","confidence":0.87,"rationale":"..."}
```

## Selection without switching

You can score personas without activating one:

```bash
frameshift select --task "debug a rust compilation error" --format json
```

This runs the full scoring pipeline but does not feed results into the switch controller. The CLI's `select` and the MCP's `frameshift_select` are both read-only -- only the daemon's evaluation loop applies the controller.
