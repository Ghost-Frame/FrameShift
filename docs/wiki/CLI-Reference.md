# CLI Reference

## Installation

```bash
cargo build --release -p frameshift-cli
# Binary: target/release/frameshift-cli
```

## Commands

### Core operations

#### `frameshift use <name> [--from <library>]`

Install, activate, and print the rendered persona in one call.

```bash
frameshift use cryptographic --from ./personas
```

#### `frameshift install <spec> [--from-path <dir>]`

Install a persona pack into the central cache. Spec format: `name@version`.

```bash
frameshift install cryptographic@0.1.0 --from-path ./personas/cryptographic
```

#### `frameshift activate <name>`

Set the active persona for the current project.

```bash
frameshift activate cryptographic
```

#### `frameshift sync`

Reconcile the central store with the project lockfile. Reports installed personas and whether anything is out of date.

#### `frameshift gc`

Remove unreferenced cache entries. Safe to run at any time.

#### `frameshift project-id`

Print the SHA-256 project ID for the current directory. The project ID is `sha256(realpath(project_root))`.

### Selection and automate mode

#### `frameshift select [--task TEXT] [--library DIR] [--format table|json]`

Score and rank personas without activating. Read-only inspection of the selection pipeline.

```bash
# Table output (default):
frameshift select --task "debug a rust compilation error"

# JSON output with full context snapshot:
frameshift select --task "debug a rust compilation error" --format json
```

JSON output includes: context snapshot (detected languages, frameworks, inferred intent), per-candidate component scores (language, lexical, intent, capability), matched tokens, anti-matched tokens, and rationale.

#### `frameshift automate on [--sensitivity 0.0-1.0]`

Enable automate mode for the current project. Sensitivity controls switching aggressiveness (default 0.5).

#### `frameshift automate off`

Disable automate mode.

#### `frameshift automate status`

Print mode state: on/off, sensitivity, currently active persona.

#### `frameshift automate lock`

Pin the current persona. Automate mode will not switch while locked.

#### `frameshift automate unlock`

Release the pin. Automate mode resumes switching.

#### `frameshift feedback --chosen <name> [--auto-pick <name>] [--intent <intent>] [--reason <text>]`

Record a selection override for preference learning. The engine bumps the chosen persona's bias (+0.05) and decays the auto-picked persona's bias (-0.03).

```bash
frameshift feedback --auto-pick web-designer --chosen rust --intent debugging
```

#### `frameshift prefs [show|reset]`

View or reset per-persona preference biases.

### Growth

#### `frameshift grow append <persona> <text>`

Append an entry to a persona's growth log (JSONL format).

```bash
frameshift grow append rust "orphan rules prevent implementing foreign traits on foreign types"
```

### Source manipulation

#### `frameshift render <persona> [--target claude|codex|gemini|generic]`

Render persona source to per-agent markdown and print to stdout. Targets control which sections are included:

- **claude** -- Full output including design notes and safety layer
- **codex** -- Omits design notes and safety layer
- **gemini** -- Omits design notes
- **generic** -- Full output (same as claude)

#### `frameshift diff <a> <b>`

Semantic diff between two persona sources. Reports added/removed/modified rules, added/removed skills, voice changes, and anchor similarity (Jaccard coefficient).

#### `frameshift rule add|remove`

Patch rules in persona TOML source. Operates on typed `rules.toml`, not rendered markdown.

#### `frameshift skill add|remove`

Patch skills in persona TOML source.

#### `frameshift migrate`

Move legacy files (`frameshift.toml`, `frameshift.lock`, `growth.md`) from the project root into the central store.

### Verification and publishing

#### `frameshift verify <persona> [--bundle <path>] [--threshold <score>] [--canned-response <text>]`

Run conformance checks against a persona. Loads the test bundle, runs each test case, computes scores, and checks against the threshold.

#### `frameshift publish <persona> [--out <dir>]`

Package a persona for distribution. Loads the source, writes it to the output directory, and renders AGENTS.md.
