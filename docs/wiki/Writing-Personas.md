# Writing Personas

## Minimum viable persona

A persona is a directory with a `pack.toml` manifest:

```
my-persona/
  pack.toml
```

```toml
schema_version = 1
name = "my-persona"
author_handle = "your-handle"
author_pubkey = "UNSIGNED"
version = "0.1.0"
license = "Elastic-2.0"

[capability_manifest]
required_tools = ["Read", "Edit", "Write", "Bash", "Grep", "Glob"]
network_egress = false
filesystem_scope = "project-only"
memory_required = "none"
memory_required_ops = []
```

Install it:

```bash
frameshift install my-persona@0.1.0 --from-path ./my-persona
```

## Capability manifest

The manifest declares what the persona needs from the host environment:

| Field | Type | Description |
|---|---|---|
| `required_tools` | string array | Tools the persona expects (Read, Edit, Write, Bash, Grep, Glob, etc.) |
| `network_egress` | bool | Whether the persona needs outbound network access |
| `filesystem_scope` | string | `"none"`, `"project-only"`, `"home"`, or `"system"` |
| `memory_required` | string | `"none"`, `"soft"`, or `"hard"` |
| `memory_required_ops` | string array | Memory operations needed: `"store"`, `"search"`, `"recall"`, `"list"`, `"forget"`, `"health"` |
| `env_vars_read` | string array | Environment variables the persona reads |
| `primary_intents` | string array | Task categories this persona handles best |
| `anti_keywords` | string array | Tokens that repel the selection engine away from this persona |

### Primary intents

Ten recognized intents: `implementation`, `debugging`, `review`, `security`, `writing`, `ops`, `testing`, `refactoring`, `performance`, `design`.

Declaring primary intents lets automate mode match personas to tasks more accurately.

### Anti-keywords

Anti-keywords score negatively in the selection pipeline. The penalty is proportional to the fraction of task tokens that match, scaled by 0.5. A cryptographic persona might declare `anti_keywords = ["frontend", "css", "react"]` to avoid being selected for UI work.

## Typed source format (advanced)

Beyond the pack manifest, Frameshift supports a structured TOML source format with four files:

```
my-persona/
  pack.toml       # Manifest
  persona.toml    # Identity, voice, anchors, classification tiers, self-eval
  rules.toml      # L1/L2/L3 rules with reasoning
  skills.toml     # Skill declarations
  patterns.toml   # Code patterns, anti-patterns, code examples
```

### persona.toml

Defines identity, voice, cascade anchors, classification tiers, conflict resolution stance, self-evaluation hooks, growth config, and references.

```toml
schema_version = 1
name = "my-persona"
version = "0.1.0"
description = "One-line description of what wakes up."
license = "Elastic-2.0"

[author]
handle = "your-handle"
pubkey = "ed25519:UNSIGNED"

[anchor.main]
tagline = "Short identity statement."
text = """
Multi-line L2 anchor. This is the coherent stance that survives
drift. Write it as who the agent IS, not what it does.
"""
default_question = "The question the agent asks before acting."

[voice]
tone = "Describe the voice: precise, careful, opinionated, etc."
text = """
How the agent communicates. What it prioritizes in expression.
"""

[[voice.questions]]
text = "Forced question the agent asks itself."

[[classification_tiers]]
name = "TIER_NAME"
description = "What this tier means."
guidance = "How the agent should act at this tier."

[conflict_resolution]
stance = "The coherent stance restated for mid-context re-anchoring."

[[cascade_anchors]]
position = "mid"
text = "Re-anchor at the middle of the persona."

[[cascade_anchors]]
position = "recency"
text = "Re-anchor at the end of the persona."

[[self_eval]]
step = "Checklist item the agent runs before non-trivial actions."

[safety_layer]
text = "Safety text appended to the prompt."

[growth]
dual_write_tags = "context:my-persona"
dual_write_source = "claude-code:my-persona"

[[references]]
category = "specs"
entries = ["https://example.com/relevant-spec"]
```

### rules.toml

Rules use a three-layer enforcement model:

- **L1** -- Non-negotiable invariants. Never-do rules with reasoning attached. Scar tissue from real incidents.
- **L2** -- Contextual defaults. Overridable with justification.
- **L3** -- Preferences and stylistic guidance.

```toml
schema_version = 1

[[rule]]
id = "unique-rule-id"
layer = "L1"
text = "The rule statement."
reasoning = "Why this rule exists -- the incident or invariant it protects."
override_inherited = false    # SD6: set true to override an L1 rule from a base persona
```

The `override_inherited` flag is relevant during composition. Mixins cannot override L1 rules from a base persona at all. The root persona can override inherited L1 rules only when `override_inherited = true`.

### skills.toml

Skill declarations tell the agent which structured workflows to invoke and when.

```toml
schema_version = 1

[[skill]]
id = "skill-name"
invoke_when = "Description of when to invoke this skill."
mandatory = false
```

### patterns.toml

Code patterns, anti-patterns, approved tech stack, and code examples.

```toml
schema_version = 1

[[stack]]
category = "crates"
items = ["tokio", "axum", "serde"]

[[pattern]]
id = "pattern-name"
text = "Description of the pattern."

[[antipattern]]
id = "anti-pattern-name"
text = "What to avoid."
use_instead = "What to do instead."
reasoning = "Why this is an anti-pattern."

[[example]]
id = "example-name"
title = "Descriptive title"
context = "When this applies"
language = "rust"
bad = """
fn do_thing() { thing().unwrap(); }
"""
good = """
fn do_thing() -> Result<(), Error> { thing()?; Ok(()) }
"""
```

## Rendering targets

The engine renders persona source to per-agent markdown. Each target controls which sections appear:

| Target | Output file | Sections included |
|---|---|---|
| claude | CLAUDE.md | Full output (all sections) |
| codex | AGENTS.md | Omits design notes and safety layer |
| gemini | GEMINI.md | Omits design notes |
| generic | AGENTS.md | Full output (same as claude) |

Rendered section order: title/tagline, L2 anchor, operating frame, required skills, L1 rules, concrete patterns, ambiguity guidance, cascade mid, conflict resolution, self-eval hooks, safety layer, growth integration, cascade recency, design notes, references. Empty sections are omitted entirely.

## Semantic diffs and patches

The `frameshift-source` crate supports typed operations on persona source:

```bash
# Semantic diff between two personas:
frameshift diff persona-a persona-b

# Add a rule:
frameshift rule add

# Remove a skill:
frameshift skill remove
```

These operate on the TOML source, not on rendered markdown. The diff reports: added/removed/modified rules (by ID), added/removed skills (by ID), voice changes (field-by-field), and anchor similarity (Jaccard coefficient over normalized tokens).

## Content validation

The `frameshift-source` crate scans persona content for potentially dangerous patterns:

- **Destructive commands** (recursive file removal, destructive database statement, etc.)
- **Sensitive paths** (/etc/passwd, ~/.ssh, etc.)
- **Permission escalation** (sudo, chmod 777, etc.)
- **Behavioral overrides** (ignore instructions, disregard, etc.)
- **Data exfiltration** (curl with file upload, etc.)
- **Broad capabilities** (unrestricted filesystem/network access)

Findings are reported at three severity levels: Info, Warning, Critical.

## Composition

Personas can extend a base and mix in overlays:

```toml
# In persona.toml:
extends = "base-persona@^1"
mixin = ["company-style@2.x", "safety-overlay@1.x"]
```

Resolution order: base -> mixins (in declared order) -> root persona. Conflicting rule/skill IDs surface at install time.

See [[Composition]] for details.

## Conformance testing

Persona packs can include a conformance baseline -- a minimum test score that gates upgrades:

```toml
# In pack.toml:
[conformance_baseline]
score = 0.92
bundle_hash = "sha256:..."
```

A newer version must meet the score floor against the same test bundle. See [[Conformance]] for the test bundle format.

## Tips

- **Write identity, not instructions.** "You are an operator who..." survives drift. "1. Do X. 2. Do Y." does not.
- **Include reasoning on L1 rules.** The reasoning helps the model understand why the constraint exists, which makes it more resistant to override.
- **Use cascade anchors.** Repeat the core identity at top, middle, and end. Three anchors beat one thorough one.
- **Declare anti-keywords.** If your persona should never be selected for certain tasks, say so explicitly.
- **Keep the scope tight.** A persona that tries to cover everything covers nothing. Better to compose two focused personas than ship one sprawling one.
