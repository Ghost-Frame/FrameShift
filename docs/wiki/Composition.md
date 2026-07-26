# Composition

Personas can extend a base and mix in overlays. This lets you build focused personas and compose them into specialized variants without duplicating content.

## Declaration

In `persona.toml`:

```toml
extends = "base-persona@^1"
mixin = ["company-style@2.x", "safety-overlay@1.x"]
```

- `extends` -- A single base persona. The root persona inherits everything from the base. Format: `name` or `name@semver-req`.
- `mixin` -- An ordered list of overlays applied after the base. Same format.

## Resolution order

```
base (extends) → mixin[0] → mixin[1] → ... → root persona
```

Each layer adds or overrides content from the previous layer. The root persona always wins.

## Override semantics

Rules and skills with duplicate IDs follow last-write-wins: later layers replace earlier ones. Patterns are concatenated from all layers (no deduplication).

### SD6 L1 protection

L1 rules from the base persona receive special protection:

- **Mixins cannot override L1 rules from the base.** Attempting to do so produces a `ComposeError::L1Override` and blocks the composition.
- **The root persona can override inherited L1 rules**, but only when the overriding rule explicitly sets `override_inherited = true`. Without that flag, the L1 rule from the base is preserved.

This prevents mixins from silently weakening safety constraints established by the base persona.

## Conflict detection

When two layers declare a rule or skill with the same `id`, the composer detects the collision and emits a `Conflict` record. The last-write-wins policy applies (later layers override earlier ones), but the conflict is logged for audit.

Three kinds of conflicts are detected:

| Conflict | Description |
|---|---|
| `RuleIdCollision` | Two layers declare a rule with the same ID |
| `SkillIdCollision` | Two layers declare a skill with the same ID |
| `PatternContradiction` | A stack item in one layer is contradicted by an anti-pattern in another |

Conflicts surface at install time, not at render time. You see them before anything activates.

## The composer

The `frameshift-compose` crate implements the merge:

1. Load the root persona source.
2. Resolve `extends` to a local path (via `LocalResolver`, which maps `name` to `<base_dir>/<name>/`).
3. Resolve each `mixin` to a local path.
4. Merge layers in order: base -> mixins -> root.
5. Apply SD6 L1 protection checks.
6. Detect and report conflicts.
7. Return the `ComposedPersona` with merged rules (carrying layer provenance), merged skills (with provenance), and concatenated patterns.

Each merged rule and skill carries a `Provenance` record indicating which layer (Base, Mixin, or Root) it came from.

## Use cases

- **Company overlay.** A `company-style` mixin that adds your team's naming conventions, commit message format, and CI requirements to any persona.
- **Safety overlay.** A `safety-overlay` mixin that adds L1 hard constraints across all personas.
- **Specialization.** A `rust-crypto` persona that extends `rust` and mixes in `cryptographic` for Rust projects with crypto code.

## Limitations

- Composition is resolved at install time, not at runtime.
- Circular extends chains are rejected.
- Mixin order matters -- later mixins override earlier ones on ID collision.
- Mixins cannot override L1 rules from the base (SD6 protection).
