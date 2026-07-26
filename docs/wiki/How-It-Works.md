# How It Works

## The problem

Most agent prompts are ranked priority lists: "First do X. Then Y. Most importantly Z." Under pressure -- long sessions, surprising inputs, multi-step debugging -- models treat lower-ranked items as optional, then irrelevant. By turn 200, the careful operator you configured has drifted into a generic assistant.

## The solution

Frameshift encodes personas as complete behavioral identities using Schubert's L1/L2/L3 behavioral architecture:

- **L2 semantic framing.** Identity as a coherent stance. "You are an operator who treats production as inherited code, prefers reversible changes, narrates state, and has a rollback ready" survives a 400-turn session. "1. Check state. 2. Be careful. 3. Have a rollback" does not.
- **L1 hard constraints.** Never-do rules with reasoning attached. Scar tissue from real incidents. These survive context erosion better than soft guidance.
- **Cascade anchors.** The same identity re-anchored at top, middle, and end of the persona. Drift propagates upward through context, so redundancy at multiple positions beats thoroughness at one.
- **Forced classification.** Each persona declares a judgment axis via classification tiers. The agent must classify before acting. The classification itself is the design pressure.
- **Self-evaluation hooks.** A checklist run before non-trivial actions.

## Data model

All state lives in `$XDG_DATA_HOME/frameshift/` (typically `~/.local/share/frameshift/`). Your project tree is never written to.

```
$XDG_DATA_HOME/frameshift/
  cache/<sha256>/                          # Content-addressed pack cache
  projects/<project-id>/
    config.toml                            # Declared persona dependencies
    lock.toml                              # Exact versions, hashes, author pubkeys
    active                                 # Currently active persona name
    personas/<name>/
      source/                              # Extracted pack contents
      rendered/{claude,codex,gemini,generic}/  # Per-agent rendered output
      growth.md                            # Legacy growth log (markdown)
      growth.jsonl                         # Structured growth log (JSONL)
    orchestrator/                          # Automate mode state, preferences, audit log
```

Project ID is `sha256(realpath(project_root))`.

## Rendering pipeline

When you activate a persona, the engine:

1. Reads the persona source (pack contents). Source files: `persona.toml`, `rules.toml`, `skills.toml`, `patterns.toml`.
2. Applies any composition layers (base persona via `extends`, overlays via `mixin`).
3. Renders to per-target markdown. Each target produces different output:
   - **Claude** -- Full output: title, L2 anchor, operating frame, skills, L1 rules, patterns, ambiguity guidance, cascade mid, conflict resolution, self-eval hooks, safety layer, growth, cascade recency, design notes, references.
   - **Codex** -- Omits design notes and safety layer.
   - **Gemini** -- Omits design notes.
   - **Generic** -- Full output (same sections as Claude).
4. Writes the rendered output to the project's central store. Empty sections are omitted entirely (no blank headings).

The rendered markdown is what your agent reads on session start. The source TOML is what you author and version.

## Content addressing

Every persona pack is content-addressed:

1. Canonical directory walk: all files sorted by NFC-normalized path.
2. For each file, hash `path\0length\0bytes\0` (null-separated). The `signature.sig` file is excluded.
3. SHA-256 of the concatenated result.
4. Optional Ed25519 signature by the author's key, covering the canonical hash.

Identical pack contents always produce the same hash, regardless of filesystem ordering or platform. The cache deduplicates naturally.

Size limits enforced during loading: 5 MB total, 50 files max, 1 MB per file.

## References

- Schubert, J. (2026). *AIReason LLM Behavioral Architecture.* https://doi.org/10.5281/zenodo.19157027
- Schubert, J. (2026). *System Frame Persistency (SFP-2).* https://doi.org/10.5281/zenodo.19154800
- Schubert, J. (2026). *Structural Transformations in Multi-Stage Dialogues.* https://doi.org/10.5281/zenodo.18843970
- Schubert, J. (2026). *SL-20: Safety-Layer Frequency Analysis.* https://doi.org/10.5281/zenodo.18143850
