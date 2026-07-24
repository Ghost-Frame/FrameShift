# Slice 001: Make FrameShift implementation evidence available to supported agent clients without publishing machine-specific configuration.

- **spec:** `spec_93df3c6f`

## Components

- Claude Code and Gemini CLI load project configuration that names the installed agent-forge-mcp command without a filesystem path.
- Codex uses its user-scoped registration for the same executable, keeping personal client state outside the repository.
- The final record uses repository-relative structural verification and the installed guard refuses the superseded non-portable review.
- FrameShift application source and deployment access-gate surfaces remain identical to origin/main.

## Hard-won conditions

- Leak-search commands become leaks themselves when their literal sensitive search target is rendered into evidence.
- Public verification should assert structure and behavior without naming a private value.
- Rejected generated artifacts are preserved under ignored quarantine until their diagnostic value expires.

## Decision: Create a clean final spec with portable evidence

- **why:** Preserve the rejected artifact outside public paths and emit a new record whose verification commands use relative files and structural assertions.
- **alternative:** Redact rendered evidence automatically -- rejected: Mutates evidence; Hides the root cause; Broader change than FrameShift registration requires
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
