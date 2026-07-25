# Slice 001: Give Creator Studio clients an exact, deterministic preview of every supported agent render before review or submission, while keeping the operation read-only and preserving the explicit publication boundary.

- **spec:** `spec_1b124fbf`

## Components

- frameshift-studio path-free DraftPreview and TargetPreview contracts
- verified nofollow typed-source staging and full-inventory revalidation
- stable four-target rendering and exact UTF-8 SHA-256 digests
- read-only frameshift_draft_preview MCP tool
- determinism, malformed-source, path-redaction, symlink-substitution, registry, and end-to-end MCP tests

## Hard-won conditions

- A draft must contain valid root-level persona.toml typed source
- Optional rules.toml, skills.toml, and patterns.toml are included only when present in the validated inventory
- Any source mismatch or whole-draft mutation during preview fails closed
- Preview output contains no managed filesystem paths
- Preview does not confirm review, create submission intent, freeze publication bytes, sign archives, or send network requests
- Formatting, full workspace tests, and workspace Clippy with warnings denied pass

## Decision: Verified temporary source snapshot in frameshift-studio

- **why:** Copy only the validated typed source files through existing bounded nofollow reads into a private temporary directory, load with frameshift-source, render all targets, then revalidate the managed draft before returning a path-free result.
- **alternative:** Render directly from managed draft directory -- rejected: Loader metadata reads can follow symlinks; Validation-to-render race can mix revisions; Source errors can embed private paths
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
