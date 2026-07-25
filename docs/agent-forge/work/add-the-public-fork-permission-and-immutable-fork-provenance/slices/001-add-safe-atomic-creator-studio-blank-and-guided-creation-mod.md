# Slice 001: Add safe atomic Creator Studio blank and guided creation modes while establishing an explicit signed fork permission and immutable provenance contract for the following verified-registry fork slice.

- **spec:** `spec_e0e3c454`

## Components

- frameshift-pack fork permission and provenance schema
- frameshift-publication fail-closed fork contract validation
- frameshift-studio atomic blank and guided templates
- frameshift-mcp bounded creation mode schema and dispatch

## Hard-won conditions

- Legacy MCP calls without template_mode still create an empty draft.
- Blank templates remain local unsigned and publication-invalid but previewable.
- Guided templates require bounded typed fields and a real-shaped Ed25519 public key.
- Fork permission defaults false and is not inferred from a license.
- Fork provenance names a distinct pack and binds an exact immutable archive SHA-256.
- All workspace tests and Clippy pass with all features; RustSec finds no vulnerabilities.

## Decision: Additive public manifest contract plus typed atomic Studio templates

- **why:** Add default-false forkable and optional validated ForkOrigin to PackManifest. Generate blank and guided templates from typed values into a staging draft, validate, then atomically publish. Leave registry verification for the next client slice.
- **alternative:** Keep fork permission and provenance only in private Studio metadata -- rejected: Permission is not signed or visible to downstream users; Provenance disappears at publication; Cannot prove the source opted into forks
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
