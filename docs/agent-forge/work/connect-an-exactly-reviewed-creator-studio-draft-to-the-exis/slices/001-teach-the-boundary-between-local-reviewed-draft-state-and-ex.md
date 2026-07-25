# Slice 001: Teach the boundary between local reviewed draft state and explicit authenticated quarantine publication, including how deterministic archives make retries and human confirmation refer to one exact artifact.

- **spec:** `spec_b92dddb4`

## Components

- frameshift-studio immutable publication snapshot
- frameshift-client deterministic signed archive preparation
- authenticated publication intent and quarantine submission transport

## Hard-won conditions

- A draft can only be frozen when review and submission intent are current for the exact inventory hash.
- Every snapshotted file is reopened without following symlinks, bounded, rehashed, and compared with a fresh final validation report.
- The manifest author key must match the selected Ed25519 signing key.
- Archive bytes are reproducible and their hash binds the intent and signed multipart submission.
- Publication remains an explicit native client action and is not exposed through MCP.

## Decision: Path-free Studio snapshot plus dedicated client publication module

- **why:** Freeze only a current reviewed, intent-confirmed draft into an opaque snapshot, then let frameshift-client deterministically sign/archive it and perform explicit authenticated intent, submission, and status operations.
- **alternative:** Put network publishing inside frameshift-studio -- rejected: Couples local draft storage to secrets and networking; Makes accidental or implicit publication easier; Harder to reuse safely across native clients
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
