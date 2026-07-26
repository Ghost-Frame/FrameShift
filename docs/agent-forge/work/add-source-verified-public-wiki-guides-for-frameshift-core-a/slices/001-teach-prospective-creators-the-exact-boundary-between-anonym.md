# Slice 001: Teach prospective creators the exact boundary between anonymous local use, account-owned publisher identity, rotatable device signing keys, managed Creator Studio drafts, human-bound review, and moderated publication.

- **spec:** `spec_6f17bd06`

## Components

- Account sessions are optional for public browsing, installation, and local persona use, but required for publisher ownership and recovery.
- Stable publisher UUIDs survive mutable display metadata, while multiple device keys can be enrolled, rotated, revoked, and preserved as historical evidence.
- Stored account tokens are reused only for their exact registry and never forwarded to a different --server target.
- Creator Studio supports safe draft creation, import, inspection, preview, reading, and writing through six MCP tools.
- Final review and submission intent require an interactive human-facing client and bind manifest, scanner report, artifact hashes, publisher UUID, and key UUID.
- Submitted artifacts enter quarantine, then progress through explicit moderation and promotion states with withdrawal, appeal, suspension, and tombstone evidence.

## Hard-won conditions

- Do not imply that accounts are required for local catalog browsing, installation, or use.
- Do not claim the current CLI or MCP server exposes final Studio review or account-backed submission.
- Do not conflate frameshift publish with the account-backed Creator Studio publication pipeline.
- Do not send a securely stored account token to a registry whose normalized base URL differs from the saved login registry.
- Any draft mutation must invalidate prior review and submission confirmation before changing content.
- Do not invent paid tiers, premium restrictions, or unpublished interface availability.

## Decision: Three lifecycle-oriented pages

- **why:** Use separate pages for account/publisher identity, Creator Studio drafting/review, and publishing/moderation, linked in lifecycle order.
- **alternative:** One comprehensive creator guide -- rejected: Blurs authority boundaries; Harder to scan and maintain; Likely duplicates CLI reference
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
