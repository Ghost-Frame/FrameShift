# Creator Studio

Creator Studio is FrameShift's managed local workspace for authoring a persona
without mixing private draft state into an installed persona or project
repository. Its draft engine is available through the core library, and six
safe authoring operations are exposed by the local MCP server.

## Draft types

A draft can begin as:

- an empty workspace;
- a blank atomic template;
- a guided template built from bounded public fields;
- a verified fork of a release that permits Studio forks; or
- a hardened import of an existing public pack directory.

Imports reject symlinks, special files, traversal, private-state paths,
unsupported public paths, and format limits before the draft becomes visible.
Each draft keeps private metadata in `draft.json` and public candidate content
under its managed `content/` directory.

## Author through MCP

The local MCP server exposes:

- `frameshift_draft_create`
- `frameshift_draft_list`
- `frameshift_draft_status`
- `frameshift_draft_preview`
- `frameshift_draft_read`
- `frameshift_draft_write`

Start with `frameshift_draft_create`, then use `frameshift_draft_status` to see
the exact public inventory and deterministic validation findings. Read and
write only documented public files. Passing removal intent to the write tool
removes an eligible public file through the same managed boundary.

`frameshift_draft_list` does not expose filesystem paths. Preview results are
also path-free and deterministic, so an agent can help inspect the candidate
persona without learning unrelated local layout.

## Validation is not approval

Status and preview help answer different questions:

- validation determines whether the current files satisfy the public pack and
  publication rules;
- preview shows what the current persona renders;
- human review determines whether the content and declared capabilities are
  actually what you intend to publish.

An agent can create, inspect, validate, preview, read, and edit drafts over MCP.
It cannot confirm final review or submission intent. Those actions require an
interactive human-facing client.

## The exact review boundary

For final review, the core freezes the valid public inventory into a private
snapshot and builds the deterministic signed archive. The review report binds:

- the full public manifest;
- scanner findings and scanner schema version;
- archive, manifest, and inventory hashes;
- the stable publisher UUID; and
- the selected publisher-key UUID.

Both review confirmation and submission intent must repeat that exact binding.
Any later file write or removal clears both confirmations before changing
content. The publisher must review and confirm the new artifact again.

This prevents an agent, interrupted edit, or background change from replacing
content after the human approved it. The final report is path-free so it can be
presented without disclosing the local draft location.

## Current interface boundary

The shipped CLI does not expose a `studio` command, and MCP deliberately stops
before final review and submission. The core library contains the review,
confirmation, and submission-snapshot primitives for an interactive client.
Do not substitute `frameshift publish` for this account-backed Studio workflow;
that command is the older author-handle publication path.

See [[Accounts and Publisher Identity]] before selecting a signer, then
[[Publishing and Moderation]] for what happens after submission.
