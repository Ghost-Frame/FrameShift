# Slice 001: Preserve the existing public GitHub Wiki as reviewed canonical core documentation and add a safe validation and staging boundary.

- **spec:** `spec_a512754f`

## Components

- docs/wiki preserves the existing public pages and metadata
- scripts/wiki-docs.sh validates and stages without committing, pushing, or deleting
- wiki-docs CI workflow validates relevant pull requests

## Hard-won conditions

- GitHub Wiki already existed and had to be preserved rather than replaced
- The Wiki repository uses master while core uses main
- GitHub workflow credentials were not assumed to have Wiki push authority
- Two dangerous-command examples were rephrased descriptively to pass public safety handling without changing product claims

## Decision: Canonical core mirror with non-destructive staging

- **why:** Preserve the current Wiki in docs/wiki, validate it in core CI, and provide a tool that refuses unmanaged remote pages before staging canonical pages into a Wiki checkout.
- **alternative:** Edit GitHub Wiki directly -- rejected: Public changes bypass core PR review and CI; No deterministic source mapping or validation; Conflicts with the settled D7 supply-chain decision
- **trust:** Verified by canonical validation, shell syntax checking, whitespace checking, and staging every canonical page into a fresh clone of the public Wiki without a deletion.
