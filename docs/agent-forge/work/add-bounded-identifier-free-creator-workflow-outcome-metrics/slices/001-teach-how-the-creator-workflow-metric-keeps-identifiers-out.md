# Slice 001: Teach how the creator workflow metric keeps identifiers out of labels while preserving actionable stage and outcome signals.

- **spec:** `spec_fcb38a5b`

## Components

- creator workflow Prometheus counter
- route-template classifier
- account auth integration evidence
- operations and observability Wiki page

## Hard-won conditions

- 198 frameshift-server tests pass
- cargo fmt passes
- Wiki validation passes
- git diff check passes
- all touched declarations commented

## Decision: Matched-route middleware classification

- **why:** Map hard-coded method and Axum MatchedPath templates to bounded stages, then classify the final response status.
- **alternative:** Per-handler domain increments -- rejected: Broad invasive edits; Early-return errors are easy to miss; Risks double counting retries and nested services; Harder to prove complete
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
