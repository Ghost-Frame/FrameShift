> **Review priority:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved. The criteria were exercised, so read the decisions below for judgment rather than for correctness.

# Record: Add bounded, identifier-free creator workflow outcome metrics to frameshift-server and document their operator contract in the canonical public Wiki sources.

- **spec:** `spec_fcb38a5b`
- **type:** enhancement

## Acceptance criteria

- Register creator_workflow_outcomes_total as an IntCounterVec with only stage and outcome labels.
- Classify only hard-coded matched route templates for account, publisher profile, publisher key, publication intent, quarantine admission, moderation, promotion, appeal, and lifecycle operations.
- Classify response results into a bounded outcome vocabulary: success, client_error, server_error, other_status, or transport_error.
- Never place account IDs, publisher handles, pack names, submission IDs, request IDs, raw paths, tokens, or error text in metric labels.
- Preserve the existing http_requests_total and latency behavior unchanged.
- Add focused unit tests for every stage mapping and outcome class plus an integration test proving an authentication rejection increments the bounded metric.
- Add a canonical docs/wiki operator page describing access control, labels, PromQL examples, interpretation limits, and the separate reconciliation evidence path; update sidebar and source map.
- Run the full frameshift-server test package in one Cargo invocation, validate canonical Wiki sources, and pass Agent-Forge completion checks.

## Edge cases

- Unmatched routes must not increment the creator workflow counter.
- Read-only public publisher lookup must not be misclassified as a creator mutation.
- Promotion must classify as promotion before the broader moderation route family.
- Transport errors have no HTTP status and must use one fixed outcome label.
- Redirect and informational statuses must use other_status.
- Nested route templates must be matched as templates, never raw request paths.
- Disabled account or quarantine routes remain unmounted and therefore produce no creator workflow stage.

## Interface contract

```text
Prometheus exposition adds creator_workflow_outcomes_total{stage="<bounded-stage>",outcome="<bounded-outcome>"}. Existing metrics and HTTP behavior remain backward compatible. Canonical Wiki docs are staged separately to the existing public GitHub Wiki only after core review and merge.
```

## Decision: Matched-route middleware classification

- **why:** Map hard-coded method and Axum MatchedPath templates to bounded stages, then classify the final response status.
- **alternative:** Per-handler domain increments -- rejected: Broad invasive edits; Early-return errors are easy to miss; Risks double counting retries and nested services; Harder to prove complete
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved

## Verification evidence

- `cargo fmt --all -- --check` -- passed
- `cargo test -p frameshift-server` -- passed
- `scripts/wiki-docs.sh validate` -- passed
- `git diff --check` -- passed
