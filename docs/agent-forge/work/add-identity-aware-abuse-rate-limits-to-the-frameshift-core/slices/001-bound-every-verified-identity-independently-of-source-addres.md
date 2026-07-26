# Slice 001: Bound every verified identity independently of source address: per-account limits on account-authenticated routes, per-signing-key limits after signature verification, and per-publisher limits after ownership authorization, complementing the per-IP boundary.

- **spec:** `spec_dbcdc01c`

## Components

- frameshift-server
- docs/wiki

## Hard-won conditions

- identity checks run only after authentication so unauthenticated callers cannot spend or create budgets
- publisher budget spent only after ownership and key authorization succeed
- intent creation deliberately carries no publisher budget because its publisher is unauthorized caller input
- missing auth extension fails closed with an internal error, never unlimited
- zero rate disables a dimension exactly like the per-IP knobs
- 429 body is fixed and never reveals which dimension tripped

## Decision: build_app-owned Arc with captured-closure middlewares and Extension for handlers

- **why:** Construct Arc<IdentityRateLimits> once in build_app from config, wire middlewares with from_fn capturing the Arc, expose to the two publisher-check handlers via axum Extension
- **alternative:** AppState field with keyed governor limiters -- rejected: 22 construction sites churn across 9 files; Test noise obscures the substantive diff
- **trust:** spec verified -- a verification run for this spec passed; this individual decision was not separately proved
