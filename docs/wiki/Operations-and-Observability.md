# Operations and Observability

Frameshift exposes a public health endpoint and an optional, bearer-protected
Prometheus endpoint. These interfaces report service health and aggregate
request outcomes. They do not expose account, publisher, pack, or request
identifiers.

## Health

`GET /healthz` returns the server version and health status for the catalog,
object store, and optional memory backend. Monitoring should inspect both the
HTTP status and the component fields in the JSON response.

## Prometheus access

`GET /metrics` is disabled unless the server starts with a non-empty
`METRICS_BEARER_TOKEN`. A disabled endpoint returns `404`. When enabled, the
endpoint requires:

```text
Authorization: Bearer <configured token>
```

Missing or incorrect credentials return `401`. Treat the token as an operator
secret and inject it through the deployment's approved secret manager.

## Core request metrics

The registry includes:

- `http_requests_total{method,path_template,status}` for request volume and HTTP
  outcomes.
- `http_request_duration_seconds{method,path_template}` for request latency.
- `packs_published_total`, `pack_downloads_total`, and `searches_total` for
  catalog activity.
- `creator_workflow_outcomes_total{stage,outcome}` for account and controlled
  publication workflows.
- `publication_moderation_snapshot_available` for the catalog snapshot status.
- `publication_quarantine_submissions` and
  `publication_quarantine_oldest_age_seconds` for initial quarantine state.
- `publication_moderation_queue_submissions` and
  `publication_moderation_queue_oldest_age_seconds` for all unresolved review
  work.
- `publication_moderation_reviewers_available` for distinct accounts holding
  at least one active moderator or administrator role.

HTTP paths use Axum's matched route templates. A path such as
`/v1/publishers/{handle}/keys/{key_id}` remains a single bounded label value;
the real handle and key identifier never enter the metric.

## Creator workflow outcomes

`creator_workflow_outcomes_total` uses two fixed label vocabularies:

| Label | Values |
|---|---|
| `stage` | `account`, `publisher`, `publisher_key`, `publication_intent`, `quarantine`, `moderation`, `promotion`, `appeal`, `lifecycle` |
| `outcome` | `success`, `client_error`, `server_error`, `other_status`, `transport_error` |

Each matching HTTP response increments one series. Repeated requests, including
retries, increment it again. The counter measures request outcomes, not unique
people or artifacts, and a successful HTTP response alone does not prove a
catalog mutation.

Useful PromQL starting points include:

```promql
sum by (stage, outcome) (
  rate(creator_workflow_outcomes_total[5m])
)
```

```promql
sum by (stage) (
  rate(creator_workflow_outcomes_total{outcome=~"server_error|transport_error"}[5m])
)
```

Alert thresholds depend on deployment traffic and service objectives. Establish
a normal baseline before treating client errors as an incident; authentication,
validation, and authorization rejections are expected client-error outcomes.

## Moderation queue

The moderation gauges are refreshed from the catalog during an authenticated
metrics scrape. They contain no labels and no account, publisher, key,
submission, or artifact identifiers.

`publication_moderation_snapshot_available` is `1` only after a successful
snapshot. It is `0` for unsupported catalog backends and catalog query failures.
When it is `0`, every dependent moderation gauge resets to zero so stale values
cannot look current. Alert on snapshot unavailability before interpreting a
zero queue as empty.

The quarantine count and age cover submissions still in the initial
`quarantined` state. The moderation queue count and age cover both
`quarantined` and `needs_review`, so requested changes remain visible until the
submission leaves unresolved review.

A queued submission is never automatically approved because no reviewer is
available. This invariant can be monitored with:

```promql
(publication_moderation_queue_submissions > 0)
and on() (publication_moderation_reviewers_available == 0)
and on() (publication_moderation_snapshot_available == 1)
```

Age thresholds depend on the deployment's published review commitment. A
growing oldest-age gauge with a nonzero reviewer count indicates backlog; a
nonzero queue with zero reviewers indicates an authority coverage failure.

## Abuse limits

Two complementary rate-limit planes bound abusive traffic. Each knob counts
requests per minute with burst capacity equal to the rate, and `0` disables
that knob. Rejections return `429` with the fixed body
`{"error":"rate limit exceeded"}` and never reveal which limit tripped.

The per-address plane runs before authentication and bounds unauthenticated
pressure:

| Variable | Default | Scope |
|---|---|---|
| `ABUSE_RATE_PER_MIN` | `60` | Per-IP limit on signed writes and telemetry |
| `DOWNLOAD_RATE_PER_MIN` | `10` | Per-IP limit on download-URL minting |

The identity plane runs strictly after authentication, so a verified identity
stays bounded while rotating addresses, identities sharing one address stay
individually bounded, and an unauthenticated caller can never spend another
identity's budget:

| Variable | Default | Scope |
|---|---|---|
| `ACCOUNT_RATE_PER_MIN` | `120` | Per verified account across all account-authenticated routes |
| `SIGNER_RATE_PER_MIN` | `60` | Per verified Ed25519 signing key across signed writes |
| `PUBLISHER_RATE_PER_MIN` | `60` | Per publisher, spent only after ownership and key authorization succeed |

Publication intent creation carries no publisher budget on purpose: the
publisher named in an intent is not yet authorized at creation time, so a
publisher-keyed limit there would let any account drain a victim publisher's
budget. Intents are bounded per account, and quarantine submissions are
bounded per verified signing key.

Set `TRUST_FORWARDED_FOR=true` only behind a proxy that rewrites
`X-Forwarded-For`; it affects the per-address plane alone.

## Ownership reconciliation

Legacy ownership reconciliation is intentionally not represented as a server
Prometheus workflow. It is a separate operator CLI with dry-run, manifest
digest, census, apply, and post-apply reconciliation evidence. Follow the
backfill procedure in
[`docs/API_COMPATIBILITY.md`](https://github.com/Ghost-Frame/FrameShift/blob/main/docs/API_COMPATIBILITY.md)
before enabling ownership reads for migrated data.

## Interpretation limits

Metrics deliberately omit raw paths, account and publisher identifiers,
handles, pack names, request IDs, tokens, and error text. Use structured server
logs and catalog audit records under the applicable access controls when an
aggregate series requires investigation.
