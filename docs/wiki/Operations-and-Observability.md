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
