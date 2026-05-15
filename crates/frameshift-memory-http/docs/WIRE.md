# frameshift-memory-http Wire Contract

All endpoints are relative to the configured `base` URL.
Request and response bodies are JSON (`Content-Type: application/json`).

## Methods

| Method | HTTP verb and path | Request body | Success response | Error responses |
|---|---|---|---|---|
| `store(text, tags, metadata)` | `POST {base}/store` | `{ "text": string, "tags": [string, ...], "metadata": object }` | 201 `{ "id": uuid-string, "created_at": RFC3339 }` | 401, 5xx |
| `search(query, k, filters)` | `POST {base}/search` | `{ "query": string, "k": usize, "filters": FiltersDto }` | 200 `{ "results": [Memory, ...] }` | 400, 401, 429, 5xx |
| `recall(id)` | `GET {base}/memories/{id}` | -- | 200 `Memory` | 401, 404, 5xx |
| `list(limit, offset)` | `GET {base}/memories?limit={n}&offset={n}` | -- | 200 `{ "items": [Memory, ...] }` | 401, 5xx |
| `forget(id)` | `DELETE {base}/memories/{id}` | -- | 204 (no body) | 401, 404, 5xx |
| `health()` | `GET {base}/health` | -- | 200 `{ "healthy": bool, "message": string }` | 5xx |

## DTO Shapes

### StoreRequest
```json
{
  "text": "the memory content",
  "tags": ["sorted", "tag", "array"],
  "metadata": { "key": "value" }
}
```

### StoreResponse
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2026-05-13T00:00:00Z"
}
```

### SearchRequest
```json
{
  "query": "search text",
  "k": 10,
  "filters": {
    "tags": ["tag-a", "tag-b"],
    "after": "2026-01-01T00:00:00Z",
    "before": "2026-12-31T23:59:59Z",
    "metadata": { "key": "value" }
  }
}
```

### SearchResponse
```json
{
  "results": [ /* array of Memory objects */ ]
}
```

### ListResponse
```json
{
  "items": [ /* array of Memory objects */ ]
}
```

### HealthResponse
```json
{
  "healthy": true,
  "message": "all systems operational"
}
```

### Memory (wire shape)
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "text": "the memory content",
  "tags": ["tag-a", "tag-b"],
  "created_at": "2026-05-13T00:00:00Z",
  "updated_at": null
}
```

Metadata fields are flattened directly into the Memory object (no nested `"metadata"` key).

## Serialization Rules

- **Tags** in `FiltersDto` are sorted lexicographically before serialization.
- **Timestamps** (`after`, `before`, `created_at`, `updated_at`) are RFC3339 strings in UTC.
- **Metadata** in `FiltersDto` is serialized as a JSON object with keys in BTreeMap order (sorted).

## Retry Policy

- **Retried:** 5xx responses and 429 (Too Many Requests).
- **Not retried:** 4xx responses (except 429), network errors that are not transient.
- **Attempts:** 3 total (1 initial + 2 retries).
- **Backoff:** Exponential, base 200ms, jitter +/- 25%.
- **Retry-After header:** Honored on 429 responses (seconds form only; HTTP-date form is ignored).

## Authentication

Supported schemes (selected at `HttpAdapter::new()` time):

| Variant | Wire representation |
|---|---|
| `Bearer(token)` | `Authorization: Bearer <token>` |
| `ApiKey { header_name, value }` | `<header_name>: <value>` |
| `OAuthBearer(token)` | `Authorization: Bearer <token>` (OAuth 2.0 semantics) |
| `Mtls { client_cert, client_key }` | TLS mutual auth via reqwest client certificate |
