# Bouclier HTTP API Contracts

The HTTP API contract is versioned independently from internal Go packages.
Operation routes use the `/api/v1` prefix. A future incompatible API contract
will use a new version prefix rather than changing the meaning of a v1 field.

## Current endpoints

| Method | Path | Success | Purpose |
|---|---|---|---|
| `GET` | `/health` | `200 OK` | Process liveness |
| `GET` | `/ready` | `200 OK` | API initialization readiness |
| `GET` | `/api/v1` | `200 OK` | API metadata |

These initial informational endpoints return their documented JSON objects
directly. Successful operation responses use the `data` envelope below.

## Request conventions

JSON request bodies must contain exactly one JSON value, must not contain
undocumented fields, and are limited to 1 MiB. The URL scan request DTO is
reserved for a later operation; no scan route is implemented in this phase.
Decoding checks only the shape and presence of `target_url`; URL normalization,
network access, and scanning belong to a future operation handler/service.

```json
{
  "target_url": "https://example.com"
}
```

## Successful operation responses

Future operation responses use a stable `data` envelope. Its `data` value
retains the operation's response contract; for scan reports this means the
canonical `bouclier-risk/v1` report fields and schema version.

```json
{
  "data": {
    "id": "operation-specific-value"
  }
}
```

Current health/readiness and metadata examples:

```json
{"status":"ok","service":"bouclier-api"}
{"status":"ready"}
{"name":"Bouclier API","version":"v1"}
```

## Error responses

Errors use a stable machine-readable `code`, safe human-readable `message`,
and the server-generated `request_id` when available. They never include
stack traces or internal error details.

```json
{
  "error": {
    "code": "invalid_request",
    "message": "The target_url field is required.",
    "request_id": "d8e8f4d0d610a69d3de113193d3b263c"
  }
}
```

| HTTP status | Meaning | Example codes |
|---|---|---|
| `400 Bad Request` | Malformed JSON, unknown fields, missing required values, or extra JSON values | `invalid_request` |
| `404 Not Found` | No route matches the request | `not_found` |
| `409 Conflict` | The operation conflicts with current resource state | `conflict` |
| `413 Content Too Large` | Request body exceeds 1 MiB | `request_too_large` |
| `500 Internal Server Error` | Unexpected server failure | `internal_error` |

Unsupported methods return `405 Method Not Allowed` and include an `Allow`
header.

## Report schema reference

The canonical report schema remains `bouclier-risk/v1`, represented by
`risk.RiskAssessment` in [`internal/risk/model.go`](../internal/risk/model.go)
and sanitized/serialized by `report.RenderJSON` in
[`internal/report/json.go`](../internal/report/json.go). The API contract does
not redefine, rename, or transform those report fields. The CLI's JSON export
continues to emit the report object itself, not the HTTP `data` envelope.
