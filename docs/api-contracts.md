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
| `POST` | `/api/v1/scans` | `200 OK` | Run a synchronous URL assessment |

Informational endpoints return their documented JSON objects directly.

## Request conventions

JSON request bodies must contain exactly one JSON value, must not contain
undocumented fields, and are limited to 1 MiB. Scan targets must be absolute
HTTP or HTTPS URLs without embedded credentials.

```json
{
  "target_url": "https://example.com"
}
```

## Successful operation responses

The scan endpoint returns the canonical `bouclier-risk/v1` report directly,
without an additional envelope. It returns `200 OK` for a completed assessment,
including assessments with suspicious findings.

Request:

```json
{"target_url":"https://example.com"}
```

Success response (abridged):

```json
{
  "schema_version": "bouclier-risk/v1",
  "target": "https://example.com/",
  "overall_score": 0,
  "classification": "low",
  "findings": [],
  "analysis_coverage": []
}
```

Scans run synchronously. The default maximum duration is 20 seconds, and the
HTTP `write_timeout` must exceed it. The maximum number of active scans is controlled by
`scanner.max_concurrent_scans` (default 10). Requests exceeding available scan
capacity receive `429 Too Many Requests`; timeouts receive `504 Gateway
Timeout`. Client cancellation cancels the scan context.

```bash
curl -X POST http://127.0.0.1:8081/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://example.com"}'
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
| `400 Bad Request` | Invalid URL syntax or a blocked destination | `invalid_target`, `destination_not_allowed` |
| `405 Method Not Allowed` | Unsupported method | `method_not_allowed` |
| `404 Not Found` | No route matches the request | `not_found` |
| `409 Conflict` | The operation conflicts with current resource state | `conflict` |
| `413 Content Too Large` | Request body exceeds 1 MiB | `request_too_large` |
| `429 Too Many Requests` | Scan capacity is exhausted | `scan_capacity_exhausted` |
| `408 Request Timeout` | The client canceled the request | `scan_canceled` |
| `504 Gateway Timeout` | Scan exceeds its configured maximum duration | `scan_timeout` |
| `500 Internal Server Error` | Unexpected server failure | `internal_error` |

Unsupported methods return `405 Method Not Allowed` and include an `Allow`
header.

## Report schema reference

The canonical report schema remains `bouclier-risk/v1`, represented by
`risk.RiskAssessment` in [`internal/risk/model.go`](../internal/risk/model.go)
and sanitized/serialized by `report.RenderJSON` in
[`internal/report/json.go`](../internal/report/json.go). The API contract does
not redefine, rename, or transform those report fields. The CLI's JSON export
continues to emit the report object itself.

## Security behavior and limitations

Scan requests use the same end-to-end scan pipeline as the CLI. Static target
checks reject unsafe IP literals and local/internal hostnames before invoking
the pipeline. HTTP and TLS transports validate DNS answers and pin approved
addresses for each connection; redirects are manually followed and each new
destination is resolved and validated before a request is made. Do not treat
this endpoint as a substitute for network-level egress controls. Because the
scan route is unauthenticated, server configuration and the serving lifecycle
accept only loopback-bound TCP listeners until authentication is implemented.
