# Bouclier REST API Reference

Bouclier provides an embedded HTTP REST server for integrating automated URL intelligence and web security assessment into CI/CD pipelines, security orchestration workflows, and internal services.

---

## 1. Running the API Server

Start the API service with the `serve` command:

```bash
bouclier serve
```

### Server Options & Flags

| Flag | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | Loopback bind host (`127.0.0.1` or `::1`). Public non-loopback interfaces are rejected for security. |
| `--port` | `8081` | Port number to listen on. |
| `--read-timeout` | `10s` | Maximum duration for reading the entire request, including the body. |
| `--write-timeout` | `30s` | Maximum duration before timing out writes of the response (must exceed scan timeout). |
| `--max-concurrent-scans` | `10` | Maximum number of simultaneous active scans. Requests beyond capacity receive HTTP 429. |

Example starting on a custom loopback port:

```bash
bouclier serve --port 9090
```

> [!IMPORTANT]
> **Loopback Binding Security Boundary:**
> Because the current API endpoints are unauthenticated, Bouclier strictly enforces loopback binding (`127.0.0.1` or `::1`). Attempts to bind to external interfaces (such as `0.0.0.0` or public IP addresses) will be rejected on startup. If remote access is required, deploy a reverse proxy (e.g. Nginx, Envoy, Caddy) in front of Bouclier with mutual TLS or bearer token authentication.

---

## 2. API Endpoints

All operational endpoints use the `/api/v1` prefix.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Process liveness probe. |
| `GET` | `/ready` | Service readiness probe (checks storage and engine initialization). |
| `GET` | `/api/v1` | Service metadata and version information. |
| `POST` | `/api/v1/scans` | Run a synchronous URL security assessment. |

---

## 3. Endpoint Specifications

### 3.1 Liveness Probe (`GET /health`)
Verifies that the HTTP listener is responsive.

**Request:**
```bash
curl -s http://127.0.0.1:8081/health
```

**Response (`200 OK`):**
```json
{
  "status": "ok",
  "service": "bouclier-api"
}
```

---

### 3.2 Readiness Probe (`GET /ready`)
Verifies that the server is initialized and ready to accept scan requests.

**Request:**
```bash
curl -s http://127.0.0.1:8081/ready
```

**Response (`200 OK`):**
```json
{
  "status": "ready"
}
```

---

### 3.3 API Metadata (`GET /api/v1`)
Provides API versioning metadata.

**Request:**
```bash
curl -s http://127.0.0.1:8081/api/v1
```

**Response (`200 OK`):**
```json
{
  "name": "Bouclier API",
  "version": "v1"
}
```

---

### 3.4 Scan Target (`POST /api/v1/scans`)
Executes a synchronous security assessment across URL heuristics, TLS configuration, Certificate Transparency logs, HTTP security headers, and local threat intelligence feeds.

#### Request Requirements
- **Headers:** `Content-Type: application/json`
- **Body Limit:** Maximum 1 MiB (`413 Content Too Large` if exceeded).
- **Format:** Strict JSON object containing a valid `target_url`.
- **Target URL:** Must be an absolute `http://` or `https://` URL. Localhost, loopback (`127.0.0.0/8`), private RFC 1918 ranges, link-local, and cloud metadata IPs (`169.254.169.254`) are blocked and return `400 Bad Request`.

**Request Example:**
```bash
curl -X POST http://127.0.0.1:8081/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

#### Response (`200 OK`)
Returns the canonical `bouclier-risk/v1` report:

```json
{
  "schema_version": "bouclier-risk/v1",
  "target": "https://example.com/",
  "overall_score": 15,
  "classification": "low",
  "scanned_at": "2026-11-09T01:00:00Z",
  "categories": {
    "url_heuristics": 0,
    "tls": 0,
    "certificate_transparency": 0,
    "http_security": 15,
    "threat_intelligence": 0
  },
  "findings": [
    {
      "code": "WEB_HSTS_MISSING",
      "severity": "low",
      "confidence": "high",
      "category": "http_security",
      "title": "Strict-Transport-Security header missing",
      "description": "The site does not enforce HTTPS via HSTS.",
      "score": 15,
      "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to response headers."
    }
  ],
  "analysis_coverage": [
    {
      "module": "url_heuristics",
      "status": "completed",
      "duration_ms": 2
    },
    {
      "module": "tls_handshake",
      "status": "completed",
      "duration_ms": 112
    },
    {
      "module": "ct_logs",
      "status": "completed",
      "duration_ms": 184
    },
    {
      "module": "http_security",
      "status": "completed",
      "duration_ms": 94
    },
    {
      "module": "threat_intelligence",
      "status": "completed",
      "duration_ms": 1
    }
  ]
}
```

---

## 4. Error Handling & Status Codes

All errors return a structured JSON response with a machine-readable `code`, human-readable `message`, and correlation `request_id`:

```json
{
  "error": {
    "code": "destination_not_allowed",
    "message": "Target resolves to a restricted private or loopback address.",
    "request_id": "4a1e9b2c3d8f7e6a"
  }
}
```

### Error Code Reference

| HTTP Status | Error Code | Cause / Remediation |
|---|---|---|
| `400 Bad Request` | `invalid_request` | Malformed JSON body or unexpected JSON fields. |
| `400 Bad Request` | `invalid_target` | Target URL is empty, missing scheme, or malformed. |
| `400 Bad Request` | `destination_not_allowed` | Target points to private, loopback, or cloud metadata address (SSRF blocked). |
| `404 Not Found` | `not_found` | Requested path does not exist. |
| `405 Method Not Allowed` | `method_not_allowed` | HTTP method not permitted on endpoint (`Allow` header included). |
| `408 Request Timeout` | `scan_canceled` | Client aborted the HTTP connection before scan completed. |
| `413 Content Too Large` | `request_too_large` | Request body exceeded the 1 MiB limit. |
| `429 Too Many Requests` | `scan_capacity_exhausted` | Active scan count reached `--max-concurrent-scans`. Retry after current scans complete. |
| `504 Gateway Timeout` | `scan_timeout` | Scan execution exceeded maximum allowed duration (default 20 seconds). |
| `500 Internal Error` | `internal_error` | Unexpected internal processing error. |

---

## 5. Integration Code Examples

### Python (using `requests`)

```python
import requests

API_URL = "http://127.0.0.1:8081/api/v1/scans"

def scan_url(target: str) -> dict:
    response = requests.post(
        API_URL,
        json={"target_url": target},
        headers={"Content-Type": "application/json"},
        timeout=35,
    )
    response.raise_for_status()
    return response.json()

if __name__ == "__main__":
    report = scan_url("https://example.com")
    print(f"Target: {report['target']}")
    print(f"Risk Score: {report['overall_score']} ({report['classification']})")
    print(f"Total Findings: {len(report['findings'])}")
```

### Node.js (Fetch API)

```javascript
async function scanUrl(targetUrl) {
  const response = await fetch("http://127.0.0.1:8081/api/v1/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_url: targetUrl }),
  });

  if (!response.ok) {
    const errorBody = await response.json();
    throw new Error(`Scan failed (${response.status}): ${errorBody.error.message}`);
  }

  return await response.json();
}

scanUrl("https://example.com")
  .then(report => console.log(`Risk: ${report.overall_score}/100 (${report.classification})`))
  .catch(err => console.error(err.message));
```
