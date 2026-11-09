# Bouclier Configuration Guide

Bouclier is designed to work out of the box with secure, sensible defaults. You can customize scanner timeouts, storage locations, server ports, and logging levels through a JSON configuration file.

---

## Configuration File Location

By default, Bouclier looks for:
- Windows: `%USERPROFILE%\.bouclier\config.json`
- Linux/macOS: `~/.bouclier/config.json`

You can specify a custom configuration file using the `--config` flag:

```bash
bouclier scan https://example.com --config /etc/bouclier/config.json
```

---

## Configuration Schema & Defaults

Below is a complete, annotated example configuration matching `configs/config.example.json`:

```json
{
  "application": {
    "name": "Bouclier",
    "version": "1.1.0-dev",
    "environment": "development"
  },
  "http_server": {
    "host": "127.0.0.1",
    "port": 8081,
    "read_header_timeout": "5s",
    "read_timeout": "15s",
    "write_timeout": "30s",
    "idle_timeout": "60s",
    "max_scan_duration": "20s"
  },
  "scanner": {
    "http_timeout": "8s",
    "tls_handshake_timeout": "5s",
    "max_redirects": 5,
    "max_concurrent_scans": 10,
    "user_agent": "Bouclier/1.1.0-dev"
  },
  "ai": {
    "enabled": false,
    "ollama": {
      "base_url": "http://127.0.0.1:11434",
      "model": "llama3.2"
    },
    "timeout": "90s",
    "max_tokens": 512
  },
  "storage": {
    "database_path": "~/.bouclier/bouclier.db",
    "cache_ttl": "24h"
  },
  "threat_intelligence": {
    "feed_update_interval": "24h",
    "feed_urls": []
  },
  "logging": {
    "level": "info",
    "structured": false
  }
}
```

---

## Section Descriptions

### `application`
- `name`: Informational application identifier.
- `version`: Version string.
- `environment`: Deployment tier (`development`, `staging`, `production`).

### `http_server`
Controls the local REST API server (`bouclier serve`):
- `host`: Loopback address to bind (`127.0.0.1`). *Wildcard `0.0.0.0` is strictly rejected to prevent unintentional LAN exposure.*
- `port`: Local TCP port (default: `8081`).
- `read_header_timeout`: Maximum time allowed to read request headers (default: `5s`).
- `read_timeout`: Maximum time allowed to read the full request body (default: `15s`).
- `write_timeout`: Maximum time allowed to write response (default: `30s`).
- `idle_timeout`: Keep-alive idle connection timeout (default: `60s`).
- `max_scan_duration`: Hard ceiling on synchronous scan execution via the API (default: `20s`).

### `scanner`
Governs outbound network security analysis:
- `http_timeout`: Timeout for passive HTTP GET requests (default: `8s`, hard max: `60s`).
- `tls_handshake_timeout`: Timeout for TLS handshake negotiation (default: `5s`, hard max: `30s`).
- `max_redirects`: Maximum HTTP redirect hops allowed before aborting (default: `5`, hard max: `20`).
- `max_concurrent_scans`: Limit of parallel background workers (default: `10`, hard max: `50`).
- `user_agent`: HTTP `User-Agent` string sent during passive web checks.

### `storage`
Configures local SQLite persistence:
- `database_path`: Path to the SQLite database. Tilde expansion (`~`) is supported across Windows, Linux, and macOS. Default: `~/.bouclier/bouclier.db`.
- `cache_ttl`: Duration to cache resolved domain lookups (default: `24h`).

### `threat_intelligence`
- `feed_update_interval`: Scheduled interval between feed synchronizations (default: `24h`).
- `feed_urls`: List of remote HTTPS threat feeds to sync during update cycles.

### `logging`
- `level`: Log filtering threshold: `debug`, `info`, `warn`, or `error` (default: `info`).
- `structured`: When `true`, emits machine-readable JSON logs via standard Go `slog`. When `false`, emits clean terminal text logs.

---

## Secret Redaction & Safety

When viewing the active configuration using `bouclier config show`:
- Sensitive fields, credentials, and API tokens are automatically replaced with `[REDACTED]`.
- URLs containing embedded query credentials or authorization tokens are scrubbed.
- The output remains valid JSON and can be safely piped or redirected.
