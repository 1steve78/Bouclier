# Bouclier CLI Reference

This document provides a comprehensive command-line reference for Bouclier v1.0.0.

---

## Global Flags

Available across all subcommands:

- `--config <path>`: Path to a custom JSON configuration file (e.g. `~/.bouclier/config.json`).
- `-h, --help`: Display help and command usage.
- `-v, --version`: Display application version and build metadata.

---

## Exit Codes

Bouclier commands return deterministic process exit codes:

| Code | Constant | Meaning |
|---|---|---|
| `0` | `ExitSuccess` | Scan or operation completed successfully; risk threshold was not exceeded. |
| `1` | `ExitGeneralError` | Operational failure (database unreadable, port in use, OS I/O failure). |
| `2` | `ExitInvalidUsage` | Command syntax error, missing required arguments, or invalid flag options. |
| `3` | `ExitScanFailure` | Scan aborted due to SSRF protection (loopback/private IP) or unrecoverable target error. |
| `4` | `ExitOutputError` | Failed to write output report to destination file. |
| `5` | `ExitRiskThresholdExceeded` | Scan succeeded and the aggregated risk score met or exceeded `--fail-on-risk`. |

---

## 1. `bouclier scan`

Assess a target URL for phishing indicators, certificate anomalies, and website security posture.

```bash
bouclier scan <url> [flags]
```

### Flags
- `-f, --format <format>`: Output format (`terminal`, `json`, `markdown`). Default: `terminal`.
- `-o, --output <path>`: Write the resulting assessment report to the specified file path (creates files with user-only `0600` permissions).
- `--timeout <duration>`: Override effective scan timeout (e.g. `15s`, `1m`, `30s`).
- `--no-ct`: Disable Certificate Transparency log lookups.
- `--ct-scope <scope>`: Certificate Transparency query scope (`exact` or `registrable`). Default: `exact`.
- `-v, --verbose`: Display detailed diagnostic logging to stderr.
- `-q, --quiet`: Suppress nonessential informational output; emit only score and findings.
- `--no-color`: Disable ANSI color sequences in terminal rendering.
- `--fail-on-risk <score>`: Exit with code `5` if the final risk score meets or exceeds this threshold (`0`–`100`).

### Examples
```bash
# Standard interactive scan with ANSI color
bouclier scan https://example.com

# Machine-readable JSON report for CI/CD pipelines
bouclier scan https://example.com --format json

# Export clean Markdown report for GitHub Pull Request summary
bouclier scan https://example.com --format markdown --output scan-report.md

# Gate build pipeline: fail if score is elevated (>= 40)
bouclier scan https://example.com --fail-on-risk 40
```

---

## 2. `bouclier tui`

Launch the full-screen interactive Bubble Tea terminal user interface.

```bash
bouclier tui [flags]
```

### Flags
- `--no-color`: Disable ANSI color themes; use monochrome presentation.
- `--config <path>`: Load scanner and storage configuration from a JSON file.

### Features
- Dashboard with recent scan history from SQLite.
- Live scan progress with per-stage status (`[✓]`, `[●]`, `[✗]`, `[-]`) and elapsed timing.
- Risk overview, finding browser, remediation viewer, and coverage breakdown.
- In-terminal JSON and Markdown export.
- Cancellation via `[ Esc ]` or `[ C ]`.

---

## 3. `bouclier history`

Browse, inspect, correlate, and manage scan assessments saved in local SQLite storage (`~/.bouclier/bouclier.db`).

### Subcommands

#### `bouclier history list [flags]`
List saved scans with pagination and filtering.
- `--target <string>`: Filter scans by exact or partial target URL/hostname.
- `--classification <tier>`: Filter by risk classification (`clean`, `low`, `guarded`, `elevated`, `high`, `critical`).
- `--min-score <n>`: Filter by minimum overall score (0–100).
- `--max-score <n>`: Filter by maximum overall score (0–100).
- `--status <status>`: Filter by execution status (`completed`, `partial`, `failed`).
- `--limit <n>`: Maximum number of records to return (default: `20`, max: `100`).
- `--offset <n>`: Number of records to skip for pagination.
- `-f, --format <format>`: Output format (`terminal`, `json`).

```bash
bouclier history list --min-score 50 --max-score 100
bouclier history list --target example.com --format json
```

#### `bouclier history show <scan-id> [flags]`
Display the full assessment report for a stored scan without rescanning. Supports short 8-char prefixes or full UUIDs.
- `-f, --format <format>`: Output format (`terminal`, `json`, `markdown`).
- `-o, --output <path>`: Write report to file.

```bash
bouclier history show 7a9b2c3d --format markdown
bouclier history show 7a9b2c3d --format json --output stored-report.json
```

#### `bouclier history correlate <target> [flags]`
Track security posture evolution for a domain across historical scans, identifying new, recurring, and resolved findings over time.
- `--limit <n>`: Maximum number of historical scans to correlate (default: `100`, max: `500`).
- `-f, --format <format>`: Output format (`terminal`, `json`, `markdown`).
- `-o, --output <path>`: Write correlation report to file.

```bash
bouclier history correlate example.com --format markdown --output trend.md
```

#### `bouclier history delete <scan-id> [flags]`
Permanently remove a scan and its associated findings from local persistence.
- `-y, --yes`: Skip interactive confirmation prompt.

```bash
bouclier history delete 7a9b2c3d --yes
```

---

## 4. `bouclier intel`

Manage local-first threat intelligence feeds, indicator lookups, and collaborative exchange bundles.

### Subcommands

#### `bouclier intel status`
Display the health and indicator metrics of the local intelligence database.

#### `bouclier intel sources list`
List all configured intelligence sources with their type, URL/file path, enabled state, and sync status.

#### `bouclier intel sources add <name> <type> <location> [flags]`
Register a new threat feed source.
- `<type>`: `local_json`, `local_csv`, or `remote_https`.
- `--description <string>`: Informational description.
- `--auth-header-env <ENV_VAR>`: Name of the environment variable storing authentication credentials (never persisted in plaintext).
- `--enabled`: Whether the source is active for synchronization (default: `true`).

```bash
# Register a local JSON feed
bouclier intel sources add custom-feed local_json ./feeds/indicators.json

# Register an authenticated remote feed referencing an environment variable
bouclier intel sources add enterprise-feed remote_https https://threats.internal.example/feed.json --auth-header-env ENTERPRISE_FEED_TOKEN
```

#### `bouclier intel sources enable <name>` / `disable <name>`
Toggle source inclusion in synchronization runs.

#### `bouclier intel sources remove <name>`
Delete a configured source and purge its ingested indicators.

#### `bouclier intel update [flags]`
Fetch and ingest indicators from all enabled feeds into local storage.
- `--source <name>`: Update only the specified feed source.

#### `bouclier intel search <query> [flags]`
Search stored threat indicators.
- `--type <type>`: Filter by indicator type (`url`, `domain`, `ipv4`, `ipv6`).
- `--limit <n>`: Maximum results (default: `20`, max: `100`).

```bash
bouclier intel search badsite.com --type domain
```

#### `bouclier intel import <file> [flags]`
Import a collaborative exchange bundle (`.bouclier-intel.json`).
- `--source-name <string>`: Override the attribution source name.

#### `bouclier intel export <file> [flags]`
Export local indicators into a verifiable collaborative bundle (`bouclier-intel-bundle/v1`) with SHA-256 integrity metadata.
- `--source-name <string>`: Export indicators originating from a specific source.
- `-f, --format <format>`: Export format (`bundle`, `json`, `csv`). Default: `bundle`.

#### `bouclier intel prune [flags]`
Delete expired indicators from the local database.
- `--all`: Purge all stored indicators.

---

## 5. `bouclier serve`

Start the local loopback HTTP API server.

```bash
bouclier serve [flags]
```

### Flags
- `--host <ip>`: Bind IP address. Default: `127.0.0.1` (wildcard `0.0.0.0` is strictly rejected for safety).
- `--port <port>`: Port to listen on. Default: `8081`.

---

## 6. `bouclier mcp`

Start the stdio Model Context Protocol (MCP) server for integration with local AI agents (e.g. Claude Desktop, Antigravity, Cursor).

```bash
bouclier mcp
```

Diagnostic logs are emitted to `stderr`, keeping `stdout` reserved for newline-delimited JSON-RPC messages.

---

## 7. `bouclier config show`

Print the active effective configuration, with sensitive values (tokens, credentials, secrets) automatically redacted.

```bash
bouclier config show [--config <path>]
```

---

## 8. `bouclier version`

Display application version, Git commit SHA, UTC build timestamp, Go runtime, and target architecture.

```bash
bouclier version
```
