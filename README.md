# Bouclier

Bouclier is a Go-based command-line security tool for phishing detection, domain risk evaluation, and website security posture assessment. It orchestrates passive URL heuristics, domain intelligence, TLS/certificate analysis, and HTTP header security checks into an explainable, deterministic risk scoring framework.

## Key Capabilities

- **Interactive Terminal UI**: Full-screen Bubble Tea terminal interface (`bouclier tui`) with live stage checklist, asynchronous scan execution, finding inspector, and keyboard navigation.
- **Single-command scanning**: Run comprehensive multi-vector assessments with `bouclier scan <url>`.
- **URL & Domain Heuristics**: Evaluates homograph/IDN spoofing, entropy, suspicious top-level domains, IP-as-host, deep subdomains, and credential indicators.
- **TLS Intelligence**: Inspects certificate validity, key strength, issuer trust, signature algorithms, expiration windows, and optional Certificate Transparency (CT) logs.
- **Passive HTTP Security Assessment**: Analyzes HTTP security response headers (HSTS, CSP, X-Frame-Options, etc.), cookie security flags (`Secure`, `HttpOnly`, `SameSite`), and safe redirect sequences.
- **Unified Deterministic Risk Scoring**: Aggregates normalized findings using the `bouclier-default` policy into an overall score (0–100) and clear classification (`clean`, `low`, `medium`, `high`, `critical`).
- **Flexible Export Formats**: Human-readable terminal output (with ANSI color, quiet, and verbose modes), structured machine-readable JSON (`bouclier-risk/v1`), and clean Markdown reports.
- **CI/CD Integration**: Supports deterministic exit codes and a `--fail-on-risk` threshold flag to gate deployment pipelines.
- **Built-in Safety**: Enforces strict SSRF mitigations, IP address pinning, private network blocks, credential scrubbing, and secure file creation permissions (`0600`).

---

## Installation & Build

### Prerequisites

- [Go 1.22](https://go.dev/dl/) or later
- Git

### Build from Source

```bash
git clone https://github.com/your-org/bouclier.git
cd bouclier
go build -o bin/bouclier.exe .
```

On Linux or macOS:
```bash
go build -o bin/bouclier .
```

Or install directly to your `$GOPATH/bin`:
```bash
go install .
```

---

## Command Reference

### Interactive Terminal UI

```bash
bouclier tui [flags]
```

Launches Bouclier's interactive Bubble Tea terminal user interface.

Options:
- `--no-color`: Disable ANSI color sequences in the interactive interface.
- `--config <path>`: Load application configuration from the specified JSON file.

### Root & Help

```bash
bouclier --help
```

Displays global options, available subcommands, and usage examples.

### Scanning a Target

```bash
bouclier scan <url> [flags]
```

Performs an end-to-end security assessment against the specified target URL.

### Displaying Version

```bash
bouclier version
```

Prints application version, Go runtime, target OS/architecture, and Git VCS revision metadata (when built with module versioning).

### Viewing Configuration

```bash
bouclier config show [--config path]
```

Prints the effective runtime configuration in formatted JSON, masking any sensitive fields.

### Starting the HTTP API server

```bash
bouclier serve
```

The initial server binds to `127.0.0.1:8081` and shuts down gracefully when interrupted. Override the host or port with flags, or configure them in the JSON file selected by `--config`:

```bash
bouclier serve --host 127.0.0.1 --port 8081
bouclier --config configs/config.json serve
```

The `http_server` configuration section accepts `host`, `port`, `read_header_timeout`, `read_timeout`, `write_timeout`, and `idle_timeout` (duration values use Go duration syntax such as `"5s"`). Defaults are `127.0.0.1`, `8081`, `5s`, `15s`, `30s`, and `60s`, respectively. Wildcard bind addresses are rejected.

Only these initial endpoints are available:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Process liveness |
| `GET` | `/ready` | API initialization readiness |
| `GET` | `/api/v1` | API name and version metadata |

Example requests:

```bash
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/ready
curl http://127.0.0.1:8081/api/v1
```

For request/response conventions, error codes, and the canonical report schema reference, see [API Contracts](docs/api-contracts.md).

---

## Example Usage

### 1. Default Terminal Scan

```bash
bouclier scan https://example.com
```

Renders a full terminal summary with ANSI colored risk badges, severity breakdown, top contributing risk factors, component coverage status, and assessment limitations.

### 2. JSON Export (Machine-Readable / SIEM)

Export to stdout:
```bash
bouclier scan https://example.com --format json
```

Export directly to a file:
```bash
bouclier scan https://example.com --format json --output assessment.json
```

The resulting file is created with restricted permissions (`0600`).

### 3. Markdown Export (Documentation / Pull Requests)

Export to stdout:
```bash
bouclier scan https://example.com --format markdown
```

Export to a file:
```bash
bouclier scan https://example.com --format markdown --output report.md
```

### 4. Adjusting Certificate Transparency (CT) Checks

Disable Certificate Transparency lookups (useful in network-isolated environments):
```bash
bouclier scan https://example.com --no-ct
```

Modify the CT search scope (`registrable` or `exact`):
```bash
bouclier scan https://example.com --ct-scope exact
```

### 5. Concise (Quiet) and Detailed (Verbose) Output

Quiet mode (prints only score and top risk factors):
```bash
bouclier scan https://example.com --quiet
```

Verbose mode (prints full finding descriptions, remediation hints, and technical evidence):
```bash
bouclier scan https://example.com --verbose
```

Disable color codes (useful for plain text logs, also auto-detected via `NO_COLOR` environment variable):
```bash
bouclier scan https://example.com --no-color
```

### 6. CI/CD Pipeline Automation with `--fail-on-risk`

Bouclier exits with code `5` (`ExitRiskThresholdExceeded`) if the calculated risk score meets or exceeds the configured threshold.

Example in a shell or CI script:
```bash
#!/usr/bin/env bash
set -e

# Fail pipeline if risk score is 50 or higher
bouclier scan "https://staging.example.com" \
  --fail-on-risk 50 \
  --format markdown \
  --output report.md

EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
  echo "Security scan passed!"
elif [ $EXIT_CODE -eq 5 ]; then
  echo "Security scan failed: risk score threshold exceeded"
  exit 1
else
  echo "Security scan failed with operational error code $EXIT_CODE"
  exit $EXIT_CODE
fi
```

---

## Interactive Terminal UI (TUI)

Bouclier provides an interactive, full-screen terminal user interface built with [Bubble Tea](https://github.com/charmbracelet/bubbletea), [Bubbles](https://github.com/charmbracelet/bubbles), and [Lipgloss](https://github.com/charmbracelet/lipgloss).

Launch with:
```bash
bouclier tui
```

### Screens & Workflow

1. **Dashboard**: Welcome banner, security capabilities summary, and quick-launch actions.
2. **Target Input**: Enter any website URL or hostname. Validates target structure before executing scans.
3. **Live Scan Progress**: Live stage checklist tracking actual pipeline execution:
   - `[✓] URL Analysis`
   - `[✓] Domain Intelligence`
   - `[●] TLS & Certificate Analysis`
   - `[ ] Certificate Transparency`
   - `[ ] HTTP Security Assessment`
   - `[ ] Risk Aggregation`
4. **Assessment Overview**: Visual risk score card (0–100), classification tier badge, severity counts, top risk contributors, and component coverage pills.
5. **Findings Explorer**: Filterable list of findings with severity tabs (`All`, `Crit`, `High`, `Med`, `Low`, `Info`) and keyboard selection.
6. **Finding Inspector**: Comprehensive detail view for the selected finding, including code, scoring category, severity, confidence, score impact, technical evidence, and remediation advice.
7. **Coverage & Limitations**: Matrix of all 13 analysis components with status badges, error reasons, and boundary limitation caveats.
8. **Report Export**: Interactive dialog to export assessments as JSON (`bouclier-risk/v1`) or Markdown with secure `0600` file permissions.
9. **Help Screen**: In-app reference for keyboard navigation, scoring methodology, and risk tiers.

### Keyboard Shortcuts

| Shortcut | Description |
|---|---|
| `q` | Quit application |
| `?` | Toggle in-app help & methodology |
| `esc` | Return to previous screen / cancel modal |
| `enter` | Select / confirm active action |
| `↑` / `↓` (`k` / `j`) | Navigate lists and items |
| `tab` / `shift+tab` | Cycle filter tabs or form controls |
| `1` – `6` | Direct severity filters in findings explorer (`1: All`, `2: Crit`, `3: High`, `4: Med`, `5: Low`, `6: Info`) |
| `p` / `n` (`←` / `→`) | Previous / next finding in detail view |
| `c` | Cancel active scan / view coverage from overview |
| `f` | View findings explorer from overview |
| `e` | Open report export dialog |
| `n` / `s` | Start a new website scan |
| `ctrl+c` | Safe force exit |

### Terminal Requirements & Adaptability

- Requires an interactive terminal (stdin and stdout connected to a terminal). Running in non-interactive pipelines outputs an informative error directing users to `bouclier scan <url>`.
- Responsive layout handles standard 80x24 terminals, wide displays, and window resize events (`tea.WindowSizeMsg`).
- Supports `--no-color` flag and the `NO_COLOR` environment variable for monochrome / plain text rendering.

---

## Command Flags

### `scan` Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--format` | `-f` | `string` | `terminal` | Output format: `terminal`, `json`, or `markdown`. |
| `--output` | `-o` | `string` | `""` (stdout) | Destination file path for report export. Creates parent directories with `0700` and files with `0600`. |
| `--timeout` | `-t` | `duration` | `10s` | Overall timeout for the scan operation (e.g. `5s`, `30s`, `1m`). |
| `--no-ct` | | `bool` | `false` | Disable Certificate Transparency lookups. |
| `--ct-scope` | | `string` | `registrable` | Certificate Transparency search scope: `registrable` (eTLD+1) or `exact` (exact FQDN). |
| `--fail-on-risk` | | `int` | `unset` | Exit with code 5 if the final risk score meets or exceeds this threshold (range: 0–100). |
| `--verbose` | `-v` | `bool` | `false` | Include comprehensive finding details, evidence, and descriptions in terminal output. |
| `--quiet` | `-q` | `bool` | `false` | Minimal terminal output showing only target, score, classification, and top risk factors. |
| `--no-color` | | `bool` | `false` | Disable ANSI color sequences in terminal output. Also honors the `NO_COLOR` environment variable. |

### Global Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--config` | `string` | `""` | Path to configuration file (defaults to `configs/config.json` if present). |
| `--help`, `-h` | | | Show help for any command. |

---

## Documented Exit Codes

Bouclier returns deterministic process exit codes for scriptability and CI integration:

| Exit Code | Constant Name | Description |
|---|---|---|
| `0` | `ExitSuccess` | Scan succeeded; if `--fail-on-risk` was set, the score was strictly below threshold. |
| `2` | `ExitInvalidUsage` | Command-line usage error: missing URL argument, unrecognized flags, invalid values, or malformed URL syntax. |
| `3` | `ExitScanFailure` | Operational scan failure: network resolution failure, unreachable target, timeout, or private IP blocked by SSRF protection. |
| `4` | `ExitOutputError` | Report formatting or file export failure: unable to serialize or write to the destination path. |
| `5` | `ExitRiskThresholdExceeded` | Scan completed successfully, but the final risk score met or exceeded the `--fail-on-risk` threshold. |

---

## Report Formats & Schema

### JSON Schema Version: `bouclier-risk/v1`

When exporting with `--format json`, Bouclier outputs a standardized JSON payload adhering to schema version `bouclier-risk/v1`. The payload contains:

- `schema_version`: Constant `"bouclier-risk/v1"`.
- `target`: The evaluated target URL.
- `assessed_at`: ISO 8601 (RFC 3339) timestamp.
- `score`: Unified risk score (integer `0`–`100`).
- `classification`: Semantic risk tier (`clean`, `low`, `medium`, `high`, `critical`).
- `policy`: Scoring policy name and version (`bouclier-default` v1.0.0).
- `severity_counts`: Distribution of findings across `info`, `low`, `medium`, `high`, `critical`.
- `category_scores`: Contributions per domain (`url_heuristic`, `domain_registration`, `tls_certificate`, `http_security`).
- `top_risk_factors`: List of the highest-impact findings contributing to the score.
- `findings`: Comprehensive list of all normalized findings with codes, titles, descriptions, severities, and confidence levels.
- `coverage`: Component status breakdown (`completed`, `partial`, `failed`, `skipped`) for each analysis subsystem.
- `limitations`: Explanatory caveats and boundary conditions for the scan.

### Markdown Output

When exporting with `--format markdown`, Bouclier generates a clean, human-readable document suitable for GitHub pull request summaries, ticket attachments, or security audits. All untrusted target content and header strings are sanitized to avoid markdown rendering vulnerabilities.

---

## Security Considerations

1. **Passive Network Requests**:
   - Bouclier performs standard DNS resolutions, passive HTTPS TLS handshakes, and bounded HTTP `GET` requests.
   - It **never** executes JavaScript, renders client-side DOM, follows untrusted file downloads, or submits web forms.
2. **SSRF and Private Network Defenses**:
   - The scanner validates every resolved IP address against RFC 1918, RFC 3927, RFC 4193, loopback, and multicast ranges.
   - Connections to private, loopback, link-local, or internal hostnames are strictly refused on both the initial connection and throughout any HTTP redirect chains.
   - Resolvers pin the validated IP address to prevent DNS rebinding attacks between check time and connection time.
3. **Credential & Sensitive Data Sanitization**:
   - User credentials embedded in URLs (e.g. `https://user:pass@example.com`) are stripped and never recorded in findings, logs, or exports.
   - Sensitive HTTP request headers (such as `Authorization` or `Cookie`) and response body payloads are never captured or emitted in reports.
4. **Export File Protection**:
   - When writing reports via `--output`, Bouclier creates parent directories with `0700` and files with `0600` permissions, ensuring report contents cannot be accessed by other users on the operating system.

---

## Capabilities & Limitations

- **Passive Security Assessment Only**: Bouclier is designed for defensive posture evaluation and phishing triage. It does not perform active vulnerability exploitation, fuzzing, brute-forcing, or denial-of-service tests.
- **Static HTTP Inspection**: Assessments evaluate HTTP response headers, status codes, and server certificates. Single-page applications (SPAs) that generate navigation or links purely via client-side JavaScript execution will not have dynamically-injected DOM nodes analyzed.
- **Risk Scores Are Not Guarantees**: Bouclier's heuristic risk score provides an indicator of anomalous patterns and security hygiene gaps. A score of `0` does not certify that a target is completely safe or free from compromise, nor does a higher score definitively prove malicious intent.

---

## Development & Testing

Run code quality checks and tests:

```bash
# Format code
gofmt -w cmd internal

# Run static analysis
go vet ./...

# Run automated tests (without external network dependencies)
go test -v -count=1 ./...

# Build binary
go build -o bin/bouclier.exe .
```

All automated unit and CLI integration tests run hermetically using mock analyzers and local test fixtures with no dependencies on external live internet services.
