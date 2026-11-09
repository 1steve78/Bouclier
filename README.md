# Bouclier | Security Intelligence Workstation

[![CI](https://github.com/1steve78/Bouclier/actions/workflows/ci.yml/badge.svg)](https://github.com/1steve78/Bouclier/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](docs/versioning.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/1steve78/Bouclier)](https://goreportcard.com/report/github.com/1steve78/Bouclier)

Bouclier is an open-source, local-first **Terminal-First Security Workstation** and command-line security assessment engine built with Go. It brings together URL heuristics, domain intelligence, TLS verification, Certificate Transparency (CT) log analysis, passive HTTP posture checks, and local threat intelligence into an explainable, deterministic risk scoring framework (`bouclier-risk/v1`).

---

## The Terminal-First Experience

In v1.1.0, Bouclier shifts from a CLI tool with an optional TUI into an integrated **Terminal-First Security Workstation**:

```bash
# Simply run bouclier in any interactive terminal
bouclier
```

Running bare `bouclier` launches directly into the interactive workstation dashboard. From here, security analysts, incident responders, and engineers navigate all capabilities using keyboard shortcuts without needing to memorize CLI commands:

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ BOUCLIER  •  Security Intelligence Workstation  •  v1.1.0                  │
│ Unified Phishing Detection, TLS Inspection, Threat Intelligence & Risk     │
└────────────────────────────────────────────────────────────────────────────┘

Good morning!  What would you like to investigate?

╭─ Workstation Modules ──────────────────────────────────────────────────────╮
│ ▶ [1] Target Scanner         Assess a target URL for phishing and TLS risks│
│   [2] Scan History           Browse past assessments & correlate trends    │
│   [3] Threat Intelligence    Manage threat feeds, search IOCs, sync/prune  │
│   [4] Security Reports       Export assessments to JSON or Markdown        │
│   [5] Configuration          Inspect active scanner, storage, and server   │
│   [6] API & MCP Services     Control local REST daemon & view MCP setup    │
│   [7] About & Integrity      Build metadata, MIT license, notices & policy │
╰────────────────────────────────────────────────────────────────────────────╯
```

### "TUI-First, Not TUI-Only"
Bouclier retains full CLI scriptability for automated workflows, CI/CD pipelines, and shell scripts:
- **Interactive TTY**: Bare `bouclier` opens the Workstation Dashboard.
- **Non-Interactive (Pipes / CI / Redirects)**: Bare `bouclier` cleanly displays standard command help and flags (exiting with code `0`).
- **Explicit Subcommands**: `bouclier scan <url>`, `bouclier history`, `bouclier intel`, `bouclier serve`, `bouclier mcp`, etc., execute directly as pure CLI commands without launching or touching the TUI.
- **Zero Subprocesses**: Both the Workstation and CLI execute the same shared in-process Go packages.

### Visual Demonstration
> [!NOTE]
> *Terminal demonstration recording (e.g. `docs/assets/bouclier-workstation.gif` / asciinema) will be added here following maintainer acceptance. The ASCII representation above reflects the exact layout rendered by the Bubble Tea workstation runtime.*

---

## Quick Start

Get started with Bouclier in seconds:

```bash
# 1. Launch the interactive workstation (in any interactive terminal)
bouclier

# 2. Or run a direct CLI security scan against a target URL
bouclier scan https://example.com

# 3. Check local threat intelligence status
bouclier intel status

# 4. View recent scan history
bouclier history list
```

---

## Documentation Quick Links

| Document | Purpose |
|---|---|
| [**Installation Guide**](docs/installation.md) | Binary downloads, installation for Windows, Linux, macOS, and checksum verification. |
| [**Upgrading Guide**](docs/upgrading.md) | Safe binary replacement, SQLite migrations, and backup procedures. |
| [**CLI Reference**](docs/cli-reference.md) | Complete guide to commands, flags, exit codes, and scripting options. |
| [**Interactive TUI Guide**](docs/tui-guide.md) | Keyboard shortcuts, screen navigation, live scan progress, and finding inspector. |
| [**Configuration Guide**](docs/configuration.md) | JSON configuration schema, environment variables, default paths, and timeouts. |
| [**Threat Intelligence**](docs/threat-intelligence.md) | Local-first feed ingestion, normalization, matching, and bundle exchange (`bouclier-intel-bundle/v1`). |
| [**REST API Reference**](docs/api-reference.md) | Loopback HTTP API daemon (`bouclier serve`), endpoints, cURL examples, and error schemas. |
| [**MCP Integration Guide**](docs/mcp-integration.md) | Claude Desktop, Antigravity, and Cursor setup with the Model Context Protocol server (`bouclier mcp`). |
| [**Reporting Methodology**](docs/reporting.md) | Deterministic 0–100 scoring, category caps, finding severity weights, and canonical schema. |
| [**Security Model & SSRF Defense**](docs/security-model.md) | Multi-layer SSRF prevention, IP socket pinning, bounded memory, and responsible disclosure. |
| [**System Architecture**](docs/architecture.md) | Comprehensive engineering design across all 24 packages and subsystems. |
| [**Versioning Policy**](docs/versioning.md) | Semantic versioning policy, linker metadata injection, and subsystem compatibility matrix. |
| [**Security Policy**](SECURITY.md) | Supported versions, GitHub Private Vulnerability Reporting, and disclosure timeline. |
| [**Contributing Guide**](CONTRIBUTING.md) | Development setup, coding standards, test suites, and pull request workflows. |
| [**Changelog**](CHANGELOG.md) | Version history and detailed changelog following Keep a Changelog. |
| [**Third-Party Notices**](THIRD_PARTY_NOTICES.md) | Complete inventory of third-party dependencies, licenses, and copyright notices. |

---

## Key Capabilities

- **Interactive Terminal UI**: Full-screen Bubble Tea terminal interface (`bouclier tui`) with live stage checklist, asynchronous scan execution, finding inspector, scan history browsing, keyboard navigation, and optional local Ollama explanations.
- **Single-command scanning**: Run comprehensive multi-vector assessments with `bouclier scan <url>`.
- **Collaborative Threat Intelligence**: Local-first malicious indicator matching (domains, URLs, IPv4, IPv6) without external lookup during scans, secure bounded feed synchronization, and cryptographic bundle import/export (`bouclier-intel-bundle/v1`) with zero background telemetry.
- **Persistent Scan History**: Local pure-Go SQLite persistence (`modernc.org/sqlite`) retaining scans across application restarts. Browse, inspect, export, and manage history via `bouclier history` and the interactive TUI.
- **URL & Domain Heuristics**: Evaluates homograph/IDN spoofing, entropy, suspicious top-level domains, IP-as-host, deep subdomains, and credential indicators.
- **TLS Intelligence**: Inspects certificate validity, key strength, issuer trust, signature algorithms, expiration windows, and optional Certificate Transparency (CT) logs.
- **Passive HTTP Security Assessment**: Analyzes HTTP security response headers (HSTS, CSP, X-Frame-Options, etc.), cookie security flags (`Secure`, `HttpOnly`, `SameSite`), and safe redirect sequences.
- **Unified Deterministic Risk Scoring**: Aggregates normalized findings using the `bouclier-default` policy into an overall score (0–100) and clear classification (`low`, `guarded`, `elevated`, `high`, `severe`).
- **Flexible Export Formats**: Human-readable terminal output (with ANSI color, quiet, and verbose modes), structured machine-readable JSON (`bouclier-risk/v1`), and clean Markdown reports.
- **CI/CD Integration**: Supports deterministic exit codes and a `--fail-on-risk` threshold flag to gate deployment pipelines.
- **Built-in Safety & Privacy**: Enforces strict SSRF mitigations, IP address pinning, private network blocks, credential scrubbing, and secure file creation permissions (`0600`). Never stores credentials, tokens, or raw HTTP bodies in persistence.

---

## Installation & Build

### Prerequisites

- [Go 1.24](https://go.dev/dl/) or later
- Git

### Build from Source

```bash
git clone https://github.com/1steve78/Bouclier.git
cd Bouclier
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

Features:
- **Welcome Dashboard**: Displays live capabilities overview and persistent recent scans loaded directly from the SQLite database.
- **Scan History Explorer (`[ H ]`)**: Browse stored scan assessments with pagination (`[` / `]`), select any past scan with arrow keys (`↑`/`↓` or `j`/`k`), and press `[ Enter ]` to open the full risk report without rescanning. Permanently delete records with `[ D ]` (includes interactive confirmation).
- **Live Scanning (`[ Enter / S ]`)**: Enter a target URL and observe asynchronous stage-by-stage progress with live elapsed timing and cancel anytime (`[ Esc ]` or `[ C ]`).
- **Risk Assessment Overview**: Comprehensive risk score dial, classification badge, and severity summary.
- **Finding Explorer (`[ F ]`)**: Filter findings by severity (`[ 1 ]`–`[ 6 ]` or `[ Tab ]`), inspect detailed remediation advice and evidence (`[ Enter ]`).
- **Coverage & Methodology (`[ C ]` / `[ ? ]`)**: Review component execution states and audit limitations.
- **Exporting (`[ E ]`)**: Export canonical JSON or Markdown reports directly to disk.

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

Performs an end-to-end security assessment against the specified target URL. Upon completion, the assessment and sanitized report are automatically persisted to the local SQLite database.

### Managing Scan History

```bash
bouclier history [command] [flags]
```

Inspect and manage historical scan assessments stored in the local SQLite database (`~/.bouclier/bouclier.db`). Allows browsing past scans, viewing full risk reports in multiple formats without repeating network scans, and removing records.

#### 1. Listing Scan History

```bash
# List recent scans (default limit: 20)
bouclier history list

# Filter by target domain substring
bouclier history list --target example.com

# Filter by risk classification
bouclier history list --classification critical

# Filter by scan status and paginate
bouclier history list --status completed --limit 10 --offset 20

# Output as structured JSON
bouclier history list --format json

# Correlate reports for a hostname and display a score graph
bouclier history correlate example.com
bouclier history correlate example.com --format markdown --output trend.md
```

Flags:
- `--limit <n>`: Maximum number of scan records to return (default: 20, max: 100).
- `--offset <n>`: Number of records to skip for pagination (default: 0).
- `--target <str>`: Filter records by target domain or URL substring.
- `--classification <class>`: Filter by risk classification (`low`, `guarded`, `elevated`, `high`, `critical`).
- `--status <status>`: Filter by execution status (`completed`, `partial`, `failed`, `cancelled`).
- `--format <fmt>`: Output format (`table` or `json`, default: `table`).

#### 2. Correlating Reports

```bash
bouclier history correlate example.com
bouclier history correlate example.com --format json --output trend.json
```

Correlation groups reports by exact normalized hostname, orders them chronologically, graphs the deterministic score, and compares consecutive reports for new and resolved findings. Finding identity uses normalized code, category, and evidence (falling back to title when evidence is empty). The latest 100 matching reports are used by default; `--limit` accepts up to 500. Output formats are `terminal`, `json`, and `markdown`. Correlation does not modify stored reports or recompute scores.

#### 3. Anchoring and Verifying Report Hashes

The optional EVM registry records the report's stored SHA-256 digest, a manually selected risk level, the submitting account, and the block timestamp. It does not publish the report, URL, or finding data. Compile with Solidity 0.8.28 using `npx --yes solc@0.8.28 --bin --abi contracts/ThreatRegistry.sol -o build/contracts`, then deploy [`contracts/ThreatRegistry.sol`](./contracts/ThreatRegistry.sol) from the account intended to remain the permanent owner. Only that owner and accounts it authorizes can submit report hashes; if Bouclier signs with another account, the owner must first call `setAuthorizedReporter(address, true)` for that address.

```powershell
$env:BOUCLIER_EVM_PRIVATE_KEY = "<private-key>"
bouclier history anchor 7a9b2c3d --rpc-url https://<evm-rpc> --contract-address 0x<deployed-contract> --risk-level 1
bouclier history verify 7a9b2c3d --rpc-url https://<evm-rpc> --contract-address 0x<deployed-contract>
```

Risk levels must be selected by a reviewer: `1` suspicious, `2` high risk, `3` confirmed malicious. Bouclier does not infer a confirmed-malicious status from its scan score. Anchor transaction metadata is also retained locally; the contract prevents duplicate hashes. The owner can correct a registered risk level with `correctReportRiskLevel(bytes32, uint8)`. The signing key is read from `BOUCLIER_EVM_PRIVATE_KEY` by default; `--private-key-env` can select another environment-variable name, but never pass the private key itself as a flag or config value. Use HTTPS for hosted RPC endpoints and a test network before any production deployment. The `verify` command compares the local report digest with the contract and reports whether any locally saved anchor metadata matches.

#### 4. Viewing a Historical Assessment

```bash
# View terminal summary for a scan (accepts 8-character prefix or full UUID)
bouclier history show 7a9b2c3d

# Export historical assessment to Markdown
bouclier history show 7a9b2c3d --format markdown --output report.md

# Output full canonical JSON (bouclier-risk/v1) to stdout
bouclier history show 7a9b2c3d --format json
```

Flags:
- `--format <fmt>`: Report format (`terminal`, `json`, or `markdown`, default: `terminal`).
- `--output <path>`: Write report to file path instead of stdout (permissions `0600`).
- `--quiet`: Minimal summary output.
- `--verbose`: Include all technical findings regardless of severity.
- `--no-color`: Disable ANSI color highlighting.

#### 5. Deleting a Historical Scan

```bash
# Delete with interactive confirmation
bouclier history delete 7a9b2c3d

# Delete without prompting
bouclier history delete 7a9b2c3d --yes
```

Flags:
- `-y`, `--yes`: Skip confirmation prompt.

### Threat Intelligence & IOC Management

Manage local threat intelligence feeds, synchronize indicators, search malicious indicators, and import/export collaborative bundles:

```bash
# Display threat intelligence health and metrics
bouclier intel status

# List configured intelligence sources
bouclier intel sources

# Synchronize enabled feeds or a specific feed
bouclier intel update
bouclier intel update feed-1

# Search indicators locally (matches exact values, domains, IPs, categories)
bouclier intel search evil-domain.com

# Import indicators from a verified bundle or raw JSON/CSV file
bouclier intel import bundle.json
bouclier intel import feed.csv --source-id custom-csv

# Export local indicators to a collaborative bundle with SHA-256 integrity check
bouclier intel export shared_bundle.json --category phishing --min-confidence 80

# Prune expired indicators
bouclier intel prune --dry-run
bouclier intel prune
```

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

The server binds to `127.0.0.1:8081` by default and shuts down gracefully when interrupted. Because the scan endpoint does not require authentication, the server only accepts literal loopback IP addresses (`127.0.0.0/8` or `::1`). Override the loopback host or port with flags, or configure them in the JSON file selected by `--config`:

```bash
bouclier serve --host 127.0.0.1 --port 8081
bouclier --config configs/config.json serve
```

The `http_server` configuration section accepts `host`, `port`, `read_header_timeout`, `read_timeout`, `write_timeout`, `idle_timeout`, and `max_scan_duration` (duration values use Go duration syntax such as `"5s"`). Defaults are `127.0.0.1`, `8081`, `5s`, `15s`, `30s`, `60s`, and `20s`, respectively. The write timeout must exceed the maximum scan duration. Non-loopback IPs, hostnames, and wildcard bind addresses are rejected. The maximum number of concurrent scans is configured with `scanner.max_concurrent_scans` (default `10`).

Available endpoints:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Process liveness |
| `GET` | `/ready` | API initialization readiness |
| `GET` | `/api/v1` | API name and version metadata |
| `POST` | `/api/v1/scans` | Synchronously assess a URL and return a `bouclier-risk/v1` report |

Example requests:

```bash
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/ready
curl http://127.0.0.1:8081/api/v1
curl -X POST http://127.0.0.1:8081/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://example.com"}'
```

Scans are synchronous, capped at 20 seconds by default, and bounded by the configured concurrent scan limit. Unsafe/private destinations are rejected. For request/response conventions, error codes, timeout behavior, and the canonical report schema reference, see [API Contracts](docs/api-contracts.md).

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
| `a` | Request an explanation from local Ollama on the assessment overview (when enabled) |
| `n` / `s` | Start a new website scan |
| `ctrl+c` | Safe force exit |

### Local Ollama Explanations

AI explanations are disabled by default and do not alter the deterministic score or saved assessment. To enable them, install/start Ollama and pull a model:

```bash
ollama serve
ollama pull llama3.2
```

In the Bouclier JSON config, set:

```json
"ai": {
  "enabled": true,
  "ollama": {
    "base_url": "http://127.0.0.1:11434",
    "model": "llama3.2"
  },
  "timeout": "90s",
  "max_tokens": 512
}
```

Then launch `bouclier --config <path-to-config.json> tui`, run a scan, and press `a` on its assessment overview. Bouclier runs `ollama list` to show installed models. Select one with the arrow keys and press Enter to generate the explanation. The selected model is used for the current TUI session and is not written back to the config file. Bouclier sends a sanitized summary of the score, findings, and coverage to the local Ollama service; it does not send raw response bodies. The configured Ollama URL must use a loopback host. Ollama must be installed and available on `PATH`.

### Terminal Requirements & Adaptability

- Requires an interactive terminal (stdin and stdout connected to a terminal). Running in non-interactive pipelines outputs an informative error directing users to `bouclier scan <url>`.
- Responsive layout handles standard 80x24 terminals, wide displays, and window resize events (`tea.WindowSizeMsg`).
- Supports `--no-color` flag and the `NO_COLOR` environment variable for monochrome / plain text rendering.
- Local AI explanations are opt-in. Set `ai.enabled` to `true`, configure the local Ollama model in `ai.ollama`, run Ollama, then press `a` on the assessment overview. Explanations do not modify findings, scores, or saved reports.

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
2. **SSRF and Prohibited Address Defenses**:
   - Outbound network dialers validate every resolved IP address before connection.
   - Prohibits loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Carrier-Grade NAT (`100.64.0.0/10`), link-local (`169.254.0.0/16`, `fe80::/10`), documentation prefixes (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`, `2001:db8::/32`), benchmarking (`198.18.0.0/15`), multicast, non-global unicast, and scoped IPv6 zones.
   - Pinned socket connections prevent DNS rebinding attacks between DNS resolution and TCP connection time.
   - Remote feed endpoints are strictly limited to standard web ports (`80`, `443`, `8080`, `8443`), rejecting connections to internal administrative services (e.g. SSH on port 22).
3. **Parser Limits & Resource Bounds**:
   - Target URLs and threat indicators are length-bounded to 8,192 bytes; domain labels are bounded to 253 characters.
   - External feed downloads and collaborative bundles are capped at 10 MiB with explicit overflow detection (`ErrFeedTooLarge`), avoiding silent truncation. Feed records are bounded to 50,000 entries.
   - Local configuration files and API / MCP payloads are bounded to 1 MiB.
4. **Credential & Sensitive Data Sanitization**:
   - User credentials embedded in URLs (e.g. `https://user:pass@example.com`) are stripped and never recorded in findings, logs, or exports.
   - Threat intelligence sources use environment variable references (`--auth-header-env`), never storing plaintext tokens or keys in persistence.
   - Structured logs automatically redact attributes matching sensitive keys (`token`, `secret`, `api_key`, `password`, `cookie`, `auth`) and scrub authorization tokens in URLs.
5. **Local API & MCP Browser Origin Protection**:
   - The local HTTP API server validates `Origin` headers, rejecting any non-loopback browser origins with HTTP 403 Forbidden to protect against drive-by cross-site port scanning and CSRF.
6. **SQLite Concurrency & Data Isolation**:
   - Persistent storage uses WAL mode with synchronized write serialization (`writeMu`), eliminating `SQLITE_BUSY` transaction lock contention across concurrent workers while preserving concurrent readers.
   - Export and database files are restricted with `0600` / `0700` filesystem permissions.

---

## Capabilities & Limitations

- **Passive Security Assessment Only**: Bouclier is designed for defensive posture evaluation and phishing triage. It does not perform active vulnerability exploitation, fuzzing, brute-forcing, or denial-of-service tests.
- **Static HTTP Inspection**: Assessments evaluate HTTP response headers, status codes, and server certificates. Single-page applications (SPAs) that generate navigation or links purely via client-side JavaScript execution will not have dynamically-injected DOM nodes analyzed.
- **Risk Scores Are Not Guarantees**: Bouclier's heuristic risk score provides an indicator of anomalous patterns and security hygiene gaps. A score of `0` does not certify that a target is completely safe or free from compromise, nor does a higher score definitively prove malicious intent.

---

## Development & Testing

Run code quality checks, tests, and benchmarks:

```bash
# Format code
gofmt -w cmd internal

# Run static analysis
go vet ./...

# Run automated tests (without external network dependencies)
go test -v -count=1 ./...

# Run tests with race detector (on Linux / CI)
go test -race ./...

# Run fuzz smoke tests (deterministic, bounded)
go test -run=^$ -fuzz=FuzzNormalizeIndicator -fuzztime=2s ./internal/intel
go test -run=^$ -fuzz=FuzzCertificateSANProcessing -fuzztime=2s ./internal/certanalysis

# Run performance benchmarks
go test -run=^$ -bench=. ./internal/heuristics ./internal/intel ./internal/risk ./internal/report ./internal/storage

# Build binary
go build -o bin/bouclier.exe .
```

All automated unit and CLI integration tests run hermetically using mock analyzers and local test fixtures with no dependencies on external live internet services.

---

## Security & Responsible Disclosure

For vulnerability reporting instructions and our disclosure policy, please consult [SECURITY.md](SECURITY.md). Vulnerabilities should be reported via [GitHub Private Vulnerability Reporting](https://github.com/1steve78/Bouclier/security/advisories/new).

---

## License

Bouclier is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 1steve78 and The Bouclier Authors.

Third-party libraries and dependencies compiled or linked into Bouclier binary distributions are licensed under their respective open-source licenses (MIT, BSD-3-Clause, Apache-2.0). Third-party dependencies are not automatically licensed under MIT; their applicable licenses and copyright notices are preserved in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
