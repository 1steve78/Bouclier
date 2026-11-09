# Changelog

All notable changes to Bouclier will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.1.0] - 2026-11-09

### Product Evolution: Bouclier | Security Intelligence Workstation
Evolved Bouclier from a CLI tool with an optional TUI into a fully integrated, production-grade **Terminal-First Security Workstation**.

### Added
- **Terminal-First Dual Entrypoint:**
  - Bare `bouclier` invocation in an interactive terminal (TTY) automatically launches directly into the Workstation Dashboard.
  - Non-interactive invocations (CI/CD pipelines, background scripts, redirected stdout/stdin) preserve the standard CLI help and exit code `0`.
  - Explicit CLI subcommands (`scan`, `history`, `intel`, `serve`, `mcp`, `config`, `version`, `tui`) execute standalone without TUI interception.
  - Shared in-process architecture: both CLI and Workstation call shared Go engine services with zero subprocess spawning.
- **7-Module Workstation Navigation:**
  - `[1] Target Scanner`: Interactive URL input with pre-validation, Certificate Transparency (`--no-ct`) toggle, match scope (`exact`/`registrable`) toggle, and request timeout cycle.
  - `[2] Scan History`: Filter historical scans by target domain, load stored assessments into findings explorer without rescanning, delete scans with confirmation dialogs, and launch trend correlation.
  - `[3] Threat Intelligence`: Manage feed sources, register sources with environment-variable credential indirection (`--auth-header-env`), toggle feeds, search local indicators, prune expired indicators, and exchange bundles.
  - `[4] Security Reports`: Export assessments to JSON (`bouclier-risk/v1`) or Markdown with custom path input and secure atomic file writes (`0600`).
  - `[5] Configuration Inspector`: Read-only structured view of all subsystem parameters with strict token/credential redaction (`[REDACTED]`).
  - `[6] API & MCP Services`: In-process loopback REST API server start/stop daemon controls on `127.0.0.1:8081`, combined with MCP stdio isolation guidance, copyable client snippets, and tool catalog.
  - `[7] About & Integrity`: Built-in tabbed inspector for build metadata, MIT License text, 38 third-party open-source notices, and security architecture guarantees.
- **Universal Command Palette (`/` or `Ctrl+K`):**
  - Instant searchable modal overlay accessible from anywhere across the workstation.
  - Fuzzy/prefix text search across workstation modules, navigation destinations, and administrative actions.
- **Multi-Scan Trend Correlation (`ScreenHistoryCorrelate`):**
  - Interactive visualization of historical target security posture evolution.
  - ASCII risk progression bars, score evolution net delta, and finding state transitions (newly emerged, recurring, and resolved findings).
- **In-TUI In-Process REST API Server Manager:**
  - Direct start/stop controls for the loopback HTTP daemon inside the workstation.
- **Accessibility & UX Polish:**
  - Time-of-day dynamic greeting (`Good morning!`, `Good afternoon!`, `Good evening!`, `Good night!`).
  - Real-time system status card (total scans, 24h count, threat feeds, active indicators, SQLite WAL connection status).
  - Responsive layout handling with minimum terminal window advisory (80x24).
  - Full `NO_COLOR` and monochrome theme toggling.

---

## [1.0.0] - 2026-11-09

Initial public release of Bouclier — an open-source, local-first URL intelligence and website security assessment platform.

### Added
- **Multi-Stage Security Engine:**
  - URL and domain heuristic analysis (homographs, suspicious TLDs, entropy, IP literal detection).
  - TLS configuration and certificate intelligence (cipher suites, protocol versions, validity periods, SAN analysis).
  - Certificate Transparency (CT) log query integration.
  - HTTP security header inspection (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Cache-Control, Cookie security attributes).
  - Local-first collaborative threat intelligence matching (domains, URLs, IPv4, IPv6 indicators).
- **Deterministic Risk Engine & Canonical Schema (`bouclier-risk/v1`):**
  - Deterministic 0–100 risk scoring with category caps preventing single-issue inflation.
  - Standard risk classification tiers (`low`, `guarded`, `elevated`, `high`, `severe`).
  - Terminal ANSI, raw JSON, and GitHub Flavored Markdown report renderers.
- **Unified Cobra CLI:**
  - `bouclier scan <url>`: Run one-shot target security assessments.
  - `bouclier tui`: Launch the interactive terminal UI.
  - `bouclier history`: Browse, show, correlate, and delete historical scan assessments.
  - `bouclier intel`: Manage threat feeds, search IOCs, sync feeds, import/export bundles, and prune expired indicators.
  - `bouclier serve`: Run the embedded REST API daemon.
  - `bouclier mcp`: Run the Model Context Protocol (MCP) server over stdio.
  - `bouclier config show`: View active configuration and defaults.
  - `bouclier version`: Inspect version, git commit, build date, Go runtime, and platform.
- **Bubble Tea Terminal User Interface (TUI):**
  - Interactive keyboard-driven navigation across 12 dedicated screens.
  - Live progress monitoring with stage-by-stage cancellation (`c` / `Esc`).
  - Finding explorer with severity filtering (`1`-`6`) and remediation details.
  - Built-in report export (JSON/Markdown) and history browser.
  - Threat intelligence manager with multi-tab status, feed source table, and IOC search.
- **Local Persistence & History:**
  - Embedded SQLite storage (`~/.bouclier/bouclier.db`) via pure-Go `modernc.org/sqlite` (zero CGO required).
  - Automated, idempotent schema migrations (versions 1 through 5).
  - SHA-256 report digest calculation and tamper-detection verification.
- **Local-First Threat Intelligence Subsystem:**
  - Support for local JSON/CSV files and remote HTTPS feeds.
  - Normalized indicator ingestion (`domain`, `url`, `ipv4`, `ipv6`).
  - Strict 90-day freshness boundaries and automatic expired indicator filtering.
  - Collaborative bundle exchange format (`bouclier-intel-bundle/v1`) with manifest SHA-256 verification.
- **Embedded REST API & MCP Server:**
  - Loopback-bound HTTP REST endpoints (`/health`, `/ready`, `/api/v1`, `/api/v1/scans`).
  - Seven read-only MCP tools (`check_url`, `inspect_tls`, `scan_headers`, `lookup_threat_feeds`, `analyze_message`, `get_report`, `verify_report`).
- **Cross-Platform Release Engineering:**
  - Automated build packaging for 6 target architectures (`windows/amd64`, `windows/arm64`, `linux/amd64`, `linux/arm64`, `darwin/arm64`, `darwin/amd64`).
  - Release archives (`.zip` for Windows, `.tar.gz` for Linux/macOS) bundling executable, `README.md`, `LICENSE`, and `THIRD_PARTY_NOTICES.md` with SHA-256 `checksums.txt`.
  - GitHub Actions release automation workflow.
- **Licensing & Compliance:**
  - Official open-source release under the MIT License (`LICENSE`).
  - Full third-party software licensing inventory and attribution in `THIRD_PARTY_NOTICES.md`.

### Security
- **Multi-Layer SSRF Defense:** Enforced IP validation blocking private RFC 1918, loopback, link-local, multicast, and cloud instance metadata addresses (`169.254.169.254`).
- **DNS Rebinding Prevention:** Custom dialer pins physical socket connections directly to pre-validated IP addresses.
- **Safe Redirect Execution:** Disabled automatic client redirects; every intermediate hop is independently parsed, resolved, and validated. Max 3–5 hops.
- **Strict SSRF Exit Code Contract:** Enforced exit code 3 (`ExitSSRFBlocked`) for targets resolving to restricted destinations.
- **Resource Exhaustion Bounds:** 10 MiB read caps on HTTP responses and threat feeds via `io.LimitReader`; bounded request timeouts and concurrency semaphores.
- **Credential Hygiene:** Eliminated plaintext feed credential storage in SQLite; replaced with environment variable indirection (`--auth-header-env`).

### Known Limitations
- **Loopback-Only REST API:** The embedded HTTP API currently binds only to loopback interfaces (`127.0.0.1` / `::1`) due to lack of built-in authentication. Production remote deployments require an authenticating reverse proxy.
- **Collaborative Bundle Signatures:** Bundle manifests verify transport integrity via SHA-256 checksums, but do not yet include asymmetric PKI digital signatures for publisher identity verification.
