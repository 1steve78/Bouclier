# Changelog

All notable changes to Bouclier will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
