# Bouclier Workstation User Manual

Bouclier is a **Terminal-First Security Workstation** and local-first URL intelligence platform. Built with Charm's [Bubble Tea](https://github.com/charmbracelet/bubbletea), Lip Gloss, and Bubbles, the workstation provides a complete, keyboard-driven security investigation console in your terminal.

---

## 1. Launching the Workstation

### Default Invocation
In an interactive terminal, simply run:

```bash
bouclier
```

Bouclier detects the interactive TTY environment and launches directly into the Workstation Dashboard.

### Explicit Launch
You can also launch the workstation explicitly:

```bash
bouclier tui
bouclier --config path/to/config.json tui
```

### Non-Interactive CLI Preservation
When run in scripts, CI/CD runners, or redirected pipelines (`|`, `>`), bare `bouclier` cleanly displays CLI usage and available flags (exiting with code `0`) without launching the TUI or hanging. Explicit subcommands (`bouclier scan`, `history`, `intel`, `serve`, `mcp`) always bypass the workstation.

---

## 2. Global Navigation & Hotkeys

| Key | Context | Action |
|---|---|---|
| `1`–`7` | Global / Dashboard | Jump directly to Workstation Modules 1 through 7 |
| `/` or `Ctrl+K` | Global | Open the Universal Command Palette |
| `?` | Global | Toggle context-aware Help screen |
| `Esc` / `Backspace` | Sub-screens | Return to previous screen or cancel input |
| `Enter` | Selection | Confirm input, open selected module, or execute action |
| `↑` / `k` | Menus / Lists | Move selection cursor up |
| `↓` / `j` | Menus / Lists | Move selection cursor down |
| `Tab` / `Shift+Tab` | Forms / Dialogs | Move focus between form fields or tabs |
| `q` | Non-input screens | Quit Bouclier Workstation |
| `Ctrl+C` | Global | Force quit immediately |

---

## 3. The 7 Workstation Modules

### Module 1: Target Scanner (`[1]`)
Assess a website URL for phishing indicators, TLS configuration anomalies, certificate issues, and passive HTTP posture weaknesses.

- **URL Input:** Type or paste target (e.g. `example.com`, `https://sub.bank.org`). Bare domains default to `https://`.
- **Options Toggles:**
  - `Certificate Transparency` (`c` or `Space`): Toggle CT log querying on/off (equivalent to `--no-ct`).
  - `CT Match Scope` (`o`): Switch between `exact` hostname and `registrable` domain matching.
  - `Analysis Timeout` (`t`): Cycle timeout duration (5s / 8s / 15s / 30s).
- **Asynchronous Execution:** Scans run non-blocking with an animated progress indicator and live elapsed timer.
- **Stage Checklist:** Live status tracking across URL Analysis, Domain Intelligence, TLS & Certificates, Certificate Transparency, HTTP Security, Threat Intelligence, and Risk Aggregation.
- **Cancellation:** Press `c` or `Esc` during an active scan to cancel immediately without freezing the UI.
- **SSRF Defense:** Private IP ranges, loopback (`127.0.0.1`), link-local, and cloud metadata addresses are blocked.

### Module 2: Scan History (`[2]`)
Browse, search, inspect, correlate, and manage past scan assessments saved in local SQLite storage.

- **Target Filtering (`f` / `F`):** Press `f` to filter history by target domain/hostname; press `F` to clear the filter.
- **Open Report (`Enter`):** Loads the complete historical assessment into the Overview and Findings Explorer without re-running network checks.
- **Trend Correlation (`c`):** Generates an on-the-fly historical trend report for the selected target host:
  - Total historical scans, first seen, and last seen timestamps.
  - Overall score evolution and net delta (`ELEVATING`, `IMPROVING`, `STABLE`).
  - ASCII historical progression bar chart.
  - Finding state transitions (newly emerged, recurring, and resolved findings).
- **Export Report (`e`):** Directly export selected historical assessment to JSON or Markdown.
- **Delete Scan (`d` / `x`):** Safely remove a scan record with an interactive `y`/`n` confirmation prompt.
- **Pagination (`[` / `]`):** Page through historical records.

### Module 3: Threat Intelligence (`[3]`)
Manage local-first threat indicators and collaborative feed sources.

- **Tab 1: Overview & Health (`1`):** Displays total active indicators, breakdown by source, database health, last sync status, and quick actions.
- **Tab 2: Sources Management (`2`):**
  - Browse configured feed sources (ID, Name, Type, Status).
  - Add Source (`a`): Register a new local JSON file or HTTPS feed.
    > [!IMPORTANT]
    > **Credential Security:** Feed credentials must be specified via environment variable names (e.g. `BOUCLIER_FEED_TOKEN`), never entered as plaintext secrets.
  - Toggle Source (`t`): Enable or disable a feed source.
  - Delete Source (`d`): Remove source and cascade-delete its associated indicators with confirmation.
- **Tab 3: Indicator Search (`3`):** Search local SQLite database for indicators matching a domain, URL, IP, or threat category.
- **Feed Synchronization (`u`):** Trigger asynchronous feed updates in the background. Press `c` to cancel.
- **Prune Expired Indicators (`p`):** Clean expired indicators from local storage with confirmation.
- **Bundle Exchange:**
  - Import Bundle (`m`): Ingest indicators from a `bouclier-intel-bundle/v1` JSON file.
  - Export Bundle (`x`): Save active local indicators into a portable JSON bundle file.

### Module 4: Security Reports (`[4]`)
Export active assessments or historical reports into structured formats.

- **Formats:**
  - **JSON (`bouclier-risk/v1`):** Canonical machine-readable assessment schema with full evidence, coverage audits, and score contributions.
  - **Markdown (`.md`):** Clean GitHub Flavored Markdown report suitable for documentation, audits, and incident tickets.
- **Destination Path:** Editable file path input (defaults to `bouclier-report.json` or `bouclier-report.md`).
- **Atomic Safe Writes:** All exports are written using atomic safe file creation with user-only `0600` permissions.

### Module 5: Configuration Inspector (`[5]`)
Read-only inspector displaying all active runtime parameters:

- **Subsystems:** Application metadata, Scanner parameters, SQLite Storage engine, Threat Intelligence feeds, Loopback HTTP Server settings, Logging, and AI / Ollama parameters.
- **Credential Redaction:** Any URLs containing credentials or sensitive query tokens (`token`, `key`, `secret`, `password`) are automatically masked as `[REDACTED]`.

### Module 6: API & MCP Services (`[6]`)
Manage background network and integration services.

- **Loopback REST API Daemon:**
  - In-process HTTP server binding strictly to loopback (`127.0.0.1:8081`).
  - Interactive Controls: Press `s` to start the REST server; press `x` to stop it.
  - Endpoints catalog: `GET /health`, `POST /api/v1/scan`, `GET /api/v1/history`, `GET /api/v1/intel/stats`, `POST /api/v1/intel/sync`.
- **Model Context Protocol (MCP) Server:**
  - Dedicated stdio JSON-RPC 2.0 interface for AI assistants (Claude Desktop, Cursor, Antigravity).
  - Stdio isolation note explaining why MCP runs as a separate CLI process (`bouclier mcp`).
  - 7 Exposed MCP Tools catalog (`scan_url`, `get_scan`, `list_scans`, `search_intel`, `get_intel_stats`, `sync_intel_feeds`, `get_config`).
  - Copyable configuration snippets for `claude_desktop_config.json`.

### Module 7: About & Integrity (`[7]`)
Built-in application metadata and compliance inspector.

- **Tab 1: Build Metadata (`1`):** Semantic version (`v1.1.0`), Git commit hash, UTC build timestamp, Go compiler version, target OS/Arch, pure-Go SQLite WAL engine.
- **Tab 2: MIT License (`2`):** Scrollable full text of the official 2026 MIT license.
- **Tab 3: Third-Party Notices (`3`):** Comprehensive breakdown of all 38 third-party open-source dependencies.
- **Tab 4: Security & Integrity (`4`):** Security guarantees, multi-layer SSRF protections, memory bounding, and responsible vulnerability disclosure policy.

---

## 4. Universal Command Palette (`/` or `Ctrl+K`)

Press `/` or `Ctrl+K` from anywhere in the workstation to open the searchable Command Palette:

```text
┌─ COMMAND PALETTE  Search actions & navigate ──────────────────────────────┐
│ > config                                                                  │
│ ──────────────────────────────────────────────────────────────────────────│
│ ▶ [Navigate]  Configuration Inspector   Inspect active scanner settings   │
│ ──────────────────────────────────────────────────────────────────────────│
│ ↑/↓ navigate  •  Enter execute  •  Esc dismiss                            │
└───────────────────────────────────────────────────────────────────────────┘
```

- Live interactive substring filtering across commands, screens, and administrative actions.
- Use `↑`/`↓` to highlight an action and press `Enter` to execute.
- Press `Esc` to dismiss and return to the active screen.

---

## 5. Accessibility & Theme Options

- **Color Themes:** Full 256-color palette with high-contrast score and severity badges.
- **Monochrome Mode:** Respects the standard `NO_COLOR` environment variable or can be toggled on-the-fly via the Command Palette (`Toggle Color Theme`).
- **Responsive Layout:** Automatically adjusts card widths and table columns on terminal resize (`tea.WindowSizeMsg`). Displays an advisory notice if the terminal is below 80x24.
