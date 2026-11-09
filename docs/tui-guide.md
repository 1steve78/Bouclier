# Bouclier Interactive TUI Guide

Bouclier features an interactive terminal user interface (TUI) powered by Charm's [Bubble Tea](https://github.com/charmbracelet/bubbletea) framework. The TUI provides a visual, keyboard-driven workflow for running URL assessments, inspecting security findings, browsing historical scans, managing local threat intelligence feeds, and exporting reports.

---

## 1. Launching the TUI

Start the interactive interface directly from your terminal:

```bash
bouclier tui
```

To load an explicit configuration file:

```bash
bouclier --config path/to/config.json tui
```

### Terminal Requirements
- **Dimensions:** Minimum 80 columns by 24 rows recommended. The TUI dynamically responds to terminal window resize events (`tea.WindowSizeMsg`).
- **Colors:** Supports 256-color and truecolor ANSI terminals.
- **Clean Exit:** Exiting via `q` or `Ctrl+C` cleanly restores cursor visibility and terminal state.

---

## 2. Screen Architecture

The TUI is organized into specialized screens managed through a central state machine:

```text
               ┌───────────────┐
               │   Dashboard   │◄─────────────────────────────┐
               └───────┬───────┘                              │
                       │                                      │
       ┌───────────────┼───────────────┐                      │
       ▼               ▼               ▼                      │
┌──────────────┐┌──────────────┐┌──────────────┐              │
│  URL Input   ││ Scan History ││ Threat Intel │              │
└──────┬───────┘└──────────────┘└──────────────┘              │
       │                                                      │
       ▼                                                      │
┌──────────────┐                                              │
│   Scanning   │ (Progress & cancellation via 'c' or Esc)     │
└──────┬───────┘                                              │
       │                                                      │
       ▼                                                      │
┌──────────────┐       ┌──────────────┐       ┌──────────────┐│
│   Overview   │──────►│   Findings   │──────►│Finding Detail││
└──────┬───────┘       └──────────────┘       └──────────────┘│
       │                                                      │
       ├──────────────►┌──────────────┐                       │
       │               │   Coverage   │                       │
       │               └──────────────┘                       │
       └──────────────►┌──────────────┐                       │
                       │    Export    │───────────────────────┘
                       └──────────────┘
```

1. **Dashboard (`ScreenDashboard`):** Landing screen displaying system status, quick actions, recent scan metrics, and navigation shortcuts.
2. **URL Input (`ScreenURLInput`):** Target input dialog with client-side syntax and private IP/SSRF pre-validation.
3. **Scanning (`ScreenScanning`):** Live pipeline progress tracking each analysis stage (URL heuristics, TLS certificate, CT logs, HTTP security, threat intelligence, risk scoring).
4. **Overview (`ScreenOverview`):** High-level risk score gauge (0–100), classification banner (`low`, `guarded`, `elevated`, `high`, `severe`), target details, and category breakdown.
5. **Findings (`ScreenFindings`):** Interactive, filterable list of all detected security issues with severity badges and category tags.
6. **Finding Detail (`ScreenFindingDetail`):** Deep-dive view for a selected finding showing technical description, raw evidence, OWASP/CWE references, and remediation advice.
7. **Coverage (`ScreenCoverage`):** Execution audit showing which analysis modules ran, duration, and whether any module timed out or was skipped.
8. **Export (`ScreenExport`):** Interactive report generator supporting JSON and Markdown output formats with custom file path selection.
9. **History (`ScreenHistory`):** Browse past scans stored in the local SQLite database, inspect earlier assessments, or delete records.
10. **Threat Intelligence (`ScreenIntel`):** Tabbed interface to review indicator counts, inspect registered feed sources, trigger background sync (`U`), and search local IOCs.
11. **Help (`ScreenHelp`):** Overlay showing keyboard shortcuts available in the current context.

---

## 3. Global Keybindings & Navigation

| Key | Context | Action |
|---|---|---|
| `q` | Most screens | Quit application (or back if in sub-view) |
| `Ctrl+C` | Global | Force quit application immediately |
| `?` | Global | Toggle context-aware Help screen |
| `Esc` / `Backspace` | Sub-screens | Return to previous screen or cancel input |
| `Enter` | Selection | Confirm input, open selected item, or trigger action |
| `↑` / `k` | Lists / Menus | Navigate up |
| `↓` / `j` | Lists / Menus | Navigate down |
| `Tab` / `Shift+Tab`| Multi-field | Move focus between elements or tabs |

---

## 4. Workflows

### 4.1 Running a Scan
1. From the **Dashboard**, press `Enter` or `n` / `s` to open the **URL Input** dialog.
2. Type or paste the target URL (e.g., `https://example.com` or `phishing-test.bank.xyz`).
   - If the scheme is omitted, `https://` is automatically assumed.
   - Private IP addresses, loopback ranges (`127.0.0.1`), and malformed URLs are rejected inline before execution.
3. Press `Enter` to start the assessment.
4. During scanning, watch stage-by-stage execution. Press `c` or `Esc` to cancel an in-flight scan at any time without freezing the UI.
5. When complete, the TUI automatically transitions to the **Overview** screen.

### 4.2 Inspecting Findings & Remediation
1. From the **Overview** screen, press `f` to navigate to **Findings**.
2. Filter findings by severity tier using number keys:
   - `1`: Show **All** findings
   - `2`: Filter **Critical** findings
   - `3`: Filter **High** findings
   - `4`: Filter **Medium** findings
   - `5`: Filter **Low** findings
   - `6`: Filter **Informational** findings
3. Use `↑`/`↓` (or `k`/`j`) to highlight a finding and press `Enter` to view **Finding Detail**.
4. In the detail screen, review the exact evidence observed (e.g. missing HTTP headers, weak cipher suites, suspicious certificate SANs) and remediation guidance.
5. Press `Esc` to return to the findings list.

### 4.3 Exporting Reports
1. From the **Overview** screen, press `e` to enter the **Export** dialog.
2. Select between:
   - **JSON:** Complete machine-readable `bouclier-risk/v1` schema.
   - **Markdown:** Formatted summary suitable for documentation and incident tickets.
3. Specify or confirm the destination file path.
4. Press `Enter` to write the report to disk.

### 4.4 Browsing History
1. From the **Dashboard**, press `h` to open **Scan History**.
2. Scroll through historical assessments saved in the local SQLite database.
3. Press `Enter` on any historical record to reload and inspect its full Overview, Findings, and Coverage screens.
4. Press `d` or `x` to delete a selected historical scan record.

### 4.5 Threat Intelligence Management
1. From the **Dashboard**, press `i` to enter the **Threat Intelligence** screen.
2. Use `Tab` / `Shift+Tab` (or number keys) to switch between tabs:
   - **Tab 1 (Status):** Database metrics, active indicator counts, feed freshness.
   - **Tab 2 (Sources):** Configured local and HTTPS feeds, last sync timestamp, and status.
   - **Tab 3 (Search):** Interactive search against the local IOC database.
3. Press `U` to initiate background feed synchronization. Sync runs asynchronously without blocking the UI.
4. Press `c` during an active sync to cancel safely.
