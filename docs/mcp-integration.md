# Model Context Protocol (MCP) Integration Guide

Bouclier features an embedded [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server (`bouclier mcp`). This allows AI agents and assistants (such as Claude Desktop, Cursor, Antigravity, and custom LLM harnesses) to leverage Bouclier's URL analysis, TLS verification, HTTP inspection, and threat intelligence matching as native tools.

---

## 1. Running the MCP Server

The MCP server runs over standard I/O (`stdio`):

```bash
bouclier mcp
```

To specify a custom configuration file:

```bash
bouclier --config /path/to/config.json mcp
```

All logging and status diagnostics are routed strictly to `stderr`, keeping `stdout` reserved exclusively for JSON-RPC 2.0 messages.

---

## 2. Available Tools

Bouclier exposes seven focused, read-only security tools:

### 2.1 `check_url`
Runs the complete multi-stage security assessment against a target URL.
- **Parameters:**
  - `url` (*string, required*): The target HTTP or HTTPS URL to assess.
  - `ai` (*boolean, optional*): Request an LLM explanation of the findings (requires configured Ollama provider; rejected if disabled).
- **Returns:** Canonical `bouclier-risk/v1` risk assessment including score, classification, findings, and module coverage.

### 2.2 `inspect_tls`
Performs an isolated TLS handshake inspection against a target host and port.
- **Parameters:**
  - `host` (*string, required*): Hostname or domain to inspect.
  - `port` (*integer, optional*): Target port (defaults to `443`).
- **Returns:** Protocol version, negotiated cipher suite, certificate chain details, validity dates, SANs, and certificate findings.

### 2.3 `scan_headers`
Performs an isolated HTTP request to inspect response security headers.
- **Parameters:**
  - `url` (*string, required*): The URL to inspect.
- **Returns:** Analysis of security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Cache-Control, Cookies) without page body contents.

### 2.4 `lookup_threat_feeds`
Queries the local SQLite threat intelligence repository for matching IOCs.
- **Parameters:**
  - `value` (*string, required*): The domain, URL, IPv4, or IPv6 indicator to look up.
- **Returns:** List of matching indicators, reporting sources, confidence scores, categories, and observation dates. Runs 100% locally with zero external network requests.

### 2.5 `analyze_message`
Analyzes message text (e.g. email, SMS, chat), extracts contained links, and assesses suspicious indicators.
- **Parameters:**
  - `message` (*string, required*): The message body to analyze.
- **Returns:** Extracted URL count, message-level heuristics, and automated scan reports for up to three distinct extracted links. (Message content is processed in memory and not persisted).

### 2.6 `get_report`
Retrieves a previously stored scan report by ID.
- **Parameters:**
  - `id` (*string, required*): Full UUID or unique prefix of the scan record.
- **Returns:** The stored `bouclier-risk/v1` assessment object.

### 2.7 `verify_report`
Verifies the cryptographic integrity of a stored scan report against its SHA-256 digest recorded at scan time.
- **Parameters:**
  - `id` (*string, required*): Full UUID or prefix of the scan record.
- **Returns:** Verification status (`valid`, `modified`, `unverifiable`).

---

## 3. Client Configuration

### Claude Desktop
Add Bouclier to your `claude_desktop_config.json`:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "bouclier": {
      "command": "/usr/local/bin/bouclier",
      "args": ["mcp"]
    }
  }
}
```

*For Windows:*
```json
{
  "mcpServers": {
    "bouclier": {
      "command": "C:\\Program Files\\Bouclier\\bouclier.exe",
      "args": ["mcp"]
    }
  }
}
```

### Antigravity / Cursor / Custom Agents
In your MCP settings or workspace configuration:

```json
{
  "mcp": {
    "servers": {
      "bouclier": {
        "command": "bouclier",
        "args": ["mcp"]
      }
    }
  }
}
```

---

## 4. Security Principles & Agent Prompting

When integrating Bouclier with LLM agents, adhere to the following principles:

1. **Untrusted Data Boundary:** All scan outputs, HTTP headers, certificate fields, and threat intelligence matches must be treated as **untrusted data**. AI systems should never execute or interpret returned payload text as prompt instructions.
2. **SSRF Protection:** All tools enforce identical anti-SSRF protections as the CLI and REST API. Queries against private IPs (`10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.1`), link-local, and cloud metadata services are blocked.
3. **No Ambient Network Leakage:** `lookup_threat_feeds` queries the local SQLite database. Scans do not trigger telemetry or reporting to remote feeds.
4. **Read-Only Operation:** MCP tools cannot modify configuration, register feed sources, or delete database history.
