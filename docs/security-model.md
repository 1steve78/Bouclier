# Bouclier Security Model & Threat Architecture

This document describes the security principles, trust boundaries, defense mechanisms, and design constraints implemented throughout Bouclier.

---

## 1. Threat Environment & Trust Boundaries

Bouclier interacts with potentially adversarial external systems:
1. **Target Websites:** Targets submitted for analysis may be operated by malicious actors, phishing kits, or compromised infrastructure designed to attack scanning agents.
2. **Threat Intelligence Feeds:** Third-party feed providers or collaborative bundles may contain malformed data, oversized payloads, or poisoned indicators.
3. **Local API / MCP Callers:** Local processes, scripts, or LLM agents querying the API or MCP interface may submit arbitrary target URLs or inputs.

### Core Security Invariants
- **Untrusted Input Invariant:** All data returned over the network (HTTP responses, TLS certificate fields, DNS records, feed payloads) is untrusted data. It is parsed strictly using bounded readers and never executed or passed to shell evaluators.
- **SSRF Immunity Invariant:** Bouclier must never be weaponized to probe, pivot into, or exfiltrate data from internal private networks, loopback services, or cloud instance metadata endpoints.
- **Local-First Privacy Invariant:** Scanning a target never triggers outbound telemetry or target disclosure to third-party threat intelligence APIs. Target matching is performed 100% locally against the embedded SQLite database.
- **No Plaintext Credential Storage:** Sensitive feed tokens or authorization headers are never stored in SQLite or written to reports. Credentials are referenced strictly via environment variables.

---

## 2. Multi-Layered SSRF Defense Architecture

Server-Side Request Forgery (SSRF) and DNS rebinding represent the primary network-level threats against automated URL analyzers. Bouclier enforces a defense-in-depth model across every network interaction.

### 2.1 Restricted Address Ranges
Every resolved IP address is verified against prohibited networks before any network socket is opened:

| Address Block | Purpose / Designation |
|---|---|
| `0.0.0.0/8` | "This network" / current network broadcast |
| `10.0.0.0/8` | RFC 1918 Private Network Class A |
| `100.64.0.0/10` | RFC 6598 Carrier-Grade NAT |
| `127.0.0.0/8` | RFC 1122 Loopback (`127.0.0.1`, etc.) |
| `169.254.0.0/16` | RFC 3927 Link-Local / Cloud Instance Metadata (`169.254.169.254`) |
| `172.16.0.0/12` | RFC 1918 Private Network Class B |
| `192.0.0.0/24` | RFC 6890 IETF Protocol Assignments |
| `192.0.2.0/24` | RFC 5737 Documentation (TEST-NET-1) |
| `192.168.0.0/16` | RFC 1918 Private Network Class C |
| `198.18.0.0/15` | RFC 2544 Network Interconnect Device Benchmark |
| `198.51.100.0/24` | RFC 5737 Documentation (TEST-NET-2) |
| `203.0.113.0/24` | RFC 5737 Documentation (TEST-NET-3) |
| `224.0.0.0/4` | RFC 5771 Multicast |
| `240.0.0.0/4` | RFC 1112 Reserved / Future Use |
| `255.255.255.255/32`| RFC 919 Broadcast |
| `::1/128` | IPv6 Loopback |
| `::/128` | IPv6 Unspecified |
| `fc00::/7` | RFC 4193 Unique Local Unicast (ULA) |
| `fe80::/10` | RFC 4291 Link-Local Unicast |
| `ff00::/8` | RFC 4291 IPv6 Multicast |

### 2.2 DNS Rebinding Defense (IP Socket Pinning)
Standard HTTP clients resolve hostnames once during DNS lookup, leaving open a window where an attacker's DNS server can return a public IP for the initial lookup and subsequently return `127.0.0.1` or `169.254.169.254` for the actual TCP connection (Time-of-Check to Time-of-Use / TOCTOU vulnerability).

Bouclier defeats DNS rebinding via **Socket Pinning**:
1. Custom dialer intercepts hostname resolution.
2. All returned IP addresses from the system resolver are evaluated against the restricted address table. If any IP resolves to a private range, the connection is aborted immediately.
3. The dialer picks a verified public IP and dials the remote TCP socket directly to that pinned IP address.
4. The HTTP/TLS `Host` header and SNI extension retain the original domain name, ensuring valid virtual hosting and TLS handshakes while guaranteeing the physical packet is routed solely to the validated public address.

### 2.3 Strict Redirect Validation
Malicious sites frequently use HTTP 301/302 redirects to point scanners towards internal resources (e.g. `http://attacker.com/redirect` -> `http://169.254.169.254/latest/meta-data/`).
- Bouclier disables automatic redirect following in Go's default `http.Client`.
- Each redirect response is caught and validated individually.
- The new `Location` URL is parsed, scheme-checked (only HTTP/HTTPS permitted), hostname-resolved, and evaluated against the SSRF filter before a subsequent connection is permitted.
- Redirect chains are capped at a maximum of 3 to 5 hops to prevent redirect loops and amplification attacks.

### 2.4 Established SSRF Exit Code Contract
When the CLI encounters a target URL that resolves to a restricted private, loopback, or cloud-metadata destination:
- Execution is safely terminated before any socket connection is initiated.
- An informative error is output: `Scan blocked by SSRF protection: target resolves to a prohibited destination`.
- The CLI exits with **Exit Code 3** (`ExitSSRFBlocked`).

---

## 3. Resource Bounds & Denial-of-Service Protection

Scanning untrusted websites exposes the analyzer to resource exhaustion attacks:

### 3.1 Memory Bounds
- **HTTP Response Bodies:** Capped at **10 MiB** via `io.LimitReader`. Scanners inspect only the initial payload needed for heuristic analysis, preventing zip bombs or unbounded streaming responses from consuming memory.
- **Threat Intelligence Feeds:** Remote feed downloads are capped at **10 MiB**. Oversized feeds are rejected before full buffering.
- **REST API Body Limit:** Request payloads to `/api/v1/scans` are limited to **1 MiB** and must contain exactly one JSON value.

### 3.2 Timeouts & Execution Bounds
- **Total Scan Duration:** Governed by context timeouts (default 20 seconds).
- **TLS Handshake Timeout:** Capped at 5 seconds.
- **HTTP Request Timeout:** Capped at 10 seconds.
- **Certificate Transparency Queries:** Background CT log queries are bounded by 5-second timeouts and run asynchronously without blocking the overall assessment.

### 3.3 Concurrency Control
- The REST API enforces a global concurrency semaphore (default 10 concurrent scans).
- Excessive simultaneous requests receive `429 Too Many Requests` rather than degrading system performance.

---

## 4. Threat Intelligence Privacy & Credential Security

### 4.1 Zero Ambient Data Disclosure
- Traditional URL scanners query cloud APIs (e.g. Google Safe Browsing, VirusTotal) transmitting the scanned URL across the wire.
- Bouclier matches targets **exclusively against local SQLite tables** (`bouclier.db`). Target URLs and assessment results are never shared externally.

### 4.2 Credential Protection
- Remote feed sources requiring authentication headers do **NOT** accept secrets as CLI arguments or JSON configuration fields.
- Sources store an environment variable pointer (e.g., `--auth-header-env BOUCLIER_FEED_TOKEN`).
- At request time, Bouclier resolves `os.Getenv(envVar)`.
- SQLite database migrations actively delete legacy plaintext credential columns.
- Credentials never appear in logs, debug dumps, terminal screens, or exported JSON/Markdown reports.
