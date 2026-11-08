# Bouclier Threat Intelligence Subsystem

## 1. Overview & Architecture

Bouclier includes a **local-first, privacy-preserving threat intelligence subsystem** (`internal/intel`) integrated directly with the SQLite persistence layer (`internal/storage`) and the unified risk engine (`internal/risk`).

### Core Design Principles
1. **Local-First Operation:** Target matching runs 100% locally against the embedded SQLite database during scans. Scans never trigger external network requests to threat intelligence feeds.
2. **Zero Ambient Data Sharing:** Bouclier does not participate in background telemetry, cloud synchronization, or automatic indicator sharing. Target URLs, scan history, private reports, and authentication credentials never leave the user's system.
3. **Strict Ingestion Safety:** Remote feed synchronization is context-aware, bounded in size (10 MiB limit), restricted to HTTPS, and strictly protected against Server-Side Request Forgery (SSRF) and DNS rebinding.
4. **Deterministic Risk Scoring:** Matches contribute to risk via explicit, capped scoring policy rules without double-counting identical indicators across multiple providers.
5. **Epistemological Integrity:** A threat intelligence match represents reported evidence from an intelligence provider, not an infallible proof of malice. Conversely, the absence of matching threat intelligence does not prove a website is benign.

---

## 2. Indicator Data Model

Bouclier normalizes, validates, and stores four canonical indicator types:

| Type | Format & Normalization Rules | Example |
|---|---|---|
| `domain` | IDNA/Punycode lowercase ASCII, trailing dots stripped, validated against the Public Suffix List (PSL). Reject URLs, schemes, ports, userinfo, IP literals, and invalid labels. | `phish-bank.com` |
| `url` | RFC 3986 normalized HTTP/HTTPS URL with credentials stripped, canonical path, and lowercase scheme/host. | `https://badsite.org/login.php` |
| `ipv4` | Canonical IPv4 dotted-decimal representation parsed via `net/netip`. Private and loopback ranges rejected on ingestion. | `198.51.100.42` |
| `ipv6` | Canonical RFC 5952 lowercase IPv6 representation parsed via `net/netip`. Brackets stripped. | `2001:db8::1` |

### Indicator Record Schema
- `id`: Stable deterministic hash (SHA-256 of `source_id + type + normalized_value`) or UUID v4.
- `type`: `domain`, `url`, `ipv4`, or `ipv6`.
- `value`: Canonical normalized indicator value.
- `source_id`: Stable identifier of the reporting source.
- `source_name`: Human-readable name of the reporting provider.
- `category`: Threat classification (e.g. `phishing`, `malware`, `c2`, `suspicious`).
- `confidence`: Bounded integer between `0` and `100`.
- `severity`: Standard severity tier (`informational`, `low`, `medium`, `high`, `critical`).
- `first_seen`: Optional RFC 3339 timestamp when the indicator was first observed.
- `last_seen`: Optional RFC 3339 timestamp when the indicator was most recently confirmed.
- `expires_at`: Optional RFC 3339 timestamp after which the indicator is inactive.
- `ingested_at`: UTC timestamp when the indicator was added to local storage.
- `source_ref`: External reference identifier or ticket number.
- `description`: Contextual explanation provided by the source.
- `metadata`: Key-value attribute map.

---

## 3. Feed Sources & Secure Ingestion Pipeline

### Supported Feed Providers
1. **Local File Provider (`local_file`):** Loads indicators from JSON array, JSON object wrapper, or CSV files on local disk.
2. **HTTPS Remote Provider (`https_feed`):** Synchronizes remote feeds with the following network safety controls:
   - **HTTPS Enforced:** Cleartext `http://` endpoints are rejected.
   - **SSRF & Private IP Blocking:** Resolves hostnames and verifies every IP address against private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local, multicast, and carrier-grade NAT address spaces before dialing.
   - **Pinned Connection:** Dialing is pinned directly to the validated IP address to prevent DNS rebinding attacks.
   - **Safe Redirect Handling:** Maximum of 3 redirects, each independently re-checked for HTTPS and non-private destination IP.
   - **Bounded Memory & Timeout:** Reads capped at 10 MiB via `io.LimitReader`; bounded request timeouts (default 15s).
   - **Zero Environment Proxy Bypass:** Custom `http.Transport` ignores ambient environment proxies.

### Deduplication and Partial Ingestion
- Ingestion processes all valid records and isolates malformed records into a structured `errors` list.
- Batch upserts deduplicate records on `(source_id, indicator_type, value)`, retaining the highest confidence score and latest observation time.

---

## 4. Intelligence Matching Engine

During scan execution, `internal/intel/matching.go` checks target coordinates against local SQLite tables:

### Match Types & Specificity
1. **Exact URL Match (`MatchExactURL`):** Target URL matches an active indicator URL character-for-character.
2. **Exact Domain Match (`MatchExactDomain`):** Target hostname matches an active domain indicator.
3. **Registrable Domain Match (`MatchRegistrableDomain`):** Target hostname's parent registrable domain (e.g. `evil.com` for `sub.evil.com`) matches an indicator.
4. **Exact IP Match (`MatchExactIP`):** Target resolved IP matches an active IPv4 or IPv6 indicator.

### Expiration & Freshness Semantics
- **Expired Indicators:** Indicators where `expires_at <= now` are strictly excluded from scan match results. Expired indicators are never matched.
- **Freshness Boundaries:**
  - `fresh`: `last_seen >= now - 90 days` (last confirmed within or at 90 days relative to the scan reference time).
  - `stale`: `last_seen < now - 90 days` (last confirmed more than 90 days ago). Stale matches map to `INTEL_MATCH_STALE` with low severity.
  - If `last_seen` is omitted, `ingested_at` is evaluated against the same 90-day threshold.

---

## 5. Risk Engine & Scoring Policy Integration

Threat intelligence matches produce catalogued risk findings in `internal/risk`:

| Code | Severity | Confidence | Category | Scored | Cap |
|---|---|---|---|---|---|
| `INTEL_MALICIOUS_URL` | Critical | High | threat-intelligence | Yes | 50 |
| `INTEL_MALICIOUS_DOMAIN` | High | High | threat-intelligence | Yes | 50 |
| `INTEL_MALICIOUS_IP` | High | High | threat-intelligence | Yes | 50 |
| `INTEL_SUSPICIOUS_REGISTRABLE_DOMAIN` | Medium | Medium | threat-intelligence | Yes | 50 |
| `INTEL_MATCH_STALE` | Low | Low | threat-intelligence | Yes | 50 |

- **Category Cap:** The `threat-intelligence` category has a cap of 60 points in `DefaultPolicy()`.
- **Deduplication:** Multiple feeds reporting the same indicator are deduplicated on code and normalized evidence to prevent score inflation.

---

## 6. Collaborative Bundle Exchange (`bouclier-intel-bundle/v1`)

Bouclier supports explicit peer exchange of threat intelligence bundles:

### Manifest & Cryptographic Integrity
```json
{
  "manifest": {
    "schema_version": "bouclier-intel-bundle/v1",
    "bundle_version": "1.0",
    "created_at": "2026-11-08T22:30:00Z",
    "generator": "Bouclier CLI",
    "indicator_count": 2,
    "checksum_sha256": "4b92b67f401ad8983...d8a"
  },
  "indicators": [ ... ]
}
```
- Every bundle is sealed with a deterministic SHA-256 checksum over the canonical indicator payload.
- Files are exported with restrictive `0600` permissions.
- Bundles never include private scan history, full reports, credentials, or cookies.

### Cryptographic Trust Model & Boundaries
> [!IMPORTANT]
> **Transport Integrity vs. Publisher Authenticity:**
> - **Transport and File Integrity:** The SHA-256 checksum proves that the indicator payload matches the bundle manifest exactly as exported. It reliably detects bit rot, truncated downloads, transmission errors, and manual tampering of the bundle contents.
> - **Publisher Identity & Trust:** The SHA-256 digest verifies *integrity relative to the manifest*; it **DOES NOT** prove the identity, reputability, or authenticity of the entity that created the bundle. Bouclier bundles currently do **NOT** include asymmetric digital signatures (such as Ed25519 or RSA-PSS) or PKI certificates. Anyone can generate a structurally valid bundle manifest with a matching SHA-256 checksum for arbitrary indicators.
> - **Operational Guideline:** Only import collaborative bundles from trusted, verified peers or sanctioned intelligence providers. Bundles should be treated as collaborative peer-to-peer data transfers, not cryptographically authenticated identity claims.

---

## 7. CLI & TUI Command Reference

### CLI Commands
- `bouclier intel status`: Summary metrics, enabled sources, and database health.
- `bouclier intel sources`: List registered threat intelligence sources (default command).
- `bouclier intel sources list`: Explicit alias to list registered sources with status and last sync time.
- `bouclier intel sources add <id> <name> <type> <endpoint>`: Register a new local or HTTPS feed source:
  - `--format`: `json` (default) or `csv`.
  - `--auth-header-env <ENV_VAR>`: Environment variable name holding the Authorization header value (e.g., `BOUCLIER_PARTNER_FEED_TOKEN`). Bouclier never accepts raw secrets via CLI flags and never persists credentials to SQLite; only the environment variable name is stored, and secrets are resolved in memory at request time.
  - `--attribution`: Source provider attribution text.
  - `--license`: Optional data license description.
  - `--interval`: Update interval duration (e.g., `12h`, `24h`; default `24h`).
  - `--disabled`: Register source in a disabled state.

> [!NOTE]
> **Credential Security Model & Migration Notice:**
> - Bouclier does **NOT** claim encryption at rest for feed credentials. Rather, it eliminates credential persistence entirely through environment variable indirection.
> - Database schema migration 5 automatically purges legacy plaintext `auth_header` values and drops the column. Users migrating from earlier schemas must update their source configurations using `--auth-header-env`.
- `bouclier intel sources remove <id>`: Delete a source, its indicators, and its sync history.
- `bouclier intel sources enable <id>`: Enable an existing source.
- `bouclier intel sources disable <id>`: Disable an existing source (excludes it from automatic synchronization).
- `bouclier intel update [source-id]`: Trigger synchronization of all enabled feeds or a specific feed.
- `bouclier intel search <query>`: Local indicator search across values, categories, and descriptions.
- `bouclier intel import <file>`: Import verified bundle or raw JSON/CSV feed.
- `bouclier intel export <file> [--category <cat>] [--min-confidence <n>]`: Export validated collaborative bundle.
- `bouclier intel prune [--dry-run] [--before <timestamp>]`: Remove expired records from local database.

### TUI Commands
- Press `I` from the Dashboard to open the Threat Intelligence screen.
- Tab `1`: Overview, indicators count, and health status.
- Tab `2`: Registered feed sources table.
- Tab `3`: Interactive indicator search.
- Press `U` to trigger asynchronous background feed synchronization (non-blocking).
- Press `C` while synchronizing to cancel the active synchronization run safely.
- Press `Esc` to return to the Dashboard.

---

## 8. Threat Intelligence Limitations

1. **Evidence, Not Guarantee:** An indicator match represents a finding reported by one or more sources. It should be investigated alongside URL heuristics, TLS certificates, and HTTP response analysis.
2. **Feed Outage Resilience:** If a threat intelligence feed or SQLite store is unavailable or unpopulated, standard security checks (URL heuristics, TLS handshake, CT logs, HTTP inspection) run without disruption.
3. **No Safety By Omission:** An assessment finding zero threat intelligence matches indicates that the destination is not present in local feeds; it does not guarantee that the site is safe.
