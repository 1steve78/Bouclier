# Bouclier Risk Scoring & Reporting Methodology

Bouclier implements a deterministic, auditable, and reproducible security scoring and reporting engine. Every scan produces a canonical report conforming to the `bouclier-risk/v1` schema.

---

## 1. Deterministic Scoring Philosophy

Unlike heuristic AI models that generate variable risk scores, Bouclier's risk engine (`internal/risk`) calculates scores using strict, deterministic arithmetic:

- **Reproducibility:** Scanning the exact same website with identical network responses and threat feeds yields the exact same numerical score.
- **Independence:** The score is a deterministic risk index (0–100), not a statistical probability of compromise.
- **Auditable Evidence:** Every point scored is tied directly to an explicit finding containing technical evidence and remediation guidance.

---

## 2. Risk Classification Tiers

Scores are mapped to five standardized risk classifications:

| Score Range | Classification | Indicator / Meaning |
|---|---|---|
| `0 – 19` | `low` | Standard security posture; minimal or informational issues detected. |
| `20 – 39` | `guarded` | Minor hygiene deficiencies (e.g. missing optional headers, aging certificate). |
| `40 – 59` | `elevated` | Notable security weaknesses (e.g. weak cipher suites, missing CSP/HSTS, suspicious domain patterns). |
| `60 – 79` | `high` | Significant indicators of compromise or severe misconfigurations (e.g. untrusted certificate, revoked status, homograph attack). |
| `80 – 100` | `severe` | Confirmed malicious IOC match, active credential phishing pattern, or critical TLS compromise. |

---

## 3. Scoring Architecture & Category Caps

To prevent minor configuration issues from disproportionately skewing the score, Bouclier uses **Category Caps**:

```text
  URL Heuristics          (raw points) ──► [ Capped at 60 ] ──┐
  TLS & Certificates      (raw points) ──► [ Capped at 50 ] ──┼──► SUM ──► [ Clamped 0-100 ] ──► Overall Score
  Certificate Transparency(raw points) ──► [ Capped at 40 ] ──┤
  HTTP Security           (raw points) ──► [ Capped at 40 ] ──┤
  Threat Intelligence     (raw points) ──► [ Capped at 60 ] ──┘
```

### Finding Severity Weights
Each finding receives a base point value determined by its severity tier:

| Severity Tier | Base Points |
|---|---|
| `critical` | 50 points |
| `high` | 30 points |
| `medium` | 15 points |
| `low` | 5 points |
| `informational` | 0 points |

Findings within the same category are summed up to that category's cap. The overall score is the sum of all category totals, clamped between 0 and 100.

---

## 4. Canonical Report Schema (`bouclier-risk/v1`)

Every scan assessment serializes into a standard JSON document:

```json
{
  "schema_version": "bouclier-risk/v1",
  "target": "https://example.com/",
  "overall_score": 35,
  "classification": "guarded",
  "scanned_at": "2026-11-09T01:00:00Z",
  "categories": {
    "url_heuristics": 0,
    "tls": 15,
    "certificate_transparency": 0,
    "http_security": 20,
    "threat_intelligence": 0
  },
  "findings": [
    {
      "code": "TLS_CIPHER_WEAK",
      "severity": "medium",
      "confidence": "high",
      "category": "tls",
      "title": "CBC-mode cipher suite negotiated",
      "description": "The server accepted TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.",
      "evidence": "Negotiated cipher suite TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013) is vulnerable to padding oracle attacks.",
      "score": 15,
      "remediation": "Configure TLS cipher suite priority to prefer AEAD ciphers (e.g. AES-GCM or CHACHA20-POLY1305)."
    },
    {
      "code": "WEB_CSP_MISSING",
      "severity": "medium",
      "confidence": "high",
      "category": "http_security",
      "title": "Content-Security-Policy header missing",
      "description": "No Content-Security-Policy header was present in the HTTP response.",
      "evidence": "HTTP response headers contained no Content-Security-Policy directive.",
      "score": 15,
      "remediation": "Deploy a Content-Security-Policy header defining trusted script and resource sources."
    },
    {
      "code": "WEB_COOKIE_SAMESITE",
      "severity": "low",
      "confidence": "high",
      "category": "http_security",
      "title": "Cookie missing SameSite attribute",
      "description": "One or more cookies lack the SameSite protection attribute.",
      "evidence": "Cookie 'session' does not define SameSite=Lax or SameSite=Strict.",
      "score": 5,
      "remediation": "Set SameSite=Lax or SameSite=Strict on all application cookies."
    }
  ],
  "analysis_coverage": [
    {
      "module": "url_heuristics",
      "status": "completed",
      "duration_ms": 2
    },
    {
      "module": "tls_handshake",
      "status": "completed",
      "duration_ms": 98
    },
    {
      "module": "ct_logs",
      "status": "completed",
      "duration_ms": 140
    },
    {
      "module": "http_security",
      "status": "completed",
      "duration_ms": 86
    },
    {
      "module": "threat_intelligence",
      "status": "completed",
      "duration_ms": 1
    }
  ]
}
```

---

## 5. Report Output Formats

### 5.1 Terminal Format
Default CLI output formatted with ANSI color indicators, category score bars, and actionable remediation summaries.

### 5.2 JSON Format (`--format json`)
Emits the exact canonical `bouclier-risk/v1` object directly to `stdout` or `--output <file>`. Ideal for ingestion into SIEMs, dashboards, and automated analysis pipelines.

### 5.3 Markdown Format (`--format markdown`)
Produces GitHub Flavored Markdown documents ready for inclusion in pull request comments, security tickets, or compliance archives:

```markdown
# Bouclier Security Assessment

**Target:** `https://example.com/`  
**Date:** 2026-11-09 01:00:00 UTC  
**Risk Score:** 35 / 100 (`guarded`)

## Category Breakdown
- URL Heuristics: 0 / 60
- TLS Configuration: 15 / 50
- Certificate Transparency: 0 / 40
- HTTP Security: 20 / 40
- Threat Intelligence: 0 / 60

## Findings (3)
...
```

---

## 6. Cryptographic Integrity & Digest Verification

When a scan is persisted into the local SQLite database (`bouclier.db`), Bouclier computes a SHA-256 digest over the canonical normalized JSON representation of the assessment.

This digest ensures:
- **Tamper Detection:** Modifying stored records or database files invalidates the stored digest.
- **Audit Verification:** Inspecting a record via `bouclier history show <id>` or through the MCP `verify_report` tool validates the on-disk record against its original signature.
