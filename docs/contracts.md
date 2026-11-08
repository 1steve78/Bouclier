# Contracts freeze

## Overview

This repository defines the contract schema for scan reports, threat intelligence correlation metadata, and the related API and on-chain submission flow. The goals are to keep the data model stable while other subsystems are built in parallel, and to ensure that a report hash is reproducible from canonicalized content without storing raw message text or sensitive URL data in the chain.

## Enums

The canonical enums are defined in `internal/model/enums.go` and are reflected exactly in the API and fixtures.

- RiskLevel: `low_risk`, `suspicious`, `high_risk`, `confirmed_malicious`
- Severity: `info`, `low`, `medium`, `high`, `critical`
- Confidence: `low`, `medium`, `high`
- Module: `url`, `domain`, `tls`, `web`, `intel`, `message`, `correlation`
- FindingSource: `rule`, `feed`, `probe`
- CheckStatus: `completed`, `skipped`, `failed`
- IndicatorType: `url`, `domain`, `ip`, `email`, `phone`, `cert_fingerprint`, `payment_handle`
- ReportKind: `url`, `message`
- ChainStatus: `pending`, `confirmed`, `failed`

## Report schema

A canonical report is a JSON object with these fields:

```json
{
  "schema_version": 1,
  "id": "report-uuid",
  "kind": "url",
  "target": {
    "input": "https://example.com/login",
    "message_sha256": "",
    "normalized_url": "https://example.com/login",
    "host": "example.com",
    "registrable_domain": "example.com"
  },
  "risk_level": "suspicious",
  "score": 42,
  "findings": [
    {
      "id": "URL_MALICIOUS_REDIRECT",
      "module": "url",
      "title": "Malicious redirect",
      "severity": "medium",
      "confidence": "high",
      "source": "rule",
      "evidence": [
        {"key": "redirect_url", "value": "https://evil.example/"}
      ],
      "impact": "User may be redirected to a phishing site.",
      "recommendation": "Block the redirect and alert the user.",
      "limitations": "This is a heuristic signal and should be verified in context."
    }
  ],
  "indicators": [{"type": "domain", "value": "evil.example"}],
  "checks": [{"module": "tls", "status": "completed", "detail": "Cert chain validated"}],
  "redirect_chain": [{"url": "https://example.com/landing", "status_code": 302, "location_host": "evil.example"}],
  "scanned_at": "2025-01-14T22:00:00Z",
  "engine_version": "1.0.0",
  "precautions": ["Do not click untrusted links."],
  "limitations": ["This is not a guarantee of safety."],
  "ai_explanation": {"provider": "ollama", "model": "llama3.2", "text": "The domain uses an unusual redirect pattern.", "generated_at": "2025-01-14T22:00:00Z"},
  "ai_observations": [{"label": "Redirect pattern", "explanation": "Redirect chain points to a lookalike host.", "excerpt": "evil.example"}],
  "linked_report_ids": ["report-123"],
  "chain": {"status": "pending", "tx_hash": "0xabc...", "network": "ethereum", "contract_address": "0x1234...", "block_number": 12345, "explorer_url": "https://etherscan.io/tx/0xabc"},
  "report_hash": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

URL reports require `target.input`, `target.normalized_url`, `target.host`, and `target.registrable_domain`. Message reports set `target.input` to the empty string and populate `target.message_sha256`; `normalized_url`, `host`, and `registrable_domain` are optional for message reports and are omitted when empty.

## Finding schema

```json
{
  "id": "TLS_CERT_EXPIRED",
  "module": "tls",
  "title": "Certificate expired",
  "severity": "high",
  "confidence": "high",
  "source": "rule",
  "evidence": [{"key": "not_after", "value": "2024-11-12T00:00:00Z"}],
  "impact": "Visitors may see certificate warnings.",
  "recommendation": "Replace the certificate immediately.",
  "limitations": "This is a signal from a single check and may be affected by stale state."
}
```

## Risk invariants

The following invariants must hold for every valid report:

- `schema_version` is exactly `1`.
- `score` is an integer between `0` and `100`.
- `risk_level` and `score` match the score ranges described below.
- `report_hash` must match `"0x" + 64 lowercase hex characters`.
- `limitations` must not be empty.
- `id` and finding IDs must be non-empty.
- Finding IDs identify a rule, not an individual finding instance; multiple findings may share an ID.
- `low_risk` means `0..24` and must not include findings at severity `high` or `critical`.
- `suspicious` means `25..59` and must include at least one finding at severity `medium` or higher.
- `high_risk` means `60..84` and must include at least two findings with severity `high` or `critical`.
- `confirmed_malicious` means `85..100` and must include at least one `feed` finding with `confidence=high`.
- Message reports are reserved for content moderation and cannot exceed `suspicious` on persuasive or urgent language alone; they require a non-`message` finding to exceed that threshold.
- Message reports must have an empty `target.input` and a populated `target.message_sha256`.

## Canonical hashing

The canonical hash is computed from a report after removing the following fields before canonical serialization:

- `id`
- `report_hash`
- `ai_explanation`
- `ai_observations`
- `precautions`
- `limitations`
- `linked_report_ids`
- `chain`

The remaining top-level fields are:

- `schema_version`
- `kind`
- `target`
- `risk_level`
- `score`
- `findings`
- `indicators`
- `checks`
- `redirect_chain`
- `scanned_at`
- `engine_version`

Important rules:

- Sort arrays before serialisation:
  - findings by `(id, canonical_json(finding))`, comparing strings by UTF-8 bytes
  - indicators by `(type, value)`, comparing strings by UTF-8 bytes
  - checks by `(module, detail)`, comparing strings by UTF-8 bytes; if both are equal, sort by status bytes for deterministic output
  - evidence by key bytes
  - `redirect_chain` keeps its original order because the flow order is meaningful
- Canonical JSON uses UTF-8, sorts every object’s keys by their UTF-8 bytes, and has no insignificant whitespace.
- Strings are surrounded by double quotes. Escape only `"` as `\"`, `\` as `\\`, and control characters below U+0020 as `\b`, `\f`, `\n`, `\r`, or `\t` where applicable; encode other such controls as `\u00xx` using lowercase hexadecimal. Emit every other character raw as UTF-8, including `<`, `>`, `&`, U+007F, U+2028, U+2029, and non-ASCII characters. Reject strings and object keys containing invalid UTF-8.
- Integers only: reject floats, exponent notation, and negative zero (`-0`).
- Empty arrays serialize as `[]`; optional empty strings and objects are omitted. Required empty strings, such as message-report `target.input`, remain present.
- Strings are hashed exactly as provided; no Unicode normalisation is applied.
- `report_hash` is `"0x" + lowercase hex(sha256(canonical_bytes))` and must be exactly 66 characters.

The Go implementation is in `internal/model/report.go` and uses `HashReport(Report)` and `CanonicalJSON(Report)` as the canonical API.

## API summary

The API is defined in `api/openapi.yaml`.

### Error envelope

```json
{"error":{"code":"invalid_input","message":"The input was malformed.","details":"..."}}
```

Allowed error codes:

- `invalid_input`
- `target_blocked`
- `rate_limited`
- `scan_timeout`
- `not_found`
- `ai_unavailable`
- `chain_unavailable`
- `already_reported`
- `internal`

### Endpoints

- `GET /health`
- `GET /config`
- `POST /scan`
- `POST /analyze-message`
- `GET /reports`
- `GET /reports/{id}`
- `POST /reports/{id}/submit`
- `GET /reports/{id}/verify`
- `GET /correlations?report_id`

The correlation strength rules are:

- `cert_fingerprint`, `payment_handle`, `phone` => strong
- `ip`, `domain`, `email` => weak; shared hosting/CDN can cause false correlation

## Chain contract summary

The solidity interface is defined in `contracts/ThreatRegistry.abi.json` and `contracts/INTERFACE.md`. The on-chain payload is intentionally minimal: only `reportHash` and `riskLevel` are recorded. URLs, messages, and raw report payloads never enter the chain.

Risk mapping:

- `1` => `suspicious`
- `2` => `high_risk`
- `3` => `confirmed_malicious`
- `0` and values greater than `3` revert.

## MCP tools summary

The MCP summary is in `docs/mcp-tools.md` and lists the tool surface:

- `check_url{url, ai?}`
- `inspect_tls{host, port=443}`
- `scan_headers{url}`
- `lookup_threat_feeds{value}`
- `analyze_message{message}`
- `get_report{id}`
- `verify_report{id}`

All tools are read-only, subject to the same SSRF protections as the REST API, and must treat tool output as untrusted data.

## Decisions

1. We use a single canonical hashing function that omits metadata fields and preserves semantically meaningful array ordering.
2. Message reports are permitted to have an empty `target.input`, but raw message content never enters the report.
3. For `high_risk` and `confirmed_malicious`, we rely on severity/confidence checks instead of ad-hoc scores to avoid ambiguous outcomes.
4. We intentionally limit on-chain data to the hash and risk level to reduce privacy and data retention risk.
5. We keep the canonical hash and report schema stable even when AI explanation metadata or chain state is later attached.
6. Finding IDs identify rule codes rather than instances, so repeated finding IDs are valid and canonical JSON breaks ties.
7. Timestamps for `scanned_at` and `ai_explanation.generated_at` use exactly `YYYY-MM-DDTHH:MM:SSZ`; offsets and fractional seconds are rejected.
8. For message reports, `target.normalized_url`, `target.host`, and `target.registrable_domain` may be omitted when empty.
