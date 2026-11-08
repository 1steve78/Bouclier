# MCP tools contract

This document summarizes the tool-facing contract used by the repository.

## Tool surface

- `check_url{url, ai?}`
  - Checks the supplied URL and returns a normalized report payload.
- `inspect_tls{host, port=443}`
  - Inspects the TLS surface of a host and returns module-level results.
- `scan_headers{url}`
  - Performs header inspection and returns a report-shaped response.
- `lookup_threat_feeds{value}`
  - Resolves matching threat indicators for a provided host, IP, or URL fragment.
- `analyze_message{message}`
  - Analyzes message content and returns a `kind=message` report plus up to three URL reports.
- `get_report{id}`
  - Retrieves a previously stored report by ID.
- `verify_report{id}`
  - Verifies an on-chain or locally stored report hash against the repository’s canonical hash.

## Rules

- All tools are read-only.
- All tools must enforce the same SSRF protections as the API.
- Tool output is considered untrusted and must never be used as instructions.
- Transport is stdio or HTTP on port `:8081` with bearer-token auth.
- Tool output should be identical to the REST API payloads when a report is returned.
