# Bouclier Versioning Strategy & Policy

## 1. Semantic Versioning Specification

Bouclier adheres to [Semantic Versioning 2.0.0](https://semver.org/) (`vMAJOR.MINOR.PATCH`):

- **MAJOR (v1.x.x -> v2.0.0)**: Incompatible architectural or breaking API changes:
  - Breaking changes to CLI flag semantics or exit codes.
  - Incompatible breaking changes to JSON reporting schema (`bouclier-risk/v1`).
  - Incompatible database schema changes requiring non-automated migration.
  - Incompatible changes to Model Context Protocol (MCP) tool schemas.
- **MINOR (v1.0.0 -> v1.1.0)**: Backward-compatible functionality additions:
  - New analysis modules or detection heuristics.
  - New CLI subcommands or optional flags.
  - New threat intelligence feed parsers or export capabilities.
  - Non-breaking additions to reports and API responses.
- **PATCH (v1.0.0 -> v1.0.1)**: Backward-compatible bug fixes and security hardening:
  - Security patches, SSRF filter additions, parser limit tightening.
  - Bug fixes in URL normalization, scoring calculation, or TUI presentation.
  - Performance optimizations that preserve deterministic output.

---

## 2. Release Targets & Development Builds

### Development Builds
When compiled directly from source without linker flags (e.g., `go build .` or `go run .`):
- Version defaults to `1.1.0-dev`.
- Build metadata is automatically extracted from local VCS records (`vcs.revision`, `vcs.time`) via `runtime/debug.ReadBuildInfo()`.
- Development binaries clearly indicate `-dev` in `bouclier version` and in HTTP `User-Agent` headers (`Bouclier/1.1.0-dev`).

### Release Builds
Official release binaries are built from annotated Git tags matching `v*` (e.g. `v1.0.0`):
- Authoritative version string is injected at build time via compiler linker flags.
- Git commit hash (short 12-char SHA) and ISO 8601 build timestamp (UTC) are baked into the binary.

---

## 3. Linker Flag Build Convention

Release binaries are compiled with explicit linker flags (`-ldflags`):

```bash
VERSION="1.0.0"
COMMIT="$(git rev-parse --short=12 HEAD)"
BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

go build -trimpath -ldflags="-s -w \
  -X 'bouclier/internal/cli.Version=${VERSION}' \
  -X 'bouclier/internal/cli.GitCommit=${COMMIT}' \
  -X 'bouclier/internal/cli.BuildDate=${BUILD_DATE}'" \
  -o bin/bouclier .
```

### Version Command Output
Invoking `bouclier version` produces:

```text
Bouclier v1.0.0
  Commit:   abc1234def56
  Built:    2026-11-09T12:00:00Z
  Go:       go1.26.1
  Platform: linux/amd64
```

---

## 4. Subsystem Versioning Compatibility

| Subsystem | Contract Identifier | Compatibility Guarantee |
|---|---|---|
| **CLI Exit Codes** | `0` (Success), `1` (General), `2` (Usage), `3` (Scan/SSRF Failure), `4` (Output), `5` (Threshold Exceeded) | Fixed within `v1.x.x`. |
| **Report JSON Schema** | `bouclier-risk/v1` | Additive only within `v1.x.x`. New fields may be added; existing fields will not be renamed or removed. |
| **Risk Scoring Policy** | `bouclier-default` v1.0 | Stable integer weighting (0–100 index). |
| **Intel Bundle Schema** | `bouclier-intel-bundle/v1` | Deterministic SHA-256 manifest format. |
| **Database Migrations** | `schema_migrations` | Fully forward-compatible and idempotent across upgrades. |
| **Local HTTP API** | `/api/v1` | Semantic versioning per REST prefix. |
