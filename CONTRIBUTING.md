# Contributing to Bouclier

Thank you for your interest in contributing to Bouclier! We welcome bug reports, documentation improvements, architectural feedback, and code contributions.

---

## 1. Development Prerequisites

To develop, build, and test Bouclier locally, you will need:
- **Go:** Version 1.24 or later ([Download Go](https://go.dev/dl/)).
- **Git:** Version 2.30 or later.
- **Operating System:** Linux, macOS, or Windows.
- **CGO:** Bouclier uses pure-Go SQLite (`modernc.org/sqlite`). **CGO is not required** (`CGO_ENABLED=0` works out of the box on all supported platforms).

---

## 2. Getting Started

### Clone the Repository
```bash
git clone https://github.com/1steve78/Bouclier.git
cd Bouclier
```

### Build the Executable
```bash
go build -o bin/bouclier .
```
*(On Windows: `go build -o bin/bouclier.exe .`)*

### Verify the Build
```bash
./bin/bouclier version
```

---

## 3. Running Tests & Code Quality Verification

Before submitting changes or opening a pull request, ensure all tests and quality checks pass cleanly:

### 3.1 Code Formatting
Bouclier adheres strictly to standard Go formatting:
```bash
gofmt -l .
```
To automatically reformat changed files:
```bash
gofmt -w .
```

### 3.2 Dependency Hygiene
Ensure `go.mod` and `go.sum` are tidy and contain no unused dependencies:
```bash
go mod tidy
git diff --exit-code go.mod go.sum
```

### 3.3 Static Analysis
Run `go vet` to catch common subtle bugs:
```bash
go vet ./...
```

### 3.4 Test Suite
Run all unit and integration tests across the repository:
```bash
go test -count=1 ./...
```

To run with verbose output and test coverage:
```bash
go test -v -cover ./...
```

---

## 4. Package Structure & Architecture Overview

When contributing code, please place logic in the appropriate module:

- `cmd/`: Cobra CLI command definitions, flags, and parameter parsing.
- `internal/heuristics/`: URL lexical parsing, homograph detection, entropy, IP literal detection.
- `internal/tlscheck/`: TLS connection dialing, handshake analysis, cipher suite evaluation.
- `internal/certanalysis/`: Certificate chain verification, validity checks, SAN parsing.
- `internal/ct/`: Certificate Transparency log lookups.
- `internal/webcheck/`: HTTP security headers, cookies, and response status inspection.
- `internal/intel/`: Threat intelligence normalization, local matching, feed sync, bundle export/import.
- `internal/risk/`: Unified risk engine, deterministic 0–100 scoring, and category caps.
- `internal/report/`: Renderers for Terminal, JSON (`bouclier-risk/v1`), and Markdown.
- `internal/storage/`: SQLite repository, schema migrations, and scan record persistence.
- `internal/tui/`: Bubble Tea interactive terminal user interface and screen state machine.
- `internal/api/`: Embedded loopback REST API server.
- `internal/mcpserver/`: Model Context Protocol (MCP) server over stdio.
- `scripts/`: Packaging, release engineering, and helper scripts.

---

## 5. Security & Contribution Guidelines

1. **SSRF Invariant:** Never bypass or weaken the SSRF protection layers in `internal/webcheck` or `internal/intel`. All external network connections must strictly validate target IP addresses against private and cloud metadata blocks, pin sockets to approved IPs, and validate every redirect hop.
2. **Deterministic Scoring:** Risk scores must remain deterministic arithmetic values. Do not introduce probabilistic random values or non-deterministic heuristics into `internal/risk`.
3. **Resource Bounds:** Any network read must be bounded by `io.LimitReader` (default 10 MiB limit) to prevent memory exhaustion.
4. **Credential Security:** Never commit secrets, API keys, or credentials. Feeds requiring authentication must use environment variable indirection (`--auth-header-env`).
5. **Backwards Compatibility:** Maintain backwards compatibility for CLI exit codes (`0`, `1`, `2`, `3`, `4`, `5`), report schema (`bouclier-risk/v1`), and configuration files.

---

## 6. Pull Request Workflow

1. Fork the repository and create a feature branch (`git checkout -b feature/my-enhancement`).
2. Implement your changes accompanied by table-driven unit tests.
3. Verify that `gofmt -l .`, `go vet ./...`, and `go test ./...` pass with zero warnings.
4. Commit your changes with clear, descriptive commit messages.
5. Push to your branch and submit a Pull Request against `main`.
