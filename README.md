# Bouclier

Bouclier is a Go command-line application for phishing detection and website security assessment. The project is intended to grow into a focused scanner with an interactive terminal interface.

## Purpose and development status

Bouclier aims to assess URLs and websites using explainable indicators, certificate and connection checks, and threat intelligence. The CLI does not yet expose a user-facing website scan command. Reusable internal analysis APIs now cover URL/domain intelligence, TLS/certificate/CT inspection, and passive HTTP security assessment; findings remain observations rather than a score or verdict.

### Current features

- `--help`, `--version`, and `--config` CLI options.
- JSON configuration defaults, loading, duration parsing, and validation.
- Configurable text or JSON `slog` logger initialization.
- URL normalization, classification, and explainable URL/domain findings.
- Bounded TLS/certificate analysis and optional Certificate Transparency lookup.
- Safe passive HTTP inspection and response analysis through internal APIs. It performs GET requests only, validates and pins public destinations, and does not execute scripts or submit forms.

### Planned features

- CLI integration for the existing URL, domain, TLS, and passive web assessment APIs.
- Risk scoring and complete scan reports after policy design and review.
- Optional local persistence and an interactive terminal UI.

See the [architecture and foundation review](docs/architecture.md) for current package status, planned boundaries, data flow, and security requirements.

## Technology stack

- Go 1.22+
- Cobra for the CLI
- Go `log/slog` for logging
- Bubble Tea, Bubbles, and Lipgloss planned for a future TUI
- SQLite planned for future local storage

## Basic CLI usage

```sh
bouclier --help
bouclier --version
bouclier --config configs/config.json
```

## Development

### Prerequisites

- Go 1.22 or later
- GNU Make for the optional Makefile shortcuts

### Repository setup

Clone the repository, change to its directory, then download its Go modules:

```sh
git clone <repository-url>
cd BOUCLIER
go mod download
```

### Configuration setup

Copy `configs/config.example.json` to `configs/config.json` and edit the copy for your local environment. The example contains defaults and no secrets. Keep local configuration and credentials out of version control.

```sh
cp configs/config.example.json configs/config.json
```

On Windows, use `Copy-Item configs/config.example.json configs/config.json` in PowerShell.

### Build and run

```sh
make build
make run
```

Build directly without Make with `go build -o bin/bouclier .` (use `bin/bouclier.exe` on Windows). The executable is placed in `bin/`.

Install to the Go bin directory with `make install` or `go install .`.

### Tests, formatting, and static analysis

```sh
make test
make fmt
make fmt-check
make vet
make check
```

Equivalent Go commands include `go test ./...`, `go fmt ./...`, and `go vet ./...`. `make test-race` runs tests with Go's race detector. CI runs formatting verification, vet, tests, and a build on pushes and pull requests targeting `main`.

### Makefile commands

Run `make help` for the full command list. Targets include `build`, `run`, `test`, `test-verbose`, `test-race`, `vet`, `fmt`, `fmt-check`, `tidy`, `clean`, `check`, and `install`.

The Makefile selects a `.exe` output and PowerShell cleanup commands on Windows. Race detector support depends on the Go toolchain and platform.

## Roadmap

1. Foundation, URL/domain intelligence, TLS/certificate/CT intelligence, and passive web assessment APIs.
2. Integrate the internal assessment engines into a user-facing CLI workflow.
3. Design and implement risk scoring and report policy.
4. Add local persistence with SQLite.
5. Build the interactive terminal experience.
