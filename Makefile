APP_NAME ?= bouclier
BIN_DIR ?= bin
GO ?= go
GOFMT ?= gofmt

GO_FILES = $(shell $(GO) list -f '{{range .GoFiles}}{{$$.Dir}}/{{.}} {{end}}{{range .TestGoFiles}}{{$$.Dir}}/{{.}} {{end}}' ./...)

ifeq ($(OS),Windows_NT)
SHELL := powershell.exe
.SHELLFLAGS := -NoProfile -Command
BINARY := $(BIN_DIR)/$(APP_NAME).exe
MKDIR_BIN = New-Item -ItemType Directory -Force -Path '$(BIN_DIR)' | Out-Null
CLEAN_BIN = if (Test-Path '$(BIN_DIR)') { Remove-Item -LiteralPath '$(BIN_DIR)' -Recurse -Force }
CLEAN_COVERAGE = if (Test-Path coverage.out) { Remove-Item -LiteralPath coverage.out -Force }; if (Test-Path coverage.html) { Remove-Item -LiteralPath coverage.html -Force }
FMT_CHECK = $$files = $(GOFMT) -l $(GO_FILES); if ($$files) { Write-Error "Go files need formatting: $$files"; exit 1 }
else
BINARY := $(BIN_DIR)/$(APP_NAME)
MKDIR_BIN = mkdir -p "$(BIN_DIR)"
CLEAN_BIN = rm -rf "$(BIN_DIR)"
CLEAN_COVERAGE = rm -f coverage.out coverage.html
FMT_CHECK = files=$$($(GOFMT) -l $(GO_FILES)); if [ -n "$$files" ]; then printf '%s\n' "$$files"; exit 1; fi
endif

.PHONY: help build run test test-verbose test-race vet fmt fmt-check tidy clean check install contracts-check

help:
	@echo "Bouclier developer commands:"
	@echo "  help         Show this command list"
	@echo "  build        Build the executable into $(BIN_DIR)/"
	@echo "  run          Run Bouclier with go run"
	@echo "  test         Run all Go tests"
	@echo "  test-verbose Run all Go tests with verbose output"
	@echo "  test-race    Run all Go tests with the race detector"
	@echo "  vet          Run go vet ./..."
	@echo "  fmt          Format all Go packages"
	@echo "  fmt-check    Fail if Go files need formatting"
	@echo "  tidy         Run go mod tidy"
	@echo "  clean        Remove generated build and coverage artifacts"
	@echo "  check        Run fmt-check, vet, and test"
	@echo "  install      Install Bouclier with go install"

build:
	@$(MKDIR_BIN)
	$(GO) build -o "$(BINARY)" .

run:
	$(GO) run .

test:
	$(GO) test ./...

test-verbose:
	$(GO) test -v ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

fmt-check:
	@$(FMT_CHECK)

tidy:
	$(GO) mod tidy

clean:
	$(GO) clean
	@$(CLEAN_BIN)
	@$(CLEAN_COVERAGE)
	$(GO) clean -testcache

check: fmt-check vet test

install:
	$(GO) install .

contracts-check:
	@$(GOFMT) -l .
	$(GO) vet ./...
	$(GO) test ./internal/model/... -race -count=1
	node scripts/verify-hash.mjs
