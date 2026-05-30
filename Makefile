SHELL := /bin/sh
GO ?= go
GOLANGCI_LINT ?= golangci-lint
GOFLAGS ?=
FUZZTIME ?= 10s

GO_FILES := $(shell find . -type f -name '*.go' -not -path './.git/*' -not -path './vendor/*')
HAS_GOMOD := $(shell test -f go.mod && echo yes)

.PHONY: help format format-check lint test test-race test-fuzz-smoke mod-check ci-docs ci

help:
	@echo 'Targets:'
	@echo '  make format           - rewrite Go formatting with gofmt and golangci-lint fmt when available'
	@echo '  make format-check     - fail when Go files are not gofmt-formatted'
	@echo '  make lint             - run golangci-lint when go.mod exists'
	@echo '  make test             - run go test ./... when go.mod exists'
	@echo '  make test-race        - run go test -race ./... when go.mod exists'
	@echo '  make test-fuzz-smoke  - run bounded fuzz targets when fuzz tests exist'
	@echo '  make mod-check        - run go mod tidy and verify go.mod/go.sum are clean'
	@echo '  make ci               - run the local CI gate'

format:
	@if [ -z "$(GO_FILES)" ]; then echo 'format: no Go files'; else gofmt -w $(GO_FILES); fi
	@if [ -n "$(HAS_GOMOD)" ] && command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then $(GOLANGCI_LINT) fmt ./...; else echo 'format: golangci-lint fmt skipped'; fi

format-check:
	@if [ -z "$(GO_FILES)" ]; then echo 'format-check: no Go files'; else files=$$(gofmt -l $(GO_FILES)); if [ -n "$$files" ]; then echo "$$files"; exit 1; fi; fi

lint:
	@if [ -z "$(HAS_GOMOD)" ]; then echo 'lint: go.mod not present; skipping until core module plan creates it'; elif ! command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then echo 'lint: golangci-lint is required; install the pinned version from docs/ci.md'; exit 127; else $(GOLANGCI_LINT) run ./...; fi

test:
	@if [ -z "$(HAS_GOMOD)" ]; then echo 'test: go.mod not present; skipping until core module plan creates it'; else $(GO) test $(GOFLAGS) ./...; fi

test-race:
	@if [ -z "$(HAS_GOMOD)" ]; then echo 'test-race: go.mod not present; skipping until core module plan creates it'; else $(GO) test $(GOFLAGS) -race ./...; fi

test-fuzz-smoke:
	@if [ -z "$(HAS_GOMOD)" ]; then echo 'test-fuzz-smoke: go.mod not present; skipping until core module plan creates it'; elif ! grep -R "^func Fuzz" --include='*_test.go' . >/dev/null 2>&1; then echo 'test-fuzz-smoke: no fuzz targets found'; else $(GO) test $(GOFLAGS) ./... -run '^$$' -fuzz=. -fuzztime=$(FUZZTIME); fi

mod-check:
	@if [ -z "$(HAS_GOMOD)" ]; then echo 'mod-check: go.mod not present; skipping until core module plan creates it'; else $(GO) mod tidy; if command -v git >/dev/null 2>&1; then git diff --exit-code -- go.mod go.sum; fi; fi

ci-docs:
	@test -f README.md
	@test -f AGENTS.md
	@test -f docs/technical.md
	@test -f docs/protocol-map.md
	@test -f docs/api-boundaries.md
	@test -f docs/security-model.md
	@test -f docs/testing.md
	@test -f docs/ci.md
	@test -f docs/plans.md
	@test -f docs/plans/00-governance-and-boundaries.md
	@test -f docs/plans/01-quality-gates-and-ci.md
	@test -f docs/plans/02-core-protocol-model.md
	@test -f docs/plans/03-registration-ceremony.md
	@test -f docs/plans/04-authentication-ceremony.md
	@test -f docs/plans/05-attestation-formats.md
	@test -f docs/plans/06-extensions.md
	@test -f docs/plans/07-trust-policy-and-metadata.md
	@test -f docs/plans/08-testing-and-conformance.md
	@test -f docs/plans/09-adapters-examples-release.md
	@test -f .github/workflows/ci.yml
	@test -f .golangci.yml
	@test -f .gitattributes
	@echo 'ci-docs: required docs and quality configuration are present'

ci: ci-docs format-check lint test test-race test-fuzz-smoke mod-check
