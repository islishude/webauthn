SHELL := /bin/sh
GO ?= go
GOLANGCI_LINT ?= golangci-lint
PRETTIER ?= npx -y prettier
GOFLAGS ?=
FUZZTIME ?= 10s

GO_FILES := $(shell find . -type f -name '*.go' -not -path './.git/*' -not -path './vendor/*')

.PHONY: help format format-check lint test test-race test-fuzz-smoke mod-check ci-docs ci

help:
	@echo 'Targets:'
	@echo '  make format           - rewrite Go and Markdown formatting'
	@echo '  make format-check     - fail when Go or Markdown files are not formatted'
	@echo '  make lint             - run golangci-lint'
	@echo '  make test             - run go test ./...'
	@echo '  make test-race        - run go test -race ./...'
	@echo '  make test-fuzz-smoke  - run bounded fuzz targets when fuzz tests exist'
	@echo '  make mod-check        - run go mod tidy and verify go.mod/go.sum are clean'
	@echo '  make ci               - run the local CI gate'

format:
	gofmt -w $(GO_FILES)
	$(GOLANGCI_LINT) fmt ./...
	$(PRETTIER) --write .

format-check:
	@files=$$(gofmt -l $(GO_FILES)); if [ -n "$$files" ]; then echo "$$files"; exit 1; fi
	$(PRETTIER) --check .

lint:
	$(GOLANGCI_LINT) run ./...

test:
	$(GO) test $(GOFLAGS) ./...

test-race:
	$(GO) test $(GOFLAGS) -race ./...

test-fuzz-smoke:
	@if ! grep -R "^func Fuzz" --include='*_test.go' . >/dev/null 2>&1; then echo 'test-fuzz-smoke: no fuzz targets found'; else $(GO) test $(GOFLAGS) ./... -run '^$$' -fuzz=. -fuzztime=$(FUZZTIME); fi

mod-check:
	$(GO) mod tidy
	@if command -v git >/dev/null 2>&1; then git diff --exit-code -- go.mod go.sum; fi

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
