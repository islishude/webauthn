SHELL := /bin/sh
GO ?= go
GOLANGCI_LINT ?= golangci-lint
PRETTIER ?= npx -y prettier
GOFLAGS ?=
FUZZTIME ?= 10s
PLAYWRIGHT_VERSION ?= 1.60.0
PLAYWRIGHT_CHROMIUM_EXECUTABLE ?=

GO_FILES := $(shell find . -type f -name '*.go' -not -path './.git/*' -not -path './vendor/*')

.PHONY: help format format-check lint test test-race test-fuzz-smoke example-build import-graph-check license-check readme-check browser-fixtures e2e e2e-headed mod-check ci-docs ci

help:
	@echo 'Targets:'
	@echo '  make format           - rewrite Go and Markdown formatting'
	@echo '  make format-check     - fail when Go or Markdown files are not formatted'
	@echo '  make lint             - run golangci-lint'
	@echo '  make test             - run go test ./...'
	@echo '  make test-race        - run go test -race ./...'
	@echo '  make test-fuzz-smoke  - run each bounded fuzz target separately'
	@echo '  make example-build    - build public examples'
	@echo '  make import-graph-check - verify root import graph boundaries'
	@echo '  make license-check    - verify dependency license manifest coverage'
	@echo '  make readme-check     - verify README references compile-checked examples'
	@echo '  make browser-fixtures - regenerate virtual-authenticator browser fixtures'
	@echo '  make e2e              - run Playwright browser e2e tests'
	@echo '  make e2e-headed       - run Playwright browser e2e tests headed'
	@echo '  make mod-check        - run go mod tidy and verify go.mod/go.sum are clean'
	@echo '  make ci               - run the local CI gate'

format:
	$(GOLANGCI_LINT) fmt ./...
	$(GO) fix ./...
	$(PRETTIER) --write .

format-check:
	$(GOLANGCI_LINT) fmt -d ./...
	$(PRETTIER) --check .
	$(GO) fix -diff ./...

lint:
	$(GOLANGCI_LINT) run ./...

test:
	$(GO) test $(GOFLAGS) -cover ./...

test-race:
	$(GO) test $(GOFLAGS) -race ./...

test-fuzz-smoke:
	@if ! grep -R "^func Fuzz" --include='*_test.go' . >/dev/null 2>&1; then \
		echo 'test-fuzz-smoke: no fuzz targets found'; \
	else \
		grep -R -n "^func Fuzz" --include='*_test.go' . | while IFS=: read -r file _ rest; do \
			dir=$$(dirname "$$file"); \
			pkg="./$${dir#./}"; \
			if [ "$$pkg" = "./." ]; then pkg="."; fi; \
			name=$$(printf '%s\n' "$$rest" | sed -E 's/^func (Fuzz[[:alnum:]_]*)\(.*$$/\1/'); \
			echo "test-fuzz-smoke: $$pkg $$name"; \
			$(GO) test $(GOFLAGS) "$$pkg" -run '^$$' -fuzz "^$$name$$" -timeout 15m -fuzztime=$(FUZZTIME) || exit $$?; \
		done; \
	fi

example-build:
	$(GO) test $(GOFLAGS) ./examples/...

import-graph-check:
	@deps="$$(GOWORK=off $(GO) list -deps .)"; \
	for dep in $$deps; do \
		case "$$dep" in \
			net/http|github.com/islishude/webauthn/attestation/*|github.com/islishude/webauthn/transport*|github.com/islishude/webauthn/browser*|github.com/islishude/webauthn/http*) \
				echo "import-graph-check: forbidden root dependency $$dep"; \
				exit 1; \
				;; \
		esac; \
	done; \
	echo 'import-graph-check: root package import graph is within documented boundaries'

license-check:
	$(GO) run ./tools/checklicenses -manifest docs/dependencies.json

readme-check:
	@for path in examples/manual examples/http examples/passkey examples/attestation docs/release.md; do \
		if ! grep -F "$$path" README.md >/dev/null; then \
			echo "readme-check: README.md does not reference $$path"; \
			exit 1; \
		fi; \
	done
	@if grep -n '^```go$$' README.md >/dev/null; then \
		echo 'readme-check: move Go snippets into compile-checked examples'; \
		exit 1; \
	fi
	@echo 'readme-check: README references compile-checked examples and release notes'

browser-fixtures:
	@tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	npm --prefix "$$tmp" install --silent --no-audit --no-fund playwright@$(PLAYWRIGHT_VERSION); \
	PLAYWRIGHT_MODULE_DIR="$$tmp/node_modules" PLAYWRIGHT_CHROMIUM_EXECUTABLE="$(PLAYWRIGHT_CHROMIUM_EXECUTABLE)" node scripts/generate-browser-fixtures.mjs

e2e:
	npm --prefix e2e ci
	npx --prefix e2e playwright install --with-deps chromium
	npm --prefix e2e test

e2e-headed:
	npm --prefix e2e ci
	npm --prefix e2e run test:headed

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
	@test -f docs/release.md
	@test -f docs/dependencies.json
	@test -f .github/workflows/ci.yml
	@test -f .golangci.yml
	@test -f .gitattributes
	@echo 'ci-docs: required docs and quality configuration are present'

ci: ci-docs readme-check format-check lint test test-race test-fuzz-smoke example-build import-graph-check license-check mod-check
