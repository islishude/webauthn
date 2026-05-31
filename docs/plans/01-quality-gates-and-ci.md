# 01 - Quality gates and CI workflow

Priority: P0.

Status: Complete, revised 2026-05-31.

## Purpose

Establish the local and GitHub Actions quality gate before implementation code starts. The gate defines one repeatable workflow for formatting, linting, tests, race checks, bounded fuzz smoke checks, module hygiene, and documentation/config presence.

## Completed deliverables

- Added `Makefile` with local targets: `format`, `format-check`, `lint`, `test`, `test-race`, `test-fuzz-smoke`, `mod-check`, `ci-docs`, and `ci`.
- Added `.github/workflows/ci.yml` with a documentation/config job, mandatory Go lint/test jobs, and Node setup for Prettier format checks.
- Added `.golangci.yml` using golangci-lint configuration version `2`, standard default linters, selected security/correctness linters, and `gofmt`/`goimports` formatters.
- Added `.gitattributes` to keep Go, module, Markdown, YAML, and Makefile text files on LF line endings.
- Added `docs/ci.md` as the authoritative description of local and CI workflows.
- Updated README, AGENTS, `docs/testing.md`, `docs/technical.md`, and `docs/plans.md` to reference the quality gate.

## Workflow contract

Local development uses `make ci` as the pre-commit/pre-PR gate. Individual targets may be used during editing, but a change is not ready until `make ci` passes.

The CI workflow has three jobs:

1. `docs-and-config` always runs and verifies required documentation and quality configuration files.
2. `lint` runs after `docs-and-config` and executes `golangci/golangci-lint-action` with the pinned golangci-lint version.
3. `test` runs after `docs-and-config` and executes Prettier-backed format check, unit tests, race tests, fuzz smoke tests, and module tidy verification through the Makefile.

The earlier module-detection job was removed after Plan 02 introduced `go.mod` and Go source files. Go quality checks are mandatory and missing module or source files are failures.

## Acceptance criteria

- Local `make ci` succeeds with the Go module present.
- Makefile Go targets do not skip based on `go.mod` or Go source file existence.
- CI runs Go lint and test jobs without a module-detection precondition.
- The workflow does not import or inspect public WebAuthn library code.

## Completion notes

Completed on 2026-05-30. Delivered files: `Makefile`, `.github/workflows/ci.yml`, `.golangci.yml`, `.gitattributes`, `docs/ci.md`, and documentation updates.

Revised on 2026-05-31. Removed `go.mod` and Go-file existence prechecks from the Makefile workflow and removed the GitHub Actions `detect-go-module` conditional path. Scope change: CI now assumes the Go module exists and runs Go checks directly.

Revised on 2026-05-31. Added Prettier formatting to `make format` through `npx -y prettier --write .` and to `make format-check` through `npx -y prettier --check .`; CI now sets up Node.js before running format checks.
