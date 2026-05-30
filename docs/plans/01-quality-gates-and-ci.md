# 01 - Quality gates and CI workflow

Priority: P0.

Status: Complete, 2026-05-30.

## Purpose

Establish the local and GitHub Actions quality gate before implementation code starts. The gate defines one repeatable workflow for formatting, linting, tests, race checks, bounded fuzz smoke checks, module hygiene, and documentation/config presence.

## Completed deliverables

- Added `Makefile` with local targets: `format`, `format-check`, `lint`, `test`, `test-race`, `test-fuzz-smoke`, `mod-check`, `ci-docs`, and `ci`.
- Added `.github/workflows/ci.yml` with a documentation/config job that runs immediately and Go lint/test jobs that activate when `go.mod` exists.
- Added `.golangci.yml` using golangci-lint configuration version `2`, standard default linters, selected security/correctness linters, and `gofmt`/`goimports` formatters.
- Added `.gitattributes` to keep Go, module, Markdown, YAML, and Makefile text files on LF line endings.
- Added `docs/ci.md` as the authoritative description of local and CI workflows.
- Updated README, AGENTS, `docs/testing.md`, `docs/technical.md`, and `docs/plans.md` to reference the quality gate.

## Workflow contract

Local development uses `make ci` as the pre-commit/pre-PR gate. Individual targets may be used during editing, but a change is not ready until `make ci` passes.

The CI workflow has four jobs:

1. `docs-and-config` always runs and verifies required documentation and quality configuration files.
2. `detect-go-module` always runs and exposes whether `go.mod` exists.
3. `lint` runs only after `go.mod` exists and executes `golangci/golangci-lint-action` with the pinned golangci-lint version.
4. `test` runs only after `go.mod` exists and executes format check, unit tests, race tests, fuzz smoke tests, and module tidy verification through the Makefile.

The conditional Go jobs intentionally keep the documentation-only baseline green before plan 02 creates the module. Once `go.mod` is present, Go quality checks become mandatory.

## Acceptance criteria

- No Go implementation files added.
- No `go.mod` added before the core protocol model plan.
- Local `make ci` succeeds in the documentation-only repository.
- CI config is present and ready to enforce Go checks after `go.mod` is created.
- The workflow does not import or inspect public WebAuthn library code.

## Completion notes

Completed on 2026-05-30. Delivered files: `Makefile`, `.github/workflows/ci.yml`, `.golangci.yml`, `.gitattributes`, `docs/ci.md`, and documentation updates.
