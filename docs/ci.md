# Local and GitHub Actions quality workflow

Status: Level 3 security, storage, standard crypto, and adapter checks active, revised 2026-09-04.

This document is the authoritative workflow for formatting, linting, testing, and CI for `github.com/islishude/webauthn`.

The repository has `go.mod` and Go source files. Go-oriented targets are mandatory quality gates and no longer check for module or Go-file existence before running.

## Toolchain baseline

The local workflow is controlled by the root `Makefile`. The GitHub workflow is `.github/workflows/ci.yml`.

Action major versions and trigger branches are defined only in
`.github/workflows/ci.yml` to avoid duplicated version drift. CI uses Go 1.27
for primary jobs, Go 1.25.0 for the minimum-version lane, Node.js 24,
Playwright `1.62.1`, golangci-lint `v2.13.1`, and
`.golangci.yml` version 2.

`go.mod` records minimum supported Go version `1.25.0`. The separate
`minimum-go` job runs `go test ./...` with that exact toolchain rather than
assuming success from the newer primary lane.

## Local prerequisites

Required local tools:

- `make`;
- a Go toolchain compatible with the `go.mod` minimum version;
- Node.js 24 with npm for the pinned Prettier, TypeScript, fixtures, and E2E
  dependencies;
- `golangci-lint v2.13.1` for `make format`, `make lint`, and full `make ci`.

Do not add golangci-lint as a project runtime dependency. Prefer the official binary installer for local development:

```sh
curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b "$(go env GOPATH)/bin" v2.13.1
```

A source install can be used as a fallback, but it should remain a developer-machine concern rather than a project dependency:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.1
```

Verify the local binary before linting:

```sh
golangci-lint version
```

## Local commands

Run these commands from the repository root.

| Command                   | Purpose                                                                                 | Mutates files                        |
| ------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------ |
| `make node-deps`          | Install the exact `e2e/package-lock.json` dependency graph with `npm ci`.               | Recreates `e2e/node_modules`         |
| `make format`             | Run configured Go formatters and pinned local Prettier.                                 | Yes                                  |
| `make format-check`       | Fail if Go or pinned Prettier formatting differs.                                       | No                                   |
| `make lint`               | Run `golangci-lint run ./...`.                                                          | No                                   |
| `make test`               | Run `go test ./...`.                                                                    | No                                   |
| `make test-race`          | Run `go test -race ./...`.                                                              | No                                   |
| `make test-fuzz-smoke`    | Discover fuzz targets and run each one with bounded fuzz time.                          | No                                   |
| `make benchmark`          | Run all Go benchmarks with allocation reporting and no unit tests.                      | No                                   |
| `make e2e-typecheck`      | Run strict TypeScript checking without emitting files.                                  | No                                   |
| `make example-build`      | Build public examples with `go test ./examples/...`.                                    | No                                   |
| `make import-graph-check` | Verify root excludes optional attestation, transport, standard crypto, and storage.     | No                                   |
| `make license-check`      | Verify `docs/dependencies.json` covers every module in `go list -m all`.                | No                                   |
| `make readme-check`       | Verify README references compile-checked examples and contains no untested Go snippets. | No                                   |
| `make browser-fixtures`   | Write reviewable Playwright/Chrome fixture output to `fixtures.next.json` by default.   | Installs e2e npm dependencies        |
| `make e2e`                | Run Playwright Chromium tests against the test-only RP app.                             | Installs e2e npm dependencies        |
| `make e2e-headed`         | Run Playwright Chromium tests against the test-only RP app in headed mode.              | Installs e2e npm dependencies        |
| `make mod-check`          | Run `go mod tidy` and verify `go.mod`/`go.sum` have no diff.                            | Yes, then must be clean              |
| `make ci-docs`            | Verify required documentation and quality config files exist.                           | No                                   |
| `make ci`                 | Run the full local quality gate.                                                        | `mod-check` may rewrite module files |

`make ci` is the required pre-PR command. It runs documentation presence checks
including required Level 3 documentation, README checks, formatting, linting, unit tests,
strict TypeScript checking, race tests, fuzz smoke tests, example builds, import
graph checks, dependency license checks, and module hygiene.

`make e2e` is intentionally separate from `make ci`. It starts the test-only
HTTPS relying-party app under `internal/e2eapp` through Playwright's
`webServer`, drives Chromium virtual authenticators, and verifies real browser
registration, authentication, replay rejection, session behavior, UV failure,
state/email binding rejection, generic error responses, and bad-signature
rejection. It also runs Playwright Credentials passkey capture, filtering,
deletion, reseeding, and credential-inclusive in-memory storage-state recovery.
The selected browser matrix remains Chromium-only.

## Formatting policy

Formatting has three layers:

1. `gofmt` is the baseline formatter and is checked by `make format-check`.
2. `golangci-lint` formatters enforce import grouping and formatter configuration in `.golangci.yml`.
3. Prettier `3.9.6` from the locked E2E dependency graph formats Markdown and
   other supported repository text files; CI invokes that same local binary.

The Go formatter set is intentionally small: `gofmt` and `goimports`. The local
import prefix is `github.com/islishude/webauthn`. Network-selected formatter
versions are not used by the quality gate.

## Linting policy

The lint configuration starts with golangci-lint's `standard` default set and enables additional correctness/security linters: `asciicheck`, `bidichk`, `bodyclose`, `durationcheck`, `errorlint`, `gosec`, `nilerr`, and `noctx`.

Any lint suppression must be narrow, placed next to the code it affects, and justified in a comment. Broad package-wide suppression is not acceptable for protocol or security-sensitive code.

## Testing policy

The local gate has eight layers:

1. `go test ./...` for ordinary unit and integration tests.
2. `go test -race ./...` for race detection on stateless and shared-state code.
3. bounded fuzz smoke tests for parser, transport-conversion, and storage JSON targets.
4. public example builds for optional adapters and integration patterns.
5. import graph verification that the root package remains independent of optional attestation and transport helpers.
6. dependency license manifest verification.
7. README reference checks and module tidy verification to prevent accidental drift.
8. strict TypeScript checking for unused and ill-typed E2E code.

Fuzz smoke tests are not a substitute for longer local or scheduled fuzzing. They are a CI tripwire for obvious parser crashes and regressions.

## GitHub Actions workflow

`.github/workflows/ci.yml` runs on pull requests and pushes to `main`.

The workflow has five jobs:

1. `docs-and-config` always runs. It calls `make ci-docs`, `make readme-check`, and checks LF line endings for Markdown, YAML, and Makefile text files.
2. `lint` runs after `docs-and-config`. It sets up Go and Node.js, installs the
   pinned dependencies once, then runs module, lint, format, and TypeScript
   checks.
3. `test` runs after `docs-and-config`. It sets up Go, then runs `make test`, `make example-build`, `make test-race`, `make test-fuzz-smoke`, `make import-graph-check`, and `make license-check`.
4. `minimum-go` runs `go test ./...` with Go 1.25.0.
5. `e2e` runs after `docs-and-config`. It sets up Go and Node.js, restores the
   Playwright browser cache from `~/.cache/ms-playwright`, runs `make e2e`
   against `https://localhost:8443`, and uploads the Playwright HTML report on
   failure.

The workflow no longer detects `go.mod` before running Go checks. Missing module files, missing Go source files, format drift, lint failures, test failures, example build failures, README reference drift, or module-tidy drift are CI failures.

The lint job runs `make mod-check`, `make lint`, and a combined
`make format-check e2e-typecheck` so the shared `node-deps` prerequisite executes
once in that invocation.

## Adding or changing checks

Any change to quality gates must update all of these files in the same change:

- `Makefile`;
- `.github/workflows/ci.yml`;
- `.golangci.yml`, when lint or formatter behavior changes;
- `docs/ci.md`;
- `docs/testing.md`, when test policy changes.

Do not add network-dependent tests to the default CI gate. Attestation metadata, certificate status, or browser interoperability checks that need network access must use explicit fixtures or separate opt-in workflows.

Browser fixture regeneration is intentionally not part of default CI. The committed fixture JSON is verified by Go tests; regenerating it uses the Playwright dependency pinned by `e2e/package-lock.json`, requires a Chromium/Chrome executable, and is an explicit developer action through `make browser-fixtures`.

The generator writes `fixtures.next.json` rather than replacing the committed
fixture. Set `BROWSER_FIXTURE_OUTPUT` to an explicit relative or absolute output
only for a deliberate provenance update, review the diff, and rename it into
place separately.

The committed Playwright 1.60.0/Chrome 148 fixture remains immutable provenance;
upgrading the live E2E dependency does not rewrite it. Passkey private keys
returned by Playwright Credentials or included in storage state remain in
memory and must not be written to tracked files or uploaded artifacts.

The Playwright e2e job is separate from browser fixture regeneration. It does
not update committed fixtures and does not import optional browser or HTTP
helpers into the root package.
