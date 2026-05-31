# Local and GitHub Actions quality workflow

Status: mandatory Go module configuration, revised 2026-05-31.

This document is the authoritative workflow for formatting, linting, testing, and CI for `github.com/islishude/webauthn`.

Plan 02 created `go.mod` and Go source files. Go-oriented targets are mandatory quality gates and no longer check for module or Go-file existence before running.

## Toolchain baseline

The local workflow is controlled by the root `Makefile`. The GitHub workflow is `.github/workflows/ci.yml`.

CI uses:

- `actions/checkout@v6`;
- `actions/setup-go@v6` with `go-version: stable`;
- `actions/setup-node@v6` for `npx`-based Prettier formatting checks;
- `golangci/golangci-lint-action@v9`;
- `golangci-lint` pinned to `v2.12.2`;
- `.golangci.yml` with configuration version `2`.

`go.mod` records minimum supported Go version `1.25`. The CI workflow continues to use `stable` for the moving latest stable lane, but release hardening may add explicit old-stable or minimum-version lanes.

## Local prerequisites

Required local tools:

- `make`;
- a Go toolchain compatible with the `go.mod` minimum version;
- Node.js with `npx` available for Prettier formatting;
- `golangci-lint v2.12.2` for `make format`, `make lint`, and full `make ci`.

Do not add golangci-lint as a project runtime dependency. Prefer the official binary installer for local development:

```sh
curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b "$(go env GOPATH)/bin" v2.12.2
```

A source install can be used as a fallback, but it should remain a developer-machine concern rather than a project dependency:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
```

Verify the local binary before linting:

```sh
golangci-lint version
```

## Local commands

Run these commands from the repository root.

| Command                | Purpose                                                                                 | Mutates files                        |
| ---------------------- | --------------------------------------------------------------------------------------- | ------------------------------------ |
| `make format`          | Run `gofmt -w` on Go files, `golangci-lint fmt ./...`, and `npx -y prettier --write .`. | Yes                                  |
| `make format-check`    | Fail if Go files are not `gofmt` formatted or `npx -y prettier --check .` fails.        | No                                   |
| `make lint`            | Run `golangci-lint run ./...`.                                                          | No                                   |
| `make test`            | Run `go test ./...`.                                                                    | No                                   |
| `make test-race`       | Run `go test -race ./...`.                                                              | No                                   |
| `make test-fuzz-smoke` | Run bounded fuzz targets when fuzz tests exist.                                         | No                                   |
| `make mod-check`       | Run `go mod tidy` and verify `go.mod`/`go.sum` have no diff.                            | Yes, then must be clean              |
| `make ci-docs`         | Verify required documentation and quality config files exist.                           | No                                   |
| `make ci`              | Run the full local quality gate.                                                        | `mod-check` may rewrite module files |

`make ci` is the required pre-PR command. It runs formatting, linting, unit tests, race tests, fuzz smoke tests, and module hygiene.

## Formatting policy

Formatting has three layers:

1. `gofmt` is the baseline formatter and is checked by `make format-check`.
2. `golangci-lint` formatters enforce import grouping and formatter configuration in `.golangci.yml`.
3. Prettier formats Markdown and other supported repository text files through `npx -y prettier --write .`; CI checks it with `npx -y prettier --check .`.

The Go formatter set is intentionally small: `gofmt` and `goimports`. The local import prefix is `github.com/islishude/webauthn`. Prettier is invoked through `npx` rather than a project runtime dependency.

## Linting policy

The lint configuration starts with golangci-lint's `standard` default set and enables additional correctness/security linters: `asciicheck`, `bidichk`, `bodyclose`, `durationcheck`, `errorlint`, `gosec`, `nilerr`, and `noctx`.

Any lint suppression must be narrow, placed next to the code it affects, and justified in a comment. Broad package-wide suppression is not acceptable for protocol or security-sensitive code.

## Testing policy

The test gate has four layers:

1. `go test ./...` for ordinary unit and integration tests.
2. `go test -race ./...` for race detection on stateless and shared-state code.
3. bounded fuzz smoke tests for parser and transport-conversion fuzz targets once they exist.
4. module tidy verification to prevent accidental dependency drift.

Fuzz smoke tests are not a substitute for longer local or scheduled fuzzing. They are a CI tripwire for obvious parser crashes and regressions.

## GitHub Actions workflow

`.github/workflows/ci.yml` runs on pull requests and pushes to `main` or `master`.

The workflow has three jobs:

1. `docs-and-config` always runs. It calls `make ci-docs` and checks LF line endings for Markdown, YAML, and Makefile text files.
2. `lint` runs after `docs-and-config`. It sets up Go and runs the official golangci-lint action with the pinned lint version.
3. `test` runs after `docs-and-config`. It sets up Go and Node.js, then runs `make format-check`, `make test`, `make test-race`, `make test-fuzz-smoke`, and `make mod-check`.

The workflow no longer detects `go.mod` before running Go checks. Missing module files, missing Go source files, format drift, lint failures, test failures, or module-tidy drift are CI failures.

## Adding or changing checks

Any change to quality gates must update all of these files in the same change:

- `Makefile`;
- `.github/workflows/ci.yml`;
- `.golangci.yml`, when lint or formatter behavior changes;
- `docs/ci.md`;
- `docs/testing.md`, when test policy changes;
- `docs/plans.md` and the relevant `docs/plans/*.md` file when a plan status or scope changes.

Do not add network-dependent tests to the default CI gate. Attestation metadata, certificate status, or browser interoperability checks that need network access must use explicit fixtures or separate opt-in workflows.
