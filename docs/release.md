# Release checklist

## Before publication

- Review [LICENSE](../LICENSE), [SECURITY.md](../SECURITY.md),
  [CHANGELOG.md](../CHANGELOG.md), and README feature claims.
- Run `make ci` from a clean worktree. This includes formatting, TypeScript,
  lint, unit/race/fuzz tests, examples, the independent consumer, root import
  isolation, dependency inventory, and module checks.
- Run `make test-minimum` for Go 1.25.0 and `make e2e` for Chromium and the
  public quickstart.
- Require passing release-branch GitHub Actions, including the
  Linux/macOS/Windows Go compatibility matrix.

See [CI](ci.md) for gate details and [testing](testing.md) for coverage limits.
Local results do not establish remote CI success.

## After tag publication

- Run `make release-install-check RELEASE_VERSION=<published-version>` with the
  exact published tag to verify installation and public consumer tests without
  local replacements.

## Version policy

Before v1, patch releases do not intentionally break the public API. Minor
releases may introduce incompatible changes with explicit migration notes.
Security fixes may tighten accepted behavior and must document the change.
Security maintenance targets the latest release (`main` before the first
release); older versions have no guaranteed backports.
