# 16 - Playwright WebAuthn browser e2e

Priority: P1.

Status: Complete, 2026-06-29.

## Purpose

Add real browser end-to-end coverage for common WebAuthn relying-party
integration flows without changing the root package's transport-neutral
boundary.

## Delivered files/packages

- `internal/e2eapp`: test-only HTTPS relying-party app with registration,
  authentication, session, replay, and debug endpoints.
- `internal/e2eapp/static`: minimal browser page that performs real
  `navigator.credentials.create()` and `navigator.credentials.get()` calls and
  converts browser DTO byte fields.
- `e2e`: Playwright Chromium test package with CDP virtual authenticator helper,
  platform passkey tests, roaming security key tests, and failure-path tests.
- `Makefile`: added `make e2e` and `make e2e-headed`.
- `.github/workflows/ci.yml`: added an independent e2e job with Playwright
  report upload on failure.
- `docs/ci.md` and `docs/testing.md`: documented the separate e2e gate and
  coverage.

## Tests

- `go test ./internal/e2eapp`
- `make e2e`

## Scope notes

- The e2e app is not a public example and intentionally lives under
  `internal/e2eapp`.
- The root package remains independent of `net/http`, `browser`, and
  `transport/http`; those dependencies are used only by the optional test app.
- `make ci` remains unchanged. Browser e2e runs through `make e2e` and the
  independent GitHub Actions job.
