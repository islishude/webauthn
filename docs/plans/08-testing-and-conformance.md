# 08 - Testing and conformance

Priority: P1.

Status: Complete, 2026-06-01.

## Purpose

Build confidence that the implementation follows WebAuthn Level 2 relying-party requirements without using public WebAuthn library code or tests.

## Prerequisites

- Plans 02 through 07 sufficiently implemented for test targets.
- Fixture generation approach documented.
- Dependency license review completed for any external conformance data.
- Plan 01 quality gate remains active in local and GitHub Actions workflows.

## Deliverables

1. Unit tests for protocol types and validators.
2. Unit tests for authenticator data parsing.
3. Unit tests for collected client data parsing and verification.
4. Registration ceremony positive and negative tests.
5. Authentication ceremony positive and negative tests.
6. Per-format attestation tests and fixtures.
7. Extension tests.
8. Codec and crypto adapter integration tests.
9. Fuzz tests for parsers and transport conversion boundaries.
10. Browser interoperability fixture suite generated for this project.
11. Conformance matrix mapping W3C relying-party verification steps to tests.
12. Import graph checks in CI.
13. Expand the existing CI workflow for unit tests, fuzz smoke tests, static analysis, examples, dependency license checks, and import graph checks as those targets become available.

## Fixture rules

- Fixtures must be generated for this project or derived from specification examples where license permits.
- Fixtures must not come from public WebAuthn library repositories.
- Fixture metadata must record source, generation date, browser/authenticator context if applicable, and sensitivity classification.
- Private keys used to generate test credentials must be test-only and clearly marked.

## Tests required before stable release

- All P0 registration and authentication verifier paths.
- All P1 attestation formats.
- All Level 2 extensions.
- Malformed input handling.
- Policy rejection paths.
- Import graph root independence.
- Race-free operation for stateless verifiers.
- Local `make ci` and GitHub Actions passing on the release branch.

## Completion update requirements

When complete, update `docs/plans.md`, this file, `docs/testing.md`, `docs/ci.md`, and README feature status.

## Completion update

Completed on 2026-06-01.

Delivered files/packages:

- Added fuzz targets for authenticator data parsing, collected client data parsing, CBOR attestation object decoding, COSE key decoding, authenticator extension map decoding, and test-only browser transport credential descriptor conversion.
- Added a Playwright 1.60.0 virtual-authenticator fixture generator and committed generated browser interoperability fixtures under `testdata/browser/virtual-authenticator`.
- Added browser fixture verification tests covering platform/discoverable UV-required registration and authentication, roaming allow-credentials username-first authentication, and tampered assertion signature rejection through a test-only ES256 verifier.
- Added explicit `make import-graph-check` and `make license-check` targets, a dependency license manifest, and GitHub Actions steps for both checks.
- Hardened the optional CBOR/COSE adapter so malformed COSE key shapes that panic inside the dependency are reported as `codec/cbor.ErrMalformedCBOR`.
- Documented W3C relying-party conformance coverage in `docs/testing.md`.

Tests:

- `go test ./...`
- `make test-fuzz-smoke FUZZTIME=1s`
- `make import-graph-check`
- `make license-check`

Scope changes:

- Browser interoperability fixtures use Chrome DevTools virtual authenticators, not hardware authenticators.
- No external public conformance dataset was imported; dependency license review covers Go module dependencies only.
- Example build checks remain in Plan 09 because public examples and optional adapters do not exist yet.

Level 3 update:

- Plan 14 updates `docs/testing.md` with Level 3 ceremony, PRF, compound
  attestation, OKP material, DTO, and deprecated `uvm` coverage. Plan 08 remains
  the original conformance and fuzzing baseline.
