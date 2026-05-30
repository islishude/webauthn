# 08 - Testing and conformance

Priority: P1.

Status: Not started.

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
