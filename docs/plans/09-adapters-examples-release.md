# 09 - Adapters, examples, and release hardening

Priority: P2.

Status: Complete, 2026-06-01.

## Purpose

Add optional integration helpers and release-quality documentation after the transport-neutral core is stable.

## Prerequisites

- Plans 02 through 08 complete or nearly complete.
- Public API names stable enough for examples.
- Root package import graph verified.
- Local and GitHub Actions quality gates passing.

## Deliverables

1. Browser JSON DTO conversion helpers as an optional package.
2. Optional `net/http` helper package that does not affect core imports.
3. Framework-neutral examples showing manual integration.
4. Example using the optional HTTP helper.
5. Example showing selected attestation format imports.
6. Example showing passkey/discoverable credential authentication.
7. Example showing direct attestation policy for restricted enrollment.
8. README feature matrix updated to match implementation.
9. Security considerations section updated for users.
10. Dependency inventory and license notes.
11. Release checklist.
12. CI example-build job and README snippet verification, when examples exist.

## Non-goals

- No framework lock-in.
- No mandatory server implementation.
- No production database adapter in core.
- No frontend framework package unless separately justified.

## Tests

- Examples compile.
- Optional HTTP helper tests use standard library only unless explicitly documented.
- Import graph checks prove optional adapters do not leak into root package.
- README snippets, if any, are tested or generated.

## Completion update requirements

When complete, update `docs/plans.md`, this file, README, `docs/ci.md`, and release notes.

## Completion notes

2026-06-01: Completed Plan 09. Added optional `browser` DTO conversion helpers for creation/request options, credential descriptors, registration responses, authentication responses, and known largeBlob byte fields using unpadded base64url. Added optional `transport/http` standard-library JSON read/write helpers with bounded body reads and generic error responses. Added compile-checked examples for manual integration, HTTP helpers, passkey/discoverable credential authentication, and selected attestation policy. Added `make example-build`, `make readme-check`, GitHub Actions example builds, README checks, and `docs/release.md`. Updated README, CI/testing/security/API/technical/protocol documentation, and the plan index. Scope changes: no third-party dependencies, storage adapter, session/cookie handling, router abstraction, frontend framework package, hidden trust roots, metadata network client, or root-package transport dependency was added.

2026-06-01 Level 3 update: Plans 11, 12, and 14 extend the optional browser and
HTTP helpers with Level 3 DTO fields, PRF byte-field conversion, and examples
using Level 3 registry helpers. Plan 09 remains the adapter baseline.
