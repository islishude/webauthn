# 15 - API cleanup and refactor

Priority: P1.

Status: Complete, 2026-06-02.

## Purpose

Refactor the completed Level 3 implementation with API-breaking changes allowed
where they reduce test friction, clarify caller-vs-attacker error boundaries,
shrink interfaces, remove dead API, and avoid unnecessary defensive-copy use in
verification hot paths.

## Prerequisites

- Plans 02 through 14 complete.
- Baseline `make ci` passing before the refactor.
- No package-boundary change that imports optional browser, HTTP, or attestation
  format packages into the root package.
- No new dependency.

## Deliverables

1. Keep protocol `Bytes()` methods defensive while adding typed equality and
   `AppendTo` helpers for byte values used in credential binding and signature
   bases.
2. Replace root RawID/CredentialID and UserHandle comparisons that used
   `Bytes()` with typed helpers.
3. Remove unused exported crypto hash API.
4. Remove `RegistrationAttestationPolicy`; require
   `AttestationTrustPolicy` for all attestation acceptance.
5. Split root decoder options into attestation object, credential public key,
   and extension map decoder fields.
6. Add injectable clocks to registration and authentication start options.
7. Refactor root finish flows around clearer validation and verification phases.
8. Share registration/authentication extension verification logic in the root
   package.
9. Add a shared internal attestation signature helper while preserving each
   attestation package's exported sentinel errors.
10. Update examples, README, and architecture/security/testing documentation.

## Tests

- Protocol tests for typed equality and `AppendTo` mutation behavior.
- Root registration and authentication tests updated for explicit trust policy,
  narrow decoder fields, injected clocks, and clearer configuration/state
  errors.
- Regression coverage for RawID/CredentialID and UserHandle comparison paths
  without relying on `Bytes()` copies.
- Attestation format tests retained for malformed statements and invalid
  signatures after shared signature-helper extraction.
- Examples remain compile-checked.
- Final readiness gate: `make ci`.

## Completion record

Completed on 2026-06-02.

Delivered files and packages:

- `protocol` byte helpers for typed equality and append-to-buffer behavior.
- root `webauthn` registration and authentication APIs with explicit trust
  policy, narrow decoder fields, injectable start clocks, clearer
  configuration/state errors, and shared extension verification.
- `codec` narrow decoder contracts without the grouped `codec.Decoders`
  interface.
- `crypto` contract surface without the unused hash API.
- `attestation/internal/attcrypto` for shared attestation signature input and
  verifier calls used by optional format packages.
- `examples/manual` and `examples/http` updated for explicit decoder contracts
  and `attestation.AcceptNone()`.
- README, technical design, API boundaries, security model, testing strategy,
  and plan documentation updated.

Tests delivered:

- `go test ./...` passed during implementation.
- `make ci` is the final required readiness gate for this plan.

Scope changes:

- API-breaking changes are intentional: callers now pass explicit decoder
  contracts and explicit attestation trust policy. `nil` trust policy rejects
  all attestations after format verification.
- No concurrency or goroutine lifecycle rewrite was needed; lifecycle cleanup is
  limited to explicit timeout clocks and clearer ceremony state validation.
- No dependency was added, removed, or vendored.
