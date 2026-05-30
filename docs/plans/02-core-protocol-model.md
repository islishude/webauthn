# 02 - Core protocol model and adapter contracts

Priority: P0.

Status: Not started.

## Purpose

Define the concrete Go module foundation without implementing ceremony behavior first. This plan creates package boundaries, protocol data structures, adapter contracts, and import graph enforcement needed by every later plan.

## Prerequisites

- Plan 00 complete.
- Plan 01 quality gates complete.
- Dependency candidates for CBOR, COSE, JWS/JWT, and X.509 behavior reviewed without inspecting public WebAuthn library code.

## Deliverables

1. Create `go.mod` with module path `github.com/islishude/webauthn` and documented minimum Go version.
2. Ensure `make ci` and GitHub Actions Go jobs activate and pass after `go.mod` is introduced.
3. Define package layout consistent with `docs/technical.md` and `docs/api-boundaries.md`.
4. Define protocol types for WebAuthn creation and request options, credential descriptors, RP entity, user entity, authenticator selection, transports, attestation conveyance, user verification, and collected client data.
5. Define byte-safe internal representations for challenge, credential ID, user handle, raw ID, authenticator data, client data JSON, attestation object, and signature.
6. Define codec adapter contracts for CBOR attestation object decoding, COSE key decoding, and extension map decoding.
7. Define crypto adapter contracts for hashing, algorithm policy, signature verification, X.509 handling, and JWS/JWT handoff.
8. Define attestation format verifier contract and registry behavior.
9. Define extension handler contract and registry behavior.
10. Add import graph tests or scripts proving the root package does not import optional attestation or transport packages.
11. Add documentation updates for any naming changes.

## Design requirements

- Root package must not depend on `net/http`.
- Root package must not import optional attestation format packages.
- Protocol types must preserve bytes internally.
- General CBOR, COSE, ASN.1, JWS/JWT, X.509, and crypto primitives must not be implemented in this repository.
- Unknown enum-like DOMString values must be handled according to WebAuthn requirements at the correct boundary.
- Duplicate attestation format registrations should fail by default.

## Tests

- Type validation tests.
- Registry duplicate and unknown format tests.
- Codec adapter contract tests using test doubles.
- Crypto adapter contract tests using test doubles.
- Import graph test for root package.
- Local `make ci` and GitHub Actions Go jobs pass after `go.mod` is present.

## Completion update requirements

When complete, update `docs/plans.md` status for plan 02 and record implemented package names here.
