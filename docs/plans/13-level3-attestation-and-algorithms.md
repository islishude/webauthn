# 13 - Level 3 attestation and algorithms

Priority: P1.

Status: Complete, revised 2026-06-02.

## Purpose

Add Level 3 attestation and algorithm support while preserving optional package
boundaries and narrow codec/crypto contracts.

## Prerequisites

- Existing Level 2 attestation format packages remain optional.
- Root CBOR/COSE boundaries remain narrow decoder contracts.
- Cryptographic operations remain delegated.

## Deliverables

1. Add `compound` attestation object normalization in the CBOR decoder.
2. Add optional `attestation/compound` verifier package.
3. Add codec public-key material support for COSE OKP keys.
4. Add Level 3 COSE algorithm constants and recommended credential parameter
   helper.
5. Keep attestation trust acceptance separate from compound sub-statement
   cryptographic validity.
6. Add tests for valid and malformed compound statements and OKP material.

## Tests

- `codec/cbor` tests cover compound statement normalization, malformed compound
  shapes, OKP key material, and wrong-shape omission.
- `attestation/compound` tests cover all-substatement success, threshold policy,
  malformed statements, nested compound rejection, and missing verifier paths.
- `protocol` tests cover Level 3 algorithm, hint, transport, and client
  capability values.
- `go test ./...` passes.

## Completion notes

2026-06-01: Completed. Delivered `attestation/compound`, compound
normalization in `codec/cbor`, OKP material in `codec`, and Level 3 algorithm
constants in `protocol`. Scope changes: no new dependency was added; Android
SafetyNet remains optional and documented as deprecated/legacy rather than
removed.

2026-06-02: Plan 15 removed the grouped `codec.Decoders` interface. The
compound normalization and OKP material delivered here remain behind the
separate attestation object, credential public-key, and extension map decoder
contracts.
