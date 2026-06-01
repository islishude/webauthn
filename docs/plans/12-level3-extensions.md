# 12 - Level 3 extensions

Priority: P1.

Status: Complete, 2026-06-01.

## Purpose

Add Level 3 extension support while keeping deprecated Level 2 `uvm` available
without making it part of the default Level 3 registry.

## Prerequisites

- Plan 11 ceremony extension routing remains operation-aware.
- Root package still accepts a caller-supplied `extension.Registry`.

## Deliverables

1. Add `extension.IDPRF`.
2. Add `PRFInput`, `PRFValues`, `PRFResult`, and `PRFHandler`.
3. Add `Level3Handlers`, `NewLevel3Registry`, and deprecated-inclusive Level 3
   registry helpers.
4. Keep PRF implementation in `extension/level3.go`, not `extension/level2.go`.
5. Mark `uvm` outputs and types as deprecated while retaining parsing support.
6. Encode/decode PRF browser JSON salts and results as unpadded base64url.

## Tests

- `extension/level3_test.go` covers registry contents, valid PRF registration
  and authentication, `evalByCredential` policy, and malformed result lengths.
- Registration/authentication integration tests cover Level 3 registry use and
  deprecated `uvm` result metadata.
- Browser DTO tests cover PRF input/output JSON conversion.
- `go test ./...` passes.

## Completion notes

2026-06-01: Completed. Delivered PRF in `extension/level3.go`; kept
`extension/level2.go` limited to Level 2 and deprecated `uvm`; added
deprecated-inclusive Level 3 registry helpers for callers that still need `uvm`.
Scope changes: `uvm` was not removed, per project requirement, and now surfaces
`extension.Result.Deprecated`.
