# 11 - Level 3 ceremonies and JSON

Priority: P0.

Status: Complete, 2026-06-01.

## Purpose

Upgrade registration and authentication ceremony inputs, state, results, and
optional browser/HTTP JSON helpers for WebAuthn Level 3.

## Prerequisites

- Plan 10 baseline accepted.
- Root package remains transport-neutral and persistence-neutral.
- Browser and HTTP helpers remain optional packages.

## Deliverables

1. Replace ceremony origin configuration with `OriginPolicy`.
2. Support `CollectedClientData.topOrigin` and policy-controlled cross-origin
   verification.
3. Retain reserved `tokenBinding` parsing but ignore it for RP verification.
4. Add Level 3 creation/request option hints and attestation format preference
   fields.
5. Add registration response `authenticatorData`, `publicKey`,
   `publicKeyAlgorithm`, and authenticator attachment fields.
6. Add authentication response authenticator attachment and credential backup
   state result propagation.
7. Update `browser` and `transport/http` DTO tests for Level 3 JSON fields.

## Tests

- `registration_test.go` covers `OriginPolicy`, `topOrigin`, reserved
  `tokenBinding`, Level 3 option fields, and response metadata.
- `authentication_test.go` covers Level 3 hints, authenticator attachment, and
  backup state propagation.
- `browser` and `transport/http` tests cover Level 3 JSON DTO fields.
- `go test ./...` passes.

## Completion notes

2026-06-01: Completed. Delivered root ceremony API changes in
`registration.go`, `authentication.go`, and `origin.go`; protocol additions in
`protocol`; browser/HTTP DTO updates in `browser` and `transport/http`; and
integration tests for accepted and rejected `topOrigin` policy paths. Scope
changes: token binding is deprecated/reserved and no longer participates in
verification policy.
