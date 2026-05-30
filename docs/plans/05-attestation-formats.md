# 05 - Modular attestation formats

Priority: P1.

Status: Not started.

## Purpose

Implement all WebAuthn Level 2 attestation statement formats as optional packages. The root package must remain usable without importing any format package beyond those selected by the application.

## Prerequisites

- Plan 02 complete.
- Plan 03 registration verifier supports format registry dispatch.
- Codec and crypto adapter decisions documented.
- Trust policy layer exists or has a minimal interface from plan 07.

## Required formats

| Format              | Package direction              | Key requirements                                                                                 |
| ------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------ |
| `none`              | `attestation/none`             | Empty statement, no trust path, policy acceptance.                                               |
| `packed`            | `attestation/packed`           | x5c/basic/AttCA, self attestation, algorithm matching, AAGUID certificate extension check.       |
| `tpm`               | `attestation/tpm`              | TPM statement shape, public area binding, certInfo binding, TPM manufacturer/version fields.     |
| `android-key`       | `attestation/androidkey`       | Android key certificate extension, challenge binding, authorization list checks.                 |
| `android-safetynet` | `attestation/androidsafetynet` | JWS response verification through dependency, nonce binding, service certificate/trust handling. |
| `fido-u2f`          | `attestation/fidou2f`          | ES256 requirement, U2F registration signature base, x5c trust path.                              |
| `apple`             | `attestation/apple`            | Apple anonymous attestation nonce and certificate checks.                                        |

## Modular import requirements

- Each format lives in an optional package.
- The root package must not import format packages.
- Format packages may share internal helpers only if those helpers do not pull unrelated heavy dependencies.
- Avoid a global init-only registration pattern as the primary API. Prefer explicit verifier construction.
- A later optional aggregate package may register all formats, but it must be outside the root package.

## Deliverables

1. Implement `none` as the minimal verifier.
2. Implement `packed` with both x5c and self-attestation paths.
3. Implement `fido-u2f` because it is important for U2F compatibility and AppID migration.
4. Implement `tpm` with documented dependency choices.
5. Implement `android-key` with documented certificate extension parsing strategy.
6. Implement `android-safetynet` with delegated JWS/JWT verification.
7. Implement `apple` anonymous attestation.
8. Add per-format tests and fixtures.
9. Add documentation showing how to import only selected formats.
10. Add import graph tests proving root remains independent.
11. Keep `make ci` and GitHub Actions green as each optional package is added.

## Tests

Each format must include:

- valid path;
- malformed CBOR shape;
- missing required field;
- wrong algorithm or key type;
- invalid signature;
- certificate requirement failure where applicable;
- trust policy acceptance and rejection where applicable.

## Completion update requirements

When each format is complete, update this file's table with completion date. When all formats are complete, update `docs/plans.md` plan 05 status.
