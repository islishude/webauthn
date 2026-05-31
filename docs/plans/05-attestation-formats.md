# 05 - Modular attestation formats

Priority: P1.

Status: In progress, 2026-05-31.

## Purpose

Implement all WebAuthn Level 2 attestation statement formats as optional packages. The root package must remain usable without importing any format package beyond those selected by the application.

## Prerequisites

- Plan 02 complete.
- Plan 03 registration verifier supports format registry dispatch.
- Codec and crypto adapter decisions documented.
- Trust policy layer exists or has a minimal interface from plan 07.

## Required formats

| Format              | Package direction              | Key requirements                                                                                 | Progress                                                                                     |
| ------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| `none`              | `attestation/none`             | Empty statement, no trust path, policy acceptance.                                               | Complete, 2026-05-31.                                                                        |
| `packed`            | `attestation/packed`           | x5c/basic/AttCA, self attestation, algorithm matching, AAGUID certificate extension check.       | Initial verifier complete, 2026-05-31; x5c trust classification remains Plan 07 policy work. |
| `tpm`               | `attestation/tpm`              | TPM statement shape, public area binding, certInfo binding, TPM manufacturer/version fields.     | Initial verifier complete, 2026-05-31; trust-chain acceptance remains Plan 07 policy work.   |
| `android-key`       | `attestation/androidkey`       | Android key certificate extension, challenge binding, authorization list checks.                 | Initial verifier complete, 2026-05-31; trust-chain acceptance remains Plan 07 policy work.   |
| `android-safetynet` | `attestation/androidsafetynet` | JWS response verification through dependency, nonce binding, service certificate/trust handling. | Not started.                                                                                 |
| `fido-u2f`          | `attestation/fidou2f`          | ES256 requirement, U2F registration signature base, x5c trust path.                              | Initial verifier complete, 2026-05-31; Basic vs AttCA classification remains Plan 07 work.   |
| `apple`             | `attestation/apple`            | Apple anonymous attestation nonce and certificate checks.                                        | Not started.                                                                                 |

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

## Progress updates

2026-05-31: Delivered the first P1 slice. Added optional `attestation/packed` with explicit construction, self-attestation verification, x5c signature verification, packed certificate shape checks, AAGUID extension matching when present, and per-format tests. No new third-party dependency was added; X.509 parsing uses the Go standard library and signatures are delegated through `crypto.SignatureVerifier`. Scope change: x5c returns `TypeUncertain` until Plan 07 metadata/trust policy work can distinguish Basic from AttCA.

2026-05-31: Delivered the second P1 slice. Added optional `attestation/fidou2f` with explicit construction, ES256 credential-key requirement, U2F registration verification data construction, single-certificate x5c trust path handling, P-256 attestation certificate key checks, and per-format tests. Added optional U2F raw public-key extraction to the `codec.CredentialPublicKey` contract and `codec/cbor` adapter. No new third-party dependency was added. Scope change: `fido-u2f` returns `TypeUncertain` until Plan 07 metadata/trust policy work can distinguish Basic from AttCA.

2026-05-31: Delivered the third P1 slice. Added optional `attestation/tpm` with explicit construction, exact TPM attestation statement field parsing, TPM 2.0 version enforcement, EC2 and RSA `pubArea` binding to codec-derived credential public key material, `certInfo` extraData and name binding, TPMT_SIGNATURE algorithm/hash checks, AIK certificate requirement checks, x5c trust path output, and per-format tests. Added optional EC2/RSA public key material extraction to the `codec.CredentialPublicKey` contract and `codec/cbor` adapter. No new third-party dependency was added. Scope change: trust-chain acceptance remains Plan 07 relying-party policy work.

2026-05-31: Delivered the fourth P1 slice. Added optional `attestation/androidkey` with explicit construction, exact Android Key attestation statement field parsing, signature verification over authenticator data plus client data hash, EC2 and RSA leaf certificate public-key binding to codec-derived credential public key material, Android Key attestation extension challenge and authorization-list checks, x5c trust path output, and per-format tests. Shared attestation statement field helpers now live under `attestation/internal/attstmt` to avoid duplicated x5c and byte cloning logic across optional format packages. No new third-party dependency was added. Scope change: trust-chain acceptance remains Plan 07 relying-party policy work.
