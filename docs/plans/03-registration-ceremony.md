# 03 - Registration ceremony

Priority: P0.

Status: Complete, 2026-05-31.

## Purpose

Implement WebAuthn Level 2 registration option generation and registration response verification in a framework-neutral way. The first usable path should support `none` attestation, then provide the extension points required by all other attestation formats.

## Prerequisites

- Plan 02 complete.
- Challenge generator and ceremony state representation available.
- Codec and crypto adapter contracts available.
- `none` attestation verifier contract available.

## Deliverables

1. Registration options builder for `PublicKeyCredentialCreationOptions`.
2. Ceremony state output containing challenge, RP ID, allowed origins or origin policy reference, requested user verification, requested extensions, allowed algorithms, timeout/expiry metadata, and user binding.
3. Registration response input model independent of HTTP and browser JSON conventions.
4. Collected client data verification for `webauthn.create`.
5. Challenge, origin, cross-origin, `topOrigin`, and reserved `tokenBinding`
   checks.
6. Attestation object decoding through codec adapter.
7. Authenticator data parsing with AT flag and attested credential data.
8. RP ID hash check.
9. User presence and user verification policy checks.
10. Credential public key algorithm allow-list check.
11. Extension output policy hook.
12. Attestation format dispatch.
13. `none` attestation acceptance through explicit policy.
14. Registration result containing credential record fields, attestation result, extension results, warnings, and caller-persisted state.

## Non-goals

- No database persistence.
- No HTTP handler.
- No frontend JavaScript helper.
- No complete non-`none` attestation format implementations in this plan.

## Tests

- Successful registration with `none` attestation.
- Malformed client data.
- Challenge mismatch.
- Origin mismatch.
- RP ID hash mismatch.
- Missing UP flag.
- Missing UV flag when required.
- Unsupported algorithm.
- Unsupported attestation format.
- `none` attestation rejected by policy.
- Truncated authenticator data.
- Missing attested credential data.
- Extension absent, unsolicited ignored, and unsolicited rejected cases.

## Completion update requirements

When complete, update `docs/plans.md`, this file, `docs/technical.md`, `docs/api-boundaries.md`, and `README.md` feature status.

## Completion record

Completed on 2026-05-31.

Delivered files and packages:

- root registration APIs: `StartRegistration`, `FinishRegistration`, `RegistrationState`, structured registration response input, credential result output, policy structs, and stable sentinel errors;
- `protocol` client data parsing, challenge decoding, authenticator data parsing, flags, AAGUID, sign counter, and attested credential data extraction;
- optional `codec/cbor` decoder for attestation objects, COSE_Key public keys, and authenticator extension maps;
- optional `attestation/none` verifier package;
- dependency updates for `github.com/fxamacker/cbor/v2 v2.9.2` and `github.com/ldclabs/cose v1.3.4`.

Tests delivered:

- successful registration with `none` attestation and explicit `AllowNone` policy;
- malformed client data, challenge mismatch, origin, cross-origin, top-origin,
  reserved token binding, RP ID hash mismatch, missing UP, missing UV when
  required, unsupported algorithm, unsupported attestation format, rejected
  `none` policy, truncated authenticator data, missing attested credential data,
  duplicate credential, and expired ceremony rejections;
- requested extension absent, unsolicited extension ignored, and unsolicited extension rejected behavior;
- concrete CBOR/COSE decoder tests for attestation object shape, duplicate map key rejection, COSE_Key raw-consumption boundary, extension map decoding, and malformed CBOR;
- `none` verifier tests for empty and non-empty attestation statements.

Scope changes: concrete CBOR and COSE_Key dependencies were added in an optional `codec/cbor` package as requested for Plan 03. The root package depends only on the existing `codec.Decoders` abstraction and does not expose concrete dependency types.

Dependency decision:

- `github.com/fxamacker/cbor/v2 v2.9.2` is used only by `codec/cbor` to decode WebAuthn CBOR structures with duplicate map key rejection.
- `github.com/ldclabs/cose v1.3.4` is used only by `codec/cbor` to decode COSE_Key material and expose the COSE algorithm identifier through `codec.CredentialPublicKey`.
- These dependencies are not imported by the root package and can be replaced behind `codec.Decoders` without changing the root registration API.
