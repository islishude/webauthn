# 03 - Registration ceremony

Priority: P0.

Status: Not started.

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
5. Challenge, origin, cross-origin, and token binding checks.
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
