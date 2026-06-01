# 04 - Authentication ceremony

Priority: P0.

Status: Complete, 2026-05-31.

## Purpose

Implement WebAuthn Level 2 authentication option generation and assertion verification in a framework-neutral way, including username-first and discoverable passkey flows.

## Prerequisites

- Plan 02 complete.
- Plan 03 complete enough to reuse client data, authenticator data, codec, crypto, and extension policy components.
- Stored credential model available.

## Deliverables

1. Authentication options builder for `PublicKeyCredentialRequestOptions`.
2. Ceremony state output containing challenge, RP ID, allowed origins or origin policy reference, requested user verification, requested extensions, allow credentials, timeout/expiry metadata, and optional username-first account binding.
3. Authentication assertion input model independent of HTTP and browser JSON conventions.
4. Allow-credentials matching when allow list is present.
5. Username-first ownership checks using caller-supplied account and credential data.
6. Discoverable-credential flow support requiring user handle mapping.
7. Collected client data verification for `webauthn.get`.
8. Challenge, origin, cross-origin, `topOrigin`, and reserved `tokenBinding`
   checks.
9. Authenticator data parsing without AT flag requirement.
10. RP ID hash check, including AppID extension policy path.
11. User presence and user verification checks.
12. Extension output policy hook.
13. Signature verification over authenticator data and SHA-256 of client data.
14. Signature counter comparison and clone-risk result.
15. Authentication result containing user binding, credential ID, counter update, extension results, and warnings.

## Non-goals

- No session creation.
- No database update.
- No risk engine beyond structured signals.
- No HTTP adapter.

## Tests

- Successful username-first authentication.
- Successful discoverable passkey authentication.
- Missing user handle in discoverable flow.
- User handle mismatch in username-first flow.
- Allow-credentials mismatch.
- Challenge mismatch.
- Origin mismatch.
- RP ID hash mismatch.
- AppID hash accepted only when extension policy and output permit it.
- Missing UP flag.
- Missing UV flag when required.
- Invalid signature.
- Unsupported algorithm.
- Counter zero/zero behavior.
- Counter increment behavior.
- Counter rollback clone-risk behavior.

## Completion update requirements

When complete, update `docs/plans.md`, this file, `docs/technical.md`, `docs/api-boundaries.md`, `docs/security-model.md`, and `README.md` feature status.

## Completion record

Completed on 2026-05-31.

Delivered files and packages:

- root authentication APIs: `StartAuthentication`, `FinishAuthentication`, `AuthenticationState`, structured assertion response input, counter policy/result types, and authentication result output;
- username-first and discoverable-credential ownership checks using caller-supplied `CredentialRecord` values;
- `webauthn.get` client data validation,
  challenge/origin/cross-origin/top-origin/reserved-token-binding checks,
  allow-credentials enforcement, RP ID hash verification, AppID hash fallback,
  UP/UV checks, signature verification through `crypto.SignatureVerifier`, and
  sign counter comparison;
- authenticator extension data parsing for authentication assertions with the ED flag;
- authentication extension policy handling for absent, ignored unsolicited, and rejected unsolicited results.

Tests delivered:

- successful username-first and discoverable authentication;
- missing discoverable user handle, username-first user-handle mismatch, allow-credentials mismatch, challenge mismatch, origin mismatch, RP ID hash mismatch, missing UP, missing required UV, invalid signature, unsupported algorithm, and counter rollback rejection;
- AppID hash acceptance only with requested extension, policy AppID, and client output;
- counter zero/zero, counter increment, and counter rollback clone-risk warning behavior;
- extension absent, unsolicited ignored, and unsolicited rejected behavior;
- authenticator data parser coverage for authentication extension data and unexpected trailing bytes.

Scope changes: none. HTTP/session/database behavior, browser JSON helpers, broader risk engines, and storage adapters remain out of scope.

Dependency decision: no runtime dependency was added in this plan. Signature verification remains behind `crypto.SignatureVerifier`, and authenticator extension decoding reuses `codec.Decoders`.
