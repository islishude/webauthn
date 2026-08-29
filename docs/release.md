# Release checklist

Status: Pre-v1 Level 3 security and API cleanup complete, revised 2026-08-28.

This file records release-readiness checks for `github.com/islishude/webauthn`.

## Release candidate requirements

- Local `make ci` passes from a clean worktree.
- GitHub Actions CI passes on the release branch.
- Root package import graph does not include `net/http`, `browser`,
  `transport/http`, `crypto/standard`, `storage/json`, or optional attestation
  format packages.
- Public examples compile through `make example-build`.
- README feature claims match implemented and tested behavior.
- Dependency inventory in `docs/dependencies.json` covers every module returned by `go list -m all`.

## Release notes

2026-08-28: Replaced the extension Handler's untyped return values with generic
normalized input and output types. `Register` is now the explicit registry
type-erasure boundary, raw output presence and null are represented by
`RawValue`, and ceremony callers retrieve known results with typed `Find` rather
than `Result.Outputs` assertions. Unknown and unrequested results remain
available through `FindRaw`. Browser/CBOR wire values and storage JSON envelopes
did not change, and no dependency was added.

2026-08-28: Closed the section-by-section Recommendation audit. Restricted
enrollment now demonstrates trusted-root and certificate-status policy; RSA
keys enforce RFC 8230 encoding and 2048–16384 bit bounds; AppID output is bound
bidirectionally to the selected hash; clone-risk rejection precedes extension
callbacks; TPM public areas are parsed strictly; Android Key and Apple accept
Ed25519 certificate keys; and legacy SafetyNet requires explicit application,
certificate, freshness, version, and integrity policy. Browser response JSON now
requires the Level 3 members and `id`/`rawId` agreement. PRF optional-member
presence and largeBlob restored-state constraints fail closed. Credential
records persist their type in storage envelope v2, whose reader remains
compatible with v1. Browser timeout hints and server challenge TTLs are now
separate. No dependency changed.

2026-08-28: Hardened caller-owned state and persistence boundaries. Finish
rejects missing expiry and unresolved user-verification policy; registration no
longer accepts or returns a precomputed credential-uniqueness boolean, and the
examples use atomic insertion instead. Unknown composite extension values retain
bounded non-string comparable CBOR keys, known authenticator-attachment changes
are included in conditional updates, HTTP responses are serialized before
headers are committed, and shared ceremony errors use operation-neutral text.
The storage JSON envelope remains version 1 and no dependency changed.

2026-08-28: Completed the frozen Recommendation section 16 inventory with 45
unique cases: 30 ceremony, 12 PRF Web Authentication API, and 3 test-only CTAP2
calculations. Authentication extension output now carries the selected
credential ID, and PRF `evalByCredential` results are checked only against that
credential before falling back to `eval`. The non-normative TPM vector's raw DER
signature remains rejected in favor of normative `TPMT_SIGNATURE`; a test-only
derived wrapper validates the intended flow. The published Ed448 pair remains
in the inventory but is skipped; the test-only CIRCL verifier and dependency
were removed. No storage format, browser wire format, root import boundary, or
production CTAP/Ed448 implementation changed.

2026-08-25: Updated the stable baseline to the final WebAuthn Level 3
Recommendation. W3C records no substantive protocol change from the 26 May
Candidate Recommendation. The audit nevertheless closed two existing gaps:
client challenges and browser/storage/PRF transport values now require exact
canonical unpadded base64url, and registration ceremony state now binds
conditional creation mediation so only that flow may omit UP. The storage JSON
envelope remains version 1; the new boolean field is omitted for ordinary
registration, so its absent zero value preserves the previous fail-closed
behavior. No dependency changed.

2026-08-23: Aligned the implementation with the 26 May 2026 WebAuthn Level 3
Candidate Recommendation and kept the 30 July Editor's Draft
`remoteClientDataJSON` extension explicit and opt-in. Added optional-member
presence checks, identifier grammar, CTAP2 canonical CBOR/required-only COSE,
Ed448 routing, complete packed/TPM/Android/Apple certificate checks, and
licensed W3C vectors. Upgraded test-only Playwright to 1.62.1 and added
Credentials lifecycle and in-memory passkey storage-state E2E. No Go dependency
or storage envelope version changed.

2026-08-23: Completed the pre-v1 Level 3 security and API cleanup. Added strict
backup/UV/RP-ID/counter state transitions, five-minute default ceremony expiry,
the 1023-byte credential ID limit, BOM-compatible client-data parsing, typed
COSE key material, an optional standard-library signature verifier, optional
versioned server-side storage JSON, start-time extension validation, immutable
registries, deterministic extension results, and replay-safe concurrent HTTP
example wiring. No third-party dependency was added.

2026-06-01: Completed Plan 09. Added optional browser JSON DTO conversion helpers, optional standard-library HTTP JSON helpers, compile-checked manual/HTTP/passkey/attestation examples, README example reference checks, CI example builds, and release documentation. No third-party dependency was added.

2026-06-01: Completed Plans 10 through 14. Upgraded the normative baseline to
WebAuthn Level 3, added `OriginPolicy`/`topOrigin`, Level 3 hints and
attestation format fields, PRF extension handling, deprecated `uvm` result
metadata, compound attestation support, OKP credential public-key material, and
Level 3 browser/HTTP DTO coverage. No third-party dependency was added.

2026-06-02: Completed Plan 15. Removed unused grouped decoder and crypto hash
API, split root finish options into narrow decoder fields, made attestation
acceptance depend only on explicit trust policy, added typed byte
comparison/append helpers, clarified configuration and ceremony-state errors,
and shared extension/signature helper logic. No third-party dependency was
added.

## Pre-v1 migration notes

- Set `RegistrationStartOptions.ConditionalMediation` only when the browser call
  uses `mediation: "conditional"`; persist the returned state so the finish
  verifier can apply the Level 3 UP exception. The zero value remains ordinary
  UP-required registration.
- Move registration UV configuration to
  `AuthenticatorSelectionCriteria.UserVerification`; the duplicate start option
  field was removed.
- Pass the selected immutable extension registry to start options whenever
  extension inputs are non-empty. Custom handlers now implement `ValidateInput`
  and side-effect-free `VerifyOutput` as `Handler[I, O]`. Wrap each custom
  handler with `extension.Register(handler)` when constructing a registry; this
  replaces passing the handler directly and is not mutable post-construction.
- `ValidateInput` now returns normalized `I`; `VerifyOutput` accepts
  `OutputRequest[I]` and returns `Verification[O]`. Raw client and authenticator
  outputs are `RawValue`s, whose zero value is absent and whose present nil
  value is explicit null. Direct handler callers must validate the input first.
- `RegistrationResult.Extensions` and `AuthenticationResult.Extensions` are
  `extension.Results`. Replace `result.Outputs[id].(T)` with
  `extension.Find(results, handler)`; use `extension.FindRaw(results, id)` only
  for unknown or unrequested evidence.
- Register a `largeBlob` handler whenever requesting that authentication
  extension. It is not accepted as an unknown pass-through because restored
  state must reapply its single-credential write constraint.
- Set `StateTTL` separately when the default ten-minute challenge lifetime is
  not appropriate. `Timeout` remains the five-minute browser hint by default,
  and configured state TTL may not be shorter than the hint. Use
  `DefaultBrowserTimeout`; `DefaultCeremonyTimeout` is now deprecated because it
  cannot name both lifetimes accurately.
- Populate `CredentialRecord.Type`; registration returns `public-key` and
  `storage/json` envelope v2 persists it. The v2 reader maps an absent type in
  legacy v1 records to `public-key` and rejects explicit empty or null values.
- An empty registration `PubKeyCredParams` now expands to the Recommendation's
  ES256/RS256 defaults. Unsupported credential types are ignored when a
  supported `public-key` entry remains and fail when none remains.
- Update custom registration response JSON to include required `id`,
  `clientExtensionResults`, `authenticatorData`, `transports`, and
  `publicKeyAlgorithm`, with `id` equal to canonical base64url `rawId`.
- Construct legacy SafetyNet verifiers with an explicit
  `androidsafetynet.Policy`; the prior policy-free constructor no longer exists.
- Rename `AppIDExcludeResult.Excluded` to `ActedUpon`; a successful `true`
  output means the extension ran, not that a credential was found and excluded.
- Authentication `extension.OutputRequest[I]` includes `SelectedCredentialID`.
  Root ceremony callers receive this automatically; callers that invoke
  `PRFHandler.VerifyOutput` directly with `evalByCredential` results must supply
  the credential that produced the assertion. Missing context fails closed when
  credential-specific selection could change the expected output.
- Remove `RegistrationFinishOptions.CredentialAlreadyRegistered`,
  `RegistrationResult.DuplicateCredential`, and `ErrDuplicateCredential`.
  Insert the verified credential under an application-owned atomic uniqueness
  constraint and map conflicts to application transport errors.
- Construct credential keys from raw COSE plus typed material. Signature inputs
  no longer carry adapter-owned `any` key handles.
- Persist credential updates conditionally using `PreviousSignCount` and the
  `*Changed` fields, including `AuthenticatorAttachmentChanged`.
  `BackupEligible` is no longer an authentication update.
- Treat zero browser timeout as five minutes and zero state TTL as ten minutes;
  reject negative or inconsistent timing, invalid backup flags, RP-ID mismatch,
  credential IDs longer than 1023 bytes, and caller-stored state missing expiry
  or a resolved user-verification policy.
- Use optional `storage/json` for versioned trusted server-side state encoding or
  map the storage-neutral root records into an application schema.

## Non-goals

- No production server, router, storage, session, cookie, CSRF, rate-limit, or account recovery adapter is shipped.
- No hidden attestation trust roots, metadata network client, OCSP/CRL client, or enterprise enrollment default is shipped.
- No root package dependency on browser JSON, `net/http`, optional transport helpers, or optional attestation formats is allowed.
