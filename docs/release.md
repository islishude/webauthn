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

2026-08-28: Completed the frozen Recommendation section 16 inventory with 45
unique cases: 30 ceremony, 12 PRF Web Authentication API, and 3 test-only CTAP2
calculations. Authentication extension output now carries the selected
credential ID, and PRF `evalByCredential` results are checked only against that
credential before falling back to `eval`. The non-normative TPM vector's raw DER
signature remains rejected in favor of normative `TPMT_SIGNATURE`; a test-only
derived wrapper validates the intended flow. Added test-only
`github.com/cloudflare/circl v1.6.5` for real Ed448 vector verification. No
storage format, browser wire format, root import boundary, or production
CTAP/Ed448 implementation changed.

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
  and `VerifyOutput`; post-construction `Register` mutation was removed.
- Authentication `extension.OutputRequest` now includes
  `SelectedCredentialID`. Root ceremony callers receive this automatically;
  callers that invoke `PRFHandler.VerifyOutput` directly with
  `evalByCredential` results must supply the credential that produced the
  assertion. Missing context fails closed when credential-specific selection
  could change the expected output.
- Construct credential keys from raw COSE plus typed material. Signature inputs
  no longer carry adapter-owned `any` key handles.
- Persist credential updates conditionally using `PreviousSignCount` and the
  `*Changed` fields. `BackupEligible` is no longer an authentication update.
- Treat zero timeout as five minutes and reject negative timeout, invalid backup
  flags, RP-ID mismatch, and credential IDs longer than 1023 bytes.
- Use optional `storage/json` for versioned trusted server-side state encoding or
  map the storage-neutral root records into an application schema.

## Non-goals

- No production server, router, storage, session, cookie, CSRF, rate-limit, or account recovery adapter is shipped.
- No hidden attestation trust roots, metadata network client, OCSP/CRL client, or enterprise enrollment default is shipped.
- No root package dependency on browser JSON, `net/http`, optional transport helpers, or optional attestation formats is allowed.
