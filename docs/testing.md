# Testing and conformance strategy

Status: API cleanup and refactor coverage complete, revised 2026-06-29.

This document defines the test approach for the planned WebAuthn/passkey server-side library.

## Test source rules

Tests may be derived from W3C specification requirements, independently generated fixtures, browser outputs collected for this project, and public conformance data when the license and source are documented.

Do not copy tests from public WebAuthn/passkey libraries. Do not translate another library's test cases into this repository.

## Local quality gate

The local quality gate is defined in `docs/ci.md` and implemented by the root `Makefile`.

The required pre-PR command is:

```sh
make ci
```

`make ci` runs Go and Prettier format checks, linting, unit tests, race tests, bounded fuzz smoke tests, import graph checks, dependency license checks, and module tidy verification without module-detection skips.

Real browser e2e coverage is available through:

```sh
make e2e
```

This target is separate from `make ci`. It runs Playwright Chromium tests
against a test-only HTTPS relying-party app in `internal/e2eapp` and uses CDP
virtual authenticators to exercise `navigator.credentials.create()` and
`navigator.credentials.get()` through the repository's browser and HTTP adapter
packages.

## Test layers

### Protocol model tests

Required coverage:

- dictionary field validation;
- enum and DOMString value handling;
- byte/string transport conversion boundaries;
- typed byte equality and append helpers that avoid defensive-copy hot paths;
- RP ID and origin policy validation;
- challenge generation and challenge comparison;
- credential descriptor and transport hint behavior;
- unknown field tolerance where the specification requires it.

### Authenticator data parser tests

Required coverage:

- minimum 37-byte authenticator data without AT or ED;
- UP and UV flag extraction;
- AT flag with attested credential data;
- ED flag with extension data;
- truncated RP ID hash, flags, counter, AAGUID, credential ID length, credential ID, and credential public key;
- invalid or inconsistent length fields;
- sign counter big-endian decoding;
- extension map boundary behavior through the codec adapter.

### Client data tests

Required coverage:

- valid `webauthn.create` and `webauthn.get` values;
- challenge mismatch;
- origin mismatch;
- `topOrigin` acceptance and rejection;
- unknown JSON keys;
- reordered JSON keys;
- optional reserved token binding absence and preservation;
- token binding ignored for relying-party verification;
- malformed UTF-8 and malformed JSON.

### Registration ceremony tests

Required coverage:

- successful registration with `none` attestation;
- RP ID hash mismatch;
- missing UP flag;
- missing UV flag when required;
- unsupported credential public key algorithm;
- unsupported attestation format;
- invalid attestation statement;
- untrusted attestation policy result;
- duplicate credential ID path surfaced to caller;
- extension requested but absent;
- unsolicited extension behavior under ignore and reject policies.

### Authentication ceremony tests

Required coverage:

- successful assertion verification;
- allow-credentials mismatch;
- credential ownership mismatch;
- missing user handle in discoverable-credential flow;
- user handle mismatch in username-first flow;
- RP ID hash mismatch;
- AppID extension hash acceptance when valid;
- missing UP flag;
- missing UV flag when required;
- signature failure;
- unsupported algorithm;
- zero-counter behavior;
- counter increment behavior;
- counter rollback clone-risk behavior.

### Browser e2e tests

Required coverage:

- platform passkey registration and discoverable login;
- roaming security key registration and username-first login;
- session creation, `/me` state, and logout clearing;
- registration and authentication state replay rejection;
- unregistered-user login rejection;
- UV-required flow failure when the virtual authenticator is not user verified;
- bogus assertion signature rejection.

### Attestation format tests

Each attestation format package must have its own tests and fixtures. At minimum:

- valid fixture;
- malformed CBOR shape;
- missing required field;
- wrong algorithm;
- invalid signature;
- certificate requirement failure where applicable;
- trust policy accepted and rejected paths where applicable.

Format-specific coverage:

- `none`: empty attestation statement and no trust path.
- `packed`: x5c/basic, self attestation, AAGUID certificate extension behavior, algorithm mismatch.
- `tpm`: TPM statement shape, certificate requirements, public key and name binding, firmware/version checks where available.
- `android-key`: Android key certificate extension parsing, challenge binding, authorization list policy.
- `android-safetynet`: legacy JWS response verification through dependency,
  nonce binding, certificate/trust policy.
- `fido-u2f`: U2F registration signature base construction and ES256 requirement.
- `apple`: anonymous attestation certificate and nonce binding behavior.

### Extension tests

Required coverage:

- `appid` authentication RP ID hash switching;
- `appidExclude` option serialization and policy representation;
- `uvm` output parsing and absence behavior;
- `credProps` output parsing for discoverable credential/passkey flows;
- `largeBlob` option and output shape handling;
- `prf` input/output handling and `evalByCredential` allow-list binding;
- deprecated `uvm` result metadata;
- unknown extension policy.

### Dependency adapter tests

Codec and crypto adapters should have tests that confirm WebAuthn-level expectations without duplicating the dependency's own test suite.

Required coverage:

- CBOR map shape extraction for attestation objects;
- COSE key conversion into verifier inputs;
- algorithm allow-list enforcement;
- ECDSA DER signature verification behavior;
- RSA PKCS#1 v1.5 and RSA-PSS behavior for supported algorithms;
- JWS/JWT verification handoff behavior for SafetyNet-like formats;
- X.509 chain acceptance and rejection through trust policy.

## Current coverage

Plan 02 added initial tests for:

- byte-safe value copy semantics, length validation, and exact challenge comparison;
- protocol option validation and unknown DOMString preservation until validation boundaries;
- codec and crypto adapter contracts using independently authored test doubles;
- attestation and extension registry duplicate rejection, unknown lookup, and case-sensitive identifiers;
- root import graph checks preventing `net/http`, transport helpers, and optional attestation format package imports.

Plan 03 added tests for:

- registration option generation and successful registration with `none` attestation;
- collected client data parsing and malformed client data rejection;
- authenticator data parsing, flags, sign count, and attested credential data extraction;
- registration rejection paths for challenge, origin, cross-origin, reserved
  token binding, RP ID hash, UP/UV, algorithm, format, attestation policy,
  duplicate credential, and expiry failures;
- extension absent, unsolicited ignored, and unsolicited rejected behavior;
- optional CBOR/COSE decoder behavior, including duplicate map key rejection and COSE_Key raw-consumption boundaries;
- optional `attestation/none` verifier behavior.

Plan 04 added tests for:

- authentication option generation and successful username-first and discoverable authentication;
- missing discoverable user handle, username-first user handle mismatch, allow-credentials mismatch, challenge mismatch, origin mismatch, RP ID hash mismatch, UP/UV failures, invalid signature, unsupported algorithm, and counter rollback rejection;
- AppID RP ID hash fallback only when requested, policy-configured, and client output indicates use;
- zero/zero, incrementing, and rollback sign counter comparison behavior;
- authentication extension absent, unsolicited ignored, and unsolicited rejected behavior;
- authenticator data parser behavior for authentication ED extension bytes and unexpected trailing bytes.

The initial Plan 05 and Plan 07 slice added tests for:

- optional `attestation/packed` self and x5c valid paths;
- packed malformed statement, missing field, algorithm mismatch, invalid signature, certificate subject/basic-constraints failure, and AAGUID mismatch paths;
- optional `attestation/fidou2f` valid path, malformed statement, wrong credential key, missing/malformed U2F public key, wrong certificate key, and invalid signature paths;
- optional `codec/cbor` U2F public key extraction and wrong-shape omission behavior;
- registration trust policy accepting and rejecting non-`none` attestation;
- default rejection of non-`none` attestation when no caller trust policy is supplied;
- continued root import graph independence from optional attestation format packages.

The completed Plan 07 trust-policy slice added tests for:

- built-in `none`, self, format allow-list, type allow-list, AAGUID, x5c trust-root, metadata, certificate status, and composition policies;
- metadata provider positive, negative, and unavailable paths;
- certificate status good, revoked, unknown, unavailable, and provider-error paths;
- registration integration with built-in trust policies while preserving `ErrRejectedAttestationPolicy` for rejected valid attestations.

The TPM Plan 05 slice added tests for:

- optional `attestation/tpm` EC2 and RSA valid paths;
- malformed TPM statement fields, unsupported algorithms, public-area parse failures, credential/public-area mismatch, certInfo magic/type/extraData/name mismatch, TPMT_SIGNATURE algorithm/hash mismatch, invalid signatures, and AIK certificate requirement failures;
- optional `codec/cbor` EC2/RSA public key material extraction and wrong-shape omission behavior;
- continued root import graph independence from optional attestation format packages.

The Android Key Plan 05 slice added tests for:

- optional `attestation/androidkey` EC2 and RSA valid paths;
- malformed statement fields, malformed x5c, invalid signature, certificate public-key mismatch, missing or malformed Android Key attestation extension, challenge mismatch, `allApplications` rejection, missing or wrong origin, and missing signing purpose;
- shared attestation statement helper reuse across optional format packages;
- continued root import graph independence from optional attestation format packages.

The Android SafetyNet Plan 05 slice added tests for:

- optional `attestation/androidsafetynet` valid path;
- malformed statement fields, JWS verifier rejection, malformed payload JSON, nonce mismatch, missing or false `ctsProfileMatch`, missing or non-numeric `timestampMs`, missing x5c chain, malformed leaf certificate, and SafetyNet service hostname mismatch;
- shared attestation statement string helper reuse across optional format packages;
- continued root import graph independence from optional attestation format packages.

The Apple Plan 05 slice added tests for:

- optional `attestation/apple` EC2 and RSA valid paths;
- malformed statement fields, missing or empty x5c, malformed certificates, missing or malformed nonce extension, nonce mismatch, missing credential public key material, leaf public-key mismatch, and leaf-first trust path preservation;
- shared X.509 certificate-chain, extension lookup, and certificate public-key binding helpers across optional format packages;
- continued root import graph independence from optional attestation format packages.

Plan 06 added tests for:

- built-in Level 2 extension handlers for `appid`, `appidExclude`, `uvm`, `credProps`, and `largeBlob`, including valid, absent-output, malformed, and wrong-operation paths;
- registration `credProps` result surfacing and unknown extension preservation/rejection policy;
- authentication `uvm` authenticator output parsing, `largeBlob` client output parsing, and AppID policy mismatch rejection;
- continued default behavior that unknown or unrequested extension outputs are observable but not accepted as trusted handler results.

Plan 08 added tests and checks for:

- fuzz targets for authenticator data parsing, collected client data parsing, CBOR attestation object decoding, COSE key decoding, authenticator extension map decoding, and browser transport credential descriptor conversion;
- browser interoperability fixture verification using the e2e Playwright dependency and Chrome DevTools virtual authenticators for platform/discoverable UV-required and roaming allow-credentials username-first flows;
- real ES256 assertion signature verification for browser fixtures through a test-only standard-library verifier, including tampered signature rejection;
- regression coverage for malformed COSE key shapes that can panic inside the selected COSE dependency, now reported as `codec/cbor.ErrMalformedCBOR`;
- explicit import graph and dependency license manifest checks in local and GitHub Actions CI.

Plan 09 added tests and checks for:

- optional `browser` DTO conversion for creation/request options, credential descriptors, registration responses, authentication responses, malformed JSON, invalid base64url, invalid protocol values, oversized user handles, known largeBlob byte fields, and unknown extension preservation;
- optional `transport/http` JSON helpers for creation/request option writing, registration/authentication response reading, body-size rejection, malformed JSON handling, and generic error responses that do not echo sensitive error text;
- compile-checked public examples under `examples/manual`, `examples/http`, `examples/passkey`, and `examples/attestation`;
- README reference checks that keep public Go usage in compile-checked examples.

Plans 10 through 14 added tests and checks for:

- `OriginPolicy` and `topOrigin` acceptance/rejection in registration finish;
- reserved `tokenBinding` client data ignored for relying-party verification;
- Level 3 hints, transports, client capabilities, algorithm constants, and
  recommended credential parameters;
- browser and HTTP DTO support for hints, attestation formats, registration
  `authenticatorData`, `publicKey`, `publicKeyAlgorithm`, authenticator
  attachment, and PRF byte-field conversion;
- Level 3 PRF handler and authentication integration, including
  `evalByCredential` allow-list binding;
- deprecated `uvm` result metadata while keeping `uvm` parsing available;
- CBOR compound attestation statement normalization and malformed compound
  rejection;
- optional `attestation/compound` verifier success, threshold policy, malformed
  statement, nested compound rejection, and missing verifier behavior;
- OKP credential public-key material extraction and wrong-shape omission;
- examples using Level 3 recommended credential parameters and Level 3 extension
  registries with deprecated support where needed.

The API cleanup added tests and checks for:

- protocol typed equality helpers for credential IDs, raw IDs, and user handles
  without relying on `Bytes()` defensive copies;
- byte-value `AppendTo` behavior for signature-base construction without
  exposing mutable stored bytes;
- registration and authentication tests updated for explicit
  `AttestationTrustPolicy`, narrow decoder fields, injected clocks, and shared
  root extension verification behavior;
- attestation format tests preserved across the shared signature helper refactor,
  including malformed statement and invalid signature rejection paths;
- example builds updated to pass explicit decoder contracts and
  `attestation.AcceptNone()` where consumer passkey `none` attestation is
  accepted.

## Fuzzing targets

Current fuzzing targets are:

- authenticator data parser;
- client data parser;
- attestation object decoding boundary;
- COSE key decoding boundary;
- extension map decoding boundary;
- browser transport DTO base64url conversion through the optional `browser` package;
- credential descriptor decoding.

Fuzz tests must not require network access.

CI fuzzing is a bounded smoke check. Longer fuzz campaigns should be run locally or in a separate scheduled workflow once parser surfaces exist.

## Browser interoperability tests

Browser-produced registration and authentication outputs are generated specifically for this project by `scripts/generate-browser-fixtures.mjs` through the Playwright dependency pinned by `e2e/package-lock.json` and Chrome DevTools virtual authenticators. The committed fixture suite lives under `testdata/browser/virtual-authenticator`.

Current fixture coverage:

- platform-style authenticator with discoverable credential and user verification required;
- roaming-style authenticator with allow-credentials username-first authentication;
- discoverable passkey-style authentication with a returned user handle;
- user verification required and preferred flows;
- `none` attestation returned by browser-created registration ceremonies;
- assertion signature verification and tampered signature rejection.

Fixtures record source, generation date, Playwright/browser context, authenticator type, and test-only sensitivity metadata. Sensitive values are synthetic and are not production account, credential, authenticator, or private-key material.

Real hardware authenticator fixtures, direct/enterprise attestation browser captures, and broader OS/browser matrix expansion remain release-hardening work after the virtual-authenticator baseline.

## Conformance tracking

The matrix below maps W3C WebAuthn Level 3 relying-party operation groups to repository tests. The rows are grouped by observable server-side behavior rather than quoting the specification step text.

| W3C relying-party operation area                                                                                        | Coverage                                                                                                                                                                                                                |
| ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Registration response type and shape validation                                                                         | `TestRegistrationFinishRejectsInvalidInputs`, `TestBrowserVirtualAuthenticatorFixturesVerify`                                                                                                                           |
| Registration collected client data type, challenge, origin, cross-origin, top-origin, and reserved token binding checks | `TestRegistrationFinishRejectsInvalidInputs`, `TestRegistrationTopOriginPolicy`, `TestRegistrationIgnoresReservedTokenBinding`, `TestParseCollectedClientData`, `FuzzParseCollectedClientData`                          |
| Registration attestation object decoding and authenticator data parsing                                                 | `TestDecoderDecodesAttestationObject`, `TestDecoderDecodesCompoundAttestationObject`, `TestParseAuthenticatorDataWithAttestedCredentialData`, `FuzzDecodeAttestationObject`, `FuzzParseAuthenticatorData`               |
| Registration RP ID hash, UP, UV, credential ID, and algorithm checks                                                    | `TestRegistrationFinishRejectsInvalidInputs`, `TestBrowserVirtualAuthenticatorFixturesVerify`                                                                                                                           |
| Registration extension output handling                                                                                  | `TestRegistrationLevel2CredPropsExtension`, `TestRegistrationUnknownExtensionPolicy`, `TestRegistrationUnrequestedKnownExtensionOutputIsUntrusted`, `extension` Level 2 handler tests                                   |
| Registration attestation format and trust policy dispatch                                                               | Attestation format package tests, `TestRegistrationAttestationTrustPolicyAcceptsNonNoneAttestation`, `TestRegistrationBuiltInAttestationTrustPolicies`                                                                  |
| Registration credential uniqueness and persistence-ready result construction                                            | `TestRegistrationFinishRejectsInvalidInputs`, `TestRegistrationWithNoneAttestation`                                                                                                                                     |
| Authentication allow-credentials and credential/user-handle ownership checks                                            | `TestAuthenticationRejectsInvalidInputs`, `TestAuthenticationUsernameFirst`, `TestAuthenticationDiscoverable`, `TestBrowserVirtualAuthenticatorFixturesVerify`                                                          |
| Authentication collected client data type, challenge, origin, cross-origin, and reserved token binding checks           | `TestAuthenticationRejectsInvalidInputs`, `FuzzParseCollectedClientData`                                                                                                                                                |
| Authentication RP ID hash and AppID extension behavior                                                                  | `TestAuthenticationRejectsInvalidInputs`, `TestAuthenticationAppIDHashAcceptedWithPolicyAndOutput`, `TestAuthenticationAppIDRejectsPolicyMismatch`                                                                      |
| Authentication UP, UV, extension output, and signature verification                                                     | `TestAuthenticationRejectsInvalidInputs`, `TestAuthenticationLevel2UVMExtension`, `TestAuthenticationLevel2LargeBlobExtension`, `TestAuthenticationLevel3PRFExtension`, `TestBrowserVirtualAuthenticatorFixturesVerify` |
| Authentication sign counter and clone-risk behavior                                                                     | `TestAuthenticationCounterPolicy`, `TestAuthenticationRejectsInvalidInputs`                                                                                                                                             |
| Parser and transport boundary robustness                                                                                | `FuzzParseAuthenticatorData`, `FuzzDecodeCredentialPublicKey`, `FuzzDecodeBrowserCredentialDescriptor`, browser package response tests, `TestDecoderCredentialPublicKeyRejectsMalformedDependencyShape`                 |
| Root modularity and dependency hygiene                                                                                  | `TestRootPackageImportGraphExcludesOptionalPackages`, `make import-graph-check`, `make license-check`, `make example-build`, `make readme-check`                                                                        |
| Protocol byte safety and allocation-sensitive comparisons                                                               | `TestCredentialIDTypedEqualityDoesNotUseDefensiveCopies`, `TestUserHandleTypedEqualityDoesNotUseDefensiveCopies`, `TestAppendToAppendsWithoutExposingStoredBytes`                                                       |

## Continuous integration expectations

The baseline CI workflow is `.github/workflows/ci.yml` and is documented in `docs/ci.md`.

Before release, CI should run:

- documentation and configuration presence checks;
- line-ending checks for text files;
- `gofmt`/`goimports` formatting checks;
- golangci-lint static analysis;
- unit tests;
- race-enabled tests for state-free components where practical;
- fuzz smoke tests with bounded time;
- dependency license checks;
- import graph checks proving root package does not import optional attestation or transport packages;
- example build checks for public integration examples;
- README checks proving usage references point to compile-checked examples.

The workflow now includes documentation/config checks, README checks, line-ending checks, formatting checks, static analysis, unit tests, race tests, bounded fuzz smoke tests, example builds, dependency license checks, import graph checks, and module hygiene.
