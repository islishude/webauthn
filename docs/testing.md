# Testing and conformance strategy

Status: Level 3 security, typed-key, storage, extension lifecycle, and adapter coverage complete, revised 2026-09-04.

This document defines the test approach for the planned WebAuthn/passkey server-side library.

## Test source rules

Tests may be derived from W3C specification requirements, independently generated fixtures, browser outputs collected for this project, and public conformance data when the license and source are documented.

The complete 45-case inventory used from the 25 August 2026 Recommendation
section 16 lives under `testdata/w3c/webauthn-level3`: 30 ceremony cases, 12 PRF
Web Authentication API cases, and 3 CTAP2 `hmac-secret` calculation cases. The
fixtures record their frozen source URL, section, test-only sensitivity, and W3C
permissive document license. Tests read only committed local data and never
fetch a specification or generator from the network. The two Ed448 ceremony
cases remain in the inventory but are skipped because the test suite does not
provide an Ed448 signature verifier.

Section 16 is non-normative. Its TPM registration object contains a DER ECDSA
signature where normative section 8.3 requires `TPMT_SIGNATURE`. Coverage
therefore asserts strict rejection of the original bytes and separately derives
a conforming in-memory wrapper for the registration/authentication flow. The
derived case is not counted among the 45 published cases.

Do not copy tests from public WebAuthn/passkey libraries. Do not translate another library's test cases into this repository.

## Local quality gate

The local quality gate is defined in `docs/ci.md` and implemented by the root `Makefile`.

The required pre-PR command is:

```sh
make ci
```

`make ci` runs Go and pinned Prettier format checks, strict TypeScript checking,
linting, unit tests, race tests, bounded fuzz smoke tests, import graph checks,
dependency license checks, and module tidy verification without module-detection
skips.

A narrow, network-independent Recommendation vector check is:

```sh
go test . -run '^TestW3CLevel3' -count=1
```

Real browser e2e coverage is available through:

```sh
make e2e
```

This target is separate from `make ci`. It runs Playwright Chromium tests
against a test-only HTTPS relying-party app in `internal/e2eapp`. Chromium CDP
virtual authenticators provide native and fault-injection coverage; Playwright
1.62.1 Credentials helpers cover passkey lifecycle and credential-inclusive
storage state through the repository's browser and HTTP adapter packages.

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
- non-canonical base64url challenge rejection even when it decodes to the
  expected bytes;
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
- missing UP accepted only for registration state bound to conditional
  mediation, with ordinary registration still rejecting it;
- missing UV flag when required;
- unsupported credential public key algorithm;
- unsupported attestation format;
- invalid attestation statement;
- unknown attestation type or trust-path classification from a verifier;
- untrusted attestation policy result;
- missing expiry and unresolved user-verification ceremony state;
- atomic duplicate credential insertion in application integration tests;
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
- missing expiry, unresolved user-verification policy, and malformed allow-list
  descriptors in caller-stored state;
- zero-counter behavior;
- counter increment behavior;
- counter rollback clone-risk behavior;
- clone-risk rejection before any custom extension output callback;
- known authenticator-attachment persistence updates and unknown attachment
  preservation.

### Browser e2e tests

Required coverage:

- platform passkey registration and discoverable login;
- roaming security key registration and username-first login;
- session creation, `/me` state, and logout clearing;
- registration and authentication state replay rejection;
- registration and username-first authentication state/email binding rejection;
- unregistered-user login rejection;
- UV-required flow failure when the virtual authenticator is not user verified;
- bogus assertion signature rejection;
- generic HTTP error responses for malformed finish requests.
- Playwright Credentials capture/filter/delete/reseed lifecycle;
- credential-inclusive in-memory storage state restored into a new context and
  used for usernameless login.

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
- `packed`: x5c/basic, self attestation, exact subject encodings, AAGUID,
  firmware, enterprise serial policy, and algorithm mismatch.
- `tpm`: TPM statement shape, public-key/name binding, strict `TPMT_SIGNATURE`,
  critical SAN and exact manufacturer/model/version attribute checks.
- `android-key`: challenge binding, exact authorization-list values, union
  default, hardware/TEE-only policy, and Ed25519 certificate-key binding.
- `android-safetynet`: legacy JWS response verification through dependency,
  nonce, application identity, signing-certificate digest, timestamp, version,
  integrity, and certificate/trust policy.
- `fido-u2f`: U2F registration signature base construction and ES256 requirement.
- `apple`: anonymous attestation certificate, Ed25519 certificate-key support,
  and DER sequence/explicit nonce binding behavior, including the W3C vector.

### Extension tests

Required coverage:

- `appid` authentication RP ID hash switching;
- AppID four-quadrant binding: true only with the AppID hash, false/absent only
  with the ordinary RP ID hash;
- `appidExclude` option serialization and policy representation;
- `uvm` output parsing and absence behavior;
- `credProps` output parsing for discoverable credential/passkey flows;
- `largeBlob` option and output shape handling;
- `prf` input/output handling and `evalByCredential` binding to both the allow
  list and the credential that actually produced the assertion;
- rejection of registration `evalByCredential` whenever the member is present,
  including an empty object;
- operation-specific PRF/largeBlob outputs, equal-input PRF results, and the
  single-credential largeBlob write rule;
- registered-handler enforcement at largeBlob start plus finish-time
  revalidation of the single-credential write rule after trusted state
  restoration;
- opt-in Editor's Draft `remoteClientDataJSON` challenge and byte binding;
- deprecated `uvm` result metadata;
- generic custom-handler registration, typed dispatch, and `Find` result
  inference without output type assertions;
- stable handler revisions, exact start/finish bindings, reserved built-in ID
  enforcement, and 64-entry registry/input/output limits;
- `RawValue` absent/null/type behavior plus defensive copying of typed
  `Clone() T` values and aggregate depth/node/byte budgets;
- unknown extension policy and recursively copied composite values with
  non-string comparable CBOR map keys.

### Dependency adapter tests

Codec and crypto adapters should have tests that confirm WebAuthn-level expectations without duplicating the dependency's own test suite.

Required coverage:

- CBOR map shape extraction for attestation objects;
- COSE key conversion into verifier inputs;
- algorithm allow-list enforcement;
- ECDSA DER signature verification behavior;
- RSA PKCS#1 v1.5 and RSA-PSS behavior for supported algorithms;
- rejection of undersized, oversized, and non-minimally encoded RSA keys;
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
  and expiry failures; credential uniqueness is now covered at the atomic
  application-insertion boundary;
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

- optional `attestation/androidkey` EC2, RSA, and Ed25519 valid paths;
- malformed statement fields, malformed x5c, invalid signature, certificate public-key mismatch, missing or malformed Android Key attestation extension, challenge mismatch, `allApplications` rejection, missing or wrong origin, and missing signing purpose;
- shared attestation statement helper reuse across optional format packages;
- continued root import graph independence from optional attestation format packages.

The Android SafetyNet Plan 05 slice added tests for:

- optional `attestation/androidsafetynet` valid path;
- malformed statement fields, JWS verifier rejection, malformed payload JSON, nonce mismatch, missing or false `ctsProfileMatch`, missing or non-numeric `timestampMs`, missing x5c chain, malformed leaf certificate, and SafetyNet service hostname mismatch;
- the audit remediation adds package name, application certificate digest,
  freshness/future-skew, version allow-list, configurable integrity, malformed
  optional integrity-claim types, and invalid policy rejection;
- shared attestation statement string helper reuse across optional format packages;
- continued root import graph independence from optional attestation format packages.

The Apple Plan 05 slice added tests for:

- optional `attestation/apple` EC2, RSA, and Ed25519 valid paths;
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

- optional `browser` DTO conversion for creation/request options, credential descriptors, registration responses, authentication responses, malformed JSON, invalid or non-canonical base64url, invalid protocol values, oversized user handles, known largeBlob byte fields, and unknown extension preservation;
- Level 3 response required-member presence plus canonical `id`/`rawId`
  agreement;
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
- OKP credential public-key material extraction and known wrong-shape rejection;
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

The pre-v1 Level 3 security cleanup added tests and checks for:

- 1023/1024-byte credential ID boundaries, UTF-8 BOM parsing while preserving
  signed bytes, separate five-minute browser timeout and ten-minute challenge
  lifetime, exact-deadline expiry, and negative timeout/challenge configuration;
- BS-without-BE rejection, immutable backup eligibility, credential RP-ID
  binding, UP/UV result surfacing, and explicitly authorized UV initialization;
- clone-risk rejection, default counter preservation, explicit rollback update,
  and conditional counter, backup, UV, and authenticator-attachment fields;
- known extension input validation at start, unknown input policy, absent unknown
  output behavior, deterministic output ordering, deep copies, and callback
  ordering after signature/attestation verification;
- typed COSE key validation and optional `crypto/standard` ECDSA, RSA PKCS#1,
  RSA-PSS, Ed25519, tampering, policy, and key-mismatch cases;
- optional `storage/json` registration/authentication/credential round trips,
  v2 credential-type persistence, absent-only v1 type migration, explicit
  empty/null type rejection, version and shape rejection, binary and integer
  extension preservation, damaged COSE rejection, and server-side storage
  fuzzing;
- the public HTTP example's per-session state isolation, one-time consumption,
  exact expiry, concurrent starts, random 64-byte user handle, existing
  credential exclusions, atomic uniqueness, and conditional updates.

The 2026-08-23 Level 3 conformance refresh added:

- present/null/empty `topOrigin` distinction, RFU flag rejection, identifier
  grammar boundaries, and unknown authenticator-attachment normalization;
- CTAP2 canonical CBOR rejection, exact attestation-object maps, required-only
  COSE parameters, Ed448 typed-key routing, and storage revalidation;
- byte-for-byte Recommendation-verified vectors for none, cross-origin,
  top-origin, the 1023-byte credential-ID boundary, Apple anonymous
  attestation, and PRF, with Ed448 retained only as non-executed inventory;
- packed enterprise/firmware/subject rules, TPM SAN profiles, Android
  hardware-enforced policy, and Apple nonce ASN.1 rejection paths;
- Playwright 1.62.1 Credentials lifecycle and in-memory credential storage-state
  E2E while retaining every existing Chromium CDP fault-injection test.

The 2026-08-25 Recommendation refresh added:

- exact canonical unpadded base64url validation for client challenges, browser
  DTO binary values, PRF credential keys, and trusted storage envelopes;
- conditional registration mediation state, its storage round trip, the
  no-UP acceptance case, and the unchanged ordinary-registration rejection;
- normative baseline and fixture verification metadata for the final Level 3
  Recommendation.

The 2026-08-28 vector completion added:

- a 45-entry unique coverage manifest with category guards for 30 ceremony, 12
  PRF Web API, and 3 CTAP2 calculation cases;
- all published ceremony algorithms and attestation formats, official-root
  certificate path checks, with the Ed448 pair retained as skipped inventory;
- strict rejection of the non-normative TPM DER-signature fixture plus a
  conforming in-memory `TPMT_SIGNATURE` derivative;
- selected-credential PRF binding, positive coverage for all 12 published PRF
  output shapes, and cross-credential cardinality rejection;
- test-only standard-library ECDH, HKDF, AES-CBC, and HMAC recomputation of every
  published CTAP2 intermediate and result without adding a CTAP product API.

The 2026-08-28 fail-closed API remediation added:

- rejection of missing ceremony expiry and unresolved user-verification policy
  in both root finish paths;
- removal of caller-computed registration uniqueness flags in favor of atomic
  application insertion, including concurrent E2E-store coverage;
- raw unknown extension preservation for bounded nested maps with comparable
  non-string CBOR keys and policy-before-copy ordering;
- conditional authenticator-attachment persistence, operation-neutral error
  text, and HTTP serialization-before-commit behavior.

The 2026-08-28 section-by-section audit remediation added:

- trusted-root and certificate-status enforcement in the restricted-enrollment
  example;
- RFC 8230 RSA size/minimal-encoding rejection and stricter TPM public-area
  unions;
- AppID hash/output four-quadrant coverage and clone-risk-before-extension
  callback ordering;
- SafetyNet package, application certificate, freshness, version, and integrity
  policy plus Android Key/Apple Ed25519 certificate binding;
- Level 3 required response-member and `id`/`rawId` checks, PRF empty-member
  presence rejection, and finish-time largeBlob state revalidation;
- credential type persistence in storage envelope v2 with v1 read compatibility.

The 2026-09-04 full-repository remediation added:

- typed-nil rejection across codec, crypto, attestation, extension, transport,
  and challenge-generator interfaces;
- shared ceremony-state and credential-record validation, stored BE/BS
  rejection, defensive credential copies, and four-field credential-update CAS
  coverage;
- exact extension handler revision bindings, reserved built-in enforcement,
  storage envelope v3 migration checks, and legacy extension-state rejection;
- bounded CBOR maps/arrays/depth/bytes, compound attestation statements,
  recursive extension clones, storage values, browser JSON, HTTP bodies, and
  total extension IDs;
- canonical origin/RP-ID/port and explicit related-origin policy coverage,
  including `http://localhost:8080` fixture compatibility;
- attestation-object and COSE decoder source-identity, COSE canonicality,
  unknown-parameter, and nil-decoder rejection; browser
  required/null/alias/size tests; and context cancellation;
- concurrent example storage, exact CAS predicates, one-time state consumption,
  shared extension registries, and browser authenticator-data transport;
- allocation-reporting benchmarks for client data, CBOR, browser response,
  extension clone, and start-operation hot paths;
- pinned Prettier, strict unused TypeScript checks, and the minimum Go 1.25 CI
  lane.

## Fuzzing targets

Current fuzzing targets are:

- authenticator data parser;
- client data parser;
- attestation object decoding boundary;
- COSE key decoding boundary;
- extension map decoding boundary;
- browser transport DTO base64url conversion through the optional `browser` package;
- credential descriptor decoding.
- registration state storage JSON decoding;
- authentication state storage JSON decoding;
- credential record storage JSON decoding.

Fuzz tests must not require network access.

CI fuzzing is a bounded smoke check. Longer fuzz campaigns should be run locally or in a separate scheduled workflow once parser surfaces exist.

## Browser interoperability tests

Browser-produced registration and authentication outputs are generated specifically for this project by `scripts/generate-browser-fixtures.mjs` through the Playwright dependency pinned by `e2e/package-lock.json` and Chrome DevTools virtual authenticators. The committed fixture suite lives under `testdata/browser/virtual-authenticator`.

Regeneration writes `fixtures.next.json` by default so review does not overwrite
the committed provenance accidentally. `BROWSER_FIXTURE_OUTPUT` may select an
explicit review destination. The generator records the current date and Level 3
Recommendation provenance, writes a mode-0600 temporary file, and publishes it
with an atomic rename.

The committed fixture remains immutable historical provenance from Playwright
1.60.0 and Chrome 148. Live E2E uses Playwright 1.62.1. Its Credentials API
exercises capture, deletion, reseeding, and credential-inclusive storage state
without writing passkey private material to disk. Chromium CDP remains the
native-browser path for transport selection, UV failure, and bogus signatures.

The experimental Playwright Credentials shim may omit registration
`authenticatorData` or mirror the entire `attestationObject` into that member.
The test-only RP normalizes only an absent value or that exact known mirror from
the authoritative `attestationObject` before invoking the strict public browser
decoder. Any other provided value is preserved, so the core equality check
still rejects mismatches; production browser parsing is not relaxed.

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

| W3C relying-party operation area                                                                                                  | Coverage                                                                                                                                                                                                                                                            |
| --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Registration response type and shape validation                                                                                   | `TestRegistrationFinishRejectsInvalidInputs`, `TestBrowserVirtualAuthenticatorFixturesVerify`                                                                                                                                                                       |
| Registration collected client data type, canonical challenge, origin, cross-origin, top-origin, and reserved token binding checks | `TestRegistrationFinishRejectsInvalidInputs`, `TestRegistrationTopOriginPolicy`, `TestRegistrationIgnoresReservedTokenBinding`, `TestParseCollectedClientData`, `TestCollectedClientDataChallengeBytesRejectsNonCanonicalBase64URL`, `FuzzParseCollectedClientData` |
| Registration attestation object decoding and authenticator data parsing                                                           | `TestDecoderDecodesAttestationObject`, `TestDecoderDecodesCompoundAttestationObject`, `TestParseAuthenticatorDataWithAttestedCredentialData`, `FuzzDecodeAttestationObject`, `FuzzParseAuthenticatorData`                                                           |
| Registration RP ID hash, mediation-aware UP, UV, backup flags, credential ID, and algorithm checks                                | `TestRegistrationFinishRejectsInvalidInputs`, `TestConditionalRegistrationDoesNotRequireUserPresence`, `TestBrowserVirtualAuthenticatorFixturesVerify`                                                                                                              |
| Registration extension input and output handling                                                                                  | Start-input, ordering, callback-order, unknown-policy tests plus `extension` handler tests                                                                                                                                                                          |
| Registration attestation format and trust policy dispatch                                                                         | Attestation format package tests, `TestRegistrationAttestationTrustPolicyAcceptsNonNoneAttestation`, `TestRegistrationBuiltInAttestationTrustPolicies`                                                                                                              |
| Registration credential construction and atomic application insertion                                                             | `TestRegistrationWithNoneAttestation`, `TestStoreInsertCredentialIsAtomic`, storage JSON round trip                                                                                                                                                                 |
| Authentication allow-credentials and credential/user-handle ownership checks                                                      | `TestAuthenticationRejectsInvalidInputs`, `TestAuthenticationUsernameFirst`, `TestAuthenticationDiscoverable`, `TestBrowserVirtualAuthenticatorFixturesVerify`                                                                                                      |
| Authentication collected client data type, challenge, origin, cross-origin, and reserved token binding checks                     | `TestAuthenticationRejectsInvalidInputs`, `FuzzParseCollectedClientData`                                                                                                                                                                                            |
| Authentication RP ID hash and AppID extension behavior                                                                            | `TestAuthenticationRejectsInvalidInputs`, `TestAuthenticationAppIDHashAcceptedWithPolicyAndOutput`, `TestAuthenticationAppIDRejectsPolicyMismatch`, `TestAuthenticationAppIDOutputBindsExpectedRPIDHash`                                                            |
| Authentication UP, UV, extension output, and signature verification                                                               | `TestAuthenticationRejectsInvalidInputs`, `TestAuthenticationLevel2UVMExtension`, `TestAuthenticationLevel2LargeBlobExtension`, `TestAuthenticationLevel3PRFExtension`, `TestBrowserVirtualAuthenticatorFixturesVerify`                                             |
| Authentication backup, UV, counter, and clone-risk behavior                                                                       | `TestAuthenticationCounterPolicy`, `TestAuthenticationUVInitializationPolicy`, `TestAuthenticationExtensionOutputDoesNotRunBeforeCloneRiskRejection`, invalid-input matrix                                                                                          |
| Parser, transport, and storage boundary robustness                                                                                | Protocol/codec/browser fuzz targets plus all three `storage/json` fuzz targets                                                                                                                                                                                      |
| Root modularity and dependency hygiene                                                                                            | `TestRootPackageImportGraphExcludesOptionalPackages`, `make import-graph-check`, `make license-check`, `make example-build`, `make readme-check`                                                                                                                    |
| Protocol byte safety and allocation-sensitive comparisons                                                                         | `TestCredentialIDTypedEqualityDoesNotUseDefensiveCopies`, `TestUserHandleTypedEqualityDoesNotUseDefensiveCopies`, `TestAppendToAppendsWithoutExposingStoredBytes`                                                                                                   |
| Recommendation section 16 vector inventory                                                                                        | `TestW3CLevel3VectorInventory`, `TestW3CLevel3CeremonyVectors`, `TestW3CLevel3PRFWebAPIVectors`, `TestW3CLevel3PRFCTAPVectors`                                                                                                                                      |

## Continuous integration expectations

The baseline CI workflow is `.github/workflows/ci.yml` and is documented in `docs/ci.md`.

Before release, CI should run:

- documentation and configuration presence checks;
- line-ending checks for text files;
- `gofmt`/`goimports` formatting checks;
- pinned Prettier formatting and strict TypeScript checks;
- golangci-lint static analysis;
- unit tests;
- race-enabled tests for state-free components where practical;
- fuzz smoke tests with bounded time;
- dependency license checks;
- import graph checks proving root package does not import optional attestation or transport packages;
- example build checks for public integration examples;
- minimum supported Go 1.25 package tests;
- README checks proving usage references point to compile-checked examples.

The workflow now includes documentation/config checks, README checks,
line-ending checks, formatting and TypeScript checks, static analysis, unit
tests, race tests, bounded fuzz smoke tests, example builds, dependency license
checks, import graph checks, minimum-Go tests, module hygiene, and separate
Chromium E2E.
