# Technical design

Status: registration, authentication, Level 3 attestation and extensions, attestation trust hooks, optional adapters, and examples implemented, revised 2026-06-01.

Module: `github.com/islishude/webauthn`.

This document describes the target design for a Go server-side WebAuthn/passkey relying-party library. It is intentionally written before implementation. It is not a code specification; it is the architectural contract that implementation work must follow.

## Source basis

The normative protocol baseline is W3C Web Authentication: An API for accessing Public Key Credentials, Level 3. MDN Web Authentication API documentation is used for browser-facing explanations, secure-context context, and passkey terminology. Implementation behavior must follow the W3C specification when there is any difference in emphasis.

No implementation code from public WebAuthn/passkey libraries may be used or consulted.

## Design objectives

The library must satisfy four primary objectives.

First, it must be framework-neutral. The core library must not depend on `net/http`, routing frameworks, cookie/session packages, or database packages. Applications pass structured inputs to the library and persist returned state themselves.

Second, it must be modular. The root package must not import all attestation formats. Each attestation statement format should be implemented behind a common verifier contract and exposed from its own package. A user who accepts only `none` and `packed` should not import TPM, Android, Apple, or SafetyNet verification dependencies.

Third, it must avoid foundational crypto and codec implementation. WebAuthn-specific parsing is part of this project; general CBOR, COSE, ASN.1, JWS/JWT, X.509 path validation, JSON, base64url, and cryptographic primitives are not. Those must be delegated to the Go standard library, dependencies, or explicitly injected adapters.

Fourth, it must aim at complete WebAuthn Level 3 relying-party support. The stable target includes registration and authentication ceremonies, Level 3 attestation and extension behavior, authenticator data parsing, collected client data validation, signature verification through a crypto adapter, attestation trust policy, and conformance-oriented tests.

## Core architecture

The core library is ceremony-oriented.

Registration is split into two application-visible phases. The first phase builds `PublicKeyCredentialCreationOptions` and returns opaque or structured ceremony state that the application stores temporarily. The second phase accepts the stored ceremony state and the browser credential response, verifies the response, and returns a credential record plus attestation and extension outcomes.

Authentication is split similarly. The first phase builds `PublicKeyCredentialRequestOptions` and returns ceremony state. The second phase accepts stored state, persisted credential material, and the browser assertion response, then returns verification status, user identity information, counter update information, and extension outcomes.

The library should not own the account model. User lookup, session creation, account recovery, credential storage, rate limiting, and audit logging remain application responsibilities.

## Planned package boundaries

Plan 02 fixed the initial package names. The dependency direction must remain stable.

| Area                        | Responsibility                                                                                                                               | Root dependency direction                                                               |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Root package                | Module documentation plus registration and authentication ceremony entry points                                                              | Does not import optional packages or `net/http`                                         |
| `protocol`                  | WebAuthn dictionaries, byte-safe values, collected client data, authenticator data, descriptors, values                                      | No attestation format dependencies                                                      |
| `attestation`               | Format verifier contract, result types, duplicate-rejecting registry, and minimal trust policy contract                                      | Root accepts explicit format verifiers and trust policy                                 |
| Attestation format packages | `none`, `packed`, `tpm`, `android-key`, legacy `android-safetynet`, `fido-u2f`, `apple`, `compound`                                          | WebAuthn attestation formats implemented as optional imports; root does not import them |
| `extension`                 | Operation-aware extension handler contract, Level 2 compatibility handlers, Level 3 handlers, result types, and duplicate-rejecting registry | Root accepts explicit extension handlers or built-in Level 3 handlers                   |
| `crypto`                    | Hash, algorithm policy, signature verification, certificate, and JWS/JWT contracts                                                           | Behind narrow contracts                                                                 |
| `codec`                     | CBOR attestation object, COSE key, and extension map decoding contracts                                                                      | Behind narrow contracts                                                                 |
| `codec/cbor`                | Optional concrete CBOR and COSE_Key decoder                                                                                                  | Not imported by root; replaceable behind `codec.Decoders`                               |
| `browser`                   | Browser JSON DTOs and unpadded base64url request/response conversion                                                                         | Optional package; not imported by the root package                                      |
| `transport/http`            | Standard-library JSON read/write helpers for browser WebAuthn transport                                                                      | Optional package; not imported by the root package                                      |

## Boundary between WebAuthn parsing and general codecs

The project may implement parsing of WebAuthn protocol-specific binary structures:

- authenticator data layout;
- flags and sign counter extraction;
- attested credential data;
- AAGUID and credential ID extraction;
- extension data boundary detection;
- validation of required and optional fields after general-purpose decoding.

The project must not implement general CBOR or COSE decoders. Attestation objects and COSE keys should be decoded through a codec dependency or adapter. The project may define the expected shapes and validate decoded values.

The project must not implement cryptographic algorithms. Hashing, signature verification, X.509 certificate parsing, certificate chain validation, and JWS/JWT verification must be delegated. The project may map WebAuthn policy requirements to those lower-level operations and validate protocol bindings.

## Data model decisions

Protocol byte values are represented internally as bytes, not as transport-specific strings. This applies to challenges, credential IDs, user handles, raw IDs, authenticator data, signatures, attestation objects, and client data JSON.

Browser-facing JSON often uses base64url string encodings for binary fields. That is transport behavior and belongs in optional JSON/browser helper packages or explicit marshal/unmarshal wrappers, not in the core ceremony logic.

Stored credential records should include at minimum:

- credential ID;
- credential public key in an adapter-consumable form;
- user handle or account binding;
- RP ID and origin policy context if needed by the application;
- signature counter;
- transports if returned by the browser;
- AAGUID;
- attestation type and trust result when retained;
- backup/discoverable/passkey-related extension results when available.

## Ceremony verification shape

Registration verification must include these categories:

1. client response shape validation;
2. `clientDataJSON` decoding and collected client data validation;
3. expected challenge comparison;
4. expected origin and cross-origin policy checks;
5. `topOrigin` policy and reserved `tokenBinding` handling;
6. attestation object CBOR decoding through a codec adapter;
7. authenticator data parsing and RP ID hash check;
8. user presence and user verification policy checks;
9. credential public key algorithm acceptance check;
10. extension output policy;
11. attestation format dispatch and cryptographic validity;
12. attestation trust policy;
13. credential uniqueness result surfaced to the caller;
14. credential record construction.

Authentication verification must include these categories:

1. credential ID allow-list and account binding checks;
2. user handle handling for username-first and discoverable-credential flows;
3. `clientDataJSON` decoding and collected client data validation;
4. expected challenge comparison;
5. expected origin and cross-origin policy checks;
6. authenticator data parsing and RP ID hash check, including AppID extension behavior;
7. user presence and user verification policy checks;
8. extension output policy;
9. signature verification over authenticator data plus SHA-256 of client data;
10. signature counter comparison and clone-risk result;
11. result construction for application persistence.

## Policy model

Protocol validity and relying-party policy are different. The implementation should preserve that distinction.

Examples:

- an attestation statement can be cryptographically valid but not trusted by RP policy;
- a signature counter mismatch can signal clone risk without forcing a single library-wide failure behavior;
- unsolicited extensions can be ignored or rejected depending on application policy;
- `none` attestation can be acceptable for consumer passkeys but unacceptable for hardware-bound enterprise enrollment;
- user verification can be `required`, `preferred`, or `discouraged` at option creation time and must be evaluated at verification time.

The API should return structured outcomes rather than reducing all policy-sensitive results to a boolean.

## Error model

Errors must be typed, stable, and suitable for application logging without leaking sensitive details to end users. Internal errors should distinguish:

- malformed input;
- unsupported algorithm or format;
- challenge mismatch;
- origin/RP ID mismatch;
- user presence or user verification failure;
- signature verification failure;
- attestation invalidity;
- attestation untrusted by policy;
- credential ownership mismatch;
- sign counter clone risk;
- extension policy failure;
- dependency/adapter failure.

Public error text should avoid embedding raw credential IDs, user handles, challenges, or assertion contents.

## Dependency strategy

Dependencies must be minimal and compartmentalized. The root package should not expose concrete dependency types from optional codec or crypto libraries unless unavoidable. Format packages may depend on specialized libraries where required, but those dependencies must not leak into unrelated formats.

The implementation should prefer standard library support for SHA-256, X.509 parsing, ASN.1 parsing, ECDSA/RSA verification, and base64url handling where it is sufficient. CBOR, COSE, and JWS/JWT require explicit dependency decisions before implementation.

Plan 03 adds `github.com/fxamacker/cbor/v2 v2.9.2` and `github.com/ldclabs/cose v1.3.4` only for the optional `codec/cbor` package. They support attestation object, authenticator extension map, and COSE_Key decoding. The root registration and authentication APIs still accept narrow codec/crypto interfaces, so replacing these dependencies does not change root API compatibility.

Plan 05's initial `attestation/packed` slice adds no dependency. It uses Go standard library X.509 parsing for packed attestation certificate shape checks and delegates attestation signature verification through `crypto.SignatureVerifier`. X.509 trust-chain acceptance remains caller policy through `attestation.TrustPolicy`.

Plan 05's initial `attestation/fidou2f` slice also adds no dependency. It uses `codec.CredentialPublicKey.U2FPublicKey` to obtain the U2F raw public key form from the selected codec, uses Go standard library X.509 parsing for the single attestation certificate, and delegates ES256 signature verification through `crypto.SignatureVerifier`.

Plan 05's initial `attestation/tpm` slice adds no dependency. It uses `codec.CredentialPublicKey.PublicKeyMaterial` to bind TPM public-area EC2 or RSA material to the credential public key, parses only the WebAuthn-required TPM public-area, certInfo, certify-info, and signature structures, uses Go standard library ASN.1/X.509 parsing for AIK certificate requirements, and delegates attestation signature verification through `crypto.SignatureVerifier`. Trust-chain acceptance remains caller policy through `attestation.TrustPolicy`.

Plan 05's initial `attestation/androidkey` slice adds no dependency. It uses `codec.CredentialPublicKey.PublicKeyMaterial` to bind the Android Key certificate public key to the credential public key, parses only the WebAuthn-required Android Key attestation extension fields with Go standard library ASN.1/X.509 support, and delegates attestation signature verification through `crypto.SignatureVerifier`. Trust-chain acceptance remains caller policy through `attestation.TrustPolicy`.

Plan 05's initial `attestation/androidsafetynet` slice adds no dependency. It uses `crypto.JWSVerifier` to delegate SafetyNet compact JWS verification and certificate-chain handling, validates the WebAuthn nonce binding and `ctsProfileMatch` payload result, checks the leaf certificate hostname for `attest.android.com`, and leaves trust-chain acceptance as caller policy through `attestation.TrustPolicy`.

Plan 05's `attestation/apple` slice adds no dependency. It uses Go standard library ASN.1/X.509 parsing to validate the Apple anonymous attestation nonce extension, uses `codec.CredentialPublicKey.PublicKeyMaterial` to bind the credential certificate public key to the credential public key, and leaves trust-chain acceptance as caller policy through `attestation.TrustPolicy`.

Plan 06 adds no dependency. It implements WebAuthn Level 2 extension handlers in `extension`, keeps browser JSON conversion out of the core API, and treats unknown or unrequested extension output as untrusted policy evidence unless a registered handler validates it.

Plan 09 adds no dependency. It implements optional `browser` DTO conversion helpers, optional `transport/http` JSON helpers, and compile-checked examples. Browser and HTTP helpers remain outside the root dependency graph, and HTTP helpers do not manage routing, sessions, cookies, CSRF, persistence, account lookup, or trust policy.

Plans 10 through 14 add no dependency. They move the normative baseline to
WebAuthn Level 3, replace legacy origin fields with `OriginPolicy`, parse and
policy-check `topOrigin`, treat `tokenBinding` as reserved client data, add
Level 3 hints and attestation format fields, add PRF extension handling in
`extension/level3.go`, retain `uvm` as deprecated opt-in support, add optional
`attestation/compound`, and extend codec key material to OKP.

## Compatibility and passkey behavior

The library should support both username-first and discoverable-credential authentication flows. Passkey-oriented behavior requires correct user handle processing, resident/discoverable credential options, user verification policy, authenticator attachment preferences, and extension results such as credential properties where supported.

The library should not assume that every passkey is hardware-bound, non-exportable, or counter-incrementing. Counter and backup-related signals should be surfaced as risk and metadata, not overinterpreted.

## Initial implementation order

Implementation should follow `docs/plans.md`. The required order is:

1. governance and boundaries;
2. local and GitHub Actions quality gates;
3. core protocol model and adapter contracts (complete, 2026-05-31);
4. registration ceremony with `none` attestation (complete, 2026-05-31);
5. authentication ceremony (complete, 2026-05-31);
6. modular attestation formats (complete, 2026-05-31);
7. extensions (complete, 2026-06-01);
8. trust and metadata policy (complete, 2026-06-01);
9. conformance tests (complete, 2026-06-01);
10. optional adapters, examples, and release hardening (complete, 2026-06-01);
11. WebAuthn Level 3 baseline (complete, 2026-06-01);
12. Level 3 ceremonies and JSON (complete, 2026-06-01);
13. Level 3 extensions (complete, 2026-06-01);
14. Level 3 attestation and algorithms (complete, 2026-06-01);
15. Level 3 conformance and release alignment (complete, 2026-06-01).

The local quality gate is `make ci`. It validates documentation and configuration immediately, then enforces README checks, Go formatting, linting, tests, race checks, fuzz smoke checks, example builds, import graph checks, dependency license checks, and module hygiene after `go.mod` exists. GitHub Actions mirrors this split so implementation work remains gated by local and CI behavior.
