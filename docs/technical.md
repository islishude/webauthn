# Technical design

Status: initial design, created 2026-05-29.

Module: `github.com/islishude/webauthn`.

This document describes the target design for a Go server-side WebAuthn/passkey relying-party library. It is intentionally written before implementation. It is not a code specification; it is the architectural contract that implementation work must follow.

## Source basis

The normative protocol baseline is W3C Web Authentication: An API for accessing Public Key Credentials, Level 2. MDN Web Authentication API documentation is used for browser-facing explanations, secure-context context, and passkey terminology. Implementation behavior must follow the W3C specification when there is any difference in emphasis.

No implementation code from public WebAuthn/passkey libraries may be used or consulted.

## Design objectives

The library must satisfy four primary objectives.

First, it must be framework-neutral. The core library must not depend on `net/http`, routing frameworks, cookie/session packages, or database packages. Applications pass structured inputs to the library and persist returned state themselves.

Second, it must be modular. The root package must not import all attestation formats. Each attestation statement format should be implemented behind a common verifier contract and exposed from its own package. A user who accepts only `none` and `packed` should not import TPM, Android, Apple, or SafetyNet verification dependencies.

Third, it must avoid foundational crypto and codec implementation. WebAuthn-specific parsing is part of this project; general CBOR, COSE, ASN.1, JWS/JWT, X.509 path validation, JSON, base64url, and cryptographic primitives are not. Those must be delegated to the Go standard library, dependencies, or explicitly injected adapters.

Fourth, it must aim at complete WebAuthn Level 2 relying-party support. The stable target includes registration and authentication ceremonies, all Level 2 attestation statement formats, Level 2 extensions, authenticator data parsing, collected client data validation, signature verification through a crypto adapter, attestation trust policy, and conformance-oriented tests.

## Core architecture

The core library is ceremony-oriented.

Registration is split into two application-visible phases. The first phase builds `PublicKeyCredentialCreationOptions` and returns opaque or structured ceremony state that the application stores temporarily. The second phase accepts the stored ceremony state and the browser credential response, verifies the response, and returns a credential record plus attestation and extension outcomes.

Authentication is split similarly. The first phase builds `PublicKeyCredentialRequestOptions` and returns ceremony state. The second phase accepts stored state, persisted credential material, and the browser assertion response, then returns verification status, user identity information, counter update information, and extension outcomes.

The library should not own the account model. User lookup, session creation, account recovery, credential storage, rate limiting, and audit logging remain application responsibilities.

## Planned package boundaries

The exact names may change before implementation, but the dependency direction must remain stable.

| Area                        | Responsibility                                                                                            | Root dependency direction                                             |
| --------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Root package                | Configuration, ceremonies, policy composition, result types, registries                                   | May depend on protocol primitives and narrow interfaces only          |
| Protocol model              | WebAuthn dictionaries, authenticator data, collected client data, credential descriptors, flags, counters | No attestation format dependencies                                    |
| Attestation registry        | Format lookup and dispatch by `fmt`                                                                       | Root accepts explicit format verifiers                                |
| Attestation format packages | `none`, `packed`, `tpm`, `android-key`, `android-safetynet`, `fido-u2f`, `apple`                          | Optional imports only                                                 |
| Extension registry          | Extension validation and output interpretation                                                            | Root accepts explicit extension handlers or built-in Level 2 handlers |
| Crypto adapter              | COSE algorithm handling, signature verification, hash binding, certificate path checks                    | Behind narrow contracts                                               |
| Codec adapter               | CBOR and JSON bridge behavior that is not covered by standard library                                     | Behind narrow contracts                                               |
| Optional transport helpers  | Browser JSON DTOs, request/response binding, optional HTTP helpers                                        | Must not be imported by the root package                              |

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
5. token binding handling where present;
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

## Compatibility and passkey behavior

The library should support both username-first and discoverable-credential authentication flows. Passkey-oriented behavior requires correct user handle processing, resident/discoverable credential options, user verification policy, authenticator attachment preferences, and extension results such as credential properties where supported.

The library should not assume that every passkey is hardware-bound, non-exportable, or counter-incrementing. Counter and backup-related signals should be surfaced as risk and metadata, not overinterpreted.

## Initial implementation order

Implementation should follow `docs/plans.md`. The required order is:

1. governance and boundaries;
2. core protocol model and adapter contracts;
3. registration ceremony with `none` attestation;
4. authentication ceremony;
5. modular attestation formats;
6. extensions;
7. trust and metadata policy;
8. conformance tests;
9. optional adapters, examples, and release hardening.
