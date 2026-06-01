# Protocol map

Status: WebAuthn Level 3 protocol, attestation, extension, adapter, and example
slices implemented, revised 2026-06-01.

This file maps WebAuthn Level 3 relying-party protocol surfaces to library
components. It is a completeness checklist, not implementation code.

## Normative baseline

Primary normative source: W3C Web Authentication Level 3.

Browser-context source: MDN Web Authentication API.

The implementation must prefer W3C text for conformance decisions. MDN is useful
for explaining how browsers expose WebAuthn, passkeys, and secure-context
behavior.

## Public key credential options

| Protocol surface                     | Component                                         | Notes                                                                                                                                                                  |
| ------------------------------------ | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PublicKeyCredentialCreationOptions` | Protocol model and registration options builder   | Required RP, user, challenge, and credential parameters; supports timeout, exclude list, authenticator selection, hints, attestation, attestation formats, extensions. |
| `PublicKeyCredentialRequestOptions`  | Protocol model and authentication options builder | Required challenge; supports timeout, RP ID, allow credentials, user verification, hints, and extensions.                                                              |
| `PublicKeyCredentialRpEntity`        | Protocol model                                    | Enforce RP ID and display-name validation separately from HTTP origin discovery.                                                                                       |
| `PublicKeyCredentialUserEntity`      | Protocol model                                    | Preserve user handle as bytes; avoid assuming usernames are stable identifiers.                                                                                        |
| `PublicKeyCredentialDescriptor`      | Protocol model                                    | Store and replay transport hints including `hybrid` and `smart-card`; unknown transports must not break parsing before validation boundaries.                          |
| `PublicKeyCredentialHint`            | Protocol model and browser DTOs                   | Preserve `security-key`, `client-device`, and `hybrid` hints as UI hints, not security facts.                                                                          |
| COSE algorithm identifiers           | Crypto adapter policy                             | Expose Level 3 algorithm constants and recommended parameter helper; do not implement COSE or cryptographic primitives in root.                                        |

## Client data

| Protocol surface                   | Component             | Required behavior                                                                    |
| ---------------------------------- | --------------------- | ------------------------------------------------------------------------------------ |
| `CollectedClientData.type`         | Ceremony verification | Must match `webauthn.create` for registration and `webauthn.get` for authentication. |
| `CollectedClientData.challenge`    | Ceremony verification | Must equal the base64url encoding of the server-generated challenge.                 |
| `CollectedClientData.origin`       | Origin policy         | Must match configured allowed origins. No HTTP request inference in core.            |
| `CollectedClientData.crossOrigin`  | Origin policy         | Must be accepted or rejected by explicit RP policy.                                  |
| `CollectedClientData.topOrigin`    | Origin policy         | If present, requires `crossOrigin` and must match configured allowed top origins.    |
| `CollectedClientData.tokenBinding` | Reserved client data  | Parsed for preservation but ignored for relying-party verification in Level 3.       |
| Unknown client data keys           | Client data parser    | Must be tolerated. Future extension fields must not break parsing.                   |

## Authenticator data

| Field                    | Component                                  | Required behavior                                                                                 |
| ------------------------ | ------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| `rpIdHash`               | Authenticator data parser and verifier     | Must equal SHA-256 of expected RP ID, or AppID hash when AppID request, policy, and output agree. |
| Flags                    | Authenticator data parser                  | Expose UP, UV, AT, ED, backup eligibility, and backup state.                                      |
| `signCount`              | Counter policy                             | Returned with comparison result and clone-risk semantics.                                         |
| Attested credential data | Registration parser                        | Required when AT flag is set in registration attestation data.                                    |
| AAGUID                   | Registration result and attestation policy | Needed for trust policy and metadata lookup.                                                      |
| Credential ID            | Registration result                        | Must be uniqueness-checked by the application or caller-provided result.                          |
| Credential public key    | Codec and crypto adapter input             | Decode through CBOR/COSE adapter; support EC2, RSA, and OKP material where the codec exposes it.  |
| Extensions               | Extension framework                        | Decode through CBOR adapter and route by extension identifier.                                    |

## Registration relying-party operation

The registration verifier covers these WebAuthn Level 3 operation groups:

1. response type and shape validation;
2. collected client data decoding;
3. type, challenge, origin, `topOrigin`, reserved `tokenBinding`, and cross-origin verification;
4. client data hash calculation;
5. attestation object decoding, including `compound` statement normalization;
6. RP ID hash, user presence, user verification, and credential algorithm checks;
7. extension result validation;
8. attestation statement format dispatch;
9. attestation trust policy;
10. credential uniqueness and persistence result construction.

The library does not create accounts, persist credentials, or decide whether an
already-registered credential belongs to another user.

## Authentication relying-party operation

The authentication verifier covers these WebAuthn Level 3 operation groups:

1. response type and shape validation;
2. allow-credentials matching when an allow list was used;
3. account and user-handle ownership checks through caller-provided state;
4. collected client data decoding;
5. type, challenge, origin, `topOrigin`, reserved `tokenBinding`, and cross-origin verification;
6. RP ID hash verification, including AppID extension behavior;
7. user presence and user verification checks;
8. extension result validation, including PRF `evalByCredential` allow-list binding;
9. signature verification over authenticator data plus SHA-256 of client data;
10. signature counter comparison and clone-risk result construction.

The library supports username-first and discoverable-credential flows. In
discoverable flows, `userHandle` is required to identify the user account
associated with the credential.

## Attestation statement formats

| Format identifier   | Package                        | Modular dependency notes                                                            | Status   |
| ------------------- | ------------------------------ | ----------------------------------------------------------------------------------- | -------- |
| `none`              | `attestation/none`             | No crypto dependency beyond structural checks                                       | Complete |
| `packed`            | `attestation/packed`           | Signature verification through adapter; X.509 parsing uses Go standard library      | Complete |
| `tpm`               | `attestation/tpm`              | Narrow TPM structure parsing and X.509 requirement checks using Go standard library | Complete |
| `android-key`       | `attestation/androidkey`       | Android Key extension parsing with Go standard library ASN.1/X.509 support          | Complete |
| `android-safetynet` | `attestation/androidsafetynet` | SafetyNet compact JWS verification delegated to `crypto.JWSVerifier`; legacy format | Complete |
| `fido-u2f`          | `attestation/fidou2f`          | U2F signature construction and certificate verification through adapters            | Complete |
| `apple`             | `attestation/apple`            | Apple anonymous attestation certificate checks through Go standard library X.509    | Complete |
| `compound`          | `attestation/compound`         | Dispatches normalized sub-statements through caller-selected verifiers              | Complete |

The root package must not import these packages automatically. Trust acceptance
remains caller policy after format verification succeeds.

## Extensions

| Extension identifier | Applicability                   | Behavior                                                                                              | Status                |
| -------------------- | ------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------- |
| `appid`              | Authentication                  | Allows RP ID hash verification against AppID when request, policy, and client output agree.           | Complete              |
| `appidExclude`       | Registration                    | Represents input and validates policy; most exclusion behavior remains client-side.                   | Complete              |
| `credProps`          | Registration                    | Surfaces discoverable/resident credential property output for passkey flows.                          | Complete              |
| `largeBlob`          | Registration and authentication | Represents inputs/outputs and leaves application data storage policy to caller.                       | Complete              |
| `prf`                | Registration and authentication | Validates PRF input/output, output lengths, and authentication `evalByCredential` allow-list binding. | Complete              |
| `uvm`                | Registration and authentication | Deprecated in Level 3; retained as opt-in support and marked `Deprecated` in extension results.       | Deprecated, supported |

`extension.NewLevel3Registry` excludes `uvm` by default.
`extension.NewLevel3RegistryWithDeprecated` includes it for callers that still
need to parse existing outputs.

## Security and privacy policy surfaces

| Area                     | Implementation hook                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------ |
| Cryptographic challenges | Server-side challenge generator and exact challenge validation.                      |
| Username enumeration     | Error shaping and option behavior do not force account existence leaks.              |
| Attestation privacy      | Defaults do not require identifying attestation unless RP policy opts in.            |
| Credential ID privacy    | Discoverable credentials and account-agnostic starts are allowed where configured.   |
| Signature counters       | Clone-risk signals are surfaced for caller policy.                                   |
| Origin and RP ID scoping | Explicit origin, top-origin, and RP ID policy; no implicit trust in request headers. |
| Transport hints          | Hints are preserved as UI hints, not security proof.                                 |

## Out-of-scope for the core package

The following remain outside root core behavior. Browser JSON and small HTTP
JSON helpers are available as optional packages, while application ownership
stays explicit:

- HTTP request parsing and response writing beyond optional `transport/http`
  JSON helpers;
- session persistence;
- database storage;
- account lookup;
- account recovery flows;
- browser JavaScript helpers beyond documented JSON DTO shapes;
- authenticator implementation;
- CTAP device communication;
- public WebAuthn library compatibility shims.
