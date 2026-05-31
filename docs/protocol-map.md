# Protocol map

Status: initial packed, TPM, Android Key, and FIDO U2F attestation slices implemented, revised 2026-05-31.

This file maps WebAuthn Level 2 relying-party protocol surfaces to planned library components. It is a completeness checklist, not implementation code.

## Normative baseline

Primary normative source: W3C Web Authentication Level 2.

Browser-context source: MDN Web Authentication API.

The implementation must prefer W3C text for conformance decisions. MDN is useful for explaining how browsers expose WebAuthn, passkeys, and secure-context behavior.

## Public key credential options

| Protocol surface                     | Planned component                                 | Notes                                                                                                                                                                               |
| ------------------------------------ | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PublicKeyCredentialCreationOptions` | Protocol model and registration options builder   | Required fields: RP, user, challenge, public key credential parameters. Optional fields: timeout, exclude credentials, authenticator selection, attestation conveyance, extensions. |
| `PublicKeyCredentialRequestOptions`  | Protocol model and authentication options builder | Required field: challenge. Optional fields: timeout, RP ID, allow credentials, user verification, extensions.                                                                       |
| `PublicKeyCredentialRpEntity`        | Protocol model                                    | Enforce RP ID and display-name validation separately from HTTP origin discovery.                                                                                                    |
| `PublicKeyCredentialUserEntity`      | Protocol model                                    | Preserve user handle as bytes; avoid assuming usernames are stable identifiers.                                                                                                     |
| `PublicKeyCredentialDescriptor`      | Protocol model                                    | Store and replay transport hints when available. Unknown transports must not break parsing.                                                                                         |
| `AuthenticatorSelectionCriteria`     | Protocol model and policy                         | Support authenticator attachment, resident key, require resident key compatibility handling, and user verification.                                                                 |
| COSE algorithm identifiers           | Crypto adapter policy                             | Accept configured algorithms; do not implement COSE from scratch.                                                                                                                   |

## Client data

| Protocol surface                   | Planned component     | Required behavior                                                                    |
| ---------------------------------- | --------------------- | ------------------------------------------------------------------------------------ |
| `CollectedClientData.type`         | Ceremony verification | Must match `webauthn.create` for registration and `webauthn.get` for authentication. |
| `CollectedClientData.challenge`    | Ceremony verification | Must equal the base64url encoding of the server-generated challenge.                 |
| `CollectedClientData.origin`       | Origin policy         | Must match configured allowed origins. No HTTP request inference in core.            |
| `CollectedClientData.crossOrigin`  | Origin policy         | Must be accepted or rejected by explicit RP policy.                                  |
| `CollectedClientData.tokenBinding` | Token binding policy  | Must tolerate absence; validate status and ID when configured and present.           |
| Unknown client data keys           | Client data parser    | Must be tolerated. Future extension fields must not break parsing.                   |

## Authenticator data

| Field                    | Planned component                          | Required behavior                                                                                                      |
| ------------------------ | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `rpIdHash`               | Authenticator data parser and verifier     | Must equal SHA-256 of expected RP ID, or AppID hash when the AppID extension is valid and used.                        |
| Flags                    | Authenticator data parser                  | Must expose UP, UV, AT, ED, backup-related bits if later supported, and RFU validation according to target spec level. |
| `signCount`              | Counter policy                             | Must be returned with comparison result and clone-risk semantics.                                                      |
| Attested credential data | Registration parser                        | Required when AT flag is set in registration attestation data.                                                         |
| AAGUID                   | Registration result and attestation policy | Needed for trust policy and metadata lookup.                                                                           |
| Credential ID            | Registration result                        | Must be uniqueness-checked by the application or a caller-provided hook.                                               |
| Credential public key    | Crypto adapter input                       | Decode through CBOR/COSE adapter; validate configured algorithm.                                                       |
| Extensions               | Extension framework                        | Decode through CBOR adapter and route by extension identifier.                                                         |

## Registration relying-party operation

The registration verifier must cover the W3C Level 2 relying-party steps in these groups:

1. response type and shape validation;
2. collected client data decoding;
3. type, challenge, origin, token binding, and cross-origin verification;
4. client data hash calculation;
5. attestation object decoding;
6. RP ID hash, user presence, user verification, and credential algorithm checks;
7. extension result validation;
8. attestation statement format dispatch;
9. attestation trust policy;
10. credential uniqueness and persistence result construction.

The library should not directly create an account, persist a credential, or decide whether an already-registered credential belongs to another user. It should return enough structured data for the application to make and record that decision.

## Authentication relying-party operation

The authentication verifier must cover the W3C Level 2 relying-party steps in these groups:

1. response type and shape validation;
2. allow-credentials matching when an allow list was used;
3. account and user-handle ownership checks through caller-provided state;
4. collected client data decoding;
5. type, challenge, origin, token binding, and cross-origin verification;
6. RP ID hash verification, including AppID extension behavior;
7. user presence and user verification checks;
8. extension result validation;
9. signature verification over authenticator data plus SHA-256 of client data;
10. signature counter comparison and clone-risk result construction.

The library must support both username-first and discoverable-credential flows. In discoverable flows, `userHandle` is required to identify the user account associated with the credential.

## Attestation statement formats

The stable completeness target includes all WebAuthn Level 2 defined attestation statement formats.

| Format identifier   | Planned package                | Modular dependency notes                                                            | Stable target  |
| ------------------- | ------------------------------ | ----------------------------------------------------------------------------------- | -------------- |
| `none`              | `attestation/none`             | No crypto dependency beyond structural checks                                       | P0 complete    |
| `packed`            | `attestation/packed`           | Signature verification through adapter; X.509 parsing uses Go standard library      | P1 in progress |
| `tpm`               | `attestation/tpm`              | Narrow TPM structure parsing and X.509 requirement checks using Go standard library | P1 in progress |
| `android-key`       | `attestation/androidkey`       | Android Key extension parsing with Go standard library ASN.1/X.509 support          | P1 in progress |
| `android-safetynet` | `attestation/androidsafetynet` | SafetyNet compact JWS verification delegated to `crypto.JWSVerifier`                | P1 in progress |
| `fido-u2f`          | `attestation/fidou2f`          | U2F signature construction and certificate verification through adapters            | P1 in progress |
| `apple`             | `attestation/apple`            | Apple anonymous attestation certificate checks through package-specific verifier    | P1             |

The root package must not import these packages automatically. A separate optional aggregate may be added only after individual packages are stable.

## Extensions

The stable completeness target includes WebAuthn Level 2 defined extensions.

| Extension identifier | Applicability                   | Planned behavior                                                                                                    |
| -------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `appid`              | Authentication                  | Support U2F migration by allowing RP ID hash verification against AppID when client output says AppID was used.     |
| `appidExclude`       | Registration                    | Represent input and validate policy; most behavior is client-side, but options and result policy must be supported. |
| `uvm`                | Registration and authentication | Parse and surface user verification method output where present.                                                    |
| `credProps`          | Registration                    | Surface discoverable/resident credential property output, useful for passkey flows.                                 |
| `largeBlob`          | Registration and authentication | Represent inputs/outputs and define policy boundaries. Server-side storage behavior remains application-specific.   |

The extension system must tolerate absent results and unknown extension keys. Unknown or unsolicited extensions should be ignored or rejected according to explicit policy, not accidentally accepted as trusted signals.

## Security and privacy sections to implement as policy

| Area                     | Planned implementation hook                                                                           |
| ------------------------ | ----------------------------------------------------------------------------------------------------- |
| Cryptographic challenges | Server-side challenge generator and exact challenge validation.                                       |
| Username enumeration     | Error shaping and registration/authentication option behavior must not force account existence leaks. |
| Attestation privacy      | Defaults should not require identifying attestation unless RP policy opts in.                         |
| Credential ID privacy    | Allow discoverable credentials and account-agnostic authentication starts where configured.           |
| Signature counters       | Surface clone-risk signals and let RP policy decide fail, warn, or continue.                          |
| Origin and RP ID scoping | Explicit origin and RP ID policy; no implicit trust in request headers.                               |
| Transport hints          | Preserve hints but treat them as hints, not security proof.                                           |

## Out-of-scope for the core package

The following may be examples or optional adapters later, but not core behavior:

- HTTP request parsing and response writing;
- session persistence;
- database storage;
- account lookup;
- account recovery flows;
- browser JavaScript helpers beyond documented JSON shapes;
- authenticator implementation;
- CTAP device communication;
- public WebAuthn library compatibility shims.
