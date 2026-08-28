# Protocol map

Status: WebAuthn Level 3 protocol, attestation, extension, adapter, and example
slices implemented, revised 2026-08-28.

This file maps WebAuthn Level 3 relying-party protocol surfaces to library
components. It is a completeness checklist, not implementation code.

## Normative baseline

Stable normative source: [W3C Web Authentication Level 3 Recommendation](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/),
25 August 2026. W3C records no substantive change from the 26 May 2026
Candidate Recommendation.

Preview source: the 30 July 2026 Editor's Draft. Preview-only behavior is
explicitly opt-in and is not included in default Level 3 registries.

Browser-context source: MDN Web Authentication API.

The implementation must prefer W3C text for conformance decisions. MDN is useful
for explaining how browsers expose WebAuthn, passkeys, and secure-context
behavior.

## Public key credential options

| Protocol surface                     | Component                                         | Notes                                                                                                                                                                  |
| ------------------------------------ | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PublicKeyCredentialCreationOptions` | Protocol model and registration options builder   | Required RP, user, challenge, and credential parameters; supports timeout, exclude list, authenticator selection, hints, attestation, attestation formats, extensions. |
| `PublicKeyCredentialRequestOptions`  | Protocol model and authentication options builder | Required challenge; supports timeout, RP ID, allow credentials, user verification, hints, and extensions.                                                              |
| Conditional creation mediation       | Registration state and verifier                   | Caller sets the outer browser mediation option; stored conditional state is the only case in which registration does not require UP.                                   |
| `PublicKeyCredentialRpEntity`        | Protocol model                                    | Enforce RP ID and display-name validation separately from HTTP origin discovery.                                                                                       |
| `PublicKeyCredentialUserEntity`      | Protocol model                                    | Preserve user handle as bytes; allow the required `displayName` member to contain the specified empty-string value.                                                    |
| `PublicKeyCredentialDescriptor`      | Protocol model                                    | Store and replay transport hints including `hybrid` and `smart-card`; unknown transports must not break parsing before validation boundaries.                          |
| `PublicKeyCredentialHint`            | Protocol model and browser DTOs                   | Preserve `security-key`, `client-device`, and `hybrid` hints as UI hints, not security facts.                                                                          |
| COSE algorithm identifiers           | Crypto adapter policy                             | Enforce Web IDL `long`, expose Ed448 `-53`, and route unsupported cryptography through caller adapters.                                                                |

## Client data

| Protocol surface                   | Component             | Required behavior                                                                                                                             |
| ---------------------------------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `CollectedClientData.type`         | Ceremony verification | Must match `webauthn.create` for registration and `webauthn.get` for authentication.                                                          |
| `CollectedClientData.challenge`    | Ceremony verification | Must exactly equal the canonical unpadded base64url encoding of the server-generated challenge; equivalent alternate spellings are malformed. |
| `CollectedClientData.origin`       | Origin policy         | Must match configured allowed origins. No HTTP request inference in core.                                                                     |
| `CollectedClientData.crossOrigin`  | Origin policy         | Must be accepted or rejected by explicit RP policy.                                                                                           |
| `CollectedClientData.topOrigin`    | Origin policy         | Presence is tracked separately; if present it must be a non-empty string, require `crossOrigin`, and match configured top origins.            |
| `CollectedClientData.tokenBinding` | Reserved client data  | Parsed for preservation but ignored for relying-party verification in Level 3.                                                                |
| Unknown client data keys           | Client data parser    | Must be tolerated. Future extension fields must not break parsing.                                                                            |

## Authenticator data

| Field                    | Component                                  | Required behavior                                                                                 |
| ------------------------ | ------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| `rpIdHash`               | Authenticator data parser and verifier     | Must equal SHA-256 of expected RP ID, or AppID hash when AppID request, policy, and output agree. |
| Flags                    | Authenticator data parser                  | Expose UP/UV/AT/ED, reject RFU bits and BS without BE, and keep backup eligibility immutable.     |
| `signCount`              | Counter policy                             | Return comparison and clone risk; preserve stored value unless explicit policy updates it.        |
| Attested credential data | Registration parser                        | Required when AT flag is set in registration attestation data.                                    |
| AAGUID                   | Registration result and attestation policy | Needed for trust policy and metadata lookup.                                                      |
| Credential ID            | Registration result                        | Must be inserted under an application-owned atomic uniqueness constraint.                         |
| Credential public key    | Codec and crypto adapter input             | Require CTAP2 canonical COSE with only required parameters; persist typed EC2/RSA/OKP material.   |
| Extensions               | Extension framework                        | Decode through CBOR adapter and route by extension identifier.                                    |

## Registration relying-party operation

The registration verifier covers these WebAuthn Level 3 operation groups:

1. response type and shape validation;
2. collected client data decoding;
3. type, challenge, origin, `topOrigin`, reserved `tokenBinding`, and cross-origin verification;
4. client data hash calculation;
5. attestation object decoding, including `compound` statement normalization;
6. RP ID hash, mediation-aware user presence, user verification, and credential algorithm checks;
7. attestation statement format dispatch and trust policy;
8. extension result validation after attestation acceptance;
9. BE/BS and UV initialization capture;
10. credential result construction for caller-owned atomic insertion.

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
8. signature verification over authenticator data plus SHA-256 of client data;
9. extension result validation after signature success, including PRF binding
   to the credential that produced the assertion;
10. backup eligibility, UV initialization, and clone-risk update policy.

The library supports username-first and discoverable-credential flows. In
discoverable flows, `userHandle` is required to identify the user account
associated with the credential.

## Attestation statement formats

| Format identifier   | Package                        | Modular dependency notes                                                                  | Status   |
| ------------------- | ------------------------------ | ----------------------------------------------------------------------------------------- | -------- |
| `none`              | `attestation/none`             | No crypto dependency beyond structural checks                                             | Complete |
| `packed`            | `attestation/packed`           | Exact subject encodings, AAGUID/firmware fields, and enterprise-only serial policy        | Complete |
| `tpm`               | `attestation/tpm`              | TPM bindings, strict `TPMT_SIGNATURE`, and critical SAN manufacturer/model/version checks | Complete |
| `android-key`       | `attestation/androidkey`       | Union default plus explicit hardware/TEE-only authorization-list policy                   | Complete |
| `android-safetynet` | `attestation/androidsafetynet` | SafetyNet compact JWS verification delegated to `crypto.JWSVerifier`; legacy format       | Complete |
| `fido-u2f`          | `attestation/fidou2f`          | U2F signature construction and certificate verification through adapters                  | Complete |
| `apple`             | `attestation/apple`            | DER sequence/explicit nonce and credential-certificate public-key binding                 | Complete |
| `compound`          | `attestation/compound`         | Dispatches normalized sub-statements through caller-selected verifiers                    | Complete |

The root package must not import these packages automatically. Trust acceptance
remains caller policy after format verification succeeds.

## Extensions

| Extension identifier   | Applicability                   | Behavior                                                                                                               | Status                |
| ---------------------- | ------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | --------------------- |
| `appid`                | Authentication                  | Allows RP ID hash verification against AppID when request, policy, and client output agree.                            | Complete              |
| `appidExclude`         | Registration                    | Represents input and validates policy; most exclusion behavior remains client-side.                                    | Complete              |
| `credProps`            | Registration                    | Surfaces discoverable/resident credential property output for passkey flows.                                           | Complete              |
| `largeBlob`            | Registration and authentication | Represents inputs/outputs and leaves application data storage policy to caller.                                        | Complete              |
| `prf`                  | Registration and authentication | Validates PRF input/output and binds `evalByCredential` results to the selected credential, not merely the allow list. | Complete              |
| `remoteClientDataJSON` | Registration and authentication | Editor's Draft client-only extension; validates ceremony/challenge and exact serialized client-data binding.           | Preview, opt-in       |
| `uvm`                  | Registration and authentication | Deprecated in Level 3; retained as opt-in support and marked `Deprecated` in extension results.                        | Deprecated, supported |

`extension.NewLevel3Registry` excludes `uvm` by default.
`extension.NewLevel3RegistryWithDeprecated` includes it for callers that still
need to parse existing outputs.

`extension.RemoteClientDataJSONHandler` is not included in either default
registry. A caller opting into it must also configure the remote origin in
`OriginPolicy`; no origin inference or wildcard is introduced.

## Recommendation test-vector accounting

The local manifest accounts for all 45 section 16 cases: 30 registration and
authentication cases, 12 PRF Web Authentication API output cases, and 3
test-only CTAP2 `hmac-secret` calculations. CTAP calculation tests do not add a
client, authenticator, or device communication surface. The non-normative TPM
registration vector's DER signature is retained as an expected rejection; a
test-only `TPMT_SIGNATURE` wrapper proves the normative path without broadening
production acceptance.

## Security and privacy policy surfaces

| Area                      | Implementation hook                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------ |
| Cryptographic challenges  | Server-side challenge generator and exact challenge validation.                      |
| Username enumeration      | Error shaping and option behavior do not force account existence leaks.              |
| Attestation privacy       | Defaults do not require identifying attestation unless RP policy opts in.            |
| Credential ID privacy     | Discoverable credentials and account-agnostic starts are allowed where configured.   |
| Signature counters        | Clone-risk signals are surfaced for caller policy.                                   |
| Server-side serialization | Optional versioned storage JSON with bounded, strict decoding.                       |
| Origin and RP ID scoping  | Explicit origin, top-origin, and RP ID policy; no implicit trust in request headers. |
| Transport hints           | Hints are preserved as UI hints, not security proof.                                 |

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
