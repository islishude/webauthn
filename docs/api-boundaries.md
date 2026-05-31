# API boundaries

Status: registration and authentication ceremony APIs plus minimal attestation trust policy implemented, revised 2026-05-31.

This document defines public API boundaries. Plan 02 established the initial Go packages and contracts. Plan 03 added transport-neutral registration ceremony APIs. Plan 04 added transport-neutral authentication ceremony APIs.

## Boundary principles

The core package must operate on explicit data structures. It must not read HTTP requests, write HTTP responses, set cookies, create sessions, or assume a browser JSON transport. This keeps the library usable in existing services, regardless of router, framework, RPC layer, or state storage.

The core package must not own user or credential persistence. Applications supply user data, stored credential data, ceremony state, and policy configuration; the library returns verified outputs and state changes.

The core package must not import optional attestation format packages. Attestation verifiers are selected explicitly through configuration or a registry supplied by the caller.

Current package boundaries:

- root `webauthn`: registration and authentication start/finish APIs, ceremony state, policy inputs, result records, and module documentation;
- `protocol`: byte-safe protocol values, option dictionaries, client data parsing, and authenticator data parsing;
- `codec`: CBOR attestation object, COSE key, and extension map decoder contracts;
- `codec/cbor`: optional concrete CBOR and COSE_Key decoder behind `codec.Decoders`;
- `crypto`: hashing, algorithm policy, signature, certificate, and JWS/JWT verifier contracts;
- `attestation`: format verifier contract, duplicate-rejecting registry, and minimal trust policy contract;
- `attestation/none`: optional `none` format verifier selected explicitly by callers;
- `attestation/packed`: optional `packed` format verifier selected explicitly by callers;
- `attestation/fidou2f`: optional `fido-u2f` format verifier selected explicitly by callers;
- `attestation/tpm`: optional `tpm` format verifier selected explicitly by callers;
- `attestation/androidkey`: optional `android-key` format verifier selected explicitly by callers;
- `attestation/androidsafetynet`: optional `android-safetynet` format verifier selected explicitly by callers;
- `attestation/apple`: optional `apple` format verifier selected explicitly by callers;
- `extension`: extension handler contract and duplicate-rejecting registry.

## Ceremony API shape

### Registration start

Plan 03 implements `StartRegistration(ctx, RegistrationStartOptions)`. Inputs include:

- RP entity and RP ID;
- allowed origins or origin policy reference;
- user entity including byte user handle;
- challenge generator or pre-generated challenge;
- allowed public key credential parameters;
- exclude credential descriptors;
- authenticator selection policy;
- attestation conveyance preference;
- requested extensions;
- timeout hint.

Outputs include:

- creation options suitable for browser transport serialization;
- ceremony state containing challenge, RP ID, origin policy reference, user binding, selected options, and expiration metadata.

The core does not persist ceremony state.

### Registration finish

Plan 03 implements `FinishRegistration(ctx, RegistrationFinishOptions)`. Inputs include:

- stored ceremony state;
- client credential response in structured form;
- selected attestation format registry;
- attestation trust policy, either the legacy `AllowNone` policy or an explicit `attestation.TrustPolicy`;
- extension policy;
- optional credential uniqueness result or callback output supplied by the application.

Outputs include:

- credential ID;
- credential public key;
- AAGUID;
- initial sign counter;
- user handle/account binding;
- transports;
- attestation format, attestation type, cryptographic validity, and trust result;
- extension outputs;
- warnings or risk flags;
- persistence-ready credential record.

The core does not insert the credential into a database.

If `RegistrationFinishOptions.AttestationTrustPolicy` is nil, the root package preserves its initial safe default: only `none` attestation can be accepted, and only when `RegistrationAttestationPolicy.AllowNone` is true. Any non-`none` format, including `packed`, requires a caller-supplied trust policy that explicitly accepts the verified attestation result.

### Authentication start

Plan 04 implements `StartAuthentication(ctx, AuthenticationStartOptions)`. Inputs include:

- RP ID;
- origin policy;
- challenge generator or pre-generated challenge;
- optional allow credential descriptors;
- user verification policy;
- requested extensions;
- timeout hint;
- optional user/account binding for username-first flows.

Outputs include:

- request options suitable for browser transport serialization;
- ceremony state containing challenge, RP ID, origin policy reference, allowed credentials, requested extensions, and expiration metadata.

The core supports empty `allowCredentials` for discoverable-credential/passkey flows.

### Authentication finish

Plan 04 implements `FinishAuthentication(ctx, AuthenticationFinishOptions)`. Inputs include:

- stored ceremony state;
- client assertion response in structured form;
- stored credential record or a caller-supplied lookup result;
- account/user-handle ownership information;
- extension policy;
- AppID extension policy if requested;
- sign counter policy.

Outputs include:

- credential ID;
- authenticated user handle/account binding;
- signature verification result;
- new sign counter;
- sign counter comparison result;
- clone-risk signal if applicable;
- extension outputs;
- persistence-ready credential update.

The core does not create a login session. Username-first flows are selected by `ExpectedUserHandle`; discoverable flows require a response user handle and caller-provided credential binding. Signature verification is delegated through `crypto.SignatureVerifier`, and counter rollback is surfaced as clone risk unless caller policy rejects it.

## Transport DTO boundary

The browser API deals with binary fields as `ArrayBuffer` values. Many server/browser JSON bridges represent those values as base64url strings. This library should separate those concerns.

Core protocol values should be byte-oriented. Optional transport packages can provide JSON-friendly DTOs and conversion helpers. The root package should not force a single JSON shape, because projects often already have frontend conventions.

## Crypto boundary

The core needs crypto operations, but must not implement primitives. It should depend on a narrow verifier contract that can:

- compute SHA-256 where required or accept a hash function dependency;
- map COSE algorithm identifiers to verifier behavior;
- verify signatures for configured algorithms;
- parse or validate credential public keys through a COSE-aware dependency;
- parse X.509 certificates and validate chains where attestation formats require it;
- verify JWS/JWT signatures for SafetyNet-like formats through a dependency.

The public API should avoid exposing a concrete COSE or CBOR library type unless unavoidable. Credential public keys may need an opaque representation plus helper methods for common storage formats.

## Codec boundary

The project may define protocol shapes expected after decoding, but must not implement general CBOR. The codec boundary should support:

- decoding attestation objects into `fmt`, `authData`, and `attStmt`;
- decoding COSE keys into an adapter-consumable key representation;
- decoding authenticator extension maps;
- rejecting duplicate or malformed map keys if the selected codec exposes such checks;
- preserving raw bytes where required for signature bases.

JSON decoding of `clientDataJSON` may use the Go standard library. Parsing must be tolerant of unknown keys and key ordering.

Plan 03 adds optional `codec/cbor` using `github.com/fxamacker/cbor/v2` and `github.com/ldclabs/cose`. This package remains replaceable because public registration APIs accept `codec.Decoders` and return `codec.CredentialPublicKey`, not concrete dependency types.

`codec.CredentialPublicKey` may also carry an optional U2F raw public key representation. This is exposed as bytes through `U2FPublicKey()` so `attestation/fidou2f` can build the U2F verification message without depending on a concrete COSE key type.

`codec.CredentialPublicKey` may also carry codec-derived EC2 or RSA public key material. This is exposed through `PublicKeyMaterial()` so `attestation/tpm`, `attestation/androidkey`, and `attestation/apple` can compare WebAuthn credential public-key values to format-specific public key material without depending on a concrete COSE key type.

## Attestation registry boundary

An attestation verifier should be addressable by the exact `fmt` identifier. Matching is case-sensitive. The registry must reject duplicate registrations unless explicitly overridden in tests.

A verifier should return at least:

- attestation type, such as none, self, basic, AttCA, anonymization CA, or uncertain;
- trust path material, if present;
- cryptographic validity result;
- format-specific warnings;
- data needed by trust policy, such as certificates or AAGUID bindings.

Trust evaluation should be outside the verifier or clearly layered on top of it. Format verification answers whether the statement is well-formed and cryptographically valid. Trust policy answers whether the relying party accepts it.

The minimal trust policy contract is `attestation.TrustPolicy`. It receives verified format evidence, authenticator data, the credential public key, and raw attestation object context, then returns an accepted/rejected trust result. Built-in trust-root, metadata, AAGUID, and certificate-status policies remain future Plan 07 work.

`attestation/packed` verifies self attestation and x5c attestation signatures. For x5c it parses the leaf-first certificate chain, validates packed attestation certificate shape requirements, and returns the x5c trust path without deciding whether the chain is trusted by the relying party.

`attestation/fidou2f` verifies the FIDO U2F registration signature base using an ES256 P-256 credential public key and a single x5c attestation certificate. It returns an x5c trust path without deciding whether the certificate represents Basic or AttCA trust.

`attestation/tpm` verifies TPM 2.0 attestation statements by binding `certInfo` to authenticator data, client data hash, and `pubArea`; binding `pubArea` to codec-derived EC2 or RSA credential public key material; checking AIK certificate shape requirements; and returning `TypeAttCA` with the leaf-first x5c trust path. The relying party still decides whether that trust path is accepted.

`attestation/androidkey` verifies Android Key attestation statements by checking the signature over authenticator data plus client data hash, binding the leaf certificate public key to codec-derived EC2 or RSA credential public key material, validating the WebAuthn-required Android Key attestation extension fields, and returning `TypeBasic` with the leaf-first x5c trust path. The relying party still decides whether that trust path is accepted.

`attestation/androidsafetynet` verifies Android SafetyNet attestation statements by delegating compact JWS verification to `crypto.JWSVerifier`, checking the SafetyNet nonce against authenticator data plus client data hash, requiring `ctsProfileMatch`, validating the SafetyNet service certificate hostname, and returning `TypeBasic` with the leaf-first x5c trust path. The relying party still decides whether that trust path is accepted.

`attestation/apple` verifies Apple anonymous attestation statements by checking the Apple nonce certificate extension against authenticator data plus client data hash, binding the leaf certificate public key to codec-derived EC2 or RSA credential public key material, and returning `TypeAnonymizationCA` with the leaf-first x5c trust path. The relying party still decides whether that trust path is accepted.

## Extension boundary

Extensions have two boundaries:

- option construction, where the RP asks the client/authenticator for extension behavior;
- result verification, where the RP interprets client and authenticator extension outputs.

Extension handlers should be optional and registered by identifier. Unknown extension results should be represented in raw form and processed according to policy. The core must not silently treat unknown extension results as trusted facts.

## Storage boundary

The library should define persistence-ready result structures, not persistence adapters in the root package. A stored credential concept should include fields required by future authentication, but applications should be free to map it into their own schema.

Optional storage examples may be added later. They must not become part of the core dependency graph.

## Optional adapter boundary

Optional packages may be added after core stabilization:

- browser JSON DTO conversion;
- `net/http` examples and small helpers;
- framework examples;
- in-memory demonstration storage;
- CLI or conformance harness helpers.

These packages must not be imported by the root package and must not define the canonical core API.
