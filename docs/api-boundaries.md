# API boundaries

Status: registration and authentication ceremony APIs, Level 3 extension
handlers, attestation trust policy, optional browser/HTTP adapters, and examples
implemented, revised 2026-06-02.

This document defines public API boundaries. Plans 10 through 14 upgraded the
previous Level 2 surface to WebAuthn Level 3 while preserving the root package's
transport-neutral architecture.

## Boundary principles

The core package operates on explicit data structures. It must not read HTTP
requests, write HTTP responses, set cookies, create sessions, or assume browser
JSON transport.

Applications supply user data, stored credential data, ceremony state, origin
policy, and trust policy. The library returns verified outputs and state changes
but does not own persistence.

The root package must not import optional attestation format packages, `browser`,
`transport/http`, or `net/http`.

## Current package boundaries

- root `webauthn`: registration and authentication start/finish APIs, ceremony
  state, origin policy, policy inputs, result records, and module documentation;
- `protocol`: byte-safe protocol values, option dictionaries, Level 3 hints,
  transports, client capabilities, collected client data, and authenticator data
  parsing;
- `codec`: attestation object, COSE key, extension map, public-key material, and
  compound statement decoder contracts;
- `codec/cbor`: optional concrete CBOR and COSE_Key decoder behind narrow
  codec contracts;
- `crypto`: algorithm policy, signature, certificate, and JWS/JWT
  verifier contracts;
- `attestation`: format verifier contract, duplicate-rejecting registry, result
  types, and trust policy contracts;
- `attestation/*`: optional selected format verifiers, including
  `attestation/compound`;
- `extension`: operation-aware extension handler contract, Level 2 compatibility
  handlers, Level 3 handlers, deprecated result metadata, and registry helpers;
- `browser`: optional browser JSON DTO conversion helpers using unpadded
  base64url for WebAuthn binary fields and Level 3 DTOs;
- `transport/http`: optional standard-library HTTP JSON helpers that depend on
  `browser` but are not imported by the root package.

## Ceremony API shape

### Registration start

`StartRegistration(ctx, RegistrationStartOptions)` accepts RP/user entities,
`OriginPolicy`, challenge configuration, credential parameters, exclude
descriptors, authenticator selection, hints, attestation conveyance,
attestation format preferences, requested extensions, user verification, and
timeout. `Now` may be injected for deterministic timeout state.

It returns creation options and caller-stored ceremony state. The core does not
persist ceremony state.

### Registration finish

`FinishRegistration(ctx, RegistrationFinishOptions)` accepts stored state,
structured registration response input, selected attestation object decoder,
credential public-key decoder, extension map decoder, attestation registry,
trust policy, extension registry, extension policy, and caller-provided
credential uniqueness result.

It returns a persistence-ready credential record, attestation validity, trust
result, extension results, backup state, authenticator attachment, and warnings.
If `AttestationTrustPolicy` is nil, no attestation is accepted after format
verification. Callers that accept consumer passkey `none` attestation should use
an explicit policy such as `attestation.AcceptNone()`.

### Authentication start

`StartAuthentication(ctx, AuthenticationStartOptions)` accepts RP ID,
`OriginPolicy`, challenge configuration, optional allow credentials,
username-first user binding, user verification, hints, requested extensions, and
timeout. `Now` may be injected for deterministic timeout state.

It returns request options and caller-stored ceremony state. Empty
`allowCredentials` is supported for discoverable/passkey flows.

### Authentication finish

`FinishAuthentication(ctx, AuthenticationFinishOptions)` accepts stored state,
structured assertion response, stored credential record, signature verifier,
algorithm policy, extension map decoder, extension registry/policy, AppID
policy, and counter policy.

It returns the authenticated user handle, counter comparison, persistence-ready
credential update, backup state, authenticator attachment, extension results,
and warnings. The core does not create a login session.

## Origin boundary

`OriginPolicy` is the single root ceremony origin configuration. It contains
allowed origins, allowed top origins, and an explicit escape hatch for legacy
cross-origin responses without `topOrigin`.

`CollectedClientData.origin` must match `AllowedOrigins`. If `topOrigin` is
present, `crossOrigin` must be true and the value must match
`AllowedTopOrigins`. Reserved `tokenBinding` client data is parsed but ignored
for relying-party verification.

The root package never infers origins from HTTP headers.

## Transport DTO boundary

Core protocol values are byte-oriented. The optional `browser` package converts
between core values and JSON DTOs for projects that use unpadded base64url for
browser `ArrayBuffer`-like fields.

Protocol `Bytes()` accessors return defensive copies. Ceremony code uses typed
comparison and `AppendTo` helpers for values such as credential IDs, raw IDs,
user handles, authenticator data, and client data JSON when allocation-free
internal comparison or signature-base construction is useful.

The browser DTOs cover:

- creation/request options, including hints and attestation formats;
- credential descriptors;
- registration responses, including Level 3 `authenticatorData`, `publicKey`,
  `publicKeyAlgorithm`, and authenticator attachment;
- authentication responses, including authenticator attachment;
- known Level 3 PRF and largeBlob byte fields while preserving unknown
  extension values.

The optional `transport/http` package reads bounded request bodies, decodes
browser JSON responses, writes browser JSON options, and writes generic JSON
errors. It does not own routing, sessions, cookies, CSRF, persistence, account
lookup, credential lookup, or ceremony-state storage.

## Codec and crypto boundary

The project may define WebAuthn-specific decoded shapes but must not implement
general CBOR, COSE, ASN.1, JWS/JWT, X.509 path building, or cryptographic
primitives.

`codec.AttestationObjectDecoder`, `codec.COSEKeyDecoder`, and
`codec.ExtensionMapDecoder` are separate contracts so root finish options only
require the exact decoding surface they use. `codec/cbor` is optional and
replaceable.
`codec.CredentialPublicKey` may carry U2F raw public key bytes and codec-derived
EC2, RSA, or OKP public key material for optional attestation packages.

`crypto` contracts delegate algorithm policy, signature verification,
certificate verification, and JWS/JWT verification. Root APIs should avoid
concrete CBOR, COSE, certificate, or metadata dependency types.

## Attestation boundary

Format verification and RP trust acceptance are separate. A verifier proves the
statement is structurally and cryptographically valid. A trust policy decides
whether the relying party accepts the result.

Optional verifiers are selected explicitly by callers:

- `attestation/none`;
- `attestation/packed`;
- `attestation/fidou2f`;
- `attestation/tpm`;
- `attestation/androidkey`;
- `attestation/androidsafetynet` for legacy SafetyNet statements;
- `attestation/apple`;
- `attestation/compound`.

`attestation/compound` verifies normalized sub-statements by dispatching to a
caller-supplied registry. It returns raw sub-results as evidence and does not
make trust decisions for the relying party.

## Extension boundary

Extensions have two boundaries: option construction and result verification.
Handlers are registered by identifier and receive the ceremony operation so they
can reject extensions used in the wrong ceremony.

`extension.NewLevel3Registry` includes `appid`, `appidExclude`, `credProps`,
`largeBlob`, and `prf`. `extension.NewLevel3RegistryWithDeprecated` also
includes `uvm`. `uvm` is retained for callers that still need it and marks
results as deprecated.

Unknown extension results are represented in raw form and processed according to
policy. The core preserves unknown and unrequested outputs as `Accepted: false`
results by default, can reject unknown outputs with `RejectUnknown`, and can
reject unrequested outputs with `RejectUnrequested`.

## Storage boundary

The library defines persistence-ready result structures, not persistence
adapters. Applications map credential records, credential updates, attestation
results, extension results, and trust outcomes into their own schema.

Storage, sessions, cookies, framework adapters, CLI tools, and conformance
harness helpers remain outside the core API.
