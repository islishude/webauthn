# API boundaries

Status: 25 August 2026 Level 3 Recommendation ceremony APIs, strict protocol
decoding, opt-in Editor's Draft extension handling, attestation trust policy,
optional browser/HTTP adapters, and examples implemented, revised 2026-08-28.

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
  parsing; `CollectedClientData.HasTopOrigin` preserves optional-member presence
  and `AlgorithmEd448` identifies COSE algorithm `-53`;
- `codec`: attestation object, COSE key, extension map, public-key material, and
  compound statement decoder contracts;
- `codec/cbor`: optional concrete CTAP2-canonical CBOR and COSE_Key decoder
  behind narrow codec contracts;
- `crypto`: algorithm policy, signature, certificate, and JWS/JWT
  verifier contracts;
- `crypto/standard`: optional explicit-policy verifier using Go standard-library
  ECDSA, RSA PKCS#1/PSS, and Ed25519 operations;
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
- `storage/json`: optional bounded, versioned JSON encoding for trusted
  server-side ceremony state and credential records.

## Ceremony API shape

### Registration start

`StartRegistration(ctx, RegistrationStartOptions)` accepts RP/user entities,
`OriginPolicy`, challenge configuration, credential parameters, exclude
descriptors, authenticator selection, hints, attestation conveyance,
attestation format preferences, requested extensions, an extension registry and
input policy, timeout, and an optional `ConditionalMediation` binding.
Registration user verification comes only from
`AuthenticatorSelection`; the zero value is `preferred`. `Now` may be injected
for deterministic timeout state. A zero `Timeout` means a five-minute browser
hint; a zero `StateTTL` means a separate ten-minute server challenge lifetime.
An empty credential-parameter list expands to the Recommendation's ES256/RS256
client defaults; unsupported credential types are ignored when at least one
`public-key` entry remains.

It returns creation options and caller-stored ceremony state. The core does not
persist ceremony state. `ConditionalMediation` does not wrap the returned public
key options: the caller must first check the client's `conditionalCreate`
capability and set `CredentialCreationOptions.mediation` to `"conditional"` in
the browser call.

### Registration finish

`FinishRegistration(ctx, RegistrationFinishOptions)` accepts stored state,
structured registration response input, selected attestation object decoder,
credential public-key decoder, extension map decoder, attestation registry,
trust policy, extension registry, and extension policy.

It returns a credential record with explicit `public-key` type, attestation validity, trust result, ordered
extension results, immutable backup eligibility, backup state, UV initialization,
authenticator attachment, and warnings.
The application must insert the returned credential under an atomic uniqueness
constraint; the core does not perform a preflight storage check or own a
persistence callback.
If `AttestationTrustPolicy` is nil, no attestation is accepted after format
verification. Callers that accept consumer passkey `none` attestation should use
an explicit policy such as `attestation.AcceptNone()`.
User presence remains required by default. It is not required only when the
trusted registration state records conditional mediation, as specified by the
Level 3 registration relying-party operation.

### Authentication start

`StartAuthentication(ctx, AuthenticationStartOptions)` accepts RP ID,
`OriginPolicy`, challenge configuration, optional allow credentials,
username-first user binding, user verification, hints, requested extensions, and
an extension registry/input policy, timeout, and state TTL. `Now` may be injected
for deterministic timeout state; zero values mean a five-minute browser hint and
a ten-minute server challenge lifetime.

It returns request options and caller-stored ceremony state. Empty
`allowCredentials` is supported for discoverable/passkey flows.

### Authentication finish

`FinishAuthentication(ctx, AuthenticationFinishOptions)` accepts stored state,
structured assertion response, stored credential record, signature verifier,
algorithm policy, extension map decoder, extension registry/policy, AppID
policy, and counter policy.

It returns the authenticated user handle, UP/UV observations, counter comparison,
UV initialization status, conditional credential update fields, backup state,
authenticator attachment, ordered extension results, and warnings. Backup
eligibility is checked against registration state and never updated.
Known authentication-time attachment changes are included in the conditional
credential update together with an explicit changed flag.

## Origin boundary

`OriginPolicy` is the single root ceremony origin configuration. It contains
allowed origins, allowed top origins, and an explicit escape hatch for legacy
cross-origin responses without `topOrigin`.

`CollectedClientData.origin` must match `AllowedOrigins`. Presence of
`topOrigin` is tracked independently of its value: a present null, empty, or
non-string value is malformed; a valid present value requires `crossOrigin`
and must match `AllowedTopOrigins`. Reserved `tokenBinding` client data is
parsed but ignored for relying-party verification.

The root package never infers origins from HTTP headers.

## Transport DTO boundary

Core protocol values are byte-oriented. The optional `browser` package converts
between core values and JSON DTOs for projects that use unpadded base64url for
browser `ArrayBuffer`-like fields. Decoders accept only the canonical unpadded
encoding, including zero trailing pad bits and no whitespace.

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

Response decoding requires every member marked `required` by the Level 3
`RegistrationResponseJSON`, `AuthenticationResponseJSON`, and nested response
dictionaries. The textual `id` must be the canonical base64url encoding of
`rawId`; registration still treats the copy inside `attestationObject` as the
cryptographic authority.

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
`codec.CredentialPublicKey` carries defensive raw COSE bytes plus typed EC2, RSA,
or OKP material. It never exposes a dependency-owned key handle. The concrete
codec rejects non-canonical CTAP2 encoding, duplicate or extra attestation-object
members, invalid identifier syntax, and optional/private COSE key parameters.
Known algorithm, key type, curve, and coordinate combinations are validated.
RSA keys additionally require RFC 8230 minimal unsigned values and a
2048–16384 bit modulus.

`crypto` contracts delegate algorithm policy, signature verification,
certificate verification, and JWS/JWT verification. Root APIs should avoid
concrete CBOR, COSE, certificate, or metadata dependency types.
`crypto/standard` is optional and requires an explicit non-empty allow-list.

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

`attestation.VerificationRequest.ConveyancePreference` carries registration
attestation conveyance into format validation. Packed verification uses it to
reject enterprise device serial extensions outside enterprise requests.
`androidkey.New` retains union authorization-list semantics, while
`androidkey.NewWithPolicy` can require hardware/TEE-enforced evidence.
`androidsafetynet.New` requires explicit application package, application
signing-certificate digest, freshness, version, and integrity policy; JWS
verification does not replace those per-request bindings.

## Extension boundary

Extensions have two boundaries: `ValidateInput` during option construction and
`VerifyOutput` only after core signature or attestation verification succeeds.
Registries are immutable after construction. Known inputs are normalized and
deep-copied; unknown inputs are preserved unless `ExtensionInputPolicy` rejects
them. The context-sensitive `largeBlob` identifier is an exception: requesting
it for authentication requires a registered handler so start-time validation,
trusted-state restoration, and storage validation apply the same semantics.
Custom handlers must be deterministic and side-effect-free because
caller-owned uniqueness and persistence decisions remain outside the root.

`extension.OutputRequest.ClientOutputPresent` and
`AuthenticatorOutputPresent` distinguish an absent extension member from an
explicit null value, so built-in handlers can reject malformed null outputs.
For authentication, `extension.OutputRequest.SelectedCredentialID` contains the
credential that passed the core credential/user binding checks; it is zero for
registration. The PRF handler uses this trusted context to select an exact
`evalByCredential` entry before falling back to `eval`, and never accepts a
result merely because it matches some other requested input.
Registration rejects `evalByCredential` by member presence, including an empty
object. Authentication finish revalidates that a restored largeBlob write state
still contains exactly one allowed credential.

`extension.NewLevel3Registry` includes `appid`, `appidExclude`, `credProps`,
`largeBlob`, and `prf`. `extension.NewLevel3RegistryWithDeprecated` also
includes `uvm`. `uvm` is retained for callers that still need it and marks
results as deprecated.

`extension.RemoteClientDataJSONHandler` implements the 30 July 2026 Editor's
Draft preview extension and is absent from both default Level 3 registries.
When explicitly registered, start binds it to ceremony type and challenge;
finish requires byte-for-byte signed client-data equality and a true output.

Unknown extension results are represented in raw form and processed in sorted ID
order. `RejectUnknown` applies only when an unknown output exists; a requested
extension with no output remains valid. Unrequested outputs can be rejected with
`RejectUnrequested`. Preserved raw values are recursively copied, including
nested maps with non-string comparable CBOR keys, with bounded nesting.

## Storage boundary

The root defines storage-neutral records and conditional updates. Applications
may map them into their own schema or use optional `storage/json` for strict,
versioned serialization. That package performs no storage I/O, encryption,
authentication, cookie sealing, or replay prevention and is only for trusted
server-side storage. Registration state serialization preserves the
conditional-mediation binding and treats its absent zero value as ordinary,
UP-required registration.
Envelope v2 persists credential type explicitly and continues to read v1
records by interpreting an absent type member as `public-key`; an explicitly
empty or null type remains malformed.
Finish rejects a missing expiry or unresolved user-verification policy whether
state was restored with `storage/json` or a caller-owned schema.

Storage backends, sessions, cookies, framework adapters, CLI tools, and
conformance harness helpers remain outside the root API.
