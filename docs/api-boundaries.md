# API boundaries

Status: core boundary contracts implemented, revised 2026-05-31.

This document defines public API boundaries. Plan 02 established the initial Go packages and contracts; ceremony APIs are still future work.

## Boundary principles

The core package must operate on explicit data structures. It must not read HTTP requests, write HTTP responses, set cookies, create sessions, or assume a browser JSON transport. This keeps the library usable in existing services, regardless of router, framework, RPC layer, or state storage.

The core package must not own user or credential persistence. Applications supply user data, stored credential data, ceremony state, and policy configuration; the library returns verified outputs and state changes.

The core package must not import optional attestation format packages. Attestation verifiers are selected explicitly through configuration or a registry supplied by the caller.

Plan 02 package boundaries:

- root `webauthn`: package documentation and future ceremony entry points;
- `protocol`: byte-safe protocol values and option/client-data models;
- `codec`: CBOR attestation object, COSE key, and extension map decoder contracts;
- `crypto`: hashing, algorithm policy, signature, certificate, and JWS/JWT verifier contracts;
- `attestation`: format verifier contract and duplicate-rejecting registry;
- `extension`: extension handler contract and duplicate-rejecting registry.

## Ceremony API shape

### Registration start

Inputs should include:

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

Outputs should include:

- creation options suitable for browser transport serialization;
- ceremony state containing challenge, RP ID, origin policy reference, user binding, selected options, and expiration metadata.

The core should not persist ceremony state.

### Registration finish

Inputs should include:

- stored ceremony state;
- client credential response in structured form;
- selected attestation format registry;
- attestation trust policy;
- extension policy;
- optional credential uniqueness result or callback output supplied by the application.

Outputs should include:

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

The core should not insert the credential into a database.

### Authentication start

Inputs should include:

- RP ID;
- origin policy;
- challenge generator or pre-generated challenge;
- optional allow credential descriptors;
- user verification policy;
- requested extensions;
- timeout hint;
- optional user/account binding for username-first flows.

Outputs should include:

- request options suitable for browser transport serialization;
- ceremony state containing challenge, RP ID, origin policy reference, allowed credentials, requested extensions, and expiration metadata.

The core should support empty `allowCredentials` for discoverable-credential/passkey flows.

### Authentication finish

Inputs should include:

- stored ceremony state;
- client assertion response in structured form;
- stored credential record or a caller-supplied lookup result;
- account/user-handle ownership information;
- extension policy;
- AppID extension policy if requested;
- sign counter policy.

Outputs should include:

- credential ID;
- authenticated user handle/account binding;
- signature verification result;
- new sign counter;
- sign counter comparison result;
- clone-risk signal if applicable;
- extension outputs;
- persistence-ready credential update.

The core should not create a login session.

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

## Attestation registry boundary

An attestation verifier should be addressable by the exact `fmt` identifier. Matching is case-sensitive. The registry must reject duplicate registrations unless explicitly overridden in tests.

A verifier should return at least:

- attestation type, such as none, self, basic, AttCA, anonymization CA, or uncertain;
- trust path material, if present;
- cryptographic validity result;
- format-specific warnings;
- data needed by trust policy, such as certificates or AAGUID bindings.

Trust evaluation should be outside the verifier or clearly layered on top of it. Format verification answers whether the statement is well-formed and cryptographically valid. Trust policy answers whether the relying party accepts it.

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
