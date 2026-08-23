# Security and privacy model

Status: Level 3 ceremony state, extension handling, attestation trust policy, standard verification, storage encoding, and optional transport helpers implemented, revised 2026-08-23.

This document records security and privacy decisions that implementation must preserve.

## Threat model

The library verifies WebAuthn relying-party server inputs from browsers and authenticators. Inputs must be treated as attacker-controlled until verified. The attacker may control the network client, submit malformed CBOR/JSON/binary fields, replay old ceremonies, swap origins, attempt credential confusion between users, exploit unsupported extensions, or use cloned authenticators.

The library does not protect the application from insecure account recovery, compromised sessions, weak TLS termination, unsafe frontend JavaScript, database compromise, or incorrect caller policy. It must provide clear outputs so the application can make correct decisions.

## Challenge policy

Challenges must be generated in a trusted server-side environment, stored temporarily by the relying party, and compared exactly during verification. The default generator should use sufficient entropy and should target at least 32 random bytes unless a caller deliberately overrides it. Inputs shorter than the WebAuthn minimum should be rejected by default.

Challenge mismatch is a hard protocol failure. The library must not offer a permissive mode that accepts mismatches.

## Origin and RP ID policy

The core library must not infer trusted origins from HTTP request headers. The caller supplies allowed origins and RP ID policy explicitly.

Registration and authentication verification must compare `CollectedClientData.origin` to the configured origin policy. `topOrigin` presence is tracked separately: present null, empty, or non-string values are malformed, while a valid present value must be explicitly allowed and paired with `crossOrigin`. Authenticator data `rpIdHash` must match SHA-256 of the expected RP ID, except when authentication explicitly uses the AppID extension and the client output indicates AppID was used.

Cross-origin use must be policy-controlled. The presence of `crossOrigin` must not be ignored if the application has configured a strict policy.

`CollectedClientData.tokenBinding` is reserved in the Level 3 target. The parser
preserves it for callers that inspect raw client data, but relying-party
verification does not accept or reject ceremonies based on token binding status
or ID.

## User presence and user verification

User presence is required for both registration and authentication. User verification must be enforced according to the configured ceremony policy. If user verification is required and the UV flag is not set, verification fails.

If user verification is preferred or discouraged, the result should be surfaced so the application can record or risk-score the ceremony.

Credential records retain `uvInitialized`. A false-to-true authentication-time
transition is returned as pending unless the caller explicitly confirms that an
equivalent additional authentication factor authorized the change.

## Credential backup state

The verifier rejects BS when BE is not set. `backupEligible` is captured at
registration and must remain identical on every assertion; only `backupState`
is mutable. Applications receive changed flags separately so persistence can use
conditional updates.

## Credential ownership and user handle policy

Username-first authentication and discoverable-credential authentication have different ownership checks.

In username-first flows, the caller already identified an account and passes stored credential material for that account. If the assertion includes a user handle, it must map to the same account.

In discoverable-credential flows, the assertion must include a user handle and the application must map that handle and credential ID to an account. The library should provide the checks and result shape but should not own the account database.

Credential ID uniqueness at registration is an application-level persistence decision. The verifier should surface the credential ID and provide a place for the caller to pass or record uniqueness checks.

## Signature verification

Authentication signatures are verified over authenticator data concatenated with SHA-256 of the serialized client data. Attestation signatures are verified according to their statement format.

The project must not implement cryptographic primitives. Signature verification and key parsing must be delegated to standard library code or adapter dependencies. The WebAuthn layer is responsible for selecting the correct signature base, algorithm policy, and protocol binding checks.

The concrete CBOR adapter rejects non-canonical CTAP2 encodings, tags,
indefinite lengths, duplicate or extra attestation-object keys, and optional or
private COSE key parameters. Authenticator RFU flag bits are rejected. These
checks occur before decoded material reaches signature or trust policy.

## Signature counter policy

Signature counters are clone-detection signals, not universally reliable monotonic counters. If both the stored counter and new counter are zero, no clone signal is available. If either is nonzero and the new counter is not greater than the stored counter, the library should return a clone-risk result.

The authentication API surfaces counter rollback as clone risk by default and
preserves the stored counter. Callers can reject clone risk or explicitly opt in
to updating the counter. Conflicting reject/update policy is invalid.

## Attestation policy

Attestation verification has two layers:

1. format validity and cryptographic verification;
2. relying-party trust acceptance.

A statement can be cryptographically valid but untrusted. A `none` attestation can be acceptable for consumer passkeys and unacceptable for restricted device enrollment. The API must preserve this distinction.

Trust anchors, metadata, certificate status, AAGUID policy, and enterprise acceptance must be explicit relying-party policy. The root package must not ship a hidden global trust store.

Attestation conveyance is passed into format verification. Packed device serial
extensions are accepted only for enterprise conveyance; TPM identity attributes,
Android hardware-enforced authorization lists, and Apple nonce ASN.1 structure
are validated before trust evaluation.

The current default remains conservative. Without a caller-supplied `attestation.TrustPolicy`, registration rejects every attestation after format verification. Callers that accept consumer passkey `none` attestation must pass an explicit policy such as `attestation.AcceptNone()`. Optional `packed`, `fido-u2f`, `tpm`, `android-key`, legacy `android-safetynet`, `apple`, and `compound` verification can prove statement validity, but x5c trust-chain acceptance is still a relying-party decision.

The `attestation` package provides explicit trust policy building blocks for `none`, self attestation, format and type allow-lists, x5c trust-root verification through caller-provided certificate verifiers, AAGUID allow-lists, caller-owned metadata lookup, caller-owned certificate status checks, and policy composition. These policies do not include built-in trust anchors, network fetching, metadata caches, or automatic restricted-enrollment defaults.

## Extension policy

Extensions are optional for clients and authenticators. Known inputs are
validated before the ceremony is emitted. Missing requested outputs are
surfaced as not accepted, while unknown-output rejection applies only when an
output actually exists. Output handlers run only after core cryptographic and
attestation trust checks succeed.

Extension outputs must not be elevated into security facts unless the extension handler has validated them and the relying-party policy accepts them. Unknown and unrequested extension outputs are preserved as untrusted raw results by default; callers can set `RejectUnknown` or `RejectUnrequested` for fail-closed behavior.

The AppID extension is accepted for RP ID hash fallback only when the request included the same `appid` input, the caller configured the same AppID in policy, and the client output reports that AppID was used.

The PRF extension validates requested inputs, output result lengths, and
`evalByCredential` binding to the authentication allow-credentials list,
operation-specific output members, result cardinality, and the equal-input
equal-output invariant. PRF
outputs are extension results for caller policy and storage; they are not login
success criteria by themselves.

`largeBlob` writes require exactly one allowed credential and a `written`
result. An `appidExclude` output, when present, must be true. Editor's Draft
`remoteClientDataJSON` requires a true client output. The remote extension is
not in default registries; an opt-in caller must configure the remote origin
explicitly, and the serialized input must remain byte-for-byte identical to
signed client data. Raw remote client data must not be included in result
logging.

The `uvm` extension is deprecated in Level 3. It is retained as explicit opt-in
support and marks parsed results as deprecated so callers can phase out policy
dependencies without losing compatibility with existing responses.

## Privacy defaults

Defaults should minimize credential and authenticator disclosure.

- Attestation conveyance should default to `none` unless the caller requests otherwise.
- Error results should support generic user-facing messages to reduce username and credential enumeration risk.
- Credential descriptors and transport hints should be treated as operational hints, not public identifiers to expose unnecessarily.
- User handles should be opaque stable identifiers, not email addresses or usernames.
- Logs must not include challenges, credential IDs, user handles, signatures, client data JSON, or attestation objects unless the application explicitly opts into sensitive debug logging.

## Malformed input handling

Malformed data should fail closed. The parser and verifier must test:

- truncated authenticator data;
- inconsistent AT and ED flags;
- missing attested credential data during registration;
- invalid credential ID lengths;
- malformed CBOR maps from the selected codec;
- non-canonical CBOR and COSE keys with optional/private parameters;
- invalid extension and attestation identifier grammar;
- unknown or unsupported `fmt` values;
- unsupported algorithms;
- invalid signatures;
- invalid or missing required client data fields;
- invalid base64url challenge values at the transport boundary.

## Time and replay

Ceremony state includes a five-minute expiry by default. Finish rejects at the
exact deadline. Callers must still atomically consume state once; optional
`storage/json` serializes trusted server-side state but does not enforce replay
prevention or make it safe for client-side cookies.

Registration and authentication start/finish options accept an injectable clock
where timeout or expiry state is evaluated. Production callers can rely on the
default wall clock, while tests and deterministic lifecycle policy can provide a
fixed clock.

## Optional transport helpers

The optional `browser` package only converts between browser JSON DTOs and transport-neutral protocol values. It treats browser JSON as attacker-controlled, rejects malformed JSON and invalid base64url encodings, validates decoded byte-oriented protocol values, and preserves unknown extension results as untrusted values for later policy handling.

The optional `transport/http` package only reads bounded JSON request bodies and writes JSON responses. It does not infer trusted origins from request headers, does not create sessions or cookies, and does not persist ceremony state or credentials. Its `WriteError` helper emits generic status text rather than raw error strings, so credential IDs, challenges, user handles, signatures, client data JSON, attestation objects, and assertion bytes are not reflected by default.

## Safe defaults checklist

Before stable release, defaults should be:

- 32-byte server-generated random challenges;
- exact challenge comparison;
- five-minute default ceremony expiry and exact-deadline rejection;
- explicit allowed origins;
- explicit allowed top origins for cross-origin ceremonies;
- explicit RP ID;
- user presence required;
- user verification enforced when policy says required;
- `none` attestation accepted only when explicit trust policy allows it;
- non-`none` attestation accepted only when caller trust policy accepts it;
- unsupported attestation formats rejected;
- unsupported algorithms rejected;
- malformed/non-canonical CBOR, optional/private COSE parameters, RFU flags,
  and invalid identifier grammar rejected;
- unsolicited extensions ignored or rejected by configured policy;
- Editor's Draft extensions absent from default Level 3 registries;
- counter rollback surfaced as clone risk;
- stored counter preserved on clone risk unless explicit policy updates it;
- BE/BS invariants and immutable backup eligibility;
- transport-neutral error objects;
- optional HTTP helper errors written generically without raw protocol material.
