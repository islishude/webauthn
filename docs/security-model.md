# Security and privacy model

Status: authentication ceremony and initial attestation trust hook implemented, revised 2026-05-31.

This document records security and privacy decisions that implementation must preserve.

## Threat model

The library verifies WebAuthn relying-party server inputs from browsers and authenticators. Inputs must be treated as attacker-controlled until verified. The attacker may control the network client, submit malformed CBOR/JSON/binary fields, replay old ceremonies, swap origins, attempt credential confusion between users, exploit unsupported extensions, or use cloned authenticators.

The library does not protect the application from insecure account recovery, compromised sessions, weak TLS termination, unsafe frontend JavaScript, database compromise, or incorrect caller policy. It must provide clear outputs so the application can make correct decisions.

## Challenge policy

Challenges must be generated in a trusted server-side environment, stored temporarily by the relying party, and compared exactly during verification. The default generator should use sufficient entropy and should target at least 32 random bytes unless a caller deliberately overrides it. Inputs shorter than the WebAuthn minimum should be rejected by default.

Challenge mismatch is a hard protocol failure. The library must not offer a permissive mode that accepts mismatches.

## Origin and RP ID policy

The core library must not infer trusted origins from HTTP request headers. The caller supplies allowed origins and RP ID policy explicitly.

Registration and authentication verification must compare `CollectedClientData.origin` to the configured origin policy. Authenticator data `rpIdHash` must match SHA-256 of the expected RP ID, except when authentication explicitly uses the AppID extension and the client output indicates AppID was used.

Cross-origin use must be policy-controlled. The presence of `crossOrigin` must not be ignored if the application has configured a strict policy.

## User presence and user verification

User presence is required for both registration and authentication. User verification must be enforced according to the configured ceremony policy. If user verification is required and the UV flag is not set, verification fails.

If user verification is preferred or discouraged, the result should be surfaced so the application can record or risk-score the ceremony.

## Credential ownership and user handle policy

Username-first authentication and discoverable-credential authentication have different ownership checks.

In username-first flows, the caller already identified an account and passes stored credential material for that account. If the assertion includes a user handle, it must map to the same account.

In discoverable-credential flows, the assertion must include a user handle and the application must map that handle and credential ID to an account. The library should provide the checks and result shape but should not own the account database.

Credential ID uniqueness at registration is an application-level persistence decision. The verifier should surface the credential ID and provide a place for the caller to pass or record uniqueness checks.

## Signature verification

Authentication signatures are verified over authenticator data concatenated with SHA-256 of the serialized client data. Attestation signatures are verified according to their statement format.

The project must not implement cryptographic primitives. Signature verification and key parsing must be delegated to standard library code or adapter dependencies. The WebAuthn layer is responsible for selecting the correct signature base, algorithm policy, and protocol binding checks.

## Signature counter policy

Signature counters are clone-detection signals, not universally reliable monotonic counters. If both the stored counter and new counter are zero, no clone signal is available. If either is nonzero and the new counter is not greater than the stored counter, the library should return a clone-risk result.

The authentication API surfaces counter rollback as clone risk by default. Callers can reject clone risk through counter policy or accept the result and apply their own warn, step-up, or continue behavior.

## Attestation policy

Attestation verification has two layers:

1. format validity and cryptographic verification;
2. relying-party trust acceptance.

A statement can be cryptographically valid but untrusted. A `none` attestation can be acceptable for consumer passkeys and unacceptable for restricted device enrollment. The API must preserve this distinction.

Trust anchors, metadata, certificate status, AAGUID policy, and enterprise acceptance must be explicit relying-party policy. The root package must not ship a hidden global trust store.

The current default remains conservative. Without a caller-supplied `attestation.TrustPolicy`, registration accepts only `none` attestation when `AllowNone` is true and rejects all non-`none` attestations after format verification. Optional `packed`, `fido-u2f`, `tpm`, `android-key`, `android-safetynet`, and `apple` verification can prove statement validity, but x5c trust-chain acceptance is still a relying-party decision.

## Extension policy

Extensions are optional for clients and authenticators. Missing requested extension outputs must be handled explicitly. Unsolicited extension outputs may occur and must be ignored or rejected according to caller policy.

Extension outputs must not be elevated into security facts unless the extension handler has validated them and the relying-party policy accepts them.

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
- unknown or unsupported `fmt` values;
- unsupported algorithms;
- invalid signatures;
- invalid or missing required client data fields;
- invalid base64url challenge values at the transport boundary.

## Time and replay

Ceremony state must include enough information for the caller to enforce expiry and single use. The core should expose expiration metadata and exact challenge checks, but storage and replay prevention remain caller responsibilities.

## Safe defaults checklist

Before stable release, defaults should be:

- 32-byte server-generated random challenges;
- exact challenge comparison;
- explicit allowed origins;
- explicit RP ID;
- user presence required;
- user verification enforced when policy says required;
- `none` attestation accepted only when policy allows it;
- non-`none` attestation accepted only when caller trust policy accepts it;
- unsupported attestation formats rejected;
- unsupported algorithms rejected;
- unsolicited extensions ignored or rejected by configured policy;
- counter rollback surfaced as clone risk;
- transport-neutral error objects.
