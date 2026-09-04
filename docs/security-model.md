# Security and privacy model

Status: Level 3 ceremony state, extension handling, attestation trust policy, standard verification, storage encoding, and optional transport helpers implemented, revised 2026-09-04.

This document records security and privacy decisions that implementation must preserve.

## Threat model

The library verifies WebAuthn relying-party server inputs from browsers and authenticators. Inputs must be treated as attacker-controlled until verified. The attacker may control the network client, submit malformed CBOR/JSON/binary fields, replay old ceremonies, swap origins, attempt credential confusion between users, exploit unsupported extensions, or use cloned authenticators.

The library does not protect the application from insecure account recovery, compromised sessions, weak TLS termination, unsafe frontend JavaScript, database compromise, or incorrect caller policy. It must provide clear outputs so the application can make correct decisions.

## Challenge policy

Challenges must be generated in a trusted server-side environment, stored temporarily by the relying party, and compared exactly during verification. The default generator should use sufficient entropy and should target at least 32 random bytes unless a caller deliberately overrides it. Inputs shorter than the WebAuthn minimum should be rejected by default.

Challenge mismatch is a hard protocol failure. Client data must contain the
exact canonical unpadded base64url encoding, not merely another string that
decodes to the same bytes. The library must not offer a permissive mode that
accepts mismatches.

## Origin and RP ID policy

The core library must not infer trusted origins from HTTP request headers. The caller supplies allowed origins and RP ID policy explicitly.

Configuration accepts only canonical scheme-and-authority origins: HTTPS is
required except for loopback HTTP, hostnames and IP literals must use canonical
lowercase serialization, explicit default or malformed ports are rejected, and
RP IDs must be lowercase DNS names. Allowed origin hosts are scoped to the RP ID
by default. `AllowRelatedOrigins` is an explicit delegation point: the caller
must validate the related-origin relationship independently and still list each
accepted origin exactly.

Registration and authentication verification must compare `CollectedClientData.origin` to the configured origin policy. `topOrigin` presence is tracked separately: present null, empty, or non-string values are malformed, while a valid present value must be explicitly allowed and paired with `crossOrigin`. Authenticator data `rpIdHash` must match SHA-256 of the expected RP ID, except when authentication explicitly uses the AppID extension and the client output indicates AppID was used.

Cross-origin use must be policy-controlled. The presence of `crossOrigin` must not be ignored if the application has configured a strict policy.

`CollectedClientData.tokenBinding` is reserved in the Level 3 target. The parser
preserves it for callers that inspect raw client data, but relying-party
verification does not accept or reject ceremonies based on token binding status
or ID.

## User presence and user verification

User presence is required for authentication and for ordinary registration. The
Level 3 conditional-registration exception is honored only when trusted
ceremony state records that the caller used `mediation: "conditional"`; its
zero value keeps the fail-closed UP requirement. The caller must separately
check the client's `conditionalCreate` capability and set the browser option.
User verification must be enforced according to the configured ceremony policy.
If user verification is required and the UV flag is not set, verification fails.

If user verification is preferred or discouraged, the result should be surfaced so the application can record or risk-score the ceremony.

Credential records retain `uvInitialized`. A false-to-true authentication-time
transition is returned as pending unless the caller explicitly confirms that an
equivalent additional authentication factor authorized the change.

## Credential backup state

The verifier rejects BS when BE is not set. `backupEligible` is captured at
registration and must remain identical on every assertion; only `backupState`
is mutable. Applications receive changed flags separately so persistence can use
conditional updates.

Authentication validates caller-stored credential type, ID, user handle, RP ID,
raw public key, attestation type, attachment, and the stored BE/BS invariant
before using it. Conditional persistence must compare the previous counter,
backup state, UV-initialization state, and authenticator attachment together;
checking only a nonzero counter does not prevent lost updates for zero-counter
authenticators.

## Credential ownership and user handle policy

Username-first authentication and discoverable-credential authentication have different ownership checks.

In username-first flows, the caller already identified an account and passes stored credential material for that account. If the assertion includes a user handle, it must map to the same account.

In discoverable-credential flows, the assertion must include a user handle and the application must map that handle and credential ID to an account. The library should provide the checks and result shape but should not own the account database.

Credential ID uniqueness at registration is an application-level persistence
decision. After verification, the application must insert the returned
credential using an atomic uniqueness constraint. A preflight lookup followed by
a separate insert is not sufficient, and the core does not accept or return a
caller-computed uniqueness boolean.

## Signature verification

Authentication signatures are verified over authenticator data concatenated with SHA-256 of the serialized client data. Attestation signatures are verified according to their statement format.

The project must not implement cryptographic primitives. Signature verification and key parsing must be delegated to standard library code or adapter dependencies. The WebAuthn layer is responsible for selecting the correct signature base, algorithm policy, and protocol binding checks.

The concrete CBOR adapter rejects non-canonical CTAP2 encodings, tags,
indefinite lengths, duplicate or extra attestation-object keys, and optional or
private COSE key parameters. RSA values must be minimally encoded and use a
2048–16384 bit modulus. Authenticator RFU flag bits are rejected. These
checks occur before decoded material reaches signature or trust policy.
Each CBOR value is additionally bounded to 1 MiB, 16 levels, 64 array elements,
and 64 map pairs. Compound attestation verifies at most 16 statements by
default; a caller may configure 2 through 64, but cannot remove the hard bound.

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
TPM statement signatures remain fail-closed to the normative `TPMT_SIGNATURE`
shape; a raw DER ECDSA signature is not accepted as a compatibility form.
Format verifiers must also return a known attestation type and one of the
package's explicit `none`, `x5c`, or raw trust-path representations; unknown
result classifications are rejected before relying-party trust policy runs.

The current default remains conservative. Without a caller-supplied `attestation.TrustPolicy`, registration rejects every attestation after format verification. Callers that accept consumer passkey `none` attestation must pass an explicit policy such as `attestation.AcceptNone()`. Optional `packed`, `fido-u2f`, `tpm`, `android-key`, legacy `android-safetynet`, `apple`, and `compound` verification can prove statement validity, but x5c trust-chain acceptance is still a relying-party decision.

The `attestation` package provides explicit trust policy building blocks for `none`, self attestation, format and type allow-lists, x5c trust-root verification through caller-provided certificate verifiers, AAGUID allow-lists, caller-owned metadata lookup, caller-owned certificate status checks, and policy composition. These policies do not include built-in trust anchors, network fetching, metadata caches, or automatic restricted-enrollment defaults.

Format, type, and AAGUID allow-lists classify evidence but do not establish
X.509 trust. Restricted enrollment must compose them with trusted roots or
trusted metadata and certificate-status policy. The public attestation example
does so and rejects self-signed or revoked paths.

Legacy SafetyNet verification additionally requires expected Android package
and application-signing-certificate digests, a bounded timestamp window, an
integrity requirement, and an optional version allow-list. JWS verification and
outer Google-root/status acceptance remain separate requirements.

Compound attestation returns successful sub-results as raw trust evidence.
`RequireTrustedRoots` deliberately does not treat that aggregate as an X.509
path; callers accepting `compound` must recursively evaluate the trust of enough
successful sub-statements rather than relying on a format allow-list alone.

The storage-neutral `CredentialRecord` does not retain attestation chains.
Deployments that need later CA-revocation response or metadata re-evaluation
must persist the `RegistrationResult.Attestation` evidence in an application
schema indexed by the credential.

## Extension policy

Extensions are optional for clients and authenticators. Known inputs are
validated before the ceremony is emitted. Missing requested outputs are
surfaced as not accepted, while unknown-output rejection applies only when an
output actually exists. Output handlers run only after core cryptographic and
attestation trust checks succeed.

Extension outputs must not be elevated into security facts unless the extension
handler has validated them and the relying-party policy accepts them. Unknown
and unrequested extension outputs are preserved as recursively copied, untrusted
raw results by default, including nested maps with non-string comparable CBOR
keys; callers can set `RejectUnknown` or `RejectUnrequested` for fail-closed
behavior. Rejection policy is applied before raw-value copying.

Known handlers normalize raw boundary data into typed inputs and outputs. The
heterogeneous registry erases those types only internally; callers recover a
known output through `extension.Find` and cannot access the erased value
directly. `RawValue` preserves absent versus explicit-null state and returns
defensive copies. `FindRaw` is reserved for unknown or unrequested evidence and
does not mark that evidence accepted.

Custom extension handlers must be deterministic and side-effect-free because a
later caller-owned atomic insert or persistence conflict can still reject an
otherwise verified registration result.

Every handler supplies a stable semantic revision. Ceremony state persists the
sorted ID/revision binding from start, and finish rejects missing, added, or
changed known bindings before output interpretation. Package-reserved built-in
IDs cannot use unknown-extension fallback. Registries and each ceremony's
combined extension ID set are limited to 64. Defensive raw-value copies are
limited to depth 32, 4096 nodes, and 1 MiB, and output dispatch observes context
cancellation between handlers. Typed result lookup also requires the querying
handler's current ID and revision to match the frozen result.

The AppID extension selects exactly one expected hash: `appid=true` requires the
AppID hash and request/policy agreement, while false or absent output requires
the ordinary RP ID hash.

The PRF extension validates requested inputs, output result lengths, and
`evalByCredential` binding to the authentication allow-credentials list,
operation-specific output members, result cardinality, and the equal-input
equal-output invariant. Authentication results are matched only against the
actual selected credential's `evalByCredential` entry, or `eval` when that entry
is absent. A missing selected-credential context fails closed when credential-
specific inputs could affect the result. PRF
outputs are extension results for caller policy and storage; they are not login
success criteria by themselves.

When a client implements PRF over CTAP `hmac-secret`, signed authenticator data
can contain an unrequested `hmac-secret` output that the RP cannot interpret.
The default policy ignores it. Enabling `RejectUnknown` or `RejectUnrequested`
intentionally trades that interoperability for stricter local policy.

Authentication requests for `largeBlob` require a registered handler so the
single-credential write constraint is enforced before state is emitted and
again after restoration. Writes require exactly one allowed credential and a
`written` result. An `appidExclude` output, when present, must be true. Editor's Draft
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
- Logs must not include challenges, credential IDs, user handles, signatures,
  client data JSON, attestation objects, PRF results, largeBlob contents, or
  other extension secrets unless the application explicitly opts into sensitive
  debug logging.

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
- invalid or non-canonical base64url challenge and transport values.

## Time and replay

The browser timeout hint defaults to five minutes while trusted challenge state
defaults to a separate ten-minute lifetime. Finish rejects missing
expiry or unresolved user-verification policy as invalid state and rejects at
the exact deadline. Callers must still atomically consume state once; optional
`storage/json` serializes trusted server-side state but does not enforce replay
prevention or make it safe for client-side cookies.

Registration and authentication start/finish options accept an injectable clock
where timeout or expiry state is evaluated. Production callers can rely on the
default wall clock, while tests and deterministic lifecycle policy can provide a
fixed clock.

## Optional transport helpers

The optional `browser` package only converts between browser JSON DTOs and transport-neutral protocol values. It treats browser JSON as attacker-controlled, requires Level 3 `toJSON()` members, binds canonical `id` to `rawId`, rejects malformed JSON and invalid base64url encodings, validates decoded byte-oriented protocol values, and preserves unknown extension results as untrusted values for later policy handling.

Browser response JSON has a fixed 1 MiB decoder limit. The redundant unsigned
registration `response.publicKey` is syntax-checked when present but is not
carried into the root response; the signed authenticator-data COSE key remains
authoritative.

The optional `transport/http` package only reads bounded JSON request bodies and
writes JSON responses. It serializes a response before committing HTTP headers,
does not infer trusted origins from request headers, does not create sessions or
cookies, and does not persist ceremony state or credentials. Its `WriteError`
helper emits generic status text rather than raw error strings, so credential
IDs, challenges, user handles, signatures, client data JSON, attestation objects,
and assertion bytes are not reflected by default.

## Safe defaults checklist

Before stable release, defaults should be:

- 32-byte server-generated random challenges;
- exact challenge comparison;
- five-minute browser timeout, ten-minute challenge lifetime, and exact-deadline
  rejection;
- explicit allowed origins;
- canonical origin/RP-ID configuration, with related origins opt-in only;
- explicit allowed top origins for cross-origin ceremonies;
- explicit RP ID;
- user presence required except for explicitly bound conditional registration;
- user verification enforced when policy says required;
- `none` attestation accepted only when explicit trust policy allows it;
- non-`none` attestation accepted only when caller trust policy accepts it;
- unsupported attestation formats rejected;
- unsupported algorithms rejected;
- malformed/non-canonical CBOR, optional/private COSE parameters, RFU flags,
  and invalid identifier grammar rejected;
- unsolicited extensions ignored or rejected by configured policy;
- exact start/finish handler bindings and bounded extension/CBOR/browser work;
- Editor's Draft extensions absent from default Level 3 registries;
- counter rollback surfaced as clone risk;
- stored counter preserved on clone risk unless explicit policy updates it;
- BE/BS invariants and immutable backup eligibility;
- transport-neutral error objects;
- optional HTTP helper errors written generically without raw protocol material.
