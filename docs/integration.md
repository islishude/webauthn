# Integration guide

Start with `preset.PasskeyConfig(rp, origins)`, customize explicitly if needed,
then call `webauthn.New(config)` once at application startup. See the executable
Go example attached to `New`, [passkey wiring](../examples/passkey/main.go),
[HTTP wiring](../examples/http/main.go), and the runnable
[quickstart](../examples/quickstart). The latter is one shared demo account,
not an account-enrollment or account-recovery policy for a production service.

## Choose policy once

`Config` uses required RP/origin values, all three decoders, a signature
verifier, an algorithm policy, an attestation registry and an explicit trust
policy. Registration and authentication defaults are grouped separately.
The constructor validates values without generating challenges, calling the
clock or performing cryptographic/trust verification. It queries the algorithm
policy, which must accept every advertised algorithm. Custom adapters remain
responsible for actually supporting those algorithms.

The passkey preset requires discoverable credentials and UV for both ceremonies,
accepts only none attestation, and imposes no attachment restriction. It uses
EdDSA/ES256/RS256 in both advertisement and verification. This is an explicit
preference list: leaving low-level credential parameters empty still selects
ES256/RS256. Neither the preset nor registration success proves hardware binding.

Root defaults remain a five-minute browser hint and a ten-minute server state
lifetime. Configure both when shortening the lifetime. The default counter
policy reports clone risk without rolling back the stored count. Review
`Counter`, `UserVerified` and `UVInitializationPending` for application policy.

Configuration slices and selection criteria are copied. Supplied decoders,
policies, registries, generators and clocks must be stable and concurrency-safe.
Do not mutate their implementations after construction. RP methods return
`ErrInvalidConfiguration` for nil/uninitialized objects.

## Registration and browser transport

Use a stable opaque user handle, unrelated to email or username. Pass all
existing account credential descriptors to registration so the browser can
exclude them. The browser receives only `start.Options` through `browser` or
`transport/http`; `start.State` stays in trusted server storage.

On the frontend use `PublicKeyCredential.parseCreationOptionsFromJSON`,
`navigator.credentials.create`, and `credential.toJSON()`. Authentication uses
`parseRequestOptionsFromJSON` and `navigator.credentials.get`. Check capabilities
before use. The server expects the complete Level 3 JSON shape, not a hand-built
subset. The public quickstart demonstrates these native calls without test shims.
Conditional creation additionally requires a capability check and matching outer
`mediation: "conditional"`; only then set `ConditionalMediation` in the request.

## Authentication and persistence

Username-first login passes `ExpectedUserHandle` and the account's
`AllowCredentials`. Discoverable login leaves both empty. Its returned user
handle and raw credential ID are **untrusted lookup hints** until verification
succeeds. Look up both together and pass the stored record to finish. Do not
establish identity merely because the database lookup succeeded.

Atomically consume each ceremony state before finish, even when parsing or
verification will fail. Bind it to the initiating browser/session and account
where applicable; enforce expiry, capacity limits and endpoint rate limits.
`storage/json` preserves required fields and extension bindings but provides no
storage I/O, sealing or replay prevention. Persist the complete v3 state; do not
serialize root byte wrappers with ordinary JSON or place unsealed state in cookies.

After registration use a database uniqueness constraint on credential ID. After
authentication apply `result.Update` conditionally: compare ID plus all of
`PreviousSignCount`, `PreviousBackupState`, `PreviousUVInitialized`, and
`PreviousAuthenticatorAttachment`, then update only the `*Changed` fields. Zero
counters do not remove the other comparisons. A conflict must not be ignored;
require a new attempt or an explicit application transaction/reverification
strategy. The comparison checks values, not a database revision; applications
that require detecting intervening writes should additionally use their own row
version or transaction. Create the session only after successful persistence.

Replace the quickstart's maps with application storage, authenticated enrollment
and recovery, HTTPS cookies, CSRF protections and rate limits before deployment.
The public HTTP example shows primitives and account/session integration points;
the localhost quickstart deliberately uses one shared demo account and fixed host.

## Extensions, state changes and errors

Request extensions explicitly. Read known results with `extension.Find` and
check `Accepted`; `FindRaw` preserves untrusted unknown/unrequested evidence.
Default registries omit UVM and preview handlers. Legacy callers can explicitly
select `NewLevel3RegistryWithDeprecated` and request UVM; keep that compatibility
configuration out of normal passkey enrollment.

Persist exact extension `Binding` ID/revision pairs. Finish requires compatible
handlers; changed RP/origin policy, UV, registration algorithms or conveyance is
also rejected by the RP object. Configuration order is retained, including origin
and algorithm lists. Start a new ceremony after changing these values. Clock,
timeout and stateless policies are not a stored config-version token; the state
retains its expiry and currently selected trust/counter policies still apply.

Use `errors.Is` for the existing sentinels and `errors.As` for typed field/length
errors; see [executable error classification](../examples/passkey/errors_test.go).
Treat invalid configuration/state/credential storage as operator issues, expired
state as a fresh-attempt condition, malformed input as a request failure, and
signature/ownership/trust failures as authentication or policy rejections.
Cancellation takes precedence when classifying wrapped adapter errors. Storage
I/O and conflicts belong to the application. Helpers return generic client
errors; do not log raw error chains containing adapter-supplied secrets.
