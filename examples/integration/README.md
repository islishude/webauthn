# Existing-account integration

Run from the repository root:

```sh
go test -race ./examples/integration
```

This is a tested application-service example, not another HTTP server. Use the
[quickstart](../quickstart) for native browser JSON conversion and the
[HTTP example](../http) for transport helpers. Construct the reusable RP with
`preset.PasskeyConfig` and `webauthn.New`, as shown in `newHarness` in
`app_test.go` and the executable `ExampleNew` in the root package.

`application` receives application-owned `accountStore`, `ceremonyStore`,
`credentialStore` and `sessionStore` implementations. `memory.go` supplies a
bounded ceremony store, encoded credential storage and application row versions.
Accounts and enrollment grants represent the host application's existing
identity system. Provision those through your application's authentication;
never grant enrollment merely from a submitted username.

- `beginEnrollment` and `finishEnrollment` recheck the current authenticated
  session's enrollment authorization and bind the ceremony to that account.
- `beginLogin` uses a non-empty username for account-bound login and an empty
  username for discoverable login. Known accounts without credentials fail;
  they never silently fall back to another login mode.
- `finishLogin` consumes matching state before parsing, verifies a credential
  found using untrusted lookup hints, evaluates risk, persists conditionally,
  and only then creates the session for `AuthenticatedAs`.

The example rejects clone risk and pending UV initialization with `errRisk`.
The application can route that result to its own additional authentication flow;
this example does not supply one. The library and passkey preset continue to
report clone risk by default. No extensions are requested. For an optional
`credProps` request, inspect `extension.Find(results, extension.CredPropsHandler{})`
and `Accepted` before using its output; absence proves no discoverability fact.

Replace the memory implementations with your own storage, authenticated account
lifecycle, session rotation/expiry, CSRF protection and endpoint rate limits. An
opaque initiating session is required for both login modes. The example does not
issue browser cookies or implement password login, enrollment bootstrapping or
account recovery. Map errors to generic public responses; keep typed categories
for internal control flow and avoid logging raw error chains or protocol data.

See [persistence contracts and reference SQL](../../docs/persistence.md). Tests
use independently generated project fixtures and real signing/verification. They
cover encoded state/credential round trips, two accounts, both login modes,
replay, expiry, revocation, state binding, duplicates, malformed input, risk,
storage failure and concurrent insert/consume/update behavior.
