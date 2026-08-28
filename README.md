# webauthn

`github.com/islishude/webauthn` is a Go server-side WebAuthn/passkey
relying-party library.

The core package is intentionally framework-neutral. It creates and verifies
registration and authentication ceremonies, then returns credential records,
conditional credential updates, attestation results, extension results, and policy outcomes for
the application to persist in its own storage.

Current status: implementation is complete. The repository has
transport-neutral registration and authentication APIs, optional attestation
format packages, a 25 August 2026 WebAuthn Level 3 Recommendation
baseline, strict CTAP2 canonical CBOR/COSE validation, Level 3 extension handlers
with deprecated `uvm` retained, a separately opt-in non-normative
`remoteClientDataJSON` preview handler, optional browser JSON and
standard-library HTTP helpers, compile-checked examples, a complete 45-case W3C
Level 3 vector inventory, real-browser conformance tests, fuzz smoke targets,
import graph checks, dependency license checks, and release documentation.

The release checklist is tracked in `docs/release.md`.

## What It Provides

The root package supports the relying-party ceremony flow:

1. Create registration options.
2. Verify registration responses.
3. Create authentication options.
4. Verify authentication assertions.
5. Return verified credential state plus explicit conditional updates.

Implemented areas:

| Area                | Status                                                                                                                                              |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Registration        | Transport-neutral start and finish APIs, including conditional-mediation state binding.                                                             |
| Authentication      | Username-first and discoverable credential/passkey flows.                                                                                           |
| Attestation formats | Optional `none`, `packed`, `fido-u2f`, `tpm`, `android-key`, legacy `android-safetynet`, `apple`, and `compound` packages.                          |
| Attestation trust   | Explicit caller-selected trust policies, trust-root hooks, metadata hooks, certificate status hooks, and AAGUID rules.                              |
| Extensions          | Recommendation `appid`, `appidExclude`, `credProps`, `largeBlob`, and `prf`; deprecated `uvm` and non-default `remoteClientDataJSON` remain opt-in. |
| Browser transport   | Optional JSON DTO conversion helpers in `browser` using unpadded base64url for WebAuthn binary fields and Level 3 DTOs.                             |
| HTTP transport      | Optional bounded JSON read/write helpers in `transport/http`.                                                                                       |
| Signature verifier  | Optional standard-library verifier for common EC, RSA PKCS#1/PSS, and Ed25519 algorithms; Ed448 routes through caller adapters.                     |
| Server storage JSON | Optional versioned, bounded encoding for trusted server-side ceremony state and credential records.                                                 |
| Examples            | Compile-checked manual, HTTP, passkey, and attestation examples.                                                                                    |
| Quality gates       | Formatting, linting, unit tests, race tests, fuzz smoke tests, examples, import graph checks, and license checks.                                   |

## Design Principles

The library is built around a few constraints that are enforced by tests and CI:

- the root package does not depend on `net/http`, routers, sessions, cookies,
  CSRF mechanisms, account lookup, databases, or persistence adapters;
- applications supply trusted origins, RP IDs, stored ceremony state, user
  bindings, credential storage, rate limits, sessions, and audit behavior;
- finish operations reject caller-stored state that omits its expiry or resolved
  user-verification policy;
- WebAuthn byte values stay byte-oriented in the core API, while browser JSON
  conversion lives in optional packages;
- attestation formats are selected explicitly by the caller and are not imported
  automatically by the root package;
- attestation statement validity and relying-party trust acceptance are separate
  results;
- foundational cryptography and codecs are delegated to the Go standard library,
  explicit dependencies, or injected interfaces instead of being reimplemented
  here.

No implementation logic or tests may be copied, translated, adapted, or derived
from public WebAuthn/passkey libraries. Stable protocol behavior is based on the
[25 August 2026 WebAuthn Level 3 Recommendation](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/).
All Level 3 conformance claims and default behavior follow this Recommendation
exclusively. The separate `remoteClientDataJSON` preview handler is excluded
from the default Level 3 registries and from the conformance baseline. MDN is
used only for browser-facing context and terminology.

## Package Layout

The package graph is designed so applications only import what they need:

- root `webauthn`: registration and authentication ceremony APIs;
- `protocol`: WebAuthn values, option dictionaries, collected client data, and
  authenticator data parsing;
- `codec`: CBOR attestation object, COSE key, and extension map decoder
  contracts;
- `codec/cbor`: optional concrete CBOR and COSE_Key decoder;
- `crypto`: algorithm policy, signature, certificate-chain, and JWS/JWT verifier
  contracts;
- `crypto/standard`: optional common-algorithm verifier using Go cryptography;
- `attestation`: format verifier registry and trust policy contracts;
- `attestation/none`: optional `none` verifier;
- `attestation/packed`: optional `packed` self and x5c verifier;
- `attestation/fidou2f`: optional `fido-u2f` verifier;
- `attestation/tpm`: optional `tpm` verifier;
- `attestation/androidkey`: optional `android-key` verifier;
- `attestation/androidsafetynet`: optional `android-safetynet` verifier;
- `attestation/apple`: optional Apple anonymous attestation verifier;
- `attestation/compound`: optional `compound` verifier that dispatches
  sub-statements through a caller-supplied attestation registry;
- `extension`: operation-aware extension handler registry, Level 2 compatibility
  handlers, and Level 3 registry helpers;
- `browser`: optional browser JSON DTO conversion helpers;
- `transport/http`: optional standard-library HTTP JSON helpers;
- `storage/json`: optional versioned server-side state/credential encoding;
- `tools/checklicenses`: local dependency manifest checker.

The root package import graph must not include `net/http`, `browser`,
`transport/http`, `crypto/standard`, `storage/json`, or optional attestation
format packages.

## Examples

Public examples are compiled by `make example-build` and by CI:

- `examples/manual` shows framework-neutral registration and authentication
  wiring with caller-owned ceremony state and credential storage.
- `examples/http` shows how to use the optional `transport/http` JSON helpers
  with `net/http`, per-session one-time state, expiry, atomic credential
  insertion, and conditional credential updates.
- `examples/passkey` shows discoverable credential authentication, including
  lookup by returned user handle and credential ID before verification.
- `examples/attestation` shows explicit attestation format selection and a
  restricted enrollment trust policy.

The README intentionally points to compile-checked examples instead of carrying
untested Go snippets.

## Security Model

The core package never infers trusted origins from request headers and never
creates sessions, cookies, database records, or account bindings. Applications
must store ceremony state server-side without dropping required fields, enforce
single use, atomically insert unique credential IDs, map user handles to
accounts, persist conditional credential updates, rate-limit endpoints, and
provide their own session and CSRF protections.

Safe behavior is the default shape:

- challenges are server-generated and compared against their exact canonical
  unpadded base64url encoding;
- origins and RP IDs are explicit policy inputs;
- cross-origin `topOrigin` checks are explicit `OriginPolicy` inputs;
- a present `topOrigin` cannot be collapsed into an absent value;
- user presence is required except for ceremony state explicitly bound to
  conditional registration mediation;
- user verification is enforced according to ceremony policy;
- invalid backup-state flags and authentication-time backup-eligibility changes
  are rejected;
- signature counter rollback is surfaced as clone risk;
- clone-risk counters are preserved unless explicit policy authorizes updating;
- zero-value ceremony timeouts expire after five minutes;
- incomplete caller-stored ceremony state fails closed;
- unsupported algorithms and formats are rejected;
- extension and attestation identifiers and concrete CBOR/COSE encodings are
  validated against their Level 3 grammar and canonical form;
- attestation acceptance requires caller-supplied trust policy such as
  `attestation.AcceptNone()` for consumer passkey `none` attestation;
- unknown, unsolicited, or unrequested extensions are ignored or rejected
  according to explicit extension policy;
- optional HTTP helpers write generic errors and do not expose raw protocol
  material.

More detail is recorded in `docs/security-model.md`.

## Dependencies

The root API is kept behind narrow interfaces where possible. Concrete
dependencies used for CBOR and COSE decoding live in the optional `codec/cbor`
package, and dependency inventory is maintained in `docs/dependencies.json`.

Before adding a dependency, document why it is needed, which protocol surface it
supports, whether it is root or optional, whether replacing it affects public API
compatibility, and its license.

## Development

The module path is `github.com/islishude/webauthn`; `go.mod` records Go
`1.25.0`.

Run commands from the repository root.

```sh
make ci
```

`make ci` is the required local readiness gate. It runs documentation checks,
README checks, formatting checks, linting, unit tests, race tests, bounded fuzz
smoke tests, example builds, root import graph checks, dependency license checks,
and module tidy verification.

Useful narrower targets:

- `make format` rewrites Go and repository text formatting.
- `make format-check` verifies formatting.
- `make lint` runs golangci-lint.
- `make test` runs unit tests.
- `make test-race` runs race-enabled tests.
- `make test-fuzz-smoke` runs bounded fuzz targets.
- `make example-build` builds public examples.
- `make import-graph-check` verifies root package dependency boundaries.
- `make license-check` verifies dependency manifest coverage.
- `make readme-check` verifies README example references.
- `make browser-fixtures` regenerates virtual-authenticator browser fixtures.
- `make e2e` runs Chromium native-CDP and Playwright Credentials passkey tests.
- `make mod-check` runs `go mod tidy` and verifies module file cleanliness.

CI behavior is documented in `docs/ci.md`.

## Documentation

- `AGENTS.md` defines repository rules for automated contributors.
- `docs/technical.md` describes architecture and package boundaries.
- `docs/protocol-map.md` maps WebAuthn Level 3 protocol areas to packages.
- `docs/api-boundaries.md` defines public API and transport boundaries.
- `docs/security-model.md` records security and privacy decisions.
- `docs/testing.md` defines the test and conformance strategy.
- `docs/ci.md` documents local and GitHub Actions quality gates.
- `docs/release.md` tracks release-readiness requirements and notes.
- `docs/dependencies.json` records module dependency licenses and scope.

When scope, deliverables, tests, dependencies, package boundaries, or quality
gates change, update the relevant docs in the same change.

## Release Readiness

A release candidate requires:

- local `make ci` passing from a clean worktree;
- GitHub Actions passing on the release branch;
- root import graph independence from optional attestation, browser, HTTP,
  standard crypto, storage JSON, and `net/http` packages;
- compile-checked examples for framework-neutral and optional HTTP integration;
- conformance coverage documented in `docs/testing.md`;
- dependency inventory in `docs/dependencies.json` matching `go list -m all`;
- README claims matching implemented and tested behavior.
