# webauthn

`github.com/islishude/webauthn` is a Go server-side WebAuthn/passkey
relying-party library.

The core package is intentionally framework-neutral. It creates and verifies
registration and authentication ceremonies, then returns credential records,
counter updates, attestation results, extension results, and policy outcomes for
the application to persist in its own storage.

Current status: implementation is complete through Plan 09. The repository has
transport-neutral registration and authentication APIs, optional attestation
format packages, WebAuthn Level 2 extension handlers, optional browser JSON and
standard-library HTTP helpers, compile-checked examples, conformance-oriented
tests, fuzz smoke targets, import graph checks, dependency license checks, and
release documentation.

The release checklist is tracked in `docs/release.md`.

## What It Provides

The root package supports the relying-party ceremony flow:

1. Create registration options.
2. Verify registration responses.
3. Create authentication options.
4. Verify authentication assertions.
5. Return persistence-ready credential and counter state.

Implemented areas:

| Area                | Status                                                                                                                 |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Registration        | Transport-neutral start and finish APIs.                                                                               |
| Authentication      | Username-first and discoverable credential/passkey flows.                                                              |
| Attestation formats | Optional `none`, `packed`, `fido-u2f`, `tpm`, `android-key`, `android-safetynet`, and `apple` packages.                |
| Attestation trust   | Explicit caller-selected trust policies, trust-root hooks, metadata hooks, certificate status hooks, and AAGUID rules. |
| Extensions          | WebAuthn Level 2 `appid`, `appidExclude`, `uvm`, `credProps`, and `largeBlob` handling.                                |
| Browser transport   | Optional JSON DTO conversion helpers in `browser` using unpadded base64url for WebAuthn binary fields.                 |
| HTTP transport      | Optional bounded JSON read/write helpers in `transport/http`.                                                          |
| Examples            | Compile-checked manual, HTTP, passkey, and attestation examples.                                                       |
| Quality gates       | Formatting, linting, unit tests, race tests, fuzz smoke tests, examples, import graph checks, and license checks.      |

## Design Principles

The library is built around a few constraints that are enforced by tests and CI:

- the root package does not depend on `net/http`, routers, sessions, cookies,
  CSRF mechanisms, account lookup, databases, or persistence adapters;
- applications supply trusted origins, RP IDs, stored ceremony state, user
  bindings, credential storage, rate limits, sessions, and audit behavior;
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
from public WebAuthn/passkey libraries. Protocol behavior is based on W3C Web
Authentication Level 2, with MDN used only for browser-facing context and
terminology.

## Package Layout

The package graph is designed so applications only import what they need:

- root `webauthn`: registration and authentication ceremony APIs;
- `protocol`: WebAuthn values, option dictionaries, collected client data, and
  authenticator data parsing;
- `codec`: CBOR attestation object, COSE key, and extension map decoder
  contracts;
- `codec/cbor`: optional concrete CBOR and COSE_Key decoder;
- `crypto`: hashing, signature, certificate-chain, and JWS/JWT verifier
  contracts;
- `attestation`: format verifier registry and trust policy contracts;
- `attestation/none`: optional `none` verifier;
- `attestation/packed`: optional `packed` self and x5c verifier;
- `attestation/fidou2f`: optional `fido-u2f` verifier;
- `attestation/tpm`: optional `tpm` verifier;
- `attestation/androidkey`: optional `android-key` verifier;
- `attestation/androidsafetynet`: optional `android-safetynet` verifier;
- `attestation/apple`: optional Apple anonymous attestation verifier;
- `extension`: operation-aware extension handler registry and Level 2 handlers;
- `browser`: optional browser JSON DTO conversion helpers;
- `transport/http`: optional standard-library HTTP JSON helpers;
- `tools/checklicenses`: local dependency manifest checker.

The root package import graph must not include `net/http`, `browser`,
`transport/http`, or optional attestation format packages.

## Examples

Public examples are compiled by `make example-build` and by CI:

- `examples/manual` shows framework-neutral registration and authentication
  wiring with caller-owned ceremony state and credential storage.
- `examples/http` shows how to use the optional `transport/http` JSON helpers
  with `net/http`.
- `examples/passkey` shows discoverable credential authentication, including
  lookup by returned user handle and credential ID before verification.
- `examples/attestation` shows explicit attestation format selection and a
  restricted enrollment trust policy.

The README intentionally points to compile-checked examples instead of carrying
untested Go snippets.

## Security Model

The core package never infers trusted origins from request headers and never
creates sessions, cookies, database records, or account bindings. Applications
must store ceremony state server-side, enforce single use and expiry, map user
handles to accounts, persist credential counter updates, rate-limit endpoints,
and provide their own session and CSRF protections.

Safe behavior is the default shape:

- challenges are server-generated and compared exactly;
- origins and RP IDs are explicit policy inputs;
- user presence is required;
- user verification is enforced according to ceremony policy;
- signature counter rollback is surfaced as clone risk;
- unsupported algorithms and formats are rejected;
- non-`none` attestation requires caller-supplied trust acceptance;
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
- `make mod-check` runs `go mod tidy` and verifies module file cleanliness.

CI behavior is documented in `docs/ci.md`.

## Documentation

- `AGENTS.md` defines repository rules for automated contributors.
- `docs/technical.md` describes architecture and package boundaries.
- `docs/protocol-map.md` maps WebAuthn Level 2 protocol areas to packages.
- `docs/api-boundaries.md` defines public API and transport boundaries.
- `docs/security-model.md` records security and privacy decisions.
- `docs/testing.md` defines the test and conformance strategy.
- `docs/ci.md` documents local and GitHub Actions quality gates.
- `docs/release.md` tracks release-readiness requirements and notes.
- `docs/dependencies.json` records module dependency licenses and scope.
- `docs/plans.md` indexes the implementation plans.
- `docs/plans/*.md` contains the detailed plan history.

When plan status, scope, deliverables, tests, dependencies, package boundaries,
or quality gates change, update the relevant docs in the same change.

## Release Readiness

A release candidate requires:

- all P0 and P1 plans in `docs/plans.md` complete;
- Plan 09 release hardening complete;
- local `make ci` passing from a clean worktree;
- GitHub Actions passing on the release branch;
- root import graph independence from optional attestation, browser, HTTP, and
  `net/http` packages;
- compile-checked examples for framework-neutral and optional HTTP integration;
- conformance coverage documented in `docs/testing.md`;
- dependency inventory in `docs/dependencies.json` matching `go list -m all`;
- README claims matching implemented and tested behavior.
