# webauthn

`github.com/islishude/webauthn` is planned as a Go server-side library for WebAuthn/passkey relying-party behavior.

Current status: Plan 09 is complete. Registration and authentication ceremony behavior is implemented; registration supports the `none` attestation path, optional `packed` self/x5c, `fido-u2f`, `tpm`, `android-key`, `android-safetynet`, and `apple` attestation verification; caller-supplied attestation trust policies, trust-root checks, metadata hooks, certificate-status hooks, AAGUID allow-lists, WebAuthn Level 2 extension handlers, browser JSON DTO helpers, optional standard-library HTTP JSON helpers, compile-checked examples, conformance-oriented tests, fuzz smoke targets, browser virtual-authenticator fixtures, import graph checks, dependency license checks, README checks, and release documentation are available.

## Goals

The library is designed to make WebAuthn easy to add to existing Go services without coupling the core to `net/http`, a specific web framework, a database layer, or a session mechanism.

The root module will focus on WebAuthn relying-party ceremonies:

- create registration options;
- verify registration responses;
- create authentication options;
- verify authentication assertions;
- return credential records, counter updates, attestation results, and policy decisions that an application can persist in its own storage.

The implementation must support complete WebAuthn Level 2 relying-party protocol behavior before a stable release. Passkey use cases are covered through WebAuthn discoverable credentials, user handles, user verification policy, authenticator selection, and browser-facing option structures.

## Design constraints

The project deliberately avoids implementing foundational cryptography and encoding libraries. It may implement WebAuthn-specific structure parsing and validation, but general-purpose CBOR, COSE, ASN.1, JWS, X.509, JSON, base64url, and cryptographic primitives must come from Go standard library packages, explicit dependencies, or injected interfaces.

The core package must stay transport-neutral. Optional browser and HTTP helpers live outside the root package, so the core API remains usable from any HTTP router, RPC service, command flow, test harness, or custom integration.

Attestation support must be modular. Importing the root module should not import every attestation verifier. Applications should select the formats they accept, such as `none`, `packed`, `tpm`, `android-key`, `android-safetynet`, `fido-u2f`, and `apple`, according to their policy and dependency appetite.

No public WebAuthn/passkey library implementation may be used, copied, translated, adapted, or referenced as source material.

## Local development workflow

The repository quality gate is active for the Go module.

Use these commands from the repository root:

- `make format` rewrites Go and Markdown formatting.
- `make format-check` verifies Go and Markdown formatting.
- `make lint` runs golangci-lint.
- `make test` runs unit tests.
- `make test-race` runs race-enabled tests.
- `make test-fuzz-smoke` runs each bounded fuzz target separately.
- `make example-build` builds public examples.
- `make import-graph-check` verifies root package dependency boundaries.
- `make license-check` verifies Go module dependency license manifest coverage.
- `make readme-check` verifies README references compile-checked examples.
- `make browser-fixtures` regenerates Playwright/Chrome virtual-authenticator interoperability fixtures.
- `make mod-check` runs `go mod tidy` and verifies module file cleanliness.
- `make ci` runs the local equivalent of the default CI gate.

Plan 02 created `go.mod`; the current module records minimum Go version `1.25.0`. Go-oriented targets are now mandatory in the local quality gate.

## CI workflow

GitHub Actions configuration lives in `.github/workflows/ci.yml`.

The default workflow runs documentation/config checks, Go lint, Go tests, race tests, fuzz smoke tests, root import graph checks, and dependency license checks without module-detection conditionals. The lint job uses `golangci/golangci-lint-action` with the pinned version recorded in the workflow; formatter and linter behavior is configured in `.golangci.yml`.

The workflow also builds public examples and verifies README references point to compile-checked examples rather than untested inline Go snippets.

The CI and local workflow are documented in `docs/ci.md`.

## Planned documentation map

- `docs/technical.md` describes the target architecture and internal boundaries.
- `docs/protocol-map.md` maps WebAuthn Level 2 protocol areas to planned library components.
- `docs/api-boundaries.md` defines the transport-neutral public API shape and module boundaries.
- `docs/security-model.md` records security and privacy policy decisions.
- `docs/testing.md` defines the test and conformance strategy.
- `docs/ci.md` defines local format/lint/test commands and GitHub Actions CI behavior.
- `docs/release.md` defines the release checklist and Plan 09 release-hardening notes.
- `docs/plans.md` is the top-level implementation plan index.
- `docs/plans/*.md` contains prioritized execution plans. When a plan is completed, both the plan file and `docs/plans.md` must be updated.

## Feature matrix

| Area                        | Status                                                                                                                  |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Registration ceremonies     | Implemented in the root package with transport-neutral start/finish APIs.                                               |
| Authentication ceremonies   | Implemented in the root package, including username-first and discoverable credential flows.                            |
| Attestation formats         | Implemented as optional packages; the root package imports none of them automatically.                                  |
| Attestation trust policy    | Implemented through explicit caller-selected policy building blocks.                                                    |
| WebAuthn Level 2 extensions | Implemented in `extension`, including AppID, AppID exclusion, UVM, credential properties, and largeBlob.                |
| Browser JSON DTOs           | Implemented in `browser` with unpadded base64url transport conversion.                                                  |
| HTTP JSON helpers           | Implemented in `transport/http`; helpers read/write JSON only and do not manage sessions, cookies, or DB.               |
| Examples                    | Compile-checked examples live under `examples/manual`, `examples/http`, `examples/passkey`, and `examples/attestation`. |
| Release checklist           | Tracked in `docs/release.md`.                                                                                           |

## Package philosophy

The package layout keeps the root package small and stable. Format-specific and adapter-specific code lives outside the root package. Current packages are:

- root package: registration and authentication start/finish APIs plus module documentation;
- `protocol`: WebAuthn option dictionaries, DOMString-like values, collected client data parsing, authenticator data parsing, and byte-safe protocol values;
- `codec`: narrow contracts for CBOR attestation object decoding, COSE key decoding, and extension map decoding;
- `codec/cbor`: optional concrete CBOR and COSE_Key decoder using explicit dependencies;
- `crypto`: narrow contracts for hashing, algorithm policy, signature verification, X.509 chain verification, and JWS/JWT handoff;
- `attestation`: format verifier contract, duplicate-rejecting registry, trust policy contract, and explicit built-in trust policy building blocks;
- `attestation/none`: optional `none` attestation verifier;
- `attestation/packed`: optional `packed` attestation verifier for self and x5c paths;
- `attestation/fidou2f`: optional `fido-u2f` attestation verifier;
- `attestation/tpm`: optional `tpm` attestation verifier;
- `attestation/androidkey`: optional `android-key` attestation verifier;
- `attestation/androidsafetynet`: optional `android-safetynet` attestation verifier;
- `attestation/apple`: optional `apple` anonymous attestation verifier;
- `extension`: operation-aware extension handler contract, duplicate-rejecting registry, and built-in WebAuthn Level 2 handlers for `appid`, `appidExclude`, `uvm`, `credProps`, and `largeBlob`.
- `tools/checklicenses`: local CI helper that verifies `docs/dependencies.json` covers the current Go module build list.
- `browser`: optional browser JSON DTO conversion helpers using unpadded base64url for WebAuthn binary fields.
- `transport/http`: optional standard-library HTTP JSON read/write helpers for applications that already manage routing, sessions, and persistence.

## Examples

Public examples are compiled by `make example-build` and by CI:

- `examples/manual` shows framework-neutral registration and authentication wiring with caller-owned state and credential storage.
- `examples/http` shows use of the optional `transport/http` JSON helpers with `net/http`.
- `examples/passkey` shows discoverable credential authentication, where the application looks up a credential by returned user handle and credential ID before verification.
- `examples/attestation` shows explicit selected attestation format imports and restricted enrollment trust policy composition.

## Security considerations

The root package never infers trusted origins from HTTP request headers and does not create sessions, cookies, or database records. Applications must store ceremony state server-side, enforce single use and expiry, map user handles to accounts, persist credential counter updates, rate-limit endpoints, and provide their own session and CSRF protections.

The optional `transport/http` package intentionally writes generic error JSON and does not expose raw credential IDs, challenges, user handles, signatures, client data JSON, attestation objects, or assertion bytes. Attestation trust remains explicit caller policy; no built-in trust roots, metadata downloads, OCSP/CRL clients, or enterprise enrollment defaults are included.

## Dependencies and licenses

Plan 09 added no third-party dependencies. Browser and HTTP helpers use the Go standard library plus existing local packages. The module dependency inventory and license notes are maintained in `docs/dependencies.json`, and release readiness is tracked in `docs/release.md`.
