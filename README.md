# webauthn

`github.com/islishude/webauthn` is planned as a Go server-side library for WebAuthn/passkey relying-party behavior.

Current status: Plan 03 registration ceremony behavior is implemented for the `none` attestation path. Authentication ceremony behavior and non-`none` attestation formats have not been implemented yet.

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

The core package must stay transport-neutral. Optional transport helpers may be added later, but the core API must be usable from any HTTP router, RPC service, command flow, test harness, or custom integration.

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
- `make test-fuzz-smoke` runs bounded fuzz targets after fuzz tests exist.
- `make mod-check` runs `go mod tidy` and verifies module file cleanliness.
- `make ci` runs the local equivalent of the default CI gate.

Plan 02 created `go.mod`; the current module records minimum Go version `1.25.0`. Go-oriented targets are now mandatory in the local quality gate.

## CI workflow

GitHub Actions configuration lives in `.github/workflows/ci.yml`.

The default workflow runs documentation/config checks, Go lint, and Go tests without module-detection conditionals. The lint job uses `golangci/golangci-lint-action` with the pinned version recorded in the workflow; formatter and linter behavior is configured in `.golangci.yml`.

The CI and local workflow are documented in `docs/ci.md`.

## Planned documentation map

- `docs/technical.md` describes the target architecture and internal boundaries.
- `docs/protocol-map.md` maps WebAuthn Level 2 protocol areas to planned library components.
- `docs/api-boundaries.md` defines the transport-neutral public API shape and module boundaries.
- `docs/security-model.md` records security and privacy policy decisions.
- `docs/testing.md` defines the test and conformance strategy.
- `docs/ci.md` defines local format/lint/test commands and GitHub Actions CI behavior.
- `docs/plans.md` is the top-level implementation plan index.
- `docs/plans/*.md` contains prioritized execution plans. When a plan is completed, both the plan file and `docs/plans.md` must be updated.

## Package philosophy

The package layout keeps the root package small and stable. Format-specific and adapter-specific code lives outside the root package. Current packages are:

- root package: registration start and finish APIs plus module documentation;
- `protocol`: WebAuthn option dictionaries, DOMString-like values, collected client data parsing, authenticator data parsing, and byte-safe protocol values;
- `codec`: narrow contracts for CBOR attestation object decoding, COSE key decoding, and extension map decoding;
- `codec/cbor`: optional concrete CBOR and COSE_Key decoder using explicit dependencies;
- `crypto`: narrow contracts for hashing, algorithm policy, signature verification, X.509 chain verification, and JWS/JWT handoff;
- `attestation`: format verifier contract and duplicate-rejecting registry;
- `attestation/none`: optional `none` attestation verifier;
- `extension`: extension handler contract and duplicate-rejecting registry.

Authentication, optional non-`none` attestation format packages, browser JSON helpers, HTTP helpers, and storage examples are still future work. Feature claims must be added only after matching code and tests exist.
