# AGENTS.md

This repository is planned as `github.com/islishude/webauthn`, a Go server-side WebAuthn/passkey library. The immediate project state is documentation-first: do not add implementation code until the root `README.md`, this file, `docs/technical.md`, `docs/protocol-map.md`, `docs/api-boundaries.md`, `docs/security-model.md`, `docs/testing.md`, `docs/ci.md`, `docs/plans.md`, and the referenced `docs/plans/*.md` files exist and are internally consistent.

## Non-negotiable constraints

1. Do not use, copy, quote, translate, adapt, or inspect source code from public WebAuthn/passkey libraries.
2. Acceptable protocol sources are public specifications and documentation, especially W3C Web Authentication Level 2 and MDN Web Authentication API documentation. Use specifications for normative behavior and MDN only for browser-facing context, compatibility, and terminology.
3. Do not implement general-purpose cryptographic primitives, CBOR, COSE, ASN.1, JWS, JWT, X.509, JSON, base64url, or similar foundational libraries. Protocol-specific parsing of WebAuthn structures is allowed; general codecs and primitives must come from Go standard library packages, explicit third-party dependencies, or injected interfaces.
4. Keep the core library independent of `net/http`, web frameworks, databases, sessions, and cookie mechanisms. Optional adapters may exist in separate packages after the core API is stable.
5. Keep attestation formats modular. Importing the root module must not pull every attestation format. Users must be able to import only the formats they need.
6. Support complete WebAuthn Level 2 relying-party server behavior before treating the module as stable: registration, authentication, attestation formats, authenticator data, client data, supported extensions, trust policy hooks, error taxonomy, and conformance tests.

## Repository workflow

Every change must preserve a documentation trail. If a plan item is completed, update both:

- `docs/plans.md`
- the corresponding `docs/plans/*.md` file

A plan update must record status, date, deliverables, and any scope changes. Do not leave completed work marked as pending.

Do not add files that conflict with the documented package boundaries. If implementation requires changing a boundary, update `docs/technical.md`, `docs/api-boundaries.md`, and the relevant plan first.

## Local and CI quality gate

The required local gate is:

```sh
make ci
```

Run narrower targets while editing, then run `make ci` before a change is considered ready. The target validates required docs/config immediately and runs Go checks once `go.mod` exists.

Quality workflow files are:

- `Makefile` for local commands;
- `.github/workflows/ci.yml` for GitHub Actions;
- `.golangci.yml` for lint and formatter configuration;
- `.gitattributes` for text line-ending normalization;
- `docs/ci.md` for workflow documentation.

Changing format, lint, test, race, fuzz, module, import-graph, or example-build behavior requires updating the local target, GitHub workflow, and documentation together.

## Source and dependency hygiene

Before adding any dependency, document why it is needed, which protocol surface it supports, whether it is required by the root package or an optional package, and whether replacing it would affect the public API.

Dependencies for codecs, COSE, X.509 path building, JWS/JWT, or metadata parsing must remain behind narrow internal or exported interfaces where possible. The project should avoid making a specific CBOR or COSE implementation part of the public API unless there is a deliberate compatibility reason.

Do not vendor external code unless there is a documented, reviewed reason. Never vendor or transcribe implementation logic from public WebAuthn libraries.

## Core architecture rules

The root package should expose ceremony-oriented APIs, not transport-oriented APIs. The intended shape is:

- registration options creation;
- registration response verification;
- authentication options creation;
- authentication assertion verification;
- result objects that the application persists through its own storage layer.

The core should accept byte-oriented protocol values and structured configuration. It should not read HTTP requests, write HTTP responses, start sessions, set cookies, or assume JSON transport details. Browser JSON helpers may be provided later as optional packages.

The root package should not automatically register every attestation format. Prefer explicit construction, such as passing selected format verifiers into a registry. A convenience aggregate package may be added later, but it must be optional and must not be imported by the root package.

## Security rules

Default behavior must be safe for relying parties:

- challenges are generated server-side with sufficient entropy;
- challenge comparisons are exact and constant-time where meaningful;
- origins and RP IDs are explicit and policy-driven;
- user presence and user verification flags are checked according to ceremony policy;
- signature counters are surfaced with clone-risk semantics instead of being silently ignored;
- attestation trust is separated from attestation cryptographic validity;
- unsolicited or unsupported extensions are handled by explicit policy;
- errors must be actionable without leaking sensitive account or credential existence details by default.

Security-sensitive changes require tests that demonstrate both acceptance and rejection paths.

## Testing rules

Tests must be based on specifications, generated fixtures, browser outputs collected specifically for this project, or independently authored fixtures. Do not copy tests from public WebAuthn libraries. If public conformance data is used, document the source and license.

For each protocol parser or verifier, include positive tests, malformed input tests, boundary-length tests, and policy rejection tests. Attestation modules must test both cryptographic verification and trust-path policy behavior where applicable.

The default test gate is `make ci`. After `go.mod` exists, this includes formatting, linting, unit tests, race tests, fuzz smoke tests when fuzz targets exist, and module tidy verification. CI must remain green before merging implementation work.

## Release-readiness rules

A release candidate must not be tagged until:

- all P0 and P1 plans in `docs/plans.md` are complete;
- local `make ci` passes;
- GitHub Actions CI passes on the release branch;
- root package import does not pull optional attestation formats;
- examples demonstrate integration without `net/http` and, separately, with an optional HTTP adapter;
- conformance coverage is documented in `docs/testing.md`;
- README accurately reflects implemented features and unsupported surfaces.
