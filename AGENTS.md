# AGENTS.md

This repository is `github.com/islishude/webauthn`, a Go server-side
WebAuthn/passkey relying-party library.

Current project state: All plans are complete. The repository now
contains the root ceremony APIs, protocol types, codec and crypto contracts,
optional attestation format packages including compound attestation, Level 3
extension handling with deprecated `uvm` retained, optional browser and HTTP
transport helpers, compile-checked examples, conformance-oriented tests, fuzz
smoke targets, import graph checks, dependency license checks, and release
documentation. The current API cleanup keeps byte accessors defensive while
using typed helpers internally, requires explicit attestation trust policy, and
keeps root decoder contracts narrow.

Agents working in this repository must preserve the documented architecture and
quality gates. If code, tests, README, plans, or design documents disagree, fix
the drift in the same change instead of treating the documents as stale notes.

## Hard constraints

1. Do not use, copy, quote, translate, adapt, inspect, or derive
   implementation logic from public WebAuthn/passkey libraries.
2. Do not copy or translate tests from public WebAuthn/passkey libraries. Tests
   must come from specifications, independently authored fixtures, generated
   fixtures, browser outputs collected for this project, or public conformance
   data with documented source and license.
3. Use W3C Web Authentication Level 3 as the normative protocol source. MDN Web
   Authentication API documentation is acceptable for browser-facing context,
   compatibility notes, and terminology, but not as a replacement for the
   specification.
4. Do not implement general-purpose cryptographic primitives, CBOR, COSE,
   ASN.1, JWS, JWT, X.509, JSON, base64url, or similar foundational libraries.
   WebAuthn-specific parsing and validation are allowed; foundational codecs
   and primitives must come from the Go standard library, explicit third-party
   dependencies, or injected interfaces.
5. Keep the root package independent of `net/http`, web frameworks, databases,
   sessions, cookies, CSRF handling, account lookup, routing, and persistence.
6. Keep optional packages optional. Importing the root package must not import
   `browser`, `transport/http`, or optional attestation format packages.
7. Keep attestation verification and attestation trust separate. Format
   packages prove statement structure and cryptographic validity; relying-party
   trust acceptance must remain explicit caller policy.
8. Do not vendor external code unless the reason, license, update process, and
   review criteria are documented. Never vendor implementation logic from public
   WebAuthn libraries.

## Documentation trail

Required project documents and quality files are:

- `README.md`;
- `AGENTS.md`;
- `docs/technical.md`;
- `docs/protocol-map.md`;
- `docs/api-boundaries.md`;
- `docs/security-model.md`;
- `docs/testing.md`;
- `docs/ci.md`;
- `docs/release.md`;
- `docs/dependencies.json`;
- `Makefile`;
- `.github/workflows/ci.yml`;
- `.golangci.yml`;
- `.gitattributes`.

Every change must preserve a documentation trail. Update documentation in the
same change when behavior, boundaries, packages, dependencies, tests, CI checks,
release status, or examples change.

## Architecture boundaries

The root package exposes ceremony-oriented APIs:

- registration option creation;
- registration response verification;
- authentication option creation;
- authentication assertion verification;
- result objects that applications persist through their own storage layer.

The core accepts byte-oriented protocol values and structured configuration. It
must not read HTTP requests, write HTTP responses, start sessions, set cookies,
infer trusted origins from request headers, or assume browser JSON transport
details.

Current package boundaries are documented in `docs/technical.md` and
`docs/api-boundaries.md`. Preserve these dependency directions:

- root `webauthn` contains transport-neutral registration and authentication
  start/finish APIs;
- `protocol` contains WebAuthn values, options, collected client data, and
  authenticator data parsing;
- `codec` contains narrow decoder contracts;
- `codec/cbor` is an optional concrete CBOR/COSE decoder package;
- `crypto` contains narrow algorithm policy, signature, certificate, and
  JWS/JWT contracts;
- `attestation` contains format verifier and trust policy contracts;
- `attestation/*` packages are optional selected format verifiers;
- `extension` contains operation-aware Level 2 and Level 3 extension handling;
- `browser` contains optional browser JSON DTO conversion helpers;
- `transport/http` contains optional standard-library JSON request/response
  helpers.

Do not add files or imports that conflict with documented package boundaries.
If a boundary must change, update `docs/technical.md`,
`docs/api-boundaries.md`, and any other affected documentation first.

## Dependency hygiene

Before adding or changing any dependency, document:

- why it is needed;
- which protocol surface it supports;
- whether it is used by the root package or an optional package;
- whether replacing it would affect public API compatibility;
- its license and dependency-manifest entry in `docs/dependencies.json`.

Dependencies for codecs, COSE, X.509 path building, JWS/JWT, metadata parsing,
or browser tooling must remain behind narrow internal or exported interfaces
where possible. Avoid exposing a specific CBOR, COSE, certificate, or metadata
implementation in the root public API unless there is a deliberate compatibility
reason documented in the design docs.

## Security rules

Default behavior must be safe for relying parties:

- challenges are generated server-side with sufficient entropy;
- challenge comparisons are exact and constant-time where meaningful;
- origins and RP IDs are explicit and policy-driven;
- cross-origin `topOrigin` values are accepted only by explicit origin policy;
- reserved `tokenBinding` client data is parsed for preservation but not used
  for relying-party verification;
- user presence is required;
- user verification is checked according to ceremony policy;
- signature counters are surfaced with clone-risk semantics;
- attestation trust is separate from attestation cryptographic validity;
- unknown, unsolicited, or unsupported extensions are handled by explicit
  policy;
- errors are actionable for logs without leaking sensitive account or credential
  existence details by default;
- optional HTTP helpers write generic errors and do not expose raw protocol
  material.

Security-sensitive changes require tests for both acceptance and rejection
paths. Parser and verifier changes must include malformed input coverage and
policy rejection coverage.

## Testing rules

Test sources must be independent of public WebAuthn library implementations.
Use W3C specification requirements, generated fixtures, browser outputs
collected for this repository, independently authored fixtures, or documented
public conformance data.

For protocol parsers and verifiers, include:

- positive tests;
- malformed input tests;
- boundary-length tests;
- unsupported algorithm or format tests where relevant;
- policy rejection tests.

Attestation modules must test both cryptographic verification and trust-policy
behavior where applicable. Optional adapter packages must test transport and
conversion boundaries without moving those dependencies into the root package.

## Local and CI quality gate

Run commands from the repository root.

The required readiness gate is:

```sh
make ci
```

Use narrower targets while editing:

- `make format` rewrites Go and Markdown formatting;
- `make format-check` verifies formatting;
- `make lint` runs golangci-lint;
- `make test` runs unit tests;
- `make test-race` runs race-enabled tests;
- `make test-fuzz-smoke` runs bounded fuzz targets;
- `make example-build` builds public examples;
- `make import-graph-check` verifies root package dependency boundaries;
- `make license-check` verifies dependency manifest coverage;
- `make readme-check` verifies README example references;
- `make mod-check` runs `go mod tidy` and verifies module-file cleanliness.

Changing format, lint, test, race, fuzz, module, import-graph, dependency
license, README, browser fixture, or example-build behavior requires updating
the local target, GitHub workflow, and documentation together.

Quality workflow files are:

- `Makefile`;
- `.github/workflows/ci.yml`;
- `.golangci.yml`;
- `.gitattributes`;
- `docs/ci.md`;
- `docs/testing.md` when test policy changes.

## Coding rules

- Keep files organized around one responsibility. Split code when a file starts
  mixing unrelated concerns or becomes difficult to scan.
- Prefer shared utility packages over hand-rolled helpers when they centralize
  protocol invariants.
- Add Go doc comments for every new exported identifier.
- Use internal comments sparingly to explain intent, constraints, assumptions,
  or edge cases.
- Keep the root package API transport-neutral and persistence-neutral.
- Keep optional attestation, browser, and HTTP dependencies outside the root
  import graph.
- Do not broaden public API types around concrete third-party dependencies
  unless the compatibility reason is documented.

## Release-readiness rules

A release candidate must not be tagged until:

- local `make ci` passes from a clean worktree;
- GitHub Actions CI passes on the release branch;
- the root package import graph does not include optional attestation formats,
  `browser`, `transport/http`, or `net/http`;
- examples demonstrate integration without `net/http` and, separately, with the
  optional HTTP adapter;
- conformance coverage is documented in `docs/testing.md`;
- dependency inventory in `docs/dependencies.json` covers every module returned
  by `go list -m all`;
- README feature claims match implemented and tested behavior.
