# AGENTS.md

This repository is `github.com/islishude/webauthn`, a Go server-side
WebAuthn/passkey relying-party library.

## Read first

Use these files as the source of truth instead of duplicating their details in
this file:

- `README.md`: supported features, packages, examples, and project status;
- `docs/technical.md`: normative sources, architecture, and design decisions;
- `docs/protocol-map.md`: specification-to-implementation coverage;
- `docs/api-boundaries.md`: public API and package dependency boundaries;
- `docs/security-model.md`: security, privacy, and failure behavior;
- `docs/testing.md`: test provenance and required coverage;
- `docs/ci.md`: local and GitHub Actions quality gates;
- `docs/release.md`: release requirements and migration notes;
- `docs/dependencies.json`: dependency scope and licenses.

`Makefile`, `.github/workflows/ci.yml`, `.golangci.yml`, and `.gitattributes`
are the executable quality configuration. When implementation, tests, README,
or design documents disagree, resolve the drift in the same change.

## Non-negotiable constraints

1. Do not use, inspect, copy, quote, translate, adapt, or derive implementation
   logic from public WebAuthn/passkey libraries.
2. Do not copy or translate their tests. Derive tests from the specification,
   independently authored or generated fixtures, browser outputs collected for
   this project, or documented public conformance data with compatible licenses.
3. Use the 26 May 2026 W3C Web Authentication Level 3 Candidate Recommendation
   as the stable normative source. Keep Editor's Draft behavior explicitly
   marked and opt-in. MDN may provide browser context, not protocol authority.
4. Do not implement general-purpose cryptography, CBOR, COSE, ASN.1, JWS/JWT,
   X.509, JSON, base64url, or similar foundations. Use the Go standard library,
   an explicit dependency, or an injected narrow interface.
5. Keep the root package transport- and persistence-neutral. It must not depend
   on `net/http`, frameworks, databases, sessions, cookies, CSRF handling,
   account lookup, routing, or storage I/O.
6. Keep optional packages outside the root import graph, including optional
   attestation formats, `browser`, `transport/http`, `crypto/standard`, and
   `storage/json`.
7. Keep attestation cryptographic verification separate from relying-party
   trust acceptance. Trust must remain explicit caller policy.
8. Do not vendor external code without documented rationale, license, update
   process, and review criteria. Never vendor public WebAuthn library logic.

## Change rules

- Preserve the package directions in `docs/technical.md` and
  `docs/api-boundaries.md`. Update those documents in the same change before
  deliberately changing a boundary.
- Preserve the fail-closed defaults in `docs/security-model.md`. Security,
  parser, and verifier changes require acceptance and rejection tests, including
  malformed input and applicable boundary, unsupported, and policy cases.
- Keep files focused on one responsibility, add Go doc comments for exported
  identifiers, and explain only non-obvious constraints or edge cases in inline
  comments.
- Before changing a dependency, document its purpose, protocol surface, package
  scope, public API impact, license, and `docs/dependencies.json` entry. Keep
  concrete codec, crypto, certificate, and metadata types behind narrow
  interfaces unless a documented compatibility requirement says otherwise.
- Update documentation together with behavior, boundaries, packages,
  dependencies, tests, quality gates, release status, or examples.

## Verification

Run commands from the repository root. Use narrow targets while editing; the
required local readiness gate is:

```sh
make ci
```

Relevant narrow targets are documented by `make help` and in `docs/ci.md`.
Changes to formatting, linting, tests, race or fuzz checks, modules, import
boundaries, dependency licenses, README checks, browser fixtures, or example
builds must update the corresponding `Makefile`, GitHub Actions workflow, and
documentation together.

Do not tag or describe a release candidate as ready until every requirement in
`docs/release.md` is satisfied, including a clean-worktree `make ci`, passing
release-branch GitHub Actions, root import isolation, examples, documentation,
and dependency inventory.
