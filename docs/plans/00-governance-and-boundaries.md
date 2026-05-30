# 00 - Governance and documentation boundaries

Priority: P0.

Status: Complete, 2026-05-29.

## Purpose

Establish the repository as a documentation-first WebAuthn/passkey server-side library project before implementation begins.

## Completed deliverables

- Root `AGENTS.md` created with project constraints, implementation rules, dependency hygiene, security rules, testing rules, and release-readiness rules.
- Root `README.md` created with project goals, current status, constraints, documentation map, and package philosophy.
- `docs/technical.md` created with target architecture.
- `docs/protocol-map.md` created with WebAuthn Level 2 coverage map.
- `docs/api-boundaries.md` created with transport-neutral API boundary rules.
- `docs/security-model.md` created with security and privacy decisions.
- `docs/testing.md` created with test and conformance strategy.
- `docs/plans.md` created as the top-level plan index.
- `docs/plans/*.md` created as split execution plans ordered by priority.

## Acceptance criteria

- No implementation code added.
- Documentation states module name `github.com/islishude/webauthn`.
- Documentation forbids copying, adapting, or referencing public WebAuthn library implementation code.
- Documentation requires core decoupling from `net/http` and frameworks.
- Documentation requires attestation formats to be optional imports.
- Documentation requires plan status synchronization when work completes.

## Follow-up

Quality gates and CI must be established by `01-quality-gates-and-ci.md` before Go implementation begins. Core implementation can then begin with `02-core-protocol-model.md`. Any change to core architecture must update this plan set before or with code changes.
