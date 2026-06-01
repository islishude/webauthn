# 14 - Level 3 conformance and release alignment

Priority: P1.

Status: Complete, 2026-06-01.

## Purpose

Align tests, examples, documentation, and release criteria with the WebAuthn
Level 3 upgrade.

## Prerequisites

- Plans 10 through 13 implemented.
- Required documentation trail remains synchronized.

## Deliverables

1. README and design docs describe Level 3 behavior.
2. Examples use Level 3 recommended credential parameters and Level 3 extension
   registries with deprecated support where needed.
3. Testing docs record Level 3 coverage and new parser/verifier tests.
4. Release checklist requires Plan 14 completion.
5. Import graph, dependency, README, and CI requirements remain unchanged unless
   intentionally updated.

## Tests

- `go test ./...` passes.
- `make ci` remains the release gate.
- `make import-graph-check` proves optional Level 3 packages do not enter the
  root import graph.
- `make readme-check` keeps README references aligned with examples.

## Completion notes

2026-06-01: Completed. Updated README, AGENTS, protocol/API/technical/security
testing docs, release notes, plan index, and examples. Scope changes: no
dependency or CI target was added; existing quality gates remain authoritative
for Level 3 readiness.
