# 10 - WebAuthn Level 3 baseline

Priority: P0.

Status: Complete, 2026-06-01.

## Purpose

Move the protocol target from WebAuthn Level 2 to WebAuthn Level 3 without
preserving old API compatibility where Level 3 semantics require different
shapes.

## Prerequisites

- Plans 02 through 09 complete.
- Existing import graph and dependency rules preserved.
- W3C WebAuthn Level 3 used as the normative source.

## Deliverables

1. Plan index updated for Level 3 work.
2. Technical, API, protocol, security, testing, release, and README documents
   updated from Level 2 to Level 3.
3. No public WebAuthn library implementation or test logic used.
4. No new dependency added for baseline mapping.

## Tests

- Documentation drift is checked through `make readme-check` and `make ci`.
- `go test ./...` verifies the upgraded protocol surfaces compile and pass.

## Completion notes

2026-06-01: Completed. Updated the project baseline to WebAuthn Level 3 and
split implementation into plans 11 through 14. Scope changes: compatibility
with removed Level 2-only API fields was not preserved, except deprecated `uvm`
support remains available as explicit opt-in behavior.
