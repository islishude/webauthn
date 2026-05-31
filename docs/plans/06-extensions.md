# 06 - Extension framework and Level 2 extensions

Priority: P1.

Status: Complete, 2026-06-01.

## Purpose

Implement a WebAuthn extension framework and support all WebAuthn Level 2 defined extensions relevant to relying-party option construction and verification.

## Prerequisites

- Plan 02 core extension registry contract complete.
- Plans 03 and 04 expose extension input/output hooks.
- Codec adapter can decode authenticator extension output maps.

## Required extensions

| Extension      | Applicability               | Planned behavior                                                                                           |
| -------------- | --------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `appid`        | Authentication              | Support U2F migration by allowing RP ID hash to match AppID when requested and indicated by client output. |
| `appidExclude` | Registration                | Represent option input and policy; most exclusion behavior is client-side.                                 |
| `uvm`          | Registration/authentication | Parse and surface user verification method output if present.                                              |
| `credProps`    | Registration                | Parse credential properties, especially resident/discoverable credential signal for passkey flows.         |
| `largeBlob`    | Registration/authentication | Represent inputs and outputs; leave application data storage policy to caller.                             |

## Deliverables

1. Extension handler interface and registry finalization.
2. Client extension input representation.
3. Client extension output representation.
4. Authenticator extension output representation.
5. Unknown extension preservation and policy handling.
6. Requested-but-absent extension behavior.
7. Unsolicited extension behavior under ignore and reject policies.
8. `appid` authentication verifier integration.
9. `appidExclude` registration option support.
10. `uvm`, `credProps`, and `largeBlob` parsing and result objects.
11. Documentation for extension policy configuration.
12. Keep `make ci` and GitHub Actions green as extension handlers are added.

## Tests

- Unknown extension ignored by default or according to documented default.
- Unknown extension rejected when policy requires.
- Requested extension absent behavior.
- `appid` accepted only when requested and client output says it was used.
- `appid` rejected on invalid AppID policy.
- `credProps` resident/discoverable result surfaced.
- `uvm` malformed output rejected or surfaced according to policy.
- `largeBlob` input/output shape tests.

## Completion update requirements

When complete, update `docs/plans.md`, this file, `docs/protocol-map.md`, `docs/security-model.md`, and README feature status.

## Completion update

Completed on 2026-06-01.

Delivered files/packages:

- `extension`: operation-aware handler requests, Level 2 extension identifiers, typed result/input structures, and built-in handlers/registry helpers for `appid`, `appidExclude`, `uvm`, `credProps`, and `largeBlob`.
- root `webauthn`: registration and authentication extension routing now passes ceremony operation, preserves unknown extension outputs as untrusted raw results by default, supports `RejectUnknown`, and rejects unrequested outputs when configured.
- authentication AppID handling now requires the requested `appid` input, caller policy `AppID`, and client output to agree before accepting the AppID RP ID hash fallback.
- Documentation updated in README, protocol map, API boundaries, security model, technical design, testing strategy, and plan index.

Tests:

- Added handler unit tests for valid, absent, malformed, and wrong-operation paths across the Level 2 extension handlers.
- Added registration/authentication integration tests for `credProps`, `uvm`, `largeBlob`, unknown extension preservation/rejection, unrequested rejection, and AppID policy mismatch.

Scope changes:

- Browser JSON DTO conversion remains out of scope for Plan 09; byte-like largeBlob values are represented in core as `[]byte`.
- Unknown and unrequested outputs are observable but never marked accepted unless a registered handler validates a requested extension.
