# Implementation plans

Status: updated plan index, revised 2026-06-01.

This file is the top-level plan index. Detailed plans live in `docs/plans/*.md` and are ordered by implementation importance using numeric prefixes. Do not collapse all planning into this file.

When a plan is completed, update this file and the corresponding plan file in the same change. Record the completion date, delivered files/packages, tests, and any scope changes.

## Status vocabulary

| Status      | Meaning                                                                |
| ----------- | ---------------------------------------------------------------------- |
| Complete    | Planned deliverables for this plan have been delivered and documented. |
| In progress | Implementation has started but acceptance criteria are not complete.   |
| Not started | No implementation work has started.                                    |
| Blocked     | Work cannot continue until a named prerequisite is resolved.           |
| Deferred    | Intentionally moved out of the current release target.                 |

## Priority-ordered plan index

| Order | Plan                                                                                | Priority | Status                       | Summary                                                                                                             |
| ----- | ----------------------------------------------------------------------------------- | -------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| 00    | [Governance and documentation boundaries](plans/00-governance-and-boundaries.md)    | P0       | Complete, 2026-05-29         | Establish README, AGENTS, docs, source restrictions, and no-code planning baseline.                                 |
| 01    | [Quality gates and CI workflow](plans/01-quality-gates-and-ci.md)                   | P0       | Complete, revised 2026-05-31 | Establish local Makefile workflow, golangci-lint configuration, LF policy, and GitHub Actions CI gate.              |
| 02    | [Core protocol model and adapter contracts](plans/02-core-protocol-model.md)        | P0       | Complete, 2026-05-31         | Define module/package layout, protocol types, codec/crypto contracts, and import graph boundaries.                  |
| 03    | [Registration ceremony](plans/03-registration-ceremony.md)                          | P0       | Complete, 2026-05-31         | Implement registration option generation and verification with explicit `none` attestation policy.                  |
| 04    | [Authentication ceremony](plans/04-authentication-ceremony.md)                      | P0       | Complete, 2026-05-31         | Implement assertion option generation and verification, including counters and discoverable credentials.            |
| 05    | [Modular attestation formats](plans/05-attestation-formats.md)                      | P1       | Complete, 2026-05-31         | Implement optional attestation formats; all WebAuthn Level 2 format verifiers are delivered as optional packages.   |
| 06    | [Extension framework and Level 2 extensions](plans/06-extensions.md)                | P1       | Complete, 2026-06-01         | Implement extension input/output handling and Level 2 extension semantics.                                          |
| 07    | [Trust policy and metadata integration](plans/07-trust-policy-and-metadata.md)      | P1       | Complete, 2026-06-01         | Add explicit attestation trust policy building blocks, metadata hooks, AAGUID policy, and certificate status hooks. |
| 08    | [Testing and conformance](plans/08-testing-and-conformance.md)                      | P1       | Complete, 2026-06-01         | Build protocol, ceremony, attestation, extension, fuzz, and interoperability coverage.                              |
| 09    | [Adapters, examples, and release hardening](plans/09-adapters-examples-release.md)  | P2       | Complete, 2026-06-01         | Added optional browser/HTTP helpers, examples, README checks, CI example builds, and release documentation.         |
| 10    | [WebAuthn Level 3 baseline](plans/10-webauthn-level3-baseline.md)                   | P0       | Complete, 2026-06-01         | Move the normative baseline to WebAuthn Level 3 and map protocol/API deltas.                                        |
| 11    | [Level 3 ceremonies and JSON](plans/11-level3-ceremonies-and-json.md)               | P0       | Complete, 2026-06-01         | Add Level 3 ceremony fields, `OriginPolicy`, `topOrigin`, browser DTO, and reserved `tokenBinding` behavior.        |
| 12    | [Level 3 extensions](plans/12-level3-extensions.md)                                 | P1       | Complete, 2026-06-01         | Add the `prf` extension in Level 3 helpers and keep `uvm` as deprecated opt-in support.                             |
| 13    | [Level 3 attestation and algorithms](plans/13-level3-attestation-and-algorithms.md) | P1       | Complete, 2026-06-01         | Add compound attestation normalization/verifier support and Level 3 algorithm/key material coverage.                |
| 14    | [Level 3 conformance and release alignment](plans/14-level3-conformance-release.md) | P1       | Complete, 2026-06-01         | Align docs, tests, examples, and release readiness with the Level 3 upgrade.                                        |

## Release gates

A stable release requires plans 02 through 14 to be complete, local `make ci` to pass, and GitHub Actions to pass on the release branch.

Root package release gates:

- no `net/http` dependency in the core import graph;
- root package does not import optional attestation format packages;
- no implementation code copied or adapted from public WebAuthn libraries;
- no general-purpose cryptography or codec library implemented in this repository;
- local `make ci` passes;
- GitHub Actions CI passes on the release branch;
- registration and authentication relying-party operations covered by tests;
- all WebAuthn Level 3 attestation and extension work in plans 10 through 14 is implemented and documented;
- README feature claims match implemented and tested behavior.

## Plan synchronization rule

Plan 01 added repository quality gates after the initial documentation pass. Because it is prerequisite infrastructure, implementation plans were renumbered so that core code begins at plan 02.

Plans 10 through 14 are a WebAuthn Level 3 upgrade addendum after Plan 09
release hardening. Their P0/P1 priority reflects upgrade importance, while
their numeric order preserves the completed Plan 00-09 history.

Future plan insertions must either preserve numeric priority ordering or
explicitly document why a later-numbered plan has higher execution priority.
