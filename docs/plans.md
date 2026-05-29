# Implementation plans

Status: initial plan index, created 2026-05-29.

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

| Order | Plan                                                                               | Priority | Status               | Summary                                                                                                    |
| ----- | ---------------------------------------------------------------------------------- | -------- | -------------------- | ---------------------------------------------------------------------------------------------------------- |
| 00    | [Governance and documentation boundaries](plans/00-governance-and-boundaries.md)   | P0       | Complete, 2026-05-29 | Establish README, AGENTS, docs, source restrictions, and no-code planning baseline.                        |
| 01    | [Core protocol model and adapter contracts](plans/01-core-protocol-model.md)       | P0       | Not started          | Define module/package layout, protocol types, codec/crypto contracts, and import graph boundaries.         |
| 02    | [Registration ceremony](plans/02-registration-ceremony.md)                         | P0       | Not started          | Implement registration option generation and verification, starting with `none` attestation.               |
| 03    | [Authentication ceremony](plans/03-authentication-ceremony.md)                     | P0       | Not started          | Implement assertion option generation and verification, including counters and discoverable credentials.   |
| 04    | [Modular attestation formats](plans/04-attestation-formats.md)                     | P1       | Not started          | Implement all WebAuthn Level 2 attestation statement formats as optional packages.                         |
| 05    | [Extension framework and Level 2 extensions](plans/05-extensions.md)               | P1       | Not started          | Implement extension input/output handling and Level 2 extension semantics.                                 |
| 06    | [Trust policy and metadata integration](plans/06-trust-policy-and-metadata.md)     | P1       | Not started          | Add trust anchor policy, metadata hooks, certificate status behavior, and attestation acceptance controls. |
| 07    | [Testing and conformance](plans/07-testing-and-conformance.md)                     | P1       | Not started          | Build protocol, ceremony, attestation, extension, fuzz, and interoperability coverage.                     |
| 08    | [Adapters, examples, and release hardening](plans/08-adapters-examples-release.md) | P2       | Not started          | Add optional transport helpers, examples, import graph checks, and release documentation.                  |

## Release gates

A stable release requires plans 01 through 07 to be complete. Plan 08 is required for a public release candidate but may continue after core protocol completeness if examples are still expanding.

Root package release gates:

- no `net/http` dependency in the core import graph;
- root package does not import optional attestation format packages;
- no implementation code copied or adapted from public WebAuthn libraries;
- no general-purpose cryptography or codec library implemented in this repository;
- registration and authentication relying-party operations covered by tests;
- all WebAuthn Level 2 attestation formats supported through optional modules;
- all WebAuthn Level 2 extensions represented and policy-checked;
- README feature claims match implemented and tested behavior.
