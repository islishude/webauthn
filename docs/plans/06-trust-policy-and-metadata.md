# 06 - Trust policy and metadata integration

Priority: P1.

Status: Not started.

## Purpose

Separate attestation cryptographic validity from relying-party trust decisions, then provide extensible trust policy hooks for attestation roots, AAGUID policy, metadata, and certificate status behavior.

## Prerequisites

- Plan 01 verifier contracts complete.
- Plan 02 registration verifier can receive attestation verification outputs.
- Plan 04 format packages expose trust path material and format-specific evidence.

## Deliverables

1. Trust policy interface for attestation acceptance.
2. Built-in policies for accept-none, reject-none, accept-self, reject-self, trust-roots, and format allow-list.
3. Trust path result structures independent of any one X.509 dependency representation where possible.
4. AAGUID policy hook.
5. Metadata provider interface.
6. Certificate status policy hook for intermediate CA certificate status where applicable.
7. Enterprise or restricted enrollment policy examples.
8. Documentation explaining cryptographic validity vs trust acceptance.

## Non-goals

- No hidden global trust store in root package.
- No mandatory network fetch during verification.
- No database-owned metadata cache in core.
- No automatic policy that accepts identifying attestation without caller configuration.

## Tests

- Valid attestation rejected by trust policy.
- Valid attestation accepted by trust policy.
- `none` attestation accepted and rejected under different policies.
- Self attestation accepted and rejected under different policies.
- Root certificate accepted/rejected behavior.
- Metadata provider positive, negative, and unavailable paths.
- Certificate status hook positive, revoked, unknown, and unavailable paths where supported.

## Completion update requirements

When complete, update `docs/plans.md`, this file, `docs/security-model.md`, and README feature status.
