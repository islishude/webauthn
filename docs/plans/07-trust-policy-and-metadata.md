# 07 - Trust policy and metadata integration

Priority: P1.

Status: Complete, 2026-06-01.

## Purpose

Separate attestation cryptographic validity from relying-party trust decisions, then provide extensible trust policy hooks for attestation roots, AAGUID policy, metadata, and certificate status behavior.

## Prerequisites

- Plan 02 verifier contracts complete.
- Plan 03 registration verifier can receive attestation verification outputs.
- Plan 05 format packages expose trust path material and format-specific evidence.

## Deliverables

1. Trust policy interface for attestation acceptance.
2. Built-in policies for accept-none, reject-none, accept-self, reject-self, trust-roots, and format allow-list.
3. Trust path result structures independent of any one X.509 dependency representation where possible.
4. AAGUID policy hook.
5. Metadata provider interface.
6. Certificate status policy hook for intermediate CA certificate status where applicable.
7. Enterprise or restricted enrollment policy examples.
8. Documentation explaining cryptographic validity vs trust acceptance.
9. Keep `make ci` and GitHub Actions green as trust-policy code is added.

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

## Progress updates

2026-05-31: Delivered the minimal trust-policy interface required by the first attestation-format slice. Added `attestation.TrustPolicy`, `TrustPolicyFunc`, `TrustRequest`, and `TrustResult`; registration now accepts an optional caller trust policy after attestation format verification. The default remains conservative: `none` follows the existing `AllowNone` policy and non-`none` attestation is rejected unless caller policy accepts it. Scope remaining: built-in accept/reject policies, trust-root evaluation, AAGUID policy, metadata provider, certificate status behavior, and restricted enrollment examples.

2026-06-01: Completed Plan 07. Added explicit built-in `attestation.TrustPolicy` implementations for accept/reject `none`, accept/reject self, format allow-list, type allow-list, trusted x5c roots through `crypto.CertificateVerifier`, AAGUID allow-list, caller-owned metadata lookup, caller-owned certificate status checks, and `AllOf`/`AnyOf` composition. `TrustRequest` now carries the registration AAGUID so policy code does not need to reparse authenticator data. Added unit tests for accept, reject, mismatch, unavailable provider, revoked/unknown/unavailable status, and composition short-circuit behavior, plus registration integration tests proving the built-in policies preserve `ErrRejectedAttestationPolicy` behavior. Scope note: no trust anchors, metadata service parser, network fetching, OCSP/CRL client, or hidden enterprise enrollment default was added; restricted enrollment is represented as explicit composable policy examples.
