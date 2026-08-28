# W3C WebAuthn Level 3 test vectors

This directory contains the complete 45-case inventory used from section 16 of
**Web Authentication: An API for accessing Public Key Credentials — Level 3**,
Recommendation, 25 August 2026:

- 30 registration and authentication ceremony cases;
- 12 Web Authentication API `prf` output cases;
- 3 CTAP2 `hmac-secret` calculation cases.

Source: <https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors>

`coverage.json` lists all 45 unique case IDs and their expected outcomes.
`ceremonies.json`, `prf-api.json`, and `prf-ctap.json` contain the corresponding
local, network-independent fixtures. The shared attestation root certificate is
included but is not counted as a separate test case.

Section 16 is non-normative. Its TPM registration vector encodes `sig` as a DER
ECDSA signature even though normative section 8.3 requires a `TPMT_SIGNATURE`.
The original bytes are retained and expected to fail strict verification. The
test suite derives an in-memory conforming wrapper from the published `r` and
`s` values and verifies that form without widening production acceptance.

The fixtures are copied from the specification under the
[W3C permissive document license](https://www.w3.org/copyright/document-license-2023/).
They contain deterministic test-only keys and credentials and no production
account, authenticator, or private-key material. The CTAP2 calculations are
test-only and do not add a client, authenticator, or device-communication API.
