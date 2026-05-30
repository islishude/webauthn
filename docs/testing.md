# Testing and conformance strategy

Status: updated design, revised 2026-05-30.

This document defines the test approach for the planned WebAuthn/passkey server-side library.

## Test source rules

Tests may be derived from W3C specification requirements, independently generated fixtures, browser outputs collected for this project, and public conformance data when the license and source are documented.

Do not copy tests from public WebAuthn/passkey libraries. Do not translate another library's test cases into this repository.

## Local quality gate

The local quality gate is defined in `docs/ci.md` and implemented by the root `Makefile`.

The required pre-PR command is:

```sh
make ci
```

During the documentation-only baseline, Go-specific targets skip because `go.mod` does not yet exist. Once plan 02 creates `go.mod`, `make ci` must run format checks, linting, unit tests, race tests, bounded fuzz smoke tests when fuzz targets exist, and module tidy verification.

## Test layers

### Protocol model tests

Required coverage:

- dictionary field validation;
- enum and DOMString value handling;
- byte/string transport conversion boundaries;
- RP ID and origin policy validation;
- challenge generation and challenge comparison;
- credential descriptor and transport hint behavior;
- unknown field tolerance where the specification requires it.

### Authenticator data parser tests

Required coverage:

- minimum 37-byte authenticator data without AT or ED;
- UP and UV flag extraction;
- AT flag with attested credential data;
- ED flag with extension data;
- truncated RP ID hash, flags, counter, AAGUID, credential ID length, credential ID, and credential public key;
- invalid or inconsistent length fields;
- sign counter big-endian decoding;
- extension map boundary behavior through the codec adapter.

### Client data tests

Required coverage:

- valid `webauthn.create` and `webauthn.get` values;
- challenge mismatch;
- origin mismatch;
- unknown JSON keys;
- reordered JSON keys;
- optional token binding absence;
- token binding `supported` and `present` behaviors;
- malformed UTF-8 and malformed JSON.

### Registration ceremony tests

Required coverage:

- successful registration with `none` attestation;
- RP ID hash mismatch;
- missing UP flag;
- missing UV flag when required;
- unsupported credential public key algorithm;
- unsupported attestation format;
- invalid attestation statement;
- untrusted attestation policy result;
- duplicate credential ID path surfaced to caller;
- extension requested but absent;
- unsolicited extension behavior under ignore and reject policies.

### Authentication ceremony tests

Required coverage:

- successful assertion verification;
- allow-credentials mismatch;
- credential ownership mismatch;
- missing user handle in discoverable-credential flow;
- user handle mismatch in username-first flow;
- RP ID hash mismatch;
- AppID extension hash acceptance when valid;
- missing UP flag;
- missing UV flag when required;
- signature failure;
- unsupported algorithm;
- zero-counter behavior;
- counter increment behavior;
- counter rollback clone-risk behavior.

### Attestation format tests

Each attestation format package must have its own tests and fixtures. At minimum:

- valid fixture;
- malformed CBOR shape;
- missing required field;
- wrong algorithm;
- invalid signature;
- certificate requirement failure where applicable;
- trust policy accepted and rejected paths where applicable.

Format-specific coverage:

- `none`: empty attestation statement and no trust path.
- `packed`: x5c/basic, self attestation, AAGUID certificate extension behavior, algorithm mismatch.
- `tpm`: TPM statement shape, certificate requirements, public key and name binding, firmware/version checks where available.
- `android-key`: Android key certificate extension parsing, challenge binding, authorization list policy.
- `android-safetynet`: JWS response verification through dependency, nonce binding, certificate/trust policy.
- `fido-u2f`: U2F registration signature base construction and ES256 requirement.
- `apple`: anonymous attestation certificate and nonce binding behavior.

### Extension tests

Required coverage:

- `appid` authentication RP ID hash switching;
- `appidExclude` option serialization and policy representation;
- `uvm` output parsing and absence behavior;
- `credProps` output parsing for discoverable credential/passkey flows;
- `largeBlob` option and output shape handling;
- unknown extension policy.

### Dependency adapter tests

Codec and crypto adapters should have tests that confirm WebAuthn-level expectations without duplicating the dependency's own test suite.

Required coverage:

- CBOR map shape extraction for attestation objects;
- COSE key conversion into verifier inputs;
- algorithm allow-list enforcement;
- ECDSA DER signature verification behavior;
- RSA PKCS#1 v1.5 and RSA-PSS behavior for supported algorithms;
- JWS/JWT verification handoff behavior for SafetyNet-like formats;
- X.509 chain acceptance and rejection through trust policy.

## Fuzzing targets

Fuzzing should be added for:

- authenticator data parser;
- client data parser;
- attestation object decoding boundary;
- extension map decoding boundary;
- transport DTO base64url conversion;
- credential descriptor decoding.

Fuzz tests must not require network access.

CI fuzzing is a bounded smoke check. Longer fuzz campaigns should be run locally or in a separate scheduled workflow once parser surfaces exist.

## Browser interoperability tests

Collect browser-produced registration and authentication outputs for representative environments when implementation exists:

- platform authenticator with discoverable credential;
- roaming security key;
- username-first authentication;
- discoverable passkey authentication;
- user verification required and preferred;
- attestation `none` and direct/enterprise-like flows where available.

Fixtures should be generated specifically for this project and documented with browser, OS, authenticator type, and date. Sensitive values must be test-only.

## Conformance tracking

`docs/testing.md` should gain a matrix when implementation starts. Each row should map a W3C relying-party verification step to tests. A stable release requires all P0 and P1 rows to be covered.

## Continuous integration expectations

The baseline CI workflow is `.github/workflows/ci.yml` and is documented in `docs/ci.md`.

Before release, CI should run:

- documentation and configuration presence checks;
- line-ending checks for text files;
- `gofmt`/`goimports` formatting checks;
- golangci-lint static analysis;
- unit tests;
- race-enabled tests for state-free components where practical;
- fuzz smoke tests with bounded time;
- dependency license checks;
- examples build checks;
- import graph checks proving root package does not import optional attestation packages.

The initial workflow includes the first seven categories that can be expressed before implementation. Dependency license checks, examples build checks, and import graph checks must be added when the corresponding files and packages exist.
