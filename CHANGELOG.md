# Changelog

## Unreleased

- Add reusable `Config`/`RelyingParty` APIs with startup validation and strict
  state/configuration matching; retain the low-level ceremony functions.
- Add explicit `preset.PasskeyConfig`: discoverable credentials, required UV,
  none attestation, standard signature verification and Level 3 extensions.
- Add the localhost quickstart with native browser JSON APIs, tested public
  examples, integration guidance, and an independent consumer module.
- Add minimum-Go and cross-platform CI coverage, project MIT license and
  private vulnerability reporting instructions.

These changes do not alter the low-level empty algorithm defaults or the v3
storage envelope. Existing low-level callers can migrate incrementally. The
RP object requires explicit decoders, trust policy and algorithm policy.
Changing its state-bound policy requires starting a fresh ceremony.

Earlier implementation changes and pre-v1 migrations are recorded in
[release notes](docs/release.md).
