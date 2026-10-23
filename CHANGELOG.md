# Changelog

## Unreleased

- Correct Level 3 boundary validation: require `first` in typed PRF values,
  reject extra compound sub-statement members and malformed Android Key
  extension fields, and decode only the defined `blob` byte member in
  largeBlob outputs. See the [conformance notes](docs/release.md#level-3-validation-corrections).

- Define v1 as the only storage envelope format, with explicit credential type,
  extension handler bindings, and strict validation. See the
  [storage format contract](docs/release.md#storage-envelope-v1).

- Breaking, for the next minor release: require Go 1.27.0 and migrate all JSON
  codecs to `encoding/json/v2`. `browser.ExtensionJSON` now contains
  `jsontext.Value`; JSON parsing rejects duplicate names and invalid UTF-8 and
  matches fields case-sensitively. Preserve optional field presence. See the [migration notes](docs/release.md#go-127-and-json-v2-migration).

- Update ECDSA adapters for current standard-library key APIs; require fixed-width
  coordinates from custom key adapters. Module tidy checks now use non-mutating
  `go mod tidy -diff`.
- Validate authenticator selection consistently before ceremony generation and
  browser conversion; report stored credential failures as `ErrInvalidCredentialRecord`.
  See the [integration contracts](docs/integration.md) for configuration and error handling.
- Add copied credential descriptors and conditional `CredentialUpdate.ApplyTo`
  with explicit conflict/invalid-update errors; preserve existing counter policies.
- Add tested multi-account application integration with encoded storage, atomic
  consumption, row versions, explicit risk rejection and reference persistence SQL.
- Clarify development installation, browser capability boundaries and fixed-version
  release installation; pin minimum Go 1.27.0 and test the latest 1.27 patch as well.

- Replace untyped ceremony extension inputs/client outputs and browser DTO
  extension maps with typed input contracts, `ClientOutputs`, and raw JSON
  messages; add handler-inferred `SetInput`. Browser option conversion now
  returns errors.
- Replace attestation evidence maps, compound raw sub-results, and untyped
  certificate roots with copyable typed evidence, explicit sub-statements, and
  certificate chains. Remove unused JWS header and certificate policy payloads.
  See [type safety](docs/type-safety.md) for these source-breaking changes.

- Add reusable `Config`/`RelyingParty` APIs with startup validation and strict
  state/configuration matching; retain the low-level ceremony functions.
- Add explicit `preset.PasskeyConfig`: discoverable credentials, required UV,
  none attestation, standard signature verification and Level 3 extensions.
- Add the localhost quickstart with native browser JSON APIs, tested public
  examples, integration guidance, and an independent consumer module.
- Add minimum-Go and cross-platform CI coverage, project MIT license and
  private vulnerability reporting instructions.

These changes do not alter the low-level empty algorithm defaults. Low-level callers must update the changed type boundaries before compiling. The
RP object requires explicit decoders, trust policy and algorithm policy.
Changing its state-bound policy requires starting a fresh ceremony.
