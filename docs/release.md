# Release checklist

## Before publication

- Review [LICENSE](../LICENSE), [SECURITY.md](../SECURITY.md),
  [CHANGELOG.md](../CHANGELOG.md), and README feature claims.
- Run `make ci` from a clean worktree. This includes formatting, TypeScript,
  lint, unit/race/fuzz tests, examples, the independent consumer, root import
  isolation, dependency inventory, and module checks.
- Run `make test-minimum` for Go 1.27.0 and `make e2e` for Chromium and the
  public quickstart.
- Require passing release-branch GitHub Actions, including the
  Linux/macOS/Windows Go compatibility matrix.

See [CI](ci.md) for gate details and [testing](testing.md) for coverage limits.
Local results do not establish remote CI success.

## After tag publication

- Run `make release-install-check RELEASE_VERSION=<published-version>` with the
  exact published tag to verify installation and public consumer tests without
  local replacements.

## Version policy

Before v1, patch releases do not intentionally break the public API. Minor
releases may introduce incompatible changes with explicit migration notes.
Security fixes may tighten accepted behavior and must document the change.
Security maintenance targets the latest release (`main` before the first
release); older versions have no guaranteed backports.

## Level 3 validation corrections

The Recommendation conformance fixes preserve public API and dependency
boundaries. Typed PRF `eval` and `evalByCredential` values now reject a nil
`First`; use a non-nil empty slice when deliberately evaluating an empty input.
Invalid restored inputs also fail finish-time validation.

Compound sub-statements with members beyond `fmt` and `attStmt` are rejected.
Android Key certificate extensions with invalid version/unique-ID types,
undefined security levels, duplicate authorization tags, or non-EXPLICIT
authorization fields are rejected before trust evaluation. EXPLICIT wrappers
must contain exactly one ASN.1 value. These changes tighten
acceptance of malformed attestations without changing caller-owned trust policy.

The browser adapter now base64url-decodes only `blob` in largeBlob outputs.
Unknown `write` output members retain their original value and remain subject
to extension policy; malformed `blob` values still fail.

## Go 1.27 and JSON v2 migration

The next minor release requires Go 1.27.0 or newer. This is an intentional
source-incompatible change and must not be released as a pre-v1 patch update.
Upgrade application toolchains and CI before upgrading this module.

All repository JSON codecs now use `encoding/json/v2`. Applications constructing
`browser.ExtensionJSON` must replace `encoding/json.RawMessage` values with
`encoding/json/jsontext.Value`; the map is now `map[string]jsontext.Value`.
No experimental build flag or new third-party dependency is required.

JSON decoding rejects duplicate member names and invalid UTF-8, and matches
struct fields case-sensitively. Unknown browser/client-data members remain
allowed; storage envelopes reject unknown members. Existing size bounds, exact
signed client-data bytes, and error sentinels remain intact. Underlying JSON
error types and messages may change; applications should use package sentinels.

Optional DTO pointers preserve explicit empty strings, empty containers, false,
and zero values through `omitzero` tags. Storage uses the sole v1 envelope
format described below; the JSON codec version and envelope version are independent.
Generic JSON output follows v2 defaults: nil maps/slices encode as empty
objects/arrays, map ordering is unspecified, and custom marshaling follows v2
method dispatch. HTTP helpers retain HTML escaping and a final newline, and
finish serialization before committing headers. Compare JSON semantically,
not by object member order. Direct serialization of private protocol byte
wrappers is unsupported; use browser DTOs or the storage encoding functions.

The standard signature adapter now requires fixed-width EC2 coordinates (32, 48,
or 66 bytes for P-256, P-384, or P-521) before standard-library point parsing.
The bundled COSE decoder already produces this representation; custom decoder
adapters must do so as well. Malformed coordinates fail as invalid public keys.

## Storage envelope v1

Version 1 is the only supported storage envelope format. All three encoders write
version 1, and all decoders reject other integer versions with
`ErrUnsupportedVersion`. The payload includes credential type, extension handler
bindings, and related-origin policy, and enforces the documented validation and
size limits. Credential type must be explicit and equal to `public-key`.

Persist the complete format using the current storage API. Ceremony states must
include all required policy and extension bindings; applications remain
responsible for expiry enforcement and single-use consumption. Envelope decoding
validates the current schema and does not infer missing required values.
