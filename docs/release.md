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
and zero values through `omitzero` tags. Storage writes remain v3, with existing
v1/v2 credential read compatibility; no stored-data rewrite is required.
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
