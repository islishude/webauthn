# Release checklist

Status: Plan 15 API cleanup complete, revised 2026-06-02.

This file records release-readiness checks for `github.com/islishude/webauthn`.

## Release candidate requirements

- All P0 and P1 plans in `docs/plans.md` are complete.
- Plan 14 Level 3 release alignment is complete.
- Plan 15 API cleanup and refactor is complete.
- Local `make ci` passes from a clean worktree.
- GitHub Actions CI passes on the release branch.
- Root package import graph does not include `net/http`, `browser`, `transport/http`, or optional attestation format packages.
- Public examples compile through `make example-build`.
- README feature claims match implemented and tested behavior.
- Dependency inventory in `docs/dependencies.json` covers every module returned by `go list -m all`.

## Release notes

2026-06-01: Completed Plan 09. Added optional browser JSON DTO conversion helpers, optional standard-library HTTP JSON helpers, compile-checked manual/HTTP/passkey/attestation examples, README example reference checks, CI example builds, and release documentation. No third-party dependency was added.

2026-06-01: Completed Plans 10 through 14. Upgraded the normative baseline to
WebAuthn Level 3, added `OriginPolicy`/`topOrigin`, Level 3 hints and
attestation format fields, PRF extension handling, deprecated `uvm` result
metadata, compound attestation support, OKP credential public-key material, and
Level 3 browser/HTTP DTO coverage. No third-party dependency was added.

2026-06-02: Completed Plan 15. Removed unused grouped decoder and crypto hash
API, split root finish options into narrow decoder fields, made attestation
acceptance depend only on explicit trust policy, added typed byte
comparison/append helpers, clarified configuration and ceremony-state errors,
and shared extension/signature helper logic. No third-party dependency was
added.

## Non-goals

- No production server, router, storage, session, cookie, CSRF, rate-limit, or account recovery adapter is shipped.
- No hidden attestation trust roots, metadata network client, OCSP/CRL client, or enterprise enrollment default is shipped.
- No root package dependency on browser JSON, `net/http`, optional transport helpers, or optional attestation formats is allowed.
