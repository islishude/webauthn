# webauthn

`github.com/islishude/webauthn` is planned as a Go server-side library for WebAuthn/passkey relying-party behavior.

Current status: documentation and execution planning only. No implementation code has been added in this planning pass.

## Goals

The library is designed to make WebAuthn easy to add to existing Go services without coupling the core to `net/http`, a specific web framework, a database layer, or a session mechanism.

The root module will focus on WebAuthn relying-party ceremonies:

- create registration options;
- verify registration responses;
- create authentication options;
- verify authentication assertions;
- return credential records, counter updates, attestation results, and policy decisions that an application can persist in its own storage.

The implementation must support complete WebAuthn Level 2 relying-party protocol behavior before a stable release. Passkey use cases are covered through WebAuthn discoverable credentials, user handles, user verification policy, authenticator selection, and browser-facing option structures.

## Design constraints

The project deliberately avoids implementing foundational cryptography and encoding libraries. It may implement WebAuthn-specific structure parsing and validation, but general-purpose CBOR, COSE, ASN.1, JWS, X.509, JSON, base64url, and cryptographic primitives must come from Go standard library packages, explicit dependencies, or injected interfaces.

The core package must stay transport-neutral. Optional transport helpers may be added later, but the core API must be usable from any HTTP router, RPC service, command flow, test harness, or custom integration.

Attestation support must be modular. Importing the root module should not import every attestation verifier. Applications should select the formats they accept, such as `none`, `packed`, `tpm`, `android-key`, `android-safetynet`, `fido-u2f`, and `apple`, according to their policy and dependency appetite.

No public WebAuthn/passkey library implementation may be used, copied, translated, adapted, or referenced as source material.

## Planned documentation map

- `docs/technical.md` describes the target architecture and internal boundaries.
- `docs/protocol-map.md` maps WebAuthn Level 2 protocol areas to planned library components.
- `docs/api-boundaries.md` defines the transport-neutral public API shape and module boundaries.
- `docs/security-model.md` records security and privacy policy decisions.
- `docs/testing.md` defines the test and conformance strategy.
- `docs/plans.md` is the top-level implementation plan index.
- `docs/plans/*.md` contains prioritized execution plans. When a plan is completed, both the plan file and `docs/plans.md` must be updated.

## Planned package philosophy

The final package layout should keep the root package small and stable. Format-specific and adapter-specific code should live outside the root package. The intended direction is:

- root package: ceremony orchestration, configuration, policy, result types, registries;
- protocol packages: WebAuthn data structures and validation helpers;
- attestation packages: one package per attestation statement format;
- extension packages: one package per WebAuthn extension when behavior is non-trivial;
- codec and crypto adapter packages: narrow wrappers over standard or third-party implementations;
- optional integration packages: JSON/browser transport helpers and framework-neutral HTTP helpers.

This README is intentionally high-level until implementation begins. Feature claims must be added only after matching code and tests exist.
