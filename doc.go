// Package webauthn is the framework-neutral root package for relying-party
// WebAuthn and passkey ceremonies.
//
// Registration and authentication APIs are implemented for transport-neutral
// relying-party ceremonies.
//
// New validates reusable Config values; RelyingParty methods accept only
// per-ceremony data. The optional preset package provides explicit passkey
// defaults. Existing package functions expose lower-level dependency injection.
// Callers own account lookup, one-time state consumption, unique credential
// insertion and conditional updates before application session creation.
package webauthn

// ModulePath is the canonical Go module path.
const ModulePath = "github.com/islishude/webauthn"
