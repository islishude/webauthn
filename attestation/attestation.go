// Package attestation defines format verifier contracts and registry behavior.
package attestation

import (
	"context"
	"errors"
	"fmt"

	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

var (
	// ErrInvalidFormat reports an empty attestation format identifier.
	ErrInvalidFormat = errors.New("attestation format is empty")
	// ErrDuplicateFormat reports a duplicate registry entry.
	ErrDuplicateFormat = errors.New("attestation format already registered")
)

// Type classifies an attestation statement result.
type Type string

const (
	TypeNone            Type = "none"
	TypeSelf            Type = "self"
	TypeBasic           Type = "basic"
	TypeAttCA           Type = "attca"
	TypeAnonymizationCA Type = "anonymization-ca"
	TypeUncertain       Type = "uncertain"
)

// TrustPathKind identifies the kind of trust path material returned by a format.
type TrustPathKind string

const (
	TrustPathNone TrustPathKind = "none"
	TrustPathX509 TrustPathKind = "x5c"
	TrustPathRaw  TrustPathKind = "raw"
)

// TrustPath carries format evidence without making trust decisions.
type TrustPath struct {
	Kind         TrustPathKind
	Certificates webcrypto.CertificateChain
	Raw          any
}

// VerificationRequest is the input passed to an attestation format verifier.
type VerificationRequest struct {
	Format               string
	AuthenticatorData    protocol.AuthenticatorData
	ClientDataHash       []byte
	Statement            codec.AttestationStatement
	CredentialPublicKey  codec.CredentialPublicKey
	RawAttestationObject protocol.AttestationObject
}

// VerificationResult separates format validity from RP trust acceptance.
type VerificationResult struct {
	Type                   Type
	TrustPath              TrustPath
	CryptographicallyValid bool
	Warnings               []string
	Evidence               map[string]any
}

// TrustRequest is the evidence, including registration AAGUID, passed to
// relying-party attestation trust policy after format verification succeeds.
type TrustRequest struct {
	Format               string
	Result               VerificationResult
	AAGUID               protocol.AAGUID
	AuthenticatorData    protocol.AuthenticatorData
	CredentialPublicKey  codec.CredentialPublicKey
	RawAttestationObject protocol.AttestationObject
}

// TrustResult records whether relying-party policy accepts attestation
// evidence after cryptographic format verification.
type TrustResult struct {
	Accepted bool
	Reason   string
	Warnings []string
}

// TrustPolicy decides whether verified attestation evidence is acceptable for
// a relying party.
type TrustPolicy interface {
	EvaluateAttestationTrust(context.Context, TrustRequest) (TrustResult, error)
}

// TrustPolicyFunc adapts a function into a TrustPolicy.
type TrustPolicyFunc func(context.Context, TrustRequest) (TrustResult, error)

// EvaluateAttestationTrust calls f(ctx, request).
func (f TrustPolicyFunc) EvaluateAttestationTrust(ctx context.Context, request TrustRequest) (TrustResult, error) {
	return f(ctx, request)
}

// Verifier verifies one exact attestation statement format identifier.
type Verifier interface {
	Format() string
	VerifyAttestation(context.Context, VerificationRequest) (VerificationResult, error)
}

// Registry is a case-sensitive verifier registry.
type Registry struct {
	verifiers map[string]Verifier
}

// NewRegistry builds a registry and rejects duplicate format identifiers.
func NewRegistry(verifiers ...Verifier) (*Registry, error) {
	registry := &Registry{verifiers: make(map[string]Verifier, len(verifiers))}
	for _, verifier := range verifiers {
		if err := registry.Register(verifier); err != nil {
			return nil, err
		}
	}

	return registry, nil
}

// Register adds a verifier. Duplicate format identifiers fail by default.
func (r *Registry) Register(verifier Verifier) error {
	if verifier == nil {
		return ErrInvalidFormat
	}

	format := verifier.Format()
	if format == "" {
		return ErrInvalidFormat
	}

	if r.verifiers == nil {
		r.verifiers = make(map[string]Verifier)
	}

	if _, exists := r.verifiers[format]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateFormat, format)
	}

	r.verifiers[format] = verifier
	return nil
}

// Lookup returns the verifier for format.
func (r *Registry) Lookup(format string) (Verifier, bool) {
	if r == nil || r.verifiers == nil {
		return nil, false
	}

	verifier, ok := r.verifiers[format]
	return verifier, ok
}
