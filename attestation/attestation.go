// Package attestation defines format verifier contracts and registry behavior.
package attestation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/internal/interfaceutil"
	"github.com/islishude/webauthn/internal/protocolidentifier"
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

// Known reports whether t is a defined WebAuthn attestation type.
func (t Type) Known() bool {
	switch t {
	case TypeNone, TypeSelf, TypeBasic, TypeAttCA, TypeAnonymizationCA, TypeUncertain:
		return true
	default:
		return false
	}
}

// TrustPathKind identifies the kind of trust path material returned by a format.
type TrustPathKind string

const (
	TrustPathNone TrustPathKind = "none"
	TrustPathX509 TrustPathKind = "x5c"
	TrustPathRaw  TrustPathKind = "raw"
)

// Known reports whether k is a trust-path representation understood by this
// package. Format verifiers must use Raw for non-X.509 evidence instead of
// inventing an unrecognized kind.
func (k TrustPathKind) Known() bool {
	switch k {
	case TrustPathNone, TrustPathX509, TrustPathRaw:
		return true
	default:
		return false
	}
}

// TrustPath carries format evidence without making trust decisions.
type TrustPath struct {
	Kind         TrustPathKind
	Certificates webcrypto.CertificateChain
	Raw          any
}

// VerificationRequest is the input passed to an attestation format verifier.
type VerificationRequest struct {
	Format               string
	ConveyancePreference protocol.AttestationConveyancePreference
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

// Clone returns a result whose mutable metadata containers do not alias the
// source result.
func (result VerificationResult) Clone() VerificationResult {
	result.TrustPath = cloneTrustPath(result.TrustPath)
	result.Warnings = slices.Clone(result.Warnings)
	result.Evidence = maps.Clone(result.Evidence)
	return result
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

// Clone returns a trust result with an independent warnings slice.
func (result TrustResult) Clone() TrustResult {
	result.Warnings = slices.Clone(result.Warnings)
	return result
}

func cloneTrustPath(path TrustPath) TrustPath {
	path.Certificates = slices.Clone(path.Certificates)
	if results, ok := path.Raw.([]VerificationResult); ok {
		cloned := make([]VerificationResult, len(results))
		for i, result := range results {
			cloned[i] = result.Clone()
		}
		path.Raw = cloned
	}
	return path
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
	if f == nil {
		return TrustResult{}, ErrTrustPolicyConfiguration
	}
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
		if interfaceutil.IsNil(verifier) || !protocolidentifier.Valid(verifier.Format()) {
			return nil, ErrInvalidFormat
		}
		format := verifier.Format()
		if _, exists := registry.verifiers[format]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateFormat, format)
		}
		registry.verifiers[format] = verifier
	}

	return registry, nil
}

// Lookup returns the verifier for format.
func (r *Registry) Lookup(format string) (Verifier, bool) {
	if r == nil || r.verifiers == nil {
		return nil, false
	}

	verifier, ok := r.verifiers[format]
	return verifier, ok
}
