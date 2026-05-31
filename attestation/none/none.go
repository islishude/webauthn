// Package none verifies WebAuthn "none" attestation statements.
package none

import (
	"context"
	"errors"

	"github.com/islishude/webauthn/attestation"
)

const format = "none"

var (
	// ErrInvalidStatement reports a non-empty "none" attestation statement.
	ErrInvalidStatement = errors.New("invalid none attestation statement")
)

// Verifier verifies the exact "none" attestation format.
type Verifier struct{}

// Format returns the WebAuthn attestation format identifier.
func (Verifier) Format() string {
	return format
}

// VerifyAttestation verifies that the "none" attestation statement is empty.
func (Verifier) VerifyAttestation(_ context.Context, request attestation.VerificationRequest) (attestation.VerificationResult, error) {
	if request.Format != format || len(request.Statement) != 0 {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeNone,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathNone},
		CryptographicallyValid: true,
	}, nil
}

// New returns a "none" attestation verifier.
func New() Verifier {
	return Verifier{}
}

var _ attestation.Verifier = Verifier{}
