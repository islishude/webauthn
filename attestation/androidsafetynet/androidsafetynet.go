// Package androidsafetynet verifies WebAuthn "android-safetynet" attestation
// statements.
package androidsafetynet

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/internal/attcrypto"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

const (
	format                 = "android-safetynet"
	safetyNetAttestDNSName = "attest.android.com"
)

var (
	// ErrInvalidStatement reports a malformed Android SafetyNet attestation
	// statement.
	ErrInvalidStatement = errors.New("invalid android-safetynet attestation statement")
	// ErrInvalidJWS reports a failed Android SafetyNet JWS verification.
	ErrInvalidJWS = errors.New("invalid android-safetynet jws")
	// ErrInvalidPayload reports a malformed or policy-rejected SafetyNet JWS
	// payload.
	ErrInvalidPayload = errors.New("invalid android-safetynet payload")
	// ErrInvalidNonce reports a SafetyNet nonce mismatch.
	ErrInvalidNonce = errors.New("invalid android-safetynet nonce")
	// ErrCertificateRequirements reports a SafetyNet certificate requirement
	// failure.
	ErrCertificateRequirements = errors.New("android-safetynet certificate requirements failed")
)

// Verifier verifies the exact "android-safetynet" attestation format.
type Verifier struct {
	jwsVerifier webcrypto.JWSVerifier
}

// New returns an Android SafetyNet attestation verifier using jwsVerifier for
// JWS signature and certificate-chain verification.
func New(jwsVerifier webcrypto.JWSVerifier) Verifier {
	return Verifier{jwsVerifier: jwsVerifier}
}

// Format returns the WebAuthn attestation format identifier.
func (Verifier) Format() string {
	return format
}

// VerifyAttestation verifies Android SafetyNet attestation statements.
func (v Verifier) VerifyAttestation(ctx context.Context, request attestation.VerificationRequest) (attestation.VerificationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Format != format || v.jwsVerifier == nil {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	statement, err := parseStatement(request.Statement)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	if request.AuthenticatorData.Len() == 0 || len(request.ClientDataHash) == 0 {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	verification, err := v.jwsVerifier.VerifyJWS(ctx, webcrypto.NewJWSToken(statement.response))
	if err != nil {
		return attestation.VerificationResult{}, fmt.Errorf("%w: %w", ErrInvalidJWS, err)
	}
	if err := validateSafetyNetCertificate(verification.Certificates); err != nil {
		return attestation.VerificationResult{}, err
	}
	if err := validatePayload(verification.Payload, expectedNonce(request.AuthenticatorData, request.ClientDataHash)); err != nil {
		return attestation.VerificationResult{}, err
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeBasic,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathX509, Certificates: verification.Certificates},
		CryptographicallyValid: true,
	}, nil
}

func expectedNonce(authenticatorData protocol.AuthenticatorData, clientDataHash []byte) string {
	digest := sha256.Sum256(attcrypto.SignedData(authenticatorData, clientDataHash))

	return base64.StdEncoding.EncodeToString(digest[:])
}

func validateSafetyNetCertificate(chain webcrypto.CertificateChain) error {
	if len(chain) == 0 {
		return ErrCertificateRequirements
	}
	leaf, err := x509.ParseCertificate(chain[0].Raw())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCertificateRequirements, err)
	}
	if err := leaf.VerifyHostname(safetyNetAttestDNSName); err != nil {
		return fmt.Errorf("%w: %w", ErrCertificateRequirements, err)
	}

	return nil
}

var _ attestation.Verifier = Verifier{}
