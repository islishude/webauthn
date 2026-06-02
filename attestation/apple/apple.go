// Package apple verifies WebAuthn "apple" anonymous attestation statements.
package apple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/internal/attcrypto"
	"github.com/islishude/webauthn/attestation/internal/x509util"
	"github.com/islishude/webauthn/protocol"
)

const format = "apple"

var (
	oidExtensionAppleAnonymousAttestationNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

	// ErrInvalidStatement reports a malformed Apple attestation statement.
	ErrInvalidStatement = errors.New("invalid apple attestation statement")
	// ErrUnsupportedKey reports credential or certificate public key material
	// that this verifier cannot bind.
	ErrUnsupportedKey = errors.New("unsupported apple attestation key")
	// ErrPublicKeyMismatch reports a mismatch between the certificate public
	// key and the credential public key material.
	ErrPublicKeyMismatch = errors.New("apple public key mismatch")
	// ErrInvalidNonce reports a malformed or mismatched Apple attestation
	// nonce extension.
	ErrInvalidNonce = errors.New("invalid apple attestation nonce")
	// ErrCertificateRequirements reports an Apple certificate requirement
	// failure.
	ErrCertificateRequirements = errors.New("apple attestation certificate requirements failed")
)

// Verifier verifies the exact "apple" attestation format.
type Verifier struct{}

// New returns an Apple anonymous attestation verifier.
func New() Verifier {
	return Verifier{}
}

// Format returns the WebAuthn attestation format identifier.
func (Verifier) Format() string {
	return format
}

// VerifyAttestation verifies Apple anonymous attestation statements.
func (Verifier) VerifyAttestation(_ context.Context, request attestation.VerificationRequest) (attestation.VerificationResult, error) {
	if request.Format != format {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	statement, err := parseStatement(request.Statement)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	if request.AuthenticatorData.Len() == 0 || len(request.ClientDataHash) == 0 {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	chain, certificates, err := x509util.ParseCertificateChain(statement.x5c, ErrInvalidStatement)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	leaf := certificates[0]
	if err := validateNonceExtension(leaf, expectedNonce(request.AuthenticatorData, request.ClientDataHash)); err != nil {
		return attestation.VerificationResult{}, err
	}
	if err := x509util.ValidatePublicKey(leaf.PublicKey, request.CredentialPublicKey.PublicKeyMaterial(), ErrUnsupportedKey, ErrPublicKeyMismatch); err != nil {
		return attestation.VerificationResult{}, err
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeAnonymizationCA,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathX509, Certificates: chain},
		CryptographicallyValid: true,
	}, nil
}

func expectedNonce(authenticatorData protocol.AuthenticatorData, clientDataHash []byte) []byte {
	digest := sha256.Sum256(attcrypto.SignedData(authenticatorData, clientDataHash))

	return digest[:]
}

func validateNonceExtension(certificate *x509.Certificate, expected []byte) error {
	extension, ok := x509util.FindExtension(certificate, oidExtensionAppleAnonymousAttestationNonce)
	if !ok {
		return ErrCertificateRequirements
	}

	var nonce []byte
	rest, err := asn1.Unmarshal(extension.Value, &nonce)
	if err != nil || len(rest) != 0 || len(nonce) != sha256.Size {
		return ErrInvalidNonce
	}
	if !bytes.Equal(nonce, expected) {
		return ErrInvalidNonce
	}

	return nil
}

var _ attestation.Verifier = Verifier{}
