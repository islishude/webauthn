// Package androidkey verifies WebAuthn "android-key" attestation statements.
package androidkey

import (
	"context"
	"errors"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/internal/attcrypto"
	"github.com/islishude/webauthn/attestation/internal/x509util"
	webcrypto "github.com/islishude/webauthn/crypto"
)

const format = "android-key"

var (
	// ErrInvalidStatement reports a malformed Android Key attestation statement.
	ErrInvalidStatement = errors.New("invalid android-key attestation statement")
	// ErrUnsupportedKey reports credential or certificate public key material
	// that this verifier cannot bind.
	ErrUnsupportedKey = errors.New("unsupported android-key attestation key")
	// ErrPublicKeyMismatch reports a mismatch between the certificate public key
	// and the credential public key material.
	ErrPublicKeyMismatch = errors.New("android-key public key mismatch")
	// ErrInvalidSignature reports an Android Key attestation signature failure.
	ErrInvalidSignature = errors.New("invalid android-key attestation signature")
	// ErrInvalidExtension reports a malformed Android Key attestation extension.
	ErrInvalidExtension = errors.New("invalid android-key attestation extension")
	// ErrCertificateRequirements reports an Android Key certificate requirement
	// failure.
	ErrCertificateRequirements = errors.New("android-key attestation certificate requirements failed")
)

// Verifier verifies the exact "android-key" attestation format.
type Verifier struct {
	signatureVerifier webcrypto.SignatureVerifier
}

// New returns an Android Key attestation verifier using signatureVerifier for
// the attestation signature check.
func New(signatureVerifier webcrypto.SignatureVerifier) Verifier {
	return Verifier{signatureVerifier: signatureVerifier}
}

// Format returns the WebAuthn attestation format identifier.
func (Verifier) Format() string {
	return format
}

// VerifyAttestation verifies Android Key attestation statements.
func (v Verifier) VerifyAttestation(ctx context.Context, request attestation.VerificationRequest) (attestation.VerificationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Format != format || v.signatureVerifier == nil {
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
	if err := x509util.ValidatePublicKey(leaf.PublicKey, request.CredentialPublicKey.PublicKeyMaterial(), ErrUnsupportedKey, ErrPublicKeyMismatch); err != nil {
		return attestation.VerificationResult{}, err
	}
	extension, ok := x509util.FindExtension(leaf, oidExtensionAndroidKeyAttestation)
	if !ok {
		return attestation.VerificationResult{}, ErrCertificateRequirements
	}
	if err := validateAndroidKeyExtension(extension.Value, request.ClientDataHash); err != nil {
		return attestation.VerificationResult{}, err
	}
	if err := attcrypto.VerifySignature(ctx, v.signatureVerifier, statement.algorithm, leaf.PublicKey, attcrypto.SignedData(request.AuthenticatorData, request.ClientDataHash), statement.signature, ErrInvalidSignature, ErrInvalidSignature); err != nil {
		return attestation.VerificationResult{}, err
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeBasic,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathX509, Certificates: chain},
		CryptographicallyValid: true,
	}, nil
}

var _ attestation.Verifier = Verifier{}
