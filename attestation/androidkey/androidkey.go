// Package androidkey verifies WebAuthn "android-key" attestation statements.
package androidkey

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/islishude/webauthn/attestation"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
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
	authenticatorData := request.AuthenticatorData.Bytes()
	if len(authenticatorData) == 0 || len(request.ClientDataHash) == 0 {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	chain, certificates, err := parseCertificateChain(statement.x5c)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	leaf := certificates[0]
	if err := validateCertificatePublicKey(leaf, request.CredentialPublicKey.PublicKeyMaterial()); err != nil {
		return attestation.VerificationResult{}, err
	}
	extension, ok := findExtension(leaf, oidExtensionAndroidKeyAttestation)
	if !ok {
		return attestation.VerificationResult{}, ErrCertificateRequirements
	}
	if err := validateAndroidKeyExtension(extension.Value, request.ClientDataHash); err != nil {
		return attestation.VerificationResult{}, err
	}
	if err := v.verifySignature(ctx, statement.algorithm, leaf.PublicKey, signedData(authenticatorData, request.ClientDataHash), statement.signature); err != nil {
		return attestation.VerificationResult{}, err
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeBasic,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathX509, Certificates: chain},
		CryptographicallyValid: true,
	}, nil
}

func signedData(authenticatorData []byte, clientDataHash []byte) []byte {
	out := make([]byte, 0, len(authenticatorData)+len(clientDataHash))
	out = append(out, authenticatorData...)
	out = append(out, clientDataHash...)

	return out
}

func (v Verifier) verifySignature(ctx context.Context, algorithm protocol.COSEAlgorithmIdentifier, publicKey any, signed []byte, signature []byte) error {
	protocolSignature, err := protocol.NewSignature(signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	if err := v.signatureVerifier.VerifySignature(ctx, webcrypto.SignatureInput{
		Algorithm: algorithm,
		PublicKey: publicKey,
		Signed:    bytes.Clone(signed),
		Signature: protocolSignature,
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	return nil
}

var _ attestation.Verifier = Verifier{}
