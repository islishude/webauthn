// Package fidou2f verifies WebAuthn "fido-u2f" attestation statements.
package fidou2f

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/internal/attcrypto"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

const (
	format         = "fido-u2f"
	algorithmES256 = protocol.COSEAlgorithmIdentifier(-7)
)

var (
	// ErrInvalidStatement reports a malformed FIDO U2F attestation statement.
	ErrInvalidStatement = errors.New("invalid fido-u2f attestation statement")
	// ErrUnsupportedKey reports a credential or attestation key that cannot be
	// used for FIDO U2F attestation verification.
	ErrUnsupportedKey = errors.New("unsupported fido-u2f attestation key")
	// ErrInvalidSignature reports a FIDO U2F attestation signature failure.
	ErrInvalidSignature = errors.New("invalid fido-u2f attestation signature")
)

// Verifier verifies the exact "fido-u2f" attestation format.
type Verifier struct {
	signatureVerifier webcrypto.SignatureVerifier
}

// New returns a FIDO U2F attestation verifier using signatureVerifier for the
// attestation signature check.
func New(signatureVerifier webcrypto.SignatureVerifier) Verifier {
	return Verifier{signatureVerifier: signatureVerifier}
}

// Format returns the WebAuthn attestation format identifier.
func (Verifier) Format() string {
	return format
}

// VerifyAttestation verifies FIDO U2F attestation statements.
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
	if request.CredentialPublicKey.Algorithm != algorithmES256 {
		return attestation.VerificationResult{}, ErrUnsupportedKey
	}
	publicKeyU2F := request.CredentialPublicKey.U2FPublicKey()
	if len(publicKeyU2F) != 65 || publicKeyU2F[0] != 0x04 {
		return attestation.VerificationResult{}, ErrUnsupportedKey
	}
	if len(request.ClientDataHash) != 32 {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	parsedAuthData, err := protocol.ParseAuthenticatorData(request.AuthenticatorData)
	if err != nil {
		return attestation.VerificationResult{}, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	if parsedAuthData.AttestedCredentialData == nil {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	chain, certificate, err := parseCertificate(statement.x5c)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	certificatePublicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || !isP256(certificatePublicKey) {
		return attestation.VerificationResult{}, ErrUnsupportedKey
	}

	verificationData := u2fVerificationData(
		parsedAuthData.RPIDHash,
		request.ClientDataHash,
		parsedAuthData.AttestedCredentialData.CredentialID,
		publicKeyU2F,
	)
	if err := v.verifySignature(ctx, certificatePublicKey, verificationData, statement.signature); err != nil {
		return attestation.VerificationResult{}, err
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeUncertain,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathX509, Certificates: chain},
		CryptographicallyValid: true,
	}, nil
}

func parseCertificate(raw []byte) (webcrypto.CertificateChain, *x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}

	return webcrypto.CertificateChain{webcrypto.NewCertificate(raw)}, certificate, nil
}

func u2fVerificationData(rpIDHash []byte, clientDataHash []byte, credentialID protocol.CredentialID, publicKeyU2F []byte) []byte {
	out := make([]byte, 0, 1+len(rpIDHash)+len(clientDataHash)+credentialID.Len()+len(publicKeyU2F))
	out = append(out, 0x00)
	out = append(out, rpIDHash...)
	out = append(out, clientDataHash...)
	out = credentialID.AppendTo(out)
	out = append(out, publicKeyU2F...)

	return out
}

func (v Verifier) verifySignature(ctx context.Context, publicKey *ecdsa.PublicKey, signed []byte, signature []byte) error {
	return attcrypto.VerifySignature(ctx, v.signatureVerifier, algorithmES256, publicKey, signed, signature, ErrInvalidStatement, ErrInvalidSignature)
}

func isP256(publicKey *ecdsa.PublicKey) bool {
	if publicKey == nil || publicKey.Curve == nil {
		return false
	}

	return publicKey.Curve.Params().Name == elliptic.P256().Params().Name
}

var _ attestation.Verifier = Verifier{}
