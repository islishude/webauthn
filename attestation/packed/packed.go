// Package packed verifies WebAuthn "packed" attestation statements.
package packed

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/internal/x509util"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

const format = "packed"

var (
	// ErrInvalidStatement reports a malformed packed attestation statement.
	ErrInvalidStatement = errors.New("invalid packed attestation statement")
	// ErrAlgorithmMismatch reports a self-attestation algorithm mismatch.
	ErrAlgorithmMismatch = errors.New("packed attestation algorithm mismatch")
	// ErrInvalidSignature reports a packed attestation signature failure.
	ErrInvalidSignature = errors.New("invalid packed attestation signature")
	// ErrCertificateRequirements reports a packed x5c certificate requirement failure.
	ErrCertificateRequirements = errors.New("packed attestation certificate requirements failed")
)

// Verifier verifies the exact "packed" attestation format.
type Verifier struct {
	signatureVerifier webcrypto.SignatureVerifier
}

// New returns a packed attestation verifier using signatureVerifier for all
// attestation signature checks.
func New(signatureVerifier webcrypto.SignatureVerifier) Verifier {
	return Verifier{signatureVerifier: signatureVerifier}
}

// Format returns the WebAuthn attestation format identifier.
func (Verifier) Format() string {
	return format
}

// VerifyAttestation verifies packed self-attestation and x5c attestation
// statements.
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
	signed := make([]byte, 0, len(authenticatorData)+len(request.ClientDataHash))
	signed = append(signed, authenticatorData...)
	signed = append(signed, request.ClientDataHash...)

	if statement.hasX5C {
		return v.verifyX5C(ctx, request, statement, signed)
	}

	return v.verifySelf(ctx, request, statement, signed)
}

func (v Verifier) verifySelf(ctx context.Context, request attestation.VerificationRequest, statement packedStatement, signed []byte) (attestation.VerificationResult, error) {
	if statement.algorithm != request.CredentialPublicKey.Algorithm {
		return attestation.VerificationResult{}, ErrAlgorithmMismatch
	}
	if err := v.verifySignature(ctx, statement.algorithm, request.CredentialPublicKey.Key, signed, statement.signature); err != nil {
		return attestation.VerificationResult{}, err
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeSelf,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathNone},
		CryptographicallyValid: true,
	}, nil
}

func (v Verifier) verifyX5C(ctx context.Context, request attestation.VerificationRequest, statement packedStatement, signed []byte) (attestation.VerificationResult, error) {
	parsedAuthData, err := protocol.ParseAuthenticatorData(request.AuthenticatorData)
	if err != nil {
		return attestation.VerificationResult{}, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	if parsedAuthData.AttestedCredentialData == nil {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	chain, certificates, err := x509util.ParseCertificateChain(statement.x5c, ErrInvalidStatement)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	leaf := certificates[0]
	if err := validatePackedCertificate(leaf, parsedAuthData.AttestedCredentialData.AAGUID); err != nil {
		return attestation.VerificationResult{}, err
	}
	if err := v.verifySignature(ctx, statement.algorithm, leaf.PublicKey, signed, statement.signature); err != nil {
		return attestation.VerificationResult{}, err
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeUncertain,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathX509, Certificates: chain},
		CryptographicallyValid: true,
	}, nil
}

func (v Verifier) verifySignature(ctx context.Context, algorithm protocol.COSEAlgorithmIdentifier, publicKey any, signed []byte, signature []byte) error {
	protocolSignature, err := protocol.NewSignature(signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidStatement, err)
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
