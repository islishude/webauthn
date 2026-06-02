// Package tpm verifies WebAuthn "tpm" attestation statements.
package tpm

import (
	"context"
	"errors"
	"fmt"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/internal/attcrypto"
	"github.com/islishude/webauthn/attestation/internal/x509util"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

const (
	format     = "tpm"
	tpmVersion = "2.0"
)

var (
	// ErrInvalidStatement reports a malformed TPM attestation statement.
	ErrInvalidStatement = errors.New("invalid tpm attestation statement")
	// ErrUnsupportedAlgorithm reports a TPM or COSE algorithm outside this
	// verifier's supported algorithm set.
	ErrUnsupportedAlgorithm = errors.New("unsupported tpm attestation algorithm")
	// ErrUnsupportedKey reports credential or TPM public key material that this
	// verifier cannot bind.
	ErrUnsupportedKey = errors.New("unsupported tpm attestation key")
	// ErrPublicKeyMismatch reports a mismatch between the COSE credential key
	// material and the TPM public area.
	ErrPublicKeyMismatch = errors.New("tpm public key mismatch")
	// ErrInvalidPublicArea reports malformed TPMT_PUBLIC data.
	ErrInvalidPublicArea = errors.New("invalid tpm public area")
	// ErrInvalidCertInfo reports malformed or mismatched TPMS_ATTEST data.
	ErrInvalidCertInfo = errors.New("invalid tpm certInfo")
	// ErrInvalidSignature reports a TPM attestation signature failure.
	ErrInvalidSignature = errors.New("invalid tpm attestation signature")
	// ErrCertificateRequirements reports an AIK certificate requirement failure.
	ErrCertificateRequirements = errors.New("tpm attestation certificate requirements failed")
)

// Verifier verifies the exact "tpm" attestation format.
type Verifier struct {
	signatureVerifier webcrypto.SignatureVerifier
}

// New returns a TPM attestation verifier using signatureVerifier for the
// attestation signature check.
func New(signatureVerifier webcrypto.SignatureVerifier) Verifier {
	return Verifier{signatureVerifier: signatureVerifier}
}

// Format returns the WebAuthn attestation format identifier.
func (Verifier) Format() string {
	return format
}

// VerifyAttestation verifies TPM attestation statements.
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
	if statement.version != tpmVersion {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}
	signatureSpec, ok := signatureAlgorithmSpec(statement.algorithm)
	if !ok {
		return attestation.VerificationResult{}, ErrUnsupportedAlgorithm
	}
	if request.AuthenticatorData.Len() == 0 || len(request.ClientDataHash) == 0 {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	parsedAuthData, err := protocol.ParseAuthenticatorData(request.AuthenticatorData)
	if err != nil {
		return attestation.VerificationResult{}, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	if parsedAuthData.AttestedCredentialData == nil {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}

	publicArea, err := parsePublicArea(statement.publicArea)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	if err := validatePublicAreaBinding(publicArea, request.CredentialPublicKey.PublicKeyMaterial()); err != nil {
		return attestation.VerificationResult{}, err
	}
	publicAreaName, err := publicArea.name()
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	extraData, err := tpmHash(signatureSpec.hashAlg, attcrypto.SignedData(request.AuthenticatorData, request.ClientDataHash))
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	certInfo, err := parseCertInfo(statement.certInfo)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	if err := validateCertInfoBinding(certInfo, extraData, publicAreaName); err != nil {
		return attestation.VerificationResult{}, err
	}

	chain, certificates, err := x509util.ParseCertificateChain(statement.x5c, ErrInvalidStatement)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	if err := validateAIKCertificate(certificates[0], parsedAuthData.AttestedCredentialData.AAGUID); err != nil {
		return attestation.VerificationResult{}, err
	}
	tpmSignature, err := parseTPMSignature(statement.signature, signatureSpec)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	if err := v.verifySignature(ctx, statement.algorithm, certificates[0].PublicKey, statement.certInfo, tpmSignature.signature); err != nil {
		return attestation.VerificationResult{}, err
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeAttCA,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathX509, Certificates: chain},
		CryptographicallyValid: true,
	}, nil
}

func (v Verifier) verifySignature(ctx context.Context, algorithm protocol.COSEAlgorithmIdentifier, publicKey any, signed []byte, signature []byte) error {
	return attcrypto.VerifySignature(ctx, v.signatureVerifier, algorithm, publicKey, signed, signature, ErrInvalidSignature, ErrInvalidSignature)
}

var _ attestation.Verifier = Verifier{}
