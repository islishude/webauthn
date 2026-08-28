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
	"slices"
	"time"

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
	// ErrPolicyConfiguration reports missing fail-closed SafetyNet expectations.
	ErrPolicyConfiguration = errors.New("android-safetynet policy configuration invalid")
)

// Verifier verifies the exact "android-safetynet" attestation format.
type Verifier struct {
	jwsVerifier webcrypto.JWSVerifier
	policy      Policy
}

// Policy binds a SafetyNet response to the expected Android application,
// signing certificate, freshness window, and integrity decision.
type Policy struct {
	// ExpectedAPKPackageName is the exact Android package allowed to produce the response.
	ExpectedAPKPackageName string
	// ExpectedAPKCertificateSHA256 contains allowed raw SHA-256 application
	// signing-certificate digests.
	ExpectedAPKCertificateSHA256 [][]byte
	// AllowedVersions optionally restricts the attestation statement's ver value.
	AllowedVersions []string
	// MaxAge is the maximum age of timestampMs and must be positive.
	MaxAge time.Duration
	// ClockSkew permits a bounded future timestamp and must not be negative.
	ClockSkew time.Duration
	// RequireCTSProfileMatch requires a true ctsProfileMatch payload claim.
	RequireCTSProfileMatch bool
	// RequireBasicIntegrity requires a true basicIntegrity payload claim.
	RequireBasicIntegrity bool
	// Now supplies the verification time; nil uses time.Now.
	Now func() time.Time
}

// New returns an Android SafetyNet attestation verifier using jwsVerifier for
// Compact JWS signature and certificate-chain verification and policy for all
// relying-party-specific payload bindings.
func New(jwsVerifier webcrypto.JWSVerifier, policy Policy) Verifier {
	return Verifier{jwsVerifier: jwsVerifier, policy: clonePolicy(policy)}
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
	if err := validatePolicy(v.policy); err != nil {
		return attestation.VerificationResult{}, err
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
	evidence, err := validatePayload(verification.Payload, expectedNonce(request.AuthenticatorData, request.ClientDataHash), statement.version, v.policy)
	if err != nil {
		return attestation.VerificationResult{}, err
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeBasic,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathX509, Certificates: verification.Certificates},
		CryptographicallyValid: true,
		Evidence:               evidence,
	}, nil
}

func clonePolicy(policy Policy) Policy {
	out := policy
	out.AllowedVersions = slices.Clone(policy.AllowedVersions)
	out.ExpectedAPKCertificateSHA256 = make([][]byte, len(policy.ExpectedAPKCertificateSHA256))
	for i, digest := range policy.ExpectedAPKCertificateSHA256 {
		out.ExpectedAPKCertificateSHA256[i] = slices.Clone(digest)
	}
	return out
}

func validatePolicy(policy Policy) error {
	if policy.ExpectedAPKPackageName == "" || len(policy.ExpectedAPKCertificateSHA256) == 0 || policy.MaxAge <= 0 || policy.ClockSkew < 0 || (!policy.RequireCTSProfileMatch && !policy.RequireBasicIntegrity) {
		return ErrPolicyConfiguration
	}
	for _, digest := range policy.ExpectedAPKCertificateSHA256 {
		if len(digest) != sha256.Size {
			return ErrPolicyConfiguration
		}
	}
	if slices.Contains(policy.AllowedVersions, "") {
		return ErrPolicyConfiguration
	}
	return nil
}

func (p Policy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
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
