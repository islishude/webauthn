// Package crypto defines WebAuthn cryptographic adapter contracts.
package crypto

import (
	"context"
	"time"

	"github.com/islishude/webauthn/protocol"
)

// HashAlgorithm identifies a hash operation needed by WebAuthn verification.
type HashAlgorithm string

const (
	HashSHA256 HashAlgorithm = "SHA-256"
)

// Hasher computes protocol-required hashes through an injected dependency.
type Hasher interface {
	Hash(algorithm HashAlgorithm, data []byte) ([]byte, error)
}

// AlgorithmPolicy decides whether a COSE algorithm is accepted by RP policy.
type AlgorithmPolicy interface {
	AcceptsAlgorithm(protocol.COSEAlgorithmIdentifier) bool
}

// SignatureInput is the WebAuthn signature verification request.
type SignatureInput struct {
	Algorithm protocol.COSEAlgorithmIdentifier
	PublicKey any
	Signed    []byte
	Signature protocol.Signature
}

// SignatureVerifier verifies WebAuthn signatures through an injected dependency.
type SignatureVerifier interface {
	VerifySignature(context.Context, SignatureInput) error
}

// Certificate is raw certificate material for adapter-owned X.509 handling.
type Certificate struct {
	raw []byte
}

// NewCertificate stores a defensive copy of raw certificate bytes.
func NewCertificate(raw []byte) Certificate {
	return Certificate{raw: cloneBytes(raw)}
}

// Raw returns a defensive copy of the certificate bytes.
func (c Certificate) Raw() []byte {
	return cloneBytes(c.raw)
}

// CertificateChain is a leaf-first certificate chain.
type CertificateChain []Certificate

// CertificateVerificationContext carries WebAuthn policy inputs for certificate
// path checks without choosing an X.509 implementation.
type CertificateVerificationContext struct {
	DNSName     string
	CurrentTime time.Time
	Roots       any
	Policy      any
}

// CertificateVerification is the adapter's certificate path result.
type CertificateVerification struct {
	Trusted  bool
	Warnings []string
}

// CertificateVerifier validates certificate chains through an injected dependency.
type CertificateVerifier interface {
	VerifyCertificateChain(context.Context, CertificateChain, CertificateVerificationContext) (CertificateVerification, error)
}

// JWSToken is raw JWS/JWT material for adapter-owned verification.
type JWSToken struct {
	raw []byte
}

// NewJWSToken stores a defensive copy of raw JWS/JWT bytes.
func NewJWSToken(raw []byte) JWSToken {
	return JWSToken{raw: cloneBytes(raw)}
}

// Raw returns a defensive copy of the token bytes.
func (t JWSToken) Raw() []byte {
	return cloneBytes(t.raw)
}

// JWSVerification is the adapter's JWS/JWT verification result.
type JWSVerification struct {
	Payload         []byte
	ProtectedHeader map[string]any
	Certificates    CertificateChain
}

// JWSVerifier verifies JWS/JWT statements through an injected dependency.
type JWSVerifier interface {
	VerifyJWS(context.Context, JWSToken) (JWSVerification, error)
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}

	out := make([]byte, len(value))
	copy(out, value)
	return out
}
