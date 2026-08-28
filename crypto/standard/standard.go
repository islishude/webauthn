// Package standard verifies common WebAuthn signature algorithms with the Go
// standard library.
package standard

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

var (
	// ErrNoAlgorithms reports construction without an explicit algorithm policy.
	ErrNoAlgorithms = errors.New("standard verifier requires allowed algorithms")
	// ErrUnsupportedAlgorithm reports an algorithm the standard verifier cannot handle.
	ErrUnsupportedAlgorithm = errors.New("standard verifier algorithm unsupported")
	// ErrInvalidPublicKey reports key material that does not match the algorithm.
	ErrInvalidPublicKey = errors.New("standard verifier public key invalid")
	// ErrInvalidSignature reports a cryptographic signature verification failure.
	ErrInvalidSignature = errors.New("standard verifier signature invalid")
)

// Verifier implements explicit algorithm policy and signature verification.
type Verifier struct {
	allowed map[protocol.COSEAlgorithmIdentifier]struct{}
}

// NewVerifier constructs a verifier for an explicit, non-empty set of supported
// algorithms.
func NewVerifier(allowed ...protocol.COSEAlgorithmIdentifier) (*Verifier, error) {
	if len(allowed) == 0 {
		return nil, ErrNoAlgorithms
	}
	verifier := &Verifier{allowed: make(map[protocol.COSEAlgorithmIdentifier]struct{}, len(allowed))}
	for _, algorithm := range allowed {
		if !supported(algorithm) {
			return nil, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, algorithm)
		}
		verifier.allowed[algorithm] = struct{}{}
	}
	return verifier, nil
}

// AcceptsAlgorithm reports whether algorithm was explicitly enabled.
func (v *Verifier) AcceptsAlgorithm(algorithm protocol.COSEAlgorithmIdentifier) bool {
	if v == nil {
		return false
	}
	_, ok := v.allowed[algorithm]
	return ok
}

// VerifySignature verifies a WebAuthn credential or attestation signature.
func (v *Verifier) VerifySignature(ctx context.Context, input webcrypto.SignatureInput) error {
	if !v.AcceptsAlgorithm(input.Algorithm) {
		return fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, input.Algorithm)
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	signature := input.Signature.Bytes()
	switch input.Algorithm {
	case protocol.AlgorithmES256, protocol.AlgorithmESP256:
		return verifyECDSA(input.PublicKey, codec.EC2CurveP256, elliptic.P256(), stdcrypto.SHA256, input.Signed, signature)
	case protocol.AlgorithmES384, protocol.AlgorithmESP384:
		return verifyECDSA(input.PublicKey, codec.EC2CurveP384, elliptic.P384(), stdcrypto.SHA384, input.Signed, signature)
	case protocol.AlgorithmES512, protocol.AlgorithmESP512:
		return verifyECDSA(input.PublicKey, codec.EC2CurveP521, elliptic.P521(), stdcrypto.SHA512, input.Signed, signature)
	case protocol.AlgorithmRS256:
		return verifyRSA(input.PublicKey, stdcrypto.SHA256, false, input.Signed, signature)
	case protocol.AlgorithmRS384:
		return verifyRSA(input.PublicKey, stdcrypto.SHA384, false, input.Signed, signature)
	case protocol.AlgorithmRS512:
		return verifyRSA(input.PublicKey, stdcrypto.SHA512, false, input.Signed, signature)
	case protocol.AlgorithmPS256:
		return verifyRSA(input.PublicKey, stdcrypto.SHA256, true, input.Signed, signature)
	case protocol.AlgorithmPS384:
		return verifyRSA(input.PublicKey, stdcrypto.SHA384, true, input.Signed, signature)
	case protocol.AlgorithmPS512:
		return verifyRSA(input.PublicKey, stdcrypto.SHA512, true, input.Signed, signature)
	case protocol.AlgorithmEdDSA, protocol.AlgorithmEd25519:
		return verifyEd25519(input.PublicKey, input.Signed, signature)
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, input.Algorithm)
	}
}

func verifyECDSA(material codec.CredentialPublicKeyMaterial, curveName string, curve elliptic.Curve, hash stdcrypto.Hash, signed []byte, signature []byte) error {
	if material.EC2 == nil || material.RSA != nil || material.OKP != nil || material.EC2.Curve != curveName {
		return ErrInvalidPublicKey
	}
	x := new(big.Int).SetBytes(material.EC2.X)
	y := new(big.Int).SetBytes(material.EC2.Y)
	publicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if _, err := publicKey.ECDH(); err != nil {
		return ErrInvalidPublicKey
	}
	digest := digest(hash, signed)
	if !ecdsa.VerifyASN1(publicKey, digest, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func verifyRSA(material codec.CredentialPublicKeyMaterial, hash stdcrypto.Hash, pss bool, signed []byte, signature []byte) error {
	if material.RSA == nil || material.EC2 != nil || material.OKP != nil || !material.RSA.Valid() {
		return ErrInvalidPublicKey
	}
	publicKey := &rsa.PublicKey{N: new(big.Int).SetBytes(material.RSA.Modulus), E: int(material.RSA.Exponent)}
	digest := digest(hash, signed)
	var err error
	if pss {
		err = rsa.VerifyPSS(publicKey, hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
	} else {
		err = rsa.VerifyPKCS1v15(publicKey, hash, digest, signature)
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	return nil
}

func verifyEd25519(material codec.CredentialPublicKeyMaterial, signed []byte, signature []byte) error {
	if material.OKP == nil || material.EC2 != nil || material.RSA != nil || material.OKP.Curve != codec.OKPCurveEd25519 || len(material.OKP.X) != ed25519.PublicKeySize {
		return ErrInvalidPublicKey
	}
	if !ed25519.Verify(ed25519.PublicKey(material.OKP.X), signed, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func digest(hash stdcrypto.Hash, signed []byte) []byte {
	switch hash {
	case stdcrypto.SHA256:
		sum := sha256.Sum256(signed)
		return sum[:]
	case stdcrypto.SHA384:
		sum := sha512.Sum384(signed)
		return sum[:]
	case stdcrypto.SHA512:
		sum := sha512.Sum512(signed)
		return sum[:]
	default:
		panic("unsupported standard verifier hash")
	}
}

func supported(algorithm protocol.COSEAlgorithmIdentifier) bool {
	switch algorithm {
	case protocol.AlgorithmEdDSA,
		protocol.AlgorithmEd25519,
		protocol.AlgorithmES256,
		protocol.AlgorithmESP256,
		protocol.AlgorithmES384,
		protocol.AlgorithmESP384,
		protocol.AlgorithmES512,
		protocol.AlgorithmESP512,
		protocol.AlgorithmRS256,
		protocol.AlgorithmRS384,
		protocol.AlgorithmRS512,
		protocol.AlgorithmPS256,
		protocol.AlgorithmPS384,
		protocol.AlgorithmPS512:
		return true
	default:
		return false
	}
}

var (
	_ webcrypto.AlgorithmPolicy   = (*Verifier)(nil)
	_ webcrypto.SignatureVerifier = (*Verifier)(nil)
)
