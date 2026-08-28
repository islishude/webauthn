package standard_test

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/crypto/standard"
	"github.com/islishude/webauthn/protocol"
)

func TestVerifierECDSAAlgorithms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm protocol.COSEAlgorithmIdentifier
		curve     elliptic.Curve
		curveName string
		hash      stdcrypto.Hash
	}{
		{name: "ES256", algorithm: protocol.AlgorithmES256, curve: elliptic.P256(), curveName: codec.EC2CurveP256, hash: stdcrypto.SHA256},
		{name: "ESP256", algorithm: protocol.AlgorithmESP256, curve: elliptic.P256(), curveName: codec.EC2CurveP256, hash: stdcrypto.SHA256},
		{name: "ES384", algorithm: protocol.AlgorithmES384, curve: elliptic.P384(), curveName: codec.EC2CurveP384, hash: stdcrypto.SHA384},
		{name: "ESP384", algorithm: protocol.AlgorithmESP384, curve: elliptic.P384(), curveName: codec.EC2CurveP384, hash: stdcrypto.SHA384},
		{name: "ES512", algorithm: protocol.AlgorithmES512, curve: elliptic.P521(), curveName: codec.EC2CurveP521, hash: stdcrypto.SHA512},
		{name: "ESP512", algorithm: protocol.AlgorithmESP512, curve: elliptic.P521(), curveName: codec.EC2CurveP521, hash: stdcrypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}
			signed := []byte("webauthn signed payload")
			signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest(tt.hash, signed))
			if err != nil {
				t.Fatalf("SignASN1() error = %v", err)
			}
			material := codec.CredentialPublicKeyMaterial{EC2: &codec.EC2PublicKeyMaterial{
				Curve: tt.curveName,
				X:     privateKey.X.FillBytes(make([]byte, (tt.curve.Params().BitSize+7)/8)),
				Y:     privateKey.Y.FillBytes(make([]byte, (tt.curve.Params().BitSize+7)/8)),
			}}
			verifyAndRejectTampering(t, tt.algorithm, material, signed, signature)
		})
	}
}

func TestVerifierRSAAlgorithms(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	material := codec.CredentialPublicKeyMaterial{RSA: &codec.RSAPublicKeyMaterial{
		Modulus:  privateKey.N.Bytes(),
		Exponent: uint32(privateKey.E), //nolint:gosec // Generated RSA exponents fit uint32.
	}}
	tests := []struct {
		name      string
		algorithm protocol.COSEAlgorithmIdentifier
		hash      stdcrypto.Hash
		pss       bool
	}{
		{name: "RS256", algorithm: protocol.AlgorithmRS256, hash: stdcrypto.SHA256},
		{name: "RS384", algorithm: protocol.AlgorithmRS384, hash: stdcrypto.SHA384},
		{name: "RS512", algorithm: protocol.AlgorithmRS512, hash: stdcrypto.SHA512},
		{name: "PS256", algorithm: protocol.AlgorithmPS256, hash: stdcrypto.SHA256, pss: true},
		{name: "PS384", algorithm: protocol.AlgorithmPS384, hash: stdcrypto.SHA384, pss: true},
		{name: "PS512", algorithm: protocol.AlgorithmPS512, hash: stdcrypto.SHA512, pss: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			signed := []byte("webauthn rsa signed payload")
			digest := digest(tt.hash, signed)
			var signature []byte
			var err error
			if tt.pss {
				signature, err = rsa.SignPSS(rand.Reader, privateKey, tt.hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: tt.hash})
			} else {
				signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, tt.hash, digest)
			}
			if err != nil {
				t.Fatalf("sign error = %v", err)
			}
			verifyAndRejectTampering(t, tt.algorithm, material, signed, signature)
		})
	}
}

func TestVerifierRejectsUndersizedRSAKey(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Deliberately undersized rejection fixture.
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	verifier, err := standard.NewVerifier(protocol.AlgorithmRS256)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	signature, err := protocol.NewSignature([]byte("signature"))
	if err != nil {
		t.Fatalf("NewSignature() error = %v", err)
	}
	err = verifier.VerifySignature(context.Background(), webcrypto.SignatureInput{
		Algorithm: protocol.AlgorithmRS256,
		PublicKey: codec.CredentialPublicKeyMaterial{RSA: &codec.RSAPublicKeyMaterial{
			Modulus:  privateKey.N.Bytes(),
			Exponent: uint32(privateKey.E), //nolint:gosec // Generated exponent fits uint32.
		}},
		Signed:    []byte("signed"),
		Signature: signature,
	})
	if !errors.Is(err, standard.ErrInvalidPublicKey) {
		t.Fatalf("VerifySignature() error = %v, want ErrInvalidPublicKey", err)
	}
}

func TestVerifierEd25519Algorithms(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	material := codec.CredentialPublicKeyMaterial{OKP: &codec.OKPPublicKeyMaterial{Curve: codec.OKPCurveEd25519, X: publicKey}}
	signed := []byte("webauthn ed25519 signed payload")
	signature := ed25519.Sign(privateKey, signed)
	for _, algorithm := range []protocol.COSEAlgorithmIdentifier{protocol.AlgorithmEdDSA, protocol.AlgorithmEd25519} {
		verifyAndRejectTampering(t, algorithm, material, signed, signature)
	}
}

func TestVerifierRequiresExplicitSupportedPolicyAndMatchingKey(t *testing.T) {
	t.Parallel()

	if _, err := standard.NewVerifier(); !errors.Is(err, standard.ErrNoAlgorithms) {
		t.Fatalf("NewVerifier() error = %v, want ErrNoAlgorithms", err)
	}
	if _, err := standard.NewVerifier(-999); !errors.Is(err, standard.ErrUnsupportedAlgorithm) {
		t.Fatalf("NewVerifier(-999) error = %v, want ErrUnsupportedAlgorithm", err)
	}

	verifier, err := standard.NewVerifier(protocol.AlgorithmES256)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	err = verifier.VerifySignature(context.Background(), webcrypto.SignatureInput{
		Algorithm: protocol.AlgorithmES256,
		PublicKey: codec.CredentialPublicKeyMaterial{RSA: &codec.RSAPublicKeyMaterial{Modulus: []byte{0x03}, Exponent: 3}},
		Signed:    []byte("payload"),
		Signature: mustSignature(t, []byte("signature")),
	})
	if !errors.Is(err, standard.ErrInvalidPublicKey) {
		t.Fatalf("VerifySignature() error = %v, want ErrInvalidPublicKey", err)
	}
}

func verifyAndRejectTampering(t *testing.T, algorithm protocol.COSEAlgorithmIdentifier, material codec.CredentialPublicKeyMaterial, signed []byte, signature []byte) {
	t.Helper()
	verifier, err := standard.NewVerifier(algorithm)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	input := webcrypto.SignatureInput{
		Algorithm: algorithm,
		PublicKey: material,
		Signed:    signed,
		Signature: mustSignature(t, signature),
	}
	if err := verifier.VerifySignature(context.Background(), input); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
	tampered := append([]byte{}, signed...)
	tampered[0] ^= 0xff
	input.Signed = tampered
	if err := verifier.VerifySignature(context.Background(), input); !errors.Is(err, standard.ErrInvalidSignature) {
		t.Fatalf("tampered VerifySignature() error = %v, want ErrInvalidSignature", err)
	}
}

func mustSignature(t *testing.T, raw []byte) protocol.Signature {
	t.Helper()
	signature, err := protocol.NewSignature(raw)
	if err != nil {
		t.Fatalf("NewSignature() error = %v", err)
	}
	return signature
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
		panic("unsupported hash")
	}
}
