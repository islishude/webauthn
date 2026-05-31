package crypto_test

import (
	"bytes"
	"context"
	"testing"

	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

func TestCryptoContractsAcceptTestDouble(t *testing.T) {
	t.Parallel()

	adapter := fakeCrypto{}
	signature, err := protocol.NewSignature([]byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("NewSignature() error = %v", err)
	}

	digest, err := adapter.Hash(webcrypto.HashSHA256, []byte("client-data"))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !bytes.Equal(digest, []byte("hash:client-data")) {
		t.Fatalf("digest = %q, want hash:client-data", digest)
	}

	if !adapter.AcceptsAlgorithm(protocol.COSEAlgorithmIdentifier(-7)) {
		t.Fatal("AcceptsAlgorithm(-7) = false, want true")
	}
	if adapter.AcceptsAlgorithm(protocol.COSEAlgorithmIdentifier(-257)) {
		t.Fatal("AcceptsAlgorithm(-257) = true, want false")
	}

	err = adapter.VerifySignature(context.Background(), webcrypto.SignatureInput{
		Algorithm: protocol.COSEAlgorithmIdentifier(-7),
		PublicKey: "public-key",
		Signed:    []byte("auth-data-and-client-hash"),
		Signature: signature,
	})
	if err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}

	chainResult, err := adapter.VerifyCertificateChain(context.Background(), webcrypto.CertificateChain{
		webcrypto.NewCertificate([]byte("leaf")),
	}, webcrypto.CertificateVerificationContext{DNSName: "example.com"})
	if err != nil {
		t.Fatalf("VerifyCertificateChain() error = %v", err)
	}
	if !chainResult.Trusted {
		t.Fatal("Trusted = false, want true")
	}

	jwsResult, err := adapter.VerifyJWS(context.Background(), webcrypto.NewJWSToken([]byte("token")))
	if err != nil {
		t.Fatalf("VerifyJWS() error = %v", err)
	}
	if !bytes.Equal(jwsResult.Payload, []byte("payload")) {
		t.Fatalf("Payload = %q, want payload", jwsResult.Payload)
	}
}

type fakeCrypto struct{}

func (fakeCrypto) Hash(_ webcrypto.HashAlgorithm, data []byte) ([]byte, error) {
	return append([]byte("hash:"), data...), nil
}

func (fakeCrypto) AcceptsAlgorithm(algorithm protocol.COSEAlgorithmIdentifier) bool {
	return algorithm == protocol.COSEAlgorithmIdentifier(-7)
}

func (fakeCrypto) VerifySignature(context.Context, webcrypto.SignatureInput) error {
	return nil
}

func (fakeCrypto) VerifyCertificateChain(context.Context, webcrypto.CertificateChain, webcrypto.CertificateVerificationContext) (webcrypto.CertificateVerification, error) {
	return webcrypto.CertificateVerification{Trusted: true}, nil
}

func (fakeCrypto) VerifyJWS(context.Context, webcrypto.JWSToken) (webcrypto.JWSVerification, error) {
	return webcrypto.JWSVerification{Payload: []byte("payload")}, nil
}

var (
	_ webcrypto.Hasher              = fakeCrypto{}
	_ webcrypto.AlgorithmPolicy     = fakeCrypto{}
	_ webcrypto.SignatureVerifier   = fakeCrypto{}
	_ webcrypto.CertificateVerifier = fakeCrypto{}
	_ webcrypto.JWSVerifier         = fakeCrypto{}
)
