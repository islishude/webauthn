package apple

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/protocol"
)

func TestVerifierAcceptsEC2AppleAttestation(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t, certificateOptions{})
	result, err := New().VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "apple",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           fixture.statement,
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeAnonymizationCA || result.TrustPath.Kind != attestation.TrustPathX509 || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid Apple anonymization CA attestation", result)
	}
	if len(result.TrustPath.Certificates) != 1 || !bytes.Equal(result.TrustPath.Certificates[0].Raw(), fixture.rawChain[0]) {
		t.Fatalf("trust path = %+v, want leaf certificate", result.TrustPath)
	}
}

func TestVerifierAcceptsRSAAppleAttestation(t *testing.T) {
	t.Parallel()

	fixture := newRSAFixture(t, certificateOptions{})
	result, err := New().VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "apple",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           fixture.statement,
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeAnonymizationCA || result.TrustPath.Kind != attestation.TrustPathX509 || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid Apple anonymization CA attestation", result)
	}
}

func TestVerifierRejectsMalformedStatement(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t, certificateOptions{})
	tests := []struct {
		name      string
		statement func() codec.AttestationStatement
	}{
		{name: "missing x5c", statement: func() codec.AttestationStatement {
			return codec.AttestationStatement{}
		}},
		{name: "empty x5c", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			statement["x5c"] = [][]byte{}
			return statement
		}},
		{name: "unexpected field", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			statement["sig"] = []byte("unexpected")
			return statement
		}},
		{name: "malformed certificate", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			statement["x5c"] = [][]byte{[]byte("not-a-certificate")}
			return statement
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := New().VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "apple",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           tt.statement(),
				CredentialPublicKey: fixture.credentialPublicKey,
			})
			if !errors.Is(err, ErrInvalidStatement) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidStatement", err)
			}
		})
	}
}

func TestVerifierRejectsNonceFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		options certificateOptions
		wantErr error
	}{
		{name: "missing extension", options: certificateOptions{omitNonceExtension: true}, wantErr: ErrCertificateRequirements},
		{name: "malformed extension", options: certificateOptions{malformedNonceExtension: true}, wantErr: ErrInvalidNonce},
		{name: "nonce mismatch", options: certificateOptions{nonce: bytes.Repeat([]byte{0xff}, 32)}, wantErr: ErrInvalidNonce},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fixture := newEC2Fixture(t, tt.options)
			_, err := New().VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "apple",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           fixture.statement,
				CredentialPublicKey: fixture.credentialPublicKey,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyAttestation() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifierRejectsCertificatePublicKeyMismatch(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t, certificateOptions{})
	tests := []struct {
		name    string
		key     codec.CredentialPublicKey
		wantErr error
	}{
		{
			name:    "missing material",
			key:     codec.NewCredentialPublicKey(-7, "credential-key", []byte{0xa0}),
			wantErr: ErrUnsupportedKey,
		},
		{
			name: "mismatched material",
			key: func() codec.CredentialPublicKey {
				material := fixture.credentialPublicKey.PublicKeyMaterial()
				material.EC2.X[0] ^= 0xff
				return codec.NewCredentialPublicKeyWithMaterial(-7, "credential-key", []byte{0xa0}, nil, material)
			}(),
			wantErr: ErrPublicKeyMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := New().VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "apple",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           fixture.statement,
				CredentialPublicKey: tt.key,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyAttestation() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifierPreservesLeafFirstTrustPath(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t, certificateOptions{extraChainCertificate: true})
	result, err := New().VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "apple",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           fixture.statement,
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if len(result.TrustPath.Certificates) != len(fixture.rawChain) {
		t.Fatalf("trust path length = %d, want %d", len(result.TrustPath.Certificates), len(fixture.rawChain))
	}
	for i, certificate := range result.TrustPath.Certificates {
		if !bytes.Equal(certificate.Raw(), fixture.rawChain[i]) {
			t.Fatalf("trust path certificate %d mismatch", i)
		}
	}
}

type fixture struct {
	authenticatorData   protocol.AuthenticatorData
	clientDataHash      []byte
	credentialPublicKey codec.CredentialPublicKey
	rawChain            [][]byte
	statement           codec.AttestationStatement
}

func newEC2Fixture(t *testing.T, options certificateOptions) fixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	material := codec.CredentialPublicKeyMaterial{EC2: &codec.EC2PublicKeyMaterial{
		Curve: codec.EC2CurveP256,
		X:     fixedBytes(key.X, 32),
		Y:     fixedBytes(key.Y, 32),
	}}

	return newFixture(t, -7, key, &key.PublicKey, material, options)
}

func newRSAFixture(t *testing.T, options certificateOptions) fixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	material := codec.CredentialPublicKeyMaterial{RSA: &codec.RSAPublicKeyMaterial{
		Modulus:  key.N.Bytes(),
		Exponent: uint32(key.E), //nolint:gosec // test key exponent is generated by crypto/rsa and fits uint32.
	}}

	return newFixture(t, -257, key, &key.PublicKey, material, options)
}

func newFixture(t *testing.T, algorithm protocol.COSEAlgorithmIdentifier, privateKey any, publicKey any, material codec.CredentialPublicKeyMaterial, options certificateOptions) fixture {
	t.Helper()

	authenticatorData := authenticatorData(t)
	clientDataHash := bytes.Repeat([]byte{0x04}, 32)
	options.authenticatorData = authenticatorData
	options.clientDataHash = clientDataHash
	rawChain := [][]byte{newCertificate(t, privateKey, publicKey, options)}
	if options.extraChainCertificate {
		rawChain = append(rawChain, newExtraCertificate(t))
	}
	statement := codec.AttestationStatement{"x5c": rawChain}

	return fixture{
		authenticatorData:   authenticatorData,
		clientDataHash:      clientDataHash,
		credentialPublicKey: codec.NewCredentialPublicKeyWithMaterial(algorithm, "credential-key", []byte{0xa0}, nil, material),
		rawChain:            rawChain,
		statement:           statement,
	}
}

func authenticatorData(t *testing.T) protocol.AuthenticatorData {
	t.Helper()

	authenticatorData, err := protocol.NewAuthenticatorData(bytes.Repeat([]byte{0x01}, protocol.MinAuthenticatorDataLength))
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}

	return authenticatorData
}

type certificateOptions struct {
	authenticatorData       protocol.AuthenticatorData
	clientDataHash          []byte
	nonce                   []byte
	omitNonceExtension      bool
	malformedNonceExtension bool
	extraChainCertificate   bool
}

func newCertificate(t *testing.T, privateKey any, publicKey any, options certificateOptions) []byte {
	t.Helper()

	template := certificateTemplate(t)
	if !options.omitNonceExtension {
		template.ExtraExtensions = []pkix.Extension{appleNonceExtension(t, options)}
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	return raw
}

func newExtraCertificate(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := certificateTemplate(t)
	template.Subject.CommonName = "Apple Attestation Intermediate"
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.KeyUsage = x509.KeyUsageCertSign
	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	return raw
}

func certificateTemplate(t *testing.T) x509.Certificate {
	t.Helper()

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("rand.Int() error = %v", err)
	}

	return x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "Apple Anonymous Attestation"},
		NotBefore:    time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 5, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

func appleNonceExtension(t *testing.T, options certificateOptions) pkix.Extension {
	t.Helper()

	nonce := options.nonce
	if nonce == nil {
		nonce = expectedNonce(options.authenticatorData, options.clientDataHash)
	}
	value := mustMarshal(t, nonce)
	if options.malformedNonceExtension {
		value = []byte{0x04, 0x03, 0x01}
	}

	return pkix.Extension{Id: oidExtensionAppleAnonymousAttestationNonce, Value: value}
}

func fixedBytes(value *big.Int, length int) []byte {
	if value == nil {
		return nil
	}
	bytes := value.Bytes()
	if len(bytes) >= length {
		return bytes[len(bytes)-length:]
	}
	out := make([]byte, length)
	copy(out[length-len(bytes):], bytes)

	return out
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()

	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	return der
}

func cloneStatement(statement codec.AttestationStatement) codec.AttestationStatement {
	out := make(codec.AttestationStatement, len(statement))
	for key, value := range statement {
		switch typed := value.(type) {
		case []byte:
			out[key] = append([]byte{}, typed...)
		case [][]byte:
			copied := make([][]byte, len(typed))
			for i, bytes := range typed {
				copied[i] = append([]byte{}, bytes...)
			}
			out[key] = copied
		default:
			out[key] = typed
		}
	}

	return out
}
