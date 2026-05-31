package fidou2f_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/fidou2f"
	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

func TestVerifierAcceptsFidoU2FAttestation(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	certificate := newCertificate(t, elliptic.P256())
	verifier := fidou2f.New(signatureVerifier{
		t:             t,
		wantAlgorithm: -7,
		wantPublicKey: certificate.leaf.PublicKey,
		wantSigned:    fixture.verificationData,
		wantSignature: []byte("signature"),
	})

	result, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "fido-u2f",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           codec.AttestationStatement{"x5c": [][]byte{certificate.raw}, "sig": []byte("signature")},
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeUncertain || result.TrustPath.Kind != attestation.TrustPathX509 || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid fido-u2f attestation", result)
	}
	if len(result.TrustPath.Certificates) != 1 || !bytes.Equal(result.TrustPath.Certificates[0].Raw(), certificate.raw) {
		t.Fatalf("trust path = %+v, want leaf certificate", result.TrustPath)
	}
}

func TestVerifierRejectsMalformedStatement(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	certificate := newCertificate(t, elliptic.P256())
	verifier := fidou2f.New(signatureVerifier{t: t})

	tests := []struct {
		name      string
		statement codec.AttestationStatement
	}{
		{name: "missing x5c", statement: codec.AttestationStatement{"sig": []byte("signature")}},
		{name: "missing sig", statement: codec.AttestationStatement{"x5c": [][]byte{certificate.raw}}},
		{name: "extra field", statement: codec.AttestationStatement{"x5c": [][]byte{certificate.raw}, "sig": []byte("signature"), "alg": int64(-7)}},
		{name: "empty x5c", statement: codec.AttestationStatement{"x5c": [][]byte{}, "sig": []byte("signature")}},
		{name: "multi cert x5c", statement: codec.AttestationStatement{"x5c": [][]byte{certificate.raw, certificate.raw}, "sig": []byte("signature")}},
		{name: "empty sig", statement: codec.AttestationStatement{"x5c": [][]byte{certificate.raw}, "sig": []byte{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "fido-u2f",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           tt.statement,
				CredentialPublicKey: fixture.credentialPublicKey,
			})
			if !errors.Is(err, fidou2f.ErrInvalidStatement) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidStatement", err)
			}
		})
	}
}

func TestVerifierRejectsUnsupportedCredentialKey(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	certificate := newCertificate(t, elliptic.P256())
	verifier := fidou2f.New(signatureVerifier{t: t})

	tests := []struct {
		name string
		key  codec.CredentialPublicKey
	}{
		{name: "non es256", key: codec.NewCredentialPublicKeyWithU2F(-257, "credential-key", []byte{0xa0}, fixture.u2fPublicKey)},
		{name: "missing u2f key", key: codec.NewCredentialPublicKey(-7, "credential-key", []byte{0xa0})},
		{name: "malformed u2f key", key: codec.NewCredentialPublicKeyWithU2F(-7, "credential-key", []byte{0xa0}, []byte{0x04, 0x01})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "fido-u2f",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           codec.AttestationStatement{"x5c": [][]byte{certificate.raw}, "sig": []byte("signature")},
				CredentialPublicKey: tt.key,
			})
			if !errors.Is(err, fidou2f.ErrUnsupportedKey) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrUnsupportedKey", err)
			}
		})
	}
}

func TestVerifierRejectsNonP256CertificateKey(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	certificate := newCertificate(t, elliptic.P384())
	verifier := fidou2f.New(signatureVerifier{t: t})

	_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "fido-u2f",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           codec.AttestationStatement{"x5c": [][]byte{certificate.raw}, "sig": []byte("signature")},
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if !errors.Is(err, fidou2f.ErrUnsupportedKey) {
		t.Fatalf("VerifyAttestation() error = %v, want ErrUnsupportedKey", err)
	}
}

func TestVerifierRejectsInvalidSignature(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	certificate := newCertificate(t, elliptic.P256())
	verifier := fidou2f.New(signatureVerifier{t: t, fail: true})

	_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "fido-u2f",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           codec.AttestationStatement{"x5c": [][]byte{certificate.raw}, "sig": []byte("signature")},
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if !errors.Is(err, fidou2f.ErrInvalidSignature) {
		t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidSignature", err)
	}
}

type fixture struct {
	authenticatorData   protocol.AuthenticatorData
	clientDataHash      []byte
	u2fPublicKey        []byte
	credentialPublicKey codec.CredentialPublicKey
	verificationData    []byte
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	rpIDHash := bytes.Repeat([]byte{0x01}, protocol.RPIDHashLength)
	clientDataHash := bytes.Repeat([]byte{0x02}, 32)
	credentialID := []byte("credential-id")
	u2fPublicKey := append([]byte{0x04}, bytes.Repeat([]byte{0x03}, 32)...)
	u2fPublicKey = append(u2fPublicKey, bytes.Repeat([]byte{0x04}, 32)...)
	authenticatorData := authenticatorData(t, rpIDHash, credentialID)
	verificationData := append([]byte{0x00}, rpIDHash...)
	verificationData = append(verificationData, clientDataHash...)
	verificationData = append(verificationData, credentialID...)
	verificationData = append(verificationData, u2fPublicKey...)

	return fixture{
		authenticatorData:   authenticatorData,
		clientDataHash:      clientDataHash,
		u2fPublicKey:        u2fPublicKey,
		credentialPublicKey: codec.NewCredentialPublicKeyWithU2F(-7, "credential-key", []byte{0xa0}, u2fPublicKey),
		verificationData:    verificationData,
	}
}

func authenticatorData(t *testing.T, rpIDHash []byte, credentialID []byte) protocol.AuthenticatorData {
	t.Helper()

	out := append([]byte{}, rpIDHash...)
	out = append(out, 0x41)
	out = append(out, 0x00, 0x00, 0x00, 0x01)
	out = append(out, bytes.Repeat([]byte{0x00}, protocol.AAGUIDLength)...)
	credentialIDLength := make([]byte, 2)
	binary.BigEndian.PutUint16(credentialIDLength, uint16(len(credentialID))) //nolint:gosec // fixture credential ID length is fixed and below uint16 max.
	out = append(out, credentialIDLength...)
	out = append(out, credentialID...)
	out = append(out, 0xa0)

	authenticatorData, err := protocol.NewAuthenticatorData(out)
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}

	return authenticatorData
}

type testCertificate struct {
	leaf *x509.Certificate
	raw  []byte
}

func newCertificate(t *testing.T, curve elliptic.Curve) testCertificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("rand.Int() error = %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "FIDO U2F Attestation",
		},
		NotBefore: time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, 5, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	return testCertificate{leaf: leaf, raw: raw}
}

type signatureVerifier struct {
	t             *testing.T
	wantAlgorithm protocol.COSEAlgorithmIdentifier
	wantPublicKey any
	wantSigned    []byte
	wantSignature []byte
	fail          bool
}

func (v signatureVerifier) VerifySignature(_ context.Context, input webcrypto.SignatureInput) error {
	v.t.Helper()

	if v.fail {
		return errors.New("signature rejected")
	}
	if v.wantAlgorithm != 0 && input.Algorithm != v.wantAlgorithm {
		v.t.Fatalf("Algorithm = %d, want %d", input.Algorithm, v.wantAlgorithm)
	}
	if v.wantPublicKey != nil && !reflect.DeepEqual(input.PublicKey, v.wantPublicKey) {
		v.t.Fatalf("PublicKey = %#v, want %#v", input.PublicKey, v.wantPublicKey)
	}
	if v.wantSigned != nil && !bytes.Equal(input.Signed, v.wantSigned) {
		v.t.Fatalf("Signed = %x, want %x", input.Signed, v.wantSigned)
	}
	if v.wantSignature != nil && !bytes.Equal(input.Signature.Bytes(), v.wantSignature) {
		v.t.Fatalf("Signature = %x, want %x", input.Signature.Bytes(), v.wantSignature)
	}

	return nil
}

var _ webcrypto.SignatureVerifier = signatureVerifier{}
