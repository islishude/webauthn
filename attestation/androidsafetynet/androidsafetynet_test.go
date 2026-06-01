package androidsafetynet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"maps"
	"math/big"
	"testing"
	"time"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

func TestVerifierAcceptsAndroidSafetyNetAttestation(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	verifier := New(jwsVerifier{
		t:          t,
		wantToken:  fixture.response,
		payload:    safetyNetPayload(t, fixture.expectedNonce, true, json.Number("1700000000000")),
		certChain:  webcrypto.CertificateChain{webcrypto.NewCertificate(fixture.certificate.raw)},
		header:     map[string]any{"alg": "RS256"},
		expectCall: true,
	})

	result, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:            "android-safetynet",
		AuthenticatorData: fixture.authenticatorData,
		ClientDataHash:    fixture.clientDataHash,
		Statement:         fixture.statement,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeBasic || result.TrustPath.Kind != attestation.TrustPathX509 || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid Android SafetyNet basic attestation", result)
	}
	if len(result.TrustPath.Certificates) != 1 || !bytes.Equal(result.TrustPath.Certificates[0].Raw(), fixture.certificate.raw) {
		t.Fatalf("trust path = %+v, want leaf certificate", result.TrustPath)
	}
}

func TestVerifierRejectsMalformedStatement(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	verifier := New(jwsVerifier{t: t})

	tests := []struct {
		name      string
		statement func() codec.AttestationStatement
	}{
		{name: "missing version", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			delete(statement, "ver")
			return statement
		}},
		{name: "missing response", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			delete(statement, "response")
			return statement
		}},
		{name: "empty version", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			statement["ver"] = ""
			return statement
		}},
		{name: "empty response", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			statement["response"] = []byte{}
			return statement
		}},
		{name: "bad response type", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			statement["response"] = "compact-jws"
			return statement
		}},
		{name: "unexpected field", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			statement["alg"] = int64(-7)
			return statement
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:            "android-safetynet",
				AuthenticatorData: fixture.authenticatorData,
				ClientDataHash:    fixture.clientDataHash,
				Statement:         tt.statement(),
			})
			if !errors.Is(err, ErrInvalidStatement) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidStatement", err)
			}
		})
	}
}

func TestVerifierRejectsJWSVerifierFailure(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	_, err := New(jwsVerifier{t: t, fail: true}).VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:            "android-safetynet",
		AuthenticatorData: fixture.authenticatorData,
		ClientDataHash:    fixture.clientDataHash,
		Statement:         fixture.statement,
	})
	if !errors.Is(err, ErrInvalidJWS) {
		t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidJWS", err)
	}
}

func TestVerifierRejectsPayloadFailures(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)

	tests := []struct {
		name    string
		payload []byte
		wantErr error
	}{
		{name: "malformed json", payload: []byte("{"), wantErr: ErrInvalidPayload},
		{name: "nonce mismatch", payload: safetyNetPayload(t, "wrong-nonce", true, json.Number("1700000000000")), wantErr: ErrInvalidNonce},
		{name: "missing ctsProfileMatch", payload: safetyNetPayloadMap(t, map[string]any{"nonce": fixture.expectedNonce, "timestampMs": json.Number("1700000000000")}), wantErr: ErrInvalidPayload},
		{name: "false ctsProfileMatch", payload: safetyNetPayload(t, fixture.expectedNonce, false, json.Number("1700000000000")), wantErr: ErrInvalidPayload},
		{name: "missing timestampMs", payload: safetyNetPayloadMap(t, map[string]any{"nonce": fixture.expectedNonce, "ctsProfileMatch": true}), wantErr: ErrInvalidPayload},
		{name: "non-numeric timestampMs", payload: safetyNetPayloadMap(t, map[string]any{"nonce": fixture.expectedNonce, "ctsProfileMatch": true, "timestampMs": "now"}), wantErr: ErrInvalidPayload},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(jwsVerifier{
				t:         t,
				payload:   tt.payload,
				certChain: webcrypto.CertificateChain{webcrypto.NewCertificate(fixture.certificate.raw)},
			}).VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:            "android-safetynet",
				AuthenticatorData: fixture.authenticatorData,
				ClientDataHash:    fixture.clientDataHash,
				Statement:         fixture.statement,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyAttestation() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifierRejectsCertificateFailures(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	wrongDNSCertificate := newCertificate(t, "wrong.example")

	tests := []struct {
		name  string
		chain webcrypto.CertificateChain
	}{
		{name: "missing chain", chain: nil},
		{name: "malformed leaf", chain: webcrypto.CertificateChain{webcrypto.NewCertificate([]byte("not-a-certificate"))}},
		{name: "hostname mismatch", chain: webcrypto.CertificateChain{webcrypto.NewCertificate(wrongDNSCertificate.raw)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(jwsVerifier{
				t:         t,
				payload:   safetyNetPayload(t, fixture.expectedNonce, true, json.Number("1700000000000")),
				certChain: tt.chain,
			}).VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:            "android-safetynet",
				AuthenticatorData: fixture.authenticatorData,
				ClientDataHash:    fixture.clientDataHash,
				Statement:         fixture.statement,
			})
			if !errors.Is(err, ErrCertificateRequirements) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrCertificateRequirements", err)
			}
		})
	}
}

type fixture struct {
	authenticatorData protocol.AuthenticatorData
	clientDataHash    []byte
	response          []byte
	expectedNonce     string
	certificate       testCertificate
	statement         codec.AttestationStatement
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	authenticatorData, err := protocol.NewAuthenticatorData(bytes.Repeat([]byte{0x01}, protocol.MinAuthenticatorDataLength))
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}
	clientDataHash := bytes.Repeat([]byte{0x02}, 32)
	response := []byte("compact-jws")
	expectedNonce := expectedNonce(authenticatorData.Bytes(), clientDataHash)
	certificate := newCertificate(t, safetyNetAttestDNSName)

	return fixture{
		authenticatorData: authenticatorData,
		clientDataHash:    clientDataHash,
		response:          response,
		expectedNonce:     expectedNonce,
		certificate:       certificate,
		statement: codec.AttestationStatement{
			"ver":      "1.0",
			"response": response,
		},
	}
}

type testCertificate struct {
	leaf *x509.Certificate
	raw  []byte
}

func newCertificate(t *testing.T, dnsName string) testCertificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 5, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
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

func safetyNetPayload(t *testing.T, nonce string, ctsProfileMatch bool, timestamp json.Number) []byte {
	t.Helper()

	return safetyNetPayloadMap(t, map[string]any{
		"nonce":           nonce,
		"ctsProfileMatch": ctsProfileMatch,
		"timestampMs":     timestamp,
	})
}

func safetyNetPayloadMap(t *testing.T, value map[string]any) []byte {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	return encoded
}

func cloneStatement(statement codec.AttestationStatement) codec.AttestationStatement {
	out := make(codec.AttestationStatement, len(statement))
	for key, value := range statement {
		switch typed := value.(type) {
		case []byte:
			out[key] = append([]byte{}, typed...)
		default:
			out[key] = typed
		}
	}

	return out
}

type jwsVerifier struct {
	t          *testing.T
	wantToken  []byte
	payload    []byte
	header     map[string]any
	certChain  webcrypto.CertificateChain
	fail       bool
	expectCall bool
}

func (v jwsVerifier) VerifyJWS(_ context.Context, token webcrypto.JWSToken) (webcrypto.JWSVerification, error) {
	v.t.Helper()

	if v.fail {
		return webcrypto.JWSVerification{}, errors.New("jws rejected")
	}
	if v.wantToken != nil && !bytes.Equal(token.Raw(), v.wantToken) {
		v.t.Fatalf("token = %x, want %x", token.Raw(), v.wantToken)
	}
	if v.expectCall && v.payload == nil {
		v.t.Fatal("VerifyJWS called without configured payload")
	}

	return webcrypto.JWSVerification{
		Payload:         append([]byte{}, v.payload...),
		ProtectedHeader: maps.Clone(v.header),
		Certificates:    cloneChain(v.certChain),
	}, nil
}

func cloneChain(value webcrypto.CertificateChain) webcrypto.CertificateChain {
	if value == nil {
		return nil
	}
	out := make(webcrypto.CertificateChain, len(value))
	copy(out, value)

	return out
}

var _ webcrypto.JWSVerifier = jwsVerifier{}
