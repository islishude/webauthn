package androidkey

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
	"reflect"
	"testing"
	"time"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/internal/attcrypto"
	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

func TestVerifierAcceptsEC2AndroidKeyAttestation(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t, extensionOptions{})
	verifier := New(signatureVerifier{
		t:             t,
		wantAlgorithm: -7,
		wantPublicKey: fixture.certificate.leaf.PublicKey,
		wantSigned:    fixture.signed,
		wantSignature: []byte("signature"),
	})

	result, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "android-key",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           fixture.statement,
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeBasic || result.TrustPath.Kind != attestation.TrustPathX509 || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid Android Key basic attestation", result)
	}
	if len(result.TrustPath.Certificates) != 1 || !bytes.Equal(result.TrustPath.Certificates[0].Raw(), fixture.certificate.raw) {
		t.Fatalf("trust path = %+v, want leaf certificate", result.TrustPath)
	}
}

func TestVerifierAcceptsRSAAndroidKeyAttestation(t *testing.T) {
	t.Parallel()

	fixture := newRSAFixture(t, extensionOptions{})
	verifier := New(signatureVerifier{
		t:             t,
		wantAlgorithm: -257,
		wantPublicKey: fixture.certificate.leaf.PublicKey,
		wantSigned:    fixture.signed,
		wantSignature: []byte("signature"),
	})

	result, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "android-key",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           fixture.statement,
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeBasic || result.TrustPath.Kind != attestation.TrustPathX509 || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid Android Key basic attestation", result)
	}
}

func TestVerifierRejectsMalformedStatement(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t, extensionOptions{})
	verifier := New(signatureVerifier{t: t})

	tests := []struct {
		name      string
		statement func() codec.AttestationStatement
	}{
		{name: "missing alg", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			delete(statement, "alg")
			return statement
		}},
		{name: "missing sig", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			delete(statement, "sig")
			return statement
		}},
		{name: "unexpected field", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			statement["extra"] = []byte{0x01}
			return statement
		}},
		{name: "empty x5c", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			statement["x5c"] = [][]byte{}
			return statement
		}},
		{name: "empty sig", statement: func() codec.AttestationStatement {
			statement := cloneStatement(fixture.statement)
			statement["sig"] = []byte{}
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

			_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "android-key",
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

func TestVerifierRejectsInvalidSignature(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t, extensionOptions{})
	_, err := New(signatureVerifier{t: t, fail: true}).VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "android-key",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           fixture.statement,
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifierRejectsCertificatePublicKeyMismatch(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t, extensionOptions{})
	verifier := New(signatureVerifier{t: t})

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

			_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "android-key",
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

func TestVerifierRejectsAndroidKeyExtensionFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		options extensionOptions
		wantErr error
	}{
		{name: "missing extension", options: extensionOptions{omitExtension: true}, wantErr: ErrCertificateRequirements},
		{name: "malformed extension", options: extensionOptions{malformedExtension: true}, wantErr: ErrInvalidExtension},
		{name: "challenge mismatch", options: extensionOptions{challenge: bytes.Repeat([]byte{0xff}, 32)}, wantErr: ErrCertificateRequirements},
		{name: "software allApplications", options: extensionOptions{softwareAllApplications: true}, wantErr: ErrCertificateRequirements},
		{name: "hardware allApplications", options: extensionOptions{hardwareAllApplications: true}, wantErr: ErrCertificateRequirements},
		{name: "missing origin", options: extensionOptions{omitOrigin: true}, wantErr: ErrCertificateRequirements},
		{name: "wrong origin", options: extensionOptions{origin: 1}, wantErr: ErrCertificateRequirements},
		{name: "missing purpose", options: extensionOptions{omitPurpose: true}, wantErr: ErrCertificateRequirements},
		{name: "wrong purpose", options: extensionOptions{purpose: 3}, wantErr: ErrCertificateRequirements},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fixture := newEC2Fixture(t, tt.options)
			_, err := New(signatureVerifier{t: t}).VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "android-key",
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

type fixture struct {
	authenticatorData   protocol.AuthenticatorData
	clientDataHash      []byte
	credentialPublicKey codec.CredentialPublicKey
	certificate         testCertificate
	signed              []byte
	statement           codec.AttestationStatement
}

func newEC2Fixture(t *testing.T, options extensionOptions) fixture {
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

func newRSAFixture(t *testing.T, options extensionOptions) fixture {
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

func newFixture(t *testing.T, algorithm protocol.COSEAlgorithmIdentifier, privateKey any, publicKey any, material codec.CredentialPublicKeyMaterial, options extensionOptions) fixture {
	t.Helper()

	authenticatorData := authenticatorData(t)
	clientDataHash := bytes.Repeat([]byte{0x04}, 32)
	options.clientDataHash = clientDataHash
	certificate := newCertificate(t, privateKey, publicKey, options)
	signed := attcrypto.SignedData(authenticatorData, clientDataHash)
	statement := codec.AttestationStatement{
		"alg": algorithm,
		"sig": []byte("signature"),
		"x5c": [][]byte{certificate.raw},
	}

	return fixture{
		authenticatorData:   authenticatorData,
		clientDataHash:      clientDataHash,
		credentialPublicKey: codec.NewCredentialPublicKeyWithMaterial(algorithm, "credential-key", []byte{0xa0}, nil, material),
		certificate:         certificate,
		signed:              signed,
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

type extensionOptions struct {
	clientDataHash          []byte
	challenge               []byte
	omitExtension           bool
	malformedExtension      bool
	softwareAllApplications bool
	hardwareAllApplications bool
	omitOrigin              bool
	origin                  int
	omitPurpose             bool
	purpose                 int
}

type testCertificate struct {
	leaf *x509.Certificate
	raw  []byte
}

func newCertificate(t *testing.T, privateKey any, publicKey any, options extensionOptions) testCertificate {
	t.Helper()

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("rand.Int() error = %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "Android Key Attestation"},
		NotBefore:    time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 5, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if !options.omitExtension {
		template.ExtraExtensions = []pkix.Extension{androidKeyExtension(t, options)}
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	return testCertificate{leaf: leaf, raw: raw}
}

func androidKeyExtension(t *testing.T, options extensionOptions) pkix.Extension {
	t.Helper()

	value := androidKeyDescriptionDER(t, options)
	if options.malformedExtension {
		value = []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	}

	return pkix.Extension{Id: oidExtensionAndroidKeyAttestation, Value: value}
}

func androidKeyDescriptionDER(t *testing.T, options extensionOptions) []byte {
	t.Helper()

	challenge := options.challenge
	if challenge == nil {
		challenge = options.clientDataHash
	}
	purpose := options.purpose
	if purpose == 0 {
		purpose = androidKeyPurposeSign
	}
	origin := options.origin

	software := authorizationList(t, authListOptions{
		includePurpose:  !options.omitPurpose,
		purpose:         purpose,
		allApplications: options.softwareAllApplications,
	})
	hardware := authorizationList(t, authListOptions{
		includeOrigin:   !options.omitOrigin,
		origin:          origin,
		allApplications: options.hardwareAllApplications,
	})

	return mustMarshal(t, []asn1.RawValue{
		rawValue(t, mustMarshal(t, 3)),
		rawValue(t, mustMarshal(t, 0)),
		rawValue(t, mustMarshal(t, 4)),
		rawValue(t, mustMarshal(t, 0)),
		rawValue(t, mustMarshal(t, challenge)),
		rawValue(t, mustMarshal(t, []byte{})),
		software,
		hardware,
	})
}

type authListOptions struct {
	includePurpose  bool
	purpose         int
	includeOrigin   bool
	origin          int
	allApplications bool
}

func authorizationList(t *testing.T, options authListOptions) asn1.RawValue {
	t.Helper()

	fields := make([]asn1.RawValue, 0, 3)
	if options.includePurpose {
		fields = append(fields, explicitValue(t, androidTagPurpose, integerSet(t, options.purpose)))
	}
	if options.allApplications {
		fields = append(fields, explicitValue(t, androidTagAllApplications, nullValue(t)))
	}
	if options.includeOrigin {
		fields = append(fields, explicitValue(t, androidTagOrigin, mustMarshal(t, options.origin)))
	}

	return rawValue(t, mustMarshal(t, fields))
}

func nullValue(t *testing.T) []byte {
	t.Helper()

	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: 5})
}

func integerSet(t *testing.T, values ...int) []byte {
	t.Helper()

	content := make([]byte, 0)
	for _, value := range values {
		content = append(content, mustMarshal(t, value)...)
	}

	return mustMarshal(t, asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1TagSet,
		IsCompound: true,
		Bytes:      content,
	})
}

func explicitValue(t *testing.T, tag int, inner []byte) asn1.RawValue {
	t.Helper()

	return rawValue(t, mustMarshal(t, asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      inner,
	}))
}

func rawValue(t *testing.T, der []byte) asn1.RawValue {
	t.Helper()

	var out asn1.RawValue
	rest, err := asn1.Unmarshal(der, &out)
	if err != nil || len(rest) != 0 {
		t.Fatalf("asn1.Unmarshal() error = %v rest=%x", err, rest)
	}

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
