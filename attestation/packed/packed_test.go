package packed_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/internal/x509util"
	attpacked "github.com/islishude/webauthn/attestation/packed"
	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

func TestVerifierAcceptsSelfAttestation(t *testing.T) {
	t.Parallel()

	fixture := newPackedFixture(t)
	credentialPublicKey := codec.NewCredentialPublicKey(-7, []byte{0xa0}, codec.CredentialPublicKeyMaterial{})
	verifier := attpacked.New(signatureVerifier{
		t:             t,
		wantAlgorithm: -7,
		wantPublicKey: []byte{0xa0},
		wantSigned:    fixture.signed,
		wantSignature: []byte("signature"),
	})

	result, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "packed",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           codec.AttestationStatement{"alg": int64(-7), "sig": []byte("signature")},
		CredentialPublicKey: credentialPublicKey,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeSelf || result.TrustPath.Kind != attestation.TrustPathNone || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid self attestation", result)
	}
}

func TestVerifierAcceptsX5CAttestation(t *testing.T) {
	t.Parallel()

	fixture := newPackedFixture(t)
	certificate := newAttestationCertificate(t, certificateOptions{aaguid: fixture.aaguid, includeAAGUID: true})
	verifier := attpacked.New(signatureVerifier{
		t:             t,
		wantAlgorithm: -7,
		wantPublicKey: certificate.leaf.PublicKey,
		wantSigned:    fixture.signed,
		wantSignature: []byte("signature"),
	})

	result, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "packed",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           codec.AttestationStatement{"alg": int64(-7), "sig": []byte("signature"), "x5c": [][]byte{certificate.raw}},
		CredentialPublicKey: codec.NewCredentialPublicKey(-7, []byte{0xa0}, codec.CredentialPublicKeyMaterial{}),
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeUncertain || result.TrustPath.Kind != attestation.TrustPathX509 || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid x5c attestation", result)
	}
	if len(result.TrustPath.Certificates) != 1 || !bytes.Equal(result.TrustPath.Certificates[0].Raw(), certificate.raw) {
		t.Fatalf("trust path = %+v, want leaf certificate", result.TrustPath)
	}
}

func TestVerifierAcceptsEnterpriseSerialNumber(t *testing.T) {
	t.Parallel()

	fixture := newPackedFixture(t)
	certificate := newAttestationCertificate(t, certificateOptions{aaguid: fixture.aaguid, enterpriseSerial: []byte("device-serial")})
	verifier := attpacked.New(signatureVerifier{t: t})
	_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:               "packed",
		ConveyancePreference: protocol.AttestationEnterprise,
		AuthenticatorData:    fixture.authenticatorData,
		ClientDataHash:       fixture.clientDataHash,
		Statement:            codec.AttestationStatement{"alg": int64(-7), "sig": []byte("signature"), "x5c": [][]byte{certificate.raw}},
		CredentialPublicKey:  codec.NewCredentialPublicKey(-7, []byte{0xa0}, codec.CredentialPublicKeyMaterial{}),
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
}

func TestVerifierRejectsMalformedStatement(t *testing.T) {
	t.Parallel()

	fixture := newPackedFixture(t)
	verifier := attpacked.New(signatureVerifier{t: t})

	tests := []struct {
		name      string
		statement codec.AttestationStatement
		wantErr   error
	}{
		{name: "missing alg", statement: codec.AttestationStatement{"sig": []byte("signature")}, wantErr: attpacked.ErrInvalidStatement},
		{name: "missing sig", statement: codec.AttestationStatement{"alg": int64(-7)}, wantErr: attpacked.ErrInvalidStatement},
		{name: "unexpected field", statement: codec.AttestationStatement{"alg": int64(-7), "sig": []byte("signature"), "ecdaaKeyId": []byte{0x01}}, wantErr: attpacked.ErrInvalidStatement},
		{name: "empty x5c", statement: codec.AttestationStatement{"alg": int64(-7), "sig": []byte("signature"), "x5c": [][]byte{}}, wantErr: attpacked.ErrInvalidStatement},
		{name: "bad x5c type", statement: codec.AttestationStatement{"alg": int64(-7), "sig": []byte("signature"), "x5c": "not-certs"}, wantErr: attpacked.ErrInvalidStatement},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "packed",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           tt.statement,
				CredentialPublicKey: codec.NewCredentialPublicKey(-7, []byte{0xa0}, codec.CredentialPublicKeyMaterial{}),
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyAttestation() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifierRejectsAlgorithmMismatch(t *testing.T) {
	t.Parallel()

	fixture := newPackedFixture(t)
	verifier := attpacked.New(signatureVerifier{t: t})

	_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "packed",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           codec.AttestationStatement{"alg": int64(-257), "sig": []byte("signature")},
		CredentialPublicKey: codec.NewCredentialPublicKey(-7, []byte{0xa0}, codec.CredentialPublicKeyMaterial{}),
	})
	if !errors.Is(err, attpacked.ErrAlgorithmMismatch) {
		t.Fatalf("VerifyAttestation() error = %v, want ErrAlgorithmMismatch", err)
	}
}

func TestVerifierRejectsInvalidSignature(t *testing.T) {
	t.Parallel()

	fixture := newPackedFixture(t)
	verifier := attpacked.New(signatureVerifier{t: t, fail: true})

	_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "packed",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           codec.AttestationStatement{"alg": int64(-7), "sig": []byte("signature")},
		CredentialPublicKey: codec.NewCredentialPublicKey(-7, []byte{0xa0}, codec.CredentialPublicKeyMaterial{}),
	})
	if !errors.Is(err, attpacked.ErrInvalidSignature) {
		t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifierRejectsCertificateRequirementFailures(t *testing.T) {
	t.Parallel()

	fixture := newPackedFixture(t)
	differentAAGUID := protocol.AAGUID{0xff}

	tests := []struct {
		name       string
		options    certificateOptions
		conveyance protocol.AttestationConveyancePreference
	}{
		{name: "missing subject ou", options: certificateOptions{aaguid: fixture.aaguid, omitOU: true}},
		{name: "basic constraints ca", options: certificateOptions{aaguid: fixture.aaguid, isCA: true}},
		{name: "aaguid mismatch", options: certificateOptions{aaguid: differentAAGUID, includeAAGUID: true}},
		{name: "subject string types", options: certificateOptions{aaguid: fixture.aaguid, wrongSubjectTypes: true}},
		{name: "negative firmware", options: certificateOptions{aaguid: fixture.aaguid, firmwarePresent: true, firmware: -1}},
		{name: "critical firmware", options: certificateOptions{aaguid: fixture.aaguid, firmwarePresent: true, firmware: 1, firmwareCritical: true}},
		{name: "non-enterprise serial", options: certificateOptions{aaguid: fixture.aaguid, enterpriseSerial: []byte("device")}},
		{name: "critical enterprise serial", options: certificateOptions{aaguid: fixture.aaguid, enterpriseSerial: []byte("device"), enterpriseSerialCritical: true}, conveyance: protocol.AttestationEnterprise},
		{name: "empty enterprise serial", options: certificateOptions{aaguid: fixture.aaguid, enterpriseSerialPresent: true}, conveyance: protocol.AttestationEnterprise},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certificate := newAttestationCertificate(t, tt.options)
			verifier := attpacked.New(signatureVerifier{t: t})
			_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:               "packed",
				ConveyancePreference: tt.conveyance,
				AuthenticatorData:    fixture.authenticatorData,
				ClientDataHash:       fixture.clientDataHash,
				Statement:            codec.AttestationStatement{"alg": int64(-7), "sig": []byte("signature"), "x5c": [][]byte{certificate.raw}},
				CredentialPublicKey:  codec.NewCredentialPublicKey(-7, []byte{0xa0}, codec.CredentialPublicKeyMaterial{}),
			})
			if !errors.Is(err, attpacked.ErrCertificateRequirements) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrCertificateRequirements", err)
			}
		})
	}
}

type packedFixture struct {
	aaguid            protocol.AAGUID
	authenticatorData protocol.AuthenticatorData
	clientDataHash    []byte
	signed            []byte
}

func newPackedFixture(t *testing.T) packedFixture {
	t.Helper()

	var aaguid protocol.AAGUID
	copy(aaguid[:], []byte("0123456789abcdef"))
	authenticatorData := authenticatorDataWithAAGUID(t, aaguid)
	clientDataHash := bytes.Repeat([]byte{0x03}, 32)
	signed := append(authenticatorData.Bytes(), clientDataHash...)

	return packedFixture{
		aaguid:            aaguid,
		authenticatorData: authenticatorData,
		clientDataHash:    clientDataHash,
		signed:            signed,
	}
}

func authenticatorDataWithAAGUID(t *testing.T, aaguid protocol.AAGUID) protocol.AuthenticatorData {
	t.Helper()

	out := bytes.Repeat([]byte{0x01}, protocol.RPIDHashLength)
	out = append(out, 0x41)
	out = append(out, 0x00, 0x00, 0x00, 0x01)
	out = append(out, aaguid[:]...)
	credentialID := []byte("credential-id")
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

type certificateOptions struct {
	aaguid                   protocol.AAGUID
	includeAAGUID            bool
	omitOU                   bool
	isCA                     bool
	wrongSubjectTypes        bool
	firmwarePresent          bool
	firmware                 int64
	firmwareCritical         bool
	enterpriseSerialPresent  bool
	enterpriseSerial         []byte
	enterpriseSerialCritical bool
}

type testCertificate struct {
	leaf *x509.Certificate
	raw  []byte
}

func newAttestationCertificate(t *testing.T, options certificateOptions) testCertificate {
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

	subject := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"Example Authenticator Vendor"},
		CommonName:   "Example Authenticator",
	}
	if !options.omitOU {
		subject.OrganizationalUnit = []string{"Authenticator Attestation"}
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		RawSubject:            packedSubjectDER(t, options.omitOU, options.wrongSubjectTypes),
		NotBefore:             time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 5, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  options.isCA,
	}
	if options.includeAAGUID {
		extensionValue, err := asn1.Marshal(options.aaguid.Bytes())
		if err != nil {
			t.Fatalf("asn1.Marshal() error = %v", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4},
			Value: extensionValue,
		})
	}
	if options.firmwarePresent {
		value, err := asn1.Marshal(options.firmware)
		if err != nil {
			t.Fatalf("asn1.Marshal() firmware error = %v", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 5}, Critical: options.firmwareCritical, Value: value})
	}
	if options.enterpriseSerialPresent || options.enterpriseSerial != nil {
		value, err := asn1.Marshal(options.enterpriseSerial)
		if err != nil {
			t.Fatalf("asn1.Marshal() serial error = %v", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 2}, Critical: options.enterpriseSerialCritical, Value: value})
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

func packedSubjectDER(t *testing.T, omitOU bool, wrongTypes bool) []byte {
	t.Helper()
	stringTag := asn1.TagUTF8String
	if wrongTypes {
		stringTag = asn1.TagPrintableString
	}
	rdns := pkix.RDNSequence{
		[]pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: []byte("US")}}},
		[]pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: asn1.RawValue{Tag: stringTag, Bytes: []byte("Example Authenticator Vendor")}}},
		[]pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: stringTag, Bytes: []byte("Example Authenticator")}}},
	}
	if !omitOU {
		rdns = append(rdns, []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: asn1.RawValue{Tag: stringTag, Bytes: []byte("Authenticator Attestation")}}})
	}
	encoded, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("asn1.Marshal() subject error = %v", err)
	}
	return encoded
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
	if raw, ok := v.wantPublicKey.([]byte); ok {
		if !bytes.Equal(input.RawCredentialPublicKey, raw) {
			v.t.Fatalf("RawCredentialPublicKey = %x, want %x", input.RawCredentialPublicKey, raw)
		}
	} else if v.wantPublicKey != nil {
		want, ok := x509util.PublicKeyMaterial(v.wantPublicKey)
		if !ok || !reflect.DeepEqual(input.PublicKey, want) {
			v.t.Fatalf("PublicKey = %#v, want %#v", input.PublicKey, want)
		}
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
