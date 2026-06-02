package tpm

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
	"encoding/binary"
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

func TestVerifierAcceptsEC2TPMAttestation(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t)
	verifier := New(signatureVerifier{
		t:             t,
		wantAlgorithm: -7,
		wantPublicKey: fixture.certificate.leaf.PublicKey,
		wantSigned:    fixture.certInfo,
		wantSignature: fixture.derSignature,
	})

	result, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "tpm",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           fixture.statement,
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeAttCA || result.TrustPath.Kind != attestation.TrustPathX509 || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid TPM AttCA attestation", result)
	}
	if len(result.TrustPath.Certificates) != 1 || !bytes.Equal(result.TrustPath.Certificates[0].Raw(), fixture.certificate.raw) {
		t.Fatalf("trust path = %+v, want leaf certificate", result.TrustPath)
	}
}

func TestVerifierAcceptsRSATPMAttestation(t *testing.T) {
	t.Parallel()

	fixture := newRSAFixture(t)
	verifier := New(signatureVerifier{
		t:             t,
		wantAlgorithm: -257,
		wantPublicKey: fixture.certificate.leaf.PublicKey,
		wantSigned:    fixture.certInfo,
		wantSignature: []byte("rsa-signature"),
	})

	result, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "tpm",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           fixture.statement,
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeAttCA || result.TrustPath.Kind != attestation.TrustPathX509 || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid TPM AttCA attestation", result)
	}
}

func TestVerifierRejectsMalformedStatement(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t)
	verifier := New(signatureVerifier{t: t})

	tests := []struct {
		name   string
		mutate func(codec.AttestationStatement)
	}{
		{name: "missing x5c", mutate: func(statement codec.AttestationStatement) { delete(statement, "x5c") }},
		{name: "unexpected field", mutate: func(statement codec.AttestationStatement) { statement["extra"] = []byte{0x01} }},
		{name: "wrong version", mutate: func(statement codec.AttestationStatement) { statement["ver"] = "1.2" }},
		{name: "empty x5c", mutate: func(statement codec.AttestationStatement) { statement["x5c"] = [][]byte{} }},
		{name: "empty signature", mutate: func(statement codec.AttestationStatement) { statement["sig"] = []byte{} }},
		{name: "empty certInfo", mutate: func(statement codec.AttestationStatement) { statement["certInfo"] = []byte{} }},
		{name: "empty pubArea", mutate: func(statement codec.AttestationStatement) { statement["pubArea"] = []byte{} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			statement := cloneStatement(fixture.statement)
			tt.mutate(statement)
			_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "tpm",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           statement,
				CredentialPublicKey: fixture.credentialPublicKey,
			})
			if !errors.Is(err, ErrInvalidStatement) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidStatement", err)
			}
		})
	}
}

func TestVerifierRejectsUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t)
	statement := cloneStatement(fixture.statement)
	statement["alg"] = int64(-999)

	_, err := New(signatureVerifier{t: t}).VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:              "tpm",
		AuthenticatorData:   fixture.authenticatorData,
		ClientDataHash:      fixture.clientDataHash,
		Statement:           statement,
		CredentialPublicKey: fixture.credentialPublicKey,
	})
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("VerifyAttestation() error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestVerifierRejectsPublicAreaFailures(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t)
	verifier := New(signatureVerifier{t: t})

	tests := []struct {
		name    string
		mutate  func(codec.AttestationStatement) codec.CredentialPublicKey
		wantErr error
	}{
		{
			name: "bad public area",
			mutate: func(statement codec.AttestationStatement) codec.CredentialPublicKey {
				statement["pubArea"] = []byte{0x00}
				return fixture.credentialPublicKey
			},
			wantErr: ErrInvalidPublicArea,
		},
		{
			name: "missing credential material",
			mutate: func(codec.AttestationStatement) codec.CredentialPublicKey {
				return codec.NewCredentialPublicKey(-7, "credential-key", []byte{0xa0})
			},
			wantErr: ErrUnsupportedKey,
		},
		{
			name: "credential mismatch",
			mutate: func(codec.AttestationStatement) codec.CredentialPublicKey {
				material := fixture.credentialPublicKey.PublicKeyMaterial()
				material.EC2.X[0] ^= 0xff
				return codec.NewCredentialPublicKeyWithMaterial(-7, "credential-key", []byte{0xa0}, nil, material)
			},
			wantErr: ErrPublicKeyMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			statement := cloneStatement(fixture.statement)
			credentialPublicKey := tt.mutate(statement)
			_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "tpm",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           statement,
				CredentialPublicKey: credentialPublicKey,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyAttestation() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifierRejectsCertInfoFailures(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t)
	verifier := New(signatureVerifier{t: t})

	tests := []struct {
		name     string
		certInfo []byte
	}{
		{name: "bad magic", certInfo: mutateBytes(fixture.certInfo, func(value []byte) { value[0] = 0x00 })},
		{name: "bad type", certInfo: mutateBytes(fixture.certInfo, func(value []byte) { binary.BigEndian.PutUint16(value[4:6], 0x8018) })},
		{name: "extraData mismatch", certInfo: buildCertInfo(t, tpmGeneratedValue, tpmSTAttestCertify, bytes.Repeat([]byte{0xff}, 32), fixture.publicAreaName)},
		{name: "name mismatch", certInfo: buildCertInfo(t, tpmGeneratedValue, tpmSTAttestCertify, fixture.extraData, []byte("wrong-name"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			statement := cloneStatement(fixture.statement)
			statement["certInfo"] = tt.certInfo
			_, err := verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "tpm",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           statement,
				CredentialPublicKey: fixture.credentialPublicKey,
			})
			if !errors.Is(err, ErrInvalidCertInfo) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidCertInfo", err)
			}
		})
	}
}

func TestVerifierRejectsSignatureFailures(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t)

	tests := []struct {
		name      string
		signature []byte
		verifier  Verifier
	}{
		{name: "malformed signature", signature: []byte{0x00}, verifier: New(signatureVerifier{t: t})},
		{name: "signature algorithm mismatch", signature: tpmRSASignature(t, tpmAlgSHA256, []byte("signature")), verifier: New(signatureVerifier{t: t})},
		{name: "signature hash mismatch", signature: tpmECDSASignature(t, tpmAlgSHA384, []byte{0x01}, []byte{0x02}), verifier: New(signatureVerifier{t: t})},
		{name: "invalid delegated signature", signature: fixture.statement["sig"].([]byte), verifier: New(signatureVerifier{t: t, fail: true})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			statement := cloneStatement(fixture.statement)
			statement["sig"] = tt.signature
			_, err := tt.verifier.VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "tpm",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           statement,
				CredentialPublicKey: fixture.credentialPublicKey,
			})
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestVerifierRejectsCertificateRequirementFailures(t *testing.T) {
	t.Parallel()

	fixture := newEC2Fixture(t)
	differentAAGUID := protocol.AAGUID{0xff}

	tests := []struct {
		name    string
		options certificateOptions
	}{
		{name: "non-empty subject", options: certificateOptions{aaguid: fixture.aaguid, includeAAGUID: true, nonEmptySubject: true}},
		{name: "missing san", options: certificateOptions{aaguid: fixture.aaguid, includeAAGUID: true, omitSAN: true}},
		{name: "missing aik eku", options: certificateOptions{aaguid: fixture.aaguid, includeAAGUID: true, omitAIKEKU: true}},
		{name: "basic constraints ca", options: certificateOptions{aaguid: fixture.aaguid, includeAAGUID: true, isCA: true}},
		{name: "aaguid mismatch", options: certificateOptions{aaguid: differentAAGUID, includeAAGUID: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certificate := newCertificate(t, tt.options)
			statement := cloneStatement(fixture.statement)
			statement["x5c"] = [][]byte{certificate.raw}
			_, err := New(signatureVerifier{t: t}).VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "tpm",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           statement,
				CredentialPublicKey: fixture.credentialPublicKey,
			})
			if !errors.Is(err, ErrCertificateRequirements) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrCertificateRequirements", err)
			}
		})
	}
}

type fixture struct {
	aaguid              protocol.AAGUID
	authenticatorData   protocol.AuthenticatorData
	clientDataHash      []byte
	credentialPublicKey codec.CredentialPublicKey
	certificate         testCertificate
	publicAreaName      []byte
	extraData           []byte
	certInfo            []byte
	derSignature        []byte
	statement           codec.AttestationStatement
}

func newEC2Fixture(t *testing.T) fixture {
	t.Helper()

	x := bytes.Repeat([]byte{0x01}, 32)
	y := bytes.Repeat([]byte{0x02}, 32)
	publicArea := buildECCPublicArea(t, tpmECCNISTP256, x, y)
	material := codec.CredentialPublicKeyMaterial{EC2: &codec.EC2PublicKeyMaterial{
		Curve: codec.EC2CurveP256,
		X:     x,
		Y:     y,
	}}

	base := newFixtureBase(t, publicArea, tpmAlgSHA256)
	certificate := newCertificate(t, certificateOptions{aaguid: base.aaguid, includeAAGUID: true})
	rBytes := []byte{0x01}
	sBytes := []byte{0x02}
	signature := tpmECDSASignature(t, tpmAlgSHA256, rBytes, sBytes)
	derSignature := derECDSASignature(t, rBytes, sBytes)
	statement := base.statement(-7, certificate.raw, signature, publicArea)

	return fixture{
		aaguid:              base.aaguid,
		authenticatorData:   base.authenticatorData,
		clientDataHash:      base.clientDataHash,
		credentialPublicKey: codec.NewCredentialPublicKeyWithMaterial(-7, "credential-key", []byte{0xa0}, nil, material),
		certificate:         certificate,
		publicAreaName:      base.publicAreaName,
		extraData:           base.extraData,
		certInfo:            base.certInfo,
		derSignature:        derSignature,
		statement:           statement,
	}
}

func newRSAFixture(t *testing.T) fixture {
	t.Helper()

	modulus := bytes.Repeat([]byte{0x03}, 256)
	publicArea := buildRSAPublicArea(t, modulus, 65537)
	material := codec.CredentialPublicKeyMaterial{RSA: &codec.RSAPublicKeyMaterial{
		Modulus:  modulus,
		Exponent: 65537,
	}}

	base := newFixtureBase(t, publicArea, tpmAlgSHA256)
	certificate := newCertificate(t, certificateOptions{aaguid: base.aaguid, includeAAGUID: true, useRSAKey: true})
	signature := tpmRSASignature(t, tpmAlgSHA256, []byte("rsa-signature"))
	statement := base.statement(-257, certificate.raw, signature, publicArea)

	return fixture{
		aaguid:              base.aaguid,
		authenticatorData:   base.authenticatorData,
		clientDataHash:      base.clientDataHash,
		credentialPublicKey: codec.NewCredentialPublicKeyWithMaterial(-257, "credential-key", []byte{0xa0}, nil, material),
		certificate:         certificate,
		publicAreaName:      base.publicAreaName,
		extraData:           base.extraData,
		certInfo:            base.certInfo,
		statement:           statement,
	}
}

type fixtureBase struct {
	aaguid            protocol.AAGUID
	authenticatorData protocol.AuthenticatorData
	clientDataHash    []byte
	publicAreaName    []byte
	extraData         []byte
	certInfo          []byte
}

func newFixtureBase(t *testing.T, publicArea []byte, hashAlg uint16) fixtureBase {
	t.Helper()

	var aaguid protocol.AAGUID
	copy(aaguid[:], []byte("0123456789abcdef"))
	authenticatorData := authenticatorData(t, aaguid)
	clientDataHash := bytes.Repeat([]byte{0x04}, 32)
	parsedPublicArea, err := parsePublicArea(publicArea)
	if err != nil {
		t.Fatalf("parsePublicArea() error = %v", err)
	}
	publicAreaName, err := parsedPublicArea.name()
	if err != nil {
		t.Fatalf("publicArea.name() error = %v", err)
	}
	extraData, err := tpmHash(hashAlg, attcrypto.SignedData(authenticatorData, clientDataHash))
	if err != nil {
		t.Fatalf("tpmHash() error = %v", err)
	}
	certInfo := buildCertInfo(t, tpmGeneratedValue, tpmSTAttestCertify, extraData, publicAreaName)

	return fixtureBase{
		aaguid:            aaguid,
		authenticatorData: authenticatorData,
		clientDataHash:    clientDataHash,
		publicAreaName:    publicAreaName,
		extraData:         extraData,
		certInfo:          certInfo,
	}
}

func (b fixtureBase) statement(algorithm protocol.COSEAlgorithmIdentifier, certificate []byte, signature []byte, publicArea []byte) codec.AttestationStatement {
	return codec.AttestationStatement{
		"ver":      "2.0",
		"alg":      algorithm,
		"x5c":      [][]byte{certificate},
		"sig":      signature,
		"certInfo": b.certInfo,
		"pubArea":  publicArea,
	}
}

func authenticatorData(t *testing.T, aaguid protocol.AAGUID) protocol.AuthenticatorData {
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

type tpmBuffer []byte

func (b *tpmBuffer) uint16(value uint16) {
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], value)
	*b = append(*b, out[:]...)
}

func (b *tpmBuffer) uint32(value uint32) {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], value)
	*b = append(*b, out[:]...)
}

func (b *tpmBuffer) uint64(value uint64) {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	*b = append(*b, out[:]...)
}

func (b *tpmBuffer) sizedBytes(value []byte) {
	b.uint16(uint16(len(value))) //nolint:gosec // test TPM blobs are fixed and below uint16 max.
	*b = append(*b, value...)
}

func (b *tpmBuffer) raw(value []byte) {
	*b = append(*b, value...)
}

func buildECCPublicArea(t *testing.T, curveID uint16, x []byte, y []byte) []byte {
	t.Helper()

	var out tpmBuffer
	out.uint16(tpmAlgECC)
	out.uint16(tpmAlgSHA256)
	out.uint32(0)
	out.sizedBytes(nil)
	out.uint16(tpmAlgNull)
	out.uint16(tpmAlgNull)
	out.uint16(curveID)
	out.uint16(tpmAlgNull)
	out.sizedBytes(x)
	out.sizedBytes(y)

	return out
}

func buildRSAPublicArea(t *testing.T, modulus []byte, exponent uint32) []byte {
	t.Helper()

	var out tpmBuffer
	out.uint16(tpmAlgRSA)
	out.uint16(tpmAlgSHA256)
	out.uint32(0)
	out.sizedBytes(nil)
	out.uint16(tpmAlgNull)
	out.uint16(tpmAlgNull)
	out.uint16(uint16(len(modulus) * 8)) //nolint:gosec // test modulus sizes are fixed and below uint16 max.
	out.uint32(exponent)
	out.sizedBytes(modulus)

	return out
}

func buildCertInfo(t *testing.T, magic uint32, attestType uint16, extraData []byte, name []byte) []byte {
	t.Helper()

	var out tpmBuffer
	out.uint32(magic)
	out.uint16(attestType)
	out.sizedBytes(nil)
	out.sizedBytes(extraData)
	out.raw(make([]byte, 17))
	out.uint64(0)
	out.sizedBytes(name)
	out.sizedBytes([]byte("qualified-name"))

	return out
}

func tpmECDSASignature(t *testing.T, hashAlg uint16, rBytes []byte, sBytes []byte) []byte {
	t.Helper()

	var out tpmBuffer
	out.uint16(tpmAlgECDSA)
	out.uint16(hashAlg)
	out.sizedBytes(rBytes)
	out.sizedBytes(sBytes)

	return out
}

func derECDSASignature(t *testing.T, rBytes []byte, sBytes []byte) []byte {
	t.Helper()

	der, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{
		R: new(big.Int).SetBytes(rBytes),
		S: new(big.Int).SetBytes(sBytes),
	})
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	return der
}

func tpmRSASignature(t *testing.T, hashAlg uint16, signature []byte) []byte {
	t.Helper()

	var out tpmBuffer
	out.uint16(tpmAlgRSASSA)
	out.uint16(hashAlg)
	out.sizedBytes(signature)

	return out
}

type certificateOptions struct {
	aaguid          protocol.AAGUID
	includeAAGUID   bool
	useRSAKey       bool
	nonEmptySubject bool
	omitSAN         bool
	omitAIKEKU      bool
	isCA            bool
}

type testCertificate struct {
	leaf *x509.Certificate
	raw  []byte
}

func newCertificate(t *testing.T, options certificateOptions) testCertificate {
	t.Helper()

	privateKey, publicKey := newCertificateKey(t, options.useRSAKey)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("rand.Int() error = %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 5, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  options.isCA,
	}
	if options.nonEmptySubject {
		template.Subject = pkix.Name{CommonName: "TPM AIK"}
	}
	if !options.omitAIKEKU {
		template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidAIKEKU}
	}
	if !options.omitSAN {
		template.ExtraExtensions = append(template.ExtraExtensions, tpmSANExtension(t))
	}
	if options.includeAAGUID {
		extensionValue, err := asn1.Marshal(options.aaguid.Bytes())
		if err != nil {
			t.Fatalf("asn1.Marshal() error = %v", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    oidExtensionFIDOAAGUID,
			Value: extensionValue,
		})
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

func newCertificateKey(t *testing.T, useRSA bool) (any, any) {
	t.Helper()

	if useRSA {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}

		return key, &key.PublicKey
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	return key, &key.PublicKey
}

func tpmSANExtension(t *testing.T) pkix.Extension {
	t.Helper()

	nameDER, err := asn1.Marshal(pkix.RDNSequence{
		[]pkix.AttributeTypeAndValue{{Type: oidTPMManufacturer, Value: "id:FFFFF1D0"}},
		[]pkix.AttributeTypeAndValue{{Type: oidTPMModel, Value: "example-model"}},
		[]pkix.AttributeTypeAndValue{{Type: oidTPMVersion, Value: "1.0"}},
	})
	if err != nil {
		t.Fatalf("asn1.Marshal() name error = %v", err)
	}
	generalNames, err := asn1.Marshal([]asn1.RawValue{{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      nameDER,
	}})
	if err != nil {
		t.Fatalf("asn1.Marshal() general names error = %v", err)
	}

	return pkix.Extension{Id: oidExtensionSubjectAltName, Value: generalNames}
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

func mutateBytes(value []byte, mutate func([]byte)) []byte {
	out := append([]byte{}, value...)
	mutate(out)

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
