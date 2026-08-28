package webauthn_test

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/fxamacker/cbor/v2"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	attandroidkey "github.com/islishude/webauthn/attestation/androidkey"
	attapple "github.com/islishude/webauthn/attestation/apple"
	attfidou2f "github.com/islishude/webauthn/attestation/fidou2f"
	attnone "github.com/islishude/webauthn/attestation/none"
	attpacked "github.com/islishude/webauthn/attestation/packed"
	atttpm "github.com/islishude/webauthn/attestation/tpm"
	"github.com/islishude/webauthn/codec"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	webcrypto "github.com/islishude/webauthn/crypto"
	cryptostandard "github.com/islishude/webauthn/crypto/standard"
	"github.com/islishude/webauthn/protocol"
)

var w3cVectorTime = time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)

func TestW3CLevel3CeremonyVectors(t *testing.T) {
	t.Parallel()

	fixture := loadW3CFixture[w3cCeremonyFixture](t, "ceremonies.json")
	rootCertificate := decodeW3CHex(t, fixture.AttestationRootCertificate)
	standardVerifier, err := cryptostandard.NewVerifier(
		protocol.AlgorithmES256,
		protocol.AlgorithmES384,
		protocol.AlgorithmES512,
		protocol.AlgorithmRS256,
		protocol.AlgorithmEdDSA,
	)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	signatures := w3cSignatureVerifier{standard: standardVerifier}
	decoder := codeccbor.MustNewDecoder()

	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()

			var registration webauthn.RegistrationResult
			if !t.Run("registration", func(t *testing.T) {
				original := decodeW3CHex(t, vector.AttestationObject)
				if vector.RegistrationExpectation == "reject-nonconformant-tpm-der" {
					if _, err := finishW3CRegistration(t, fixture, vector, original, rootCertificate, signatures, decoder); !errors.Is(err, atttpm.ErrInvalidSignature) {
						t.Fatalf("FinishRegistration(original TPM vector) error = %v, want ErrInvalidSignature", err)
					}
					original = conformW3CTPMSignature(t, original, decoder)
				}

				var err error
				registration, err = finishW3CRegistration(t, fixture, vector, original, rootCertificate, signatures, decoder)
				if err != nil {
					t.Fatalf("FinishRegistration() error = %v", err)
				}
				algorithm := protocol.COSEAlgorithmIdentifier(vector.Algorithm)
				if registration.Credential.PublicKey.Algorithm != algorithm {
					t.Fatalf("credential algorithm = %d, want %d", registration.Credential.PublicKey.Algorithm, algorithm)
				}
				if registration.Attestation.Type != attestation.Type(vector.ExpectedAttestationType) || !registration.Attestation.CryptographicallyValid {
					t.Fatalf("attestation = %+v, want type %q and cryptographically valid", registration.Attestation, vector.ExpectedAttestationType)
				}
				if !registration.AttestationTrust.Accepted {
					t.Fatalf("attestation trust = %+v, want accepted", registration.AttestationTrust)
				}
				if vector.Name == "none-es256-long-credential-id" && registration.Credential.ID.Len() != protocol.MaxCredentialIDLength {
					t.Fatalf("credential ID length = %d, want %d", registration.Credential.ID.Len(), protocol.MaxCredentialIDLength)
				}
			}) {
				return
			}

			t.Run("authentication", func(t *testing.T) {
				result, err := finishW3CAuthentication(t, fixture, vector, registration.Credential, signatures, decoder)
				if err != nil {
					t.Fatalf("FinishAuthentication() error = %v", err)
				}
				if !result.AuthenticatedAs.Equal(registration.Credential.UserHandle) || !result.Credential.ID.Equal(registration.Credential.ID) {
					t.Fatalf("authentication result = %+v", result)
				}
			})
		})
	}
}

func finishW3CRegistration(
	t *testing.T,
	fixture w3cCeremonyFixture,
	vector w3cCeremonyVector,
	attestationObjectBytes []byte,
	rootCertificate []byte,
	signatures w3cSignatureVerifier,
	decoder *codeccbor.Decoder,
) (webauthn.RegistrationResult, error) {
	t.Helper()

	userHandle, err := protocol.NewUserHandle([]byte("w3c-" + vector.Name))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	originPolicy := w3cOriginPolicy(fixture, vector)
	conveyance := protocol.AttestationDirect
	if vector.Format == "none" {
		conveyance = protocol.AttestationNone
	}
	start, err := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
		RP:           protocol.RPEntity{ID: fixture.RPID, Name: "W3C Test RP"},
		User:         protocol.UserEntity{ID: userHandle, Name: "w3c-user", DisplayName: ""},
		OriginPolicy: originPolicy,
		Challenge:    mustProtocolChallenge(t, decodeW3CHex(t, vector.RegistrationChallenge)),
		PubKeyCredParams: []protocol.CredentialParameter{{
			Type:      protocol.CredentialTypePublicKey,
			Algorithm: protocol.COSEAlgorithmIdentifier(vector.Algorithm),
		}},
		Attestation: conveyance,
		Now:         func() time.Time { return w3cVectorTime },
	})
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}
	rawID, err := protocol.NewRawID(decodeW3CHex(t, vector.CredentialID))
	if err != nil {
		t.Fatalf("NewRawID() error = %v", err)
	}
	clientDataJSON, err := protocol.NewClientDataJSON(decodeW3CHex(t, vector.RegistrationClientDataJSON))
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}
	attestationObject, err := protocol.NewAttestationObject(attestationObjectBytes)
	if err != nil {
		t.Fatalf("NewAttestationObject() error = %v", err)
	}
	registry, trustPolicy := w3cAttestationConfiguration(t, vector, rootCertificate, signatures)
	return webauthn.FinishRegistration(context.Background(), webauthn.RegistrationFinishOptions{
		State: start.State,
		Response: webauthn.RegistrationResponse{
			Type:              protocol.CredentialTypePublicKey,
			RawID:             rawID,
			ClientDataJSON:    clientDataJSON,
			AttestationObject: attestationObject,
		},
		AttestationObjectDecoder:   decoder,
		CredentialPublicKeyDecoder: decoder,
		ExtensionMapDecoder:        decoder,
		AttestationRegistry:        registry,
		AttestationTrustPolicy:     trustPolicy,
		Now:                        func() time.Time { return w3cVectorTime },
	})
}

func finishW3CAuthentication(
	t *testing.T,
	fixture w3cCeremonyFixture,
	vector w3cCeremonyVector,
	credential webauthn.CredentialRecord,
	signatures w3cSignatureVerifier,
	decoder *codeccbor.Decoder,
) (webauthn.AuthenticationResult, error) {
	t.Helper()

	originPolicy := w3cOriginPolicy(fixture, vector)
	start, err := webauthn.StartAuthentication(context.Background(), webauthn.AuthenticationStartOptions{
		RPID:               fixture.RPID,
		OriginPolicy:       originPolicy,
		Challenge:          mustProtocolChallenge(t, decodeW3CHex(t, vector.AuthenticationChallenge)),
		AllowCredentials:   []protocol.CredentialDescriptor{{Type: protocol.CredentialTypePublicKey, ID: credential.ID}},
		ExpectedUserHandle: credential.UserHandle,
		Now:                func() time.Time { return w3cVectorTime },
	})
	if err != nil {
		t.Fatalf("StartAuthentication() error = %v", err)
	}
	rawID, err := protocol.NewRawID(decodeW3CHex(t, vector.CredentialID))
	if err != nil {
		t.Fatalf("NewRawID() error = %v", err)
	}
	clientDataJSON, err := protocol.NewClientDataJSON(decodeW3CHex(t, vector.AuthenticationClientDataJSON))
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}
	authenticatorData, err := protocol.NewAuthenticatorData(decodeW3CHex(t, vector.AuthenticatorData))
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}
	signature, err := protocol.NewSignature(decodeW3CHex(t, vector.Signature))
	if err != nil {
		t.Fatalf("NewSignature() error = %v", err)
	}
	return webauthn.FinishAuthentication(context.Background(), webauthn.AuthenticationFinishOptions{
		State: start.State,
		Response: webauthn.AuthenticationResponse{
			Type:              protocol.CredentialTypePublicKey,
			RawID:             rawID,
			ClientDataJSON:    clientDataJSON,
			AuthenticatorData: authenticatorData,
			Signature:         signature,
		},
		Credential:          credential,
		SignatureVerifier:   signatures,
		AlgorithmPolicy:     signatures,
		ExtensionMapDecoder: decoder,
		Now:                 func() time.Time { return w3cVectorTime },
	})
}

func w3cOriginPolicy(fixture w3cCeremonyFixture, vector w3cCeremonyVector) webauthn.OriginPolicy {
	policy := webauthn.OriginPolicy{AllowedOrigins: []string{fixture.Origin}}
	switch vector.Name {
	case "none-es256-cross-origin":
		policy.AllowCrossOriginWithoutTopOrigin = true
	case "none-es256-top-origin":
		policy.AllowedTopOrigins = []string{fixture.TopOrigin}
	}
	return policy
}

func w3cAttestationConfiguration(
	t *testing.T,
	vector w3cCeremonyVector,
	rootCertificate []byte,
	signatures w3cSignatureVerifier,
) (*attestation.Registry, attestation.TrustPolicy) {
	t.Helper()

	var verifier attestation.Verifier
	var trustPolicy attestation.TrustPolicy
	switch vector.Format {
	case "none":
		verifier = attnone.New()
		trustPolicy = attestation.AcceptNone()
	case "packed":
		verifier = attpacked.New(signatures)
		if vector.ExpectedAttestationType == string(attestation.TypeSelf) {
			trustPolicy = attestation.AcceptSelf()
		}
	case "tpm":
		verifier = atttpm.New(signatures)
	case "android-key":
		verifier = attandroidkey.New(signatures)
	case "apple":
		verifier = attapple.New()
	case "fido-u2f":
		verifier = attfidou2f.New(signatures)
	default:
		t.Fatalf("unknown W3C attestation format %q", vector.Format)
	}
	if trustPolicy == nil {
		trustPolicy = attestation.AllOf(
			attestation.AllowFormats(vector.Format),
			attestation.RequireTrustedRoots(w3cCertificateVerifier{}, webcrypto.CertificateVerificationContext{
				CurrentTime: w3cVectorTime,
				Roots:       rootCertificate,
			}),
		)
	}
	registry, err := attestation.NewRegistry(verifier)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return registry, trustPolicy
}

type w3cSignatureVerifier struct {
	standard *cryptostandard.Verifier
}

func (v w3cSignatureVerifier) AcceptsAlgorithm(algorithm protocol.COSEAlgorithmIdentifier) bool {
	return algorithm == protocol.AlgorithmEd448 || v.standard.AcceptsAlgorithm(algorithm)
}

func (v w3cSignatureVerifier) VerifySignature(ctx context.Context, input webcrypto.SignatureInput) error {
	if input.Algorithm != protocol.AlgorithmEd448 {
		return v.standard.VerifySignature(ctx, input)
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	if input.PublicKey.OKP == nil || input.PublicKey.EC2 != nil || input.PublicKey.RSA != nil ||
		input.PublicKey.OKP.Curve != codec.OKPCurveEd448 || len(input.PublicKey.OKP.X) != ed448.PublicKeySize {
		return errors.New("W3C Ed448 public key is invalid")
	}
	if !ed448.Verify(ed448.PublicKey(input.PublicKey.OKP.X), input.Signed, input.Signature.Bytes(), "") {
		return errors.New("W3C Ed448 signature is invalid")
	}
	return nil
}

type w3cCertificateVerifier struct{}

func (w3cCertificateVerifier) VerifyCertificateChain(
	ctx context.Context,
	chain webcrypto.CertificateChain,
	verificationContext webcrypto.CertificateVerificationContext,
) (webcrypto.CertificateVerification, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return webcrypto.CertificateVerification{}, ctx.Err()
		default:
		}
	}
	rootDER, ok := verificationContext.Roots.([]byte)
	if !ok || len(rootDER) == 0 || len(chain) == 0 {
		return webcrypto.CertificateVerification{}, errors.New("W3C certificate verifier requires a root and leaf-first chain")
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return webcrypto.CertificateVerification{}, fmt.Errorf("parse W3C root: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	var leaf *x509.Certificate
	for index, encoded := range chain {
		certificate, err := x509.ParseCertificate(encoded.Raw())
		if err != nil {
			return webcrypto.CertificateVerification{}, fmt.Errorf("parse W3C chain certificate %d: %w", index, err)
		}
		if index == 0 {
			leaf = certificate
			// Go's generic verifier does not consume a critical directoryName
			// subjectAltName. The TPM format verifier has already validated that
			// exact SAN profile before the trust policy runs.
			leaf.UnhandledCriticalExtensions = slices.DeleteFunc(
				leaf.UnhandledCriticalExtensions,
				func(oid asn1.ObjectIdentifier) bool { return oid.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) },
			)
		} else {
			intermediates.AddCert(certificate)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   verificationContext.CurrentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return webcrypto.CertificateVerification{}, fmt.Errorf("verify W3C attestation chain: %w", err)
	}
	return webcrypto.CertificateVerification{Trusted: true}, nil
}

func conformW3CTPMSignature(t *testing.T, raw []byte, decoder *codeccbor.Decoder) []byte {
	t.Helper()

	attestationObject, err := protocol.NewAttestationObject(raw)
	if err != nil {
		t.Fatalf("NewAttestationObject() error = %v", err)
	}
	decoded, err := decoder.DecodeAttestationObject(attestationObject)
	if err != nil {
		t.Fatalf("DecodeAttestationObject() error = %v", err)
	}
	statement := maps.Clone(decoded.Statement)
	signature, ok := statement["sig"].([]byte)
	if !ok || len(signature) == 0 || signature[0] != 0x30 {
		t.Fatalf("W3C TPM signature = %T %x, want DER ECDSA", statement["sig"], signature)
	}
	var ecdsaSignature struct {
		R *big.Int
		S *big.Int
	}
	rest, err := asn1.Unmarshal(signature, &ecdsaSignature)
	if err != nil || len(rest) != 0 || ecdsaSignature.R == nil || ecdsaSignature.S == nil ||
		ecdsaSignature.R.Sign() <= 0 || ecdsaSignature.S.Sign() <= 0 ||
		ecdsaSignature.R.BitLen() > 256 || ecdsaSignature.S.BitLen() > 256 {
		t.Fatalf("parse W3C TPM DER signature: rest=%x value=%+v error=%v", rest, ecdsaSignature, err)
	}
	r := ecdsaSignature.R.FillBytes(make([]byte, 32))
	s := ecdsaSignature.S.FillBytes(make([]byte, 32))
	tpmSignature := make([]byte, 0, 4+2+len(r)+2+len(s))
	tpmSignature = appendW3CUint16(tpmSignature, 0x0018)
	tpmSignature = appendW3CUint16(tpmSignature, 0x000b)
	tpmSignature = appendW3CUint16(tpmSignature, 32)
	tpmSignature = append(tpmSignature, r...)
	tpmSignature = appendW3CUint16(tpmSignature, 32)
	tpmSignature = append(tpmSignature, s...)
	statement["sig"] = tpmSignature

	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("CanonicalEncOptions().EncMode() error = %v", err)
	}
	encoded, err := mode.Marshal(map[string]any{
		"fmt":      decoded.Format,
		"authData": decoded.AuthenticatorData.Bytes(),
		"attStmt":  statement,
	})
	if err != nil {
		t.Fatalf("Marshal(conforming TPM attestation) error = %v", err)
	}
	return encoded
}

func appendW3CUint16(out []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(out, encoded[:]...)
}

var (
	_ webcrypto.AlgorithmPolicy     = w3cSignatureVerifier{}
	_ webcrypto.SignatureVerifier   = w3cSignatureVerifier{}
	_ webcrypto.CertificateVerifier = w3cCertificateVerifier{}
)
