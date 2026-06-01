package webauthn_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"os"
	"testing"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	"github.com/islishude/webauthn/codec"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

func TestBrowserVirtualAuthenticatorFixturesVerify(t *testing.T) {
	t.Parallel()

	fixtures := readBrowserFixtureFile(t)
	if fixtures.Metadata.GeneratedAt != "2026-06-01" {
		t.Fatalf("GeneratedAt = %q, want 2026-06-01", fixtures.Metadata.GeneratedAt)
	}
	if fixtures.Metadata.ExternalConformanceData != "none" {
		t.Fatalf("ExternalConformanceData = %q, want none", fixtures.Metadata.ExternalConformanceData)
	}

	for _, fixture := range fixtures.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()

			registrationResult := verifyBrowserFixtureRegistration(t, fixture)
			authenticationResult := verifyBrowserFixtureAuthentication(t, fixture, registrationResult.Credential)
			if !bytes.Equal(authenticationResult.AuthenticatedAs.Bytes(), registrationResult.Credential.UserHandle.Bytes()) {
				t.Fatalf("AuthenticatedAs = %x, want %x", authenticationResult.AuthenticatedAs.Bytes(), registrationResult.Credential.UserHandle.Bytes())
			}

			options := browserFixtureAuthenticationOptions(t, fixture, registrationResult.Credential)
			signatureBytes := options.Response.Signature.Bytes()
			signatureBytes[len(signatureBytes)-1] ^= 0x01
			options.Response.Signature = mustSignature(t, signatureBytes)
			_, err := webauthn.FinishAuthentication(context.Background(), options)
			if !errors.Is(err, webauthn.ErrInvalidSignature) {
				t.Fatalf("FinishAuthentication() tampered signature error = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func verifyBrowserFixtureRegistration(t *testing.T, fixture browserFixture) webauthn.RegistrationResult {
	t.Helper()

	challenge := mustChallengeFromBase64URL(t, fixture.Registration.Challenge)
	userHandle := mustUserHandleFromBase64URL(t, fixture.User.ID)
	start, err := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
		RP: protocol.RPEntity{
			ID:   fixture.RPID,
			Name: "WebAuthn Test RP",
		},
		User: protocol.UserEntity{
			ID:          userHandle,
			Name:        fixture.User.Name,
			DisplayName: fixture.User.DisplayName,
		},
		AllowedOrigins: []string{fixture.Origin},
		Challenge:      challenge,
		PubKeyCredParams: []protocol.CredentialParameter{
			{Type: protocol.CredentialTypePublicKey, Algorithm: -7},
		},
		AuthenticatorSelection: &fixture.Registration.AuthenticatorSelection,
		Attestation:            protocol.AttestationNone,
		UserVerification:       fixture.Registration.UserVerification,
	})
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}

	registry, err := attestation.NewRegistry(attnone.New())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	result, err := webauthn.FinishRegistration(context.Background(), webauthn.RegistrationFinishOptions{
		State: start.State,
		Response: webauthn.RegistrationResponse{
			Type:                   fixture.Registration.Type,
			RawID:                  mustRawIDFromBase64URL(t, fixture.Registration.RawID),
			ClientDataJSON:         mustClientDataJSONFromBase64URL(t, fixture.Registration.ClientDataJSON),
			AttestationObject:      mustAttestationObjectFromBase64URL(t, fixture.Registration.AttestationObject),
			Transports:             fixture.Registration.Transports,
			ClientExtensionResults: fixture.Registration.ClientExtensionResults,
		},
		Decoders:            codeccbor.MustNewDecoder(),
		AttestationRegistry: registry,
		AttestationPolicy:   webauthn.RegistrationAttestationPolicy{AllowNone: true},
		ExtensionRegistry:   mustLevel2Registry(t),
	})
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if result.Credential.SignCount == 0 {
		t.Fatalf("registration sign count = 0, want virtual authenticator counter")
	}

	return result
}

func verifyBrowserFixtureAuthentication(t *testing.T, fixture browserFixture, credential webauthn.CredentialRecord) webauthn.AuthenticationResult {
	t.Helper()

	options := browserFixtureAuthenticationOptions(t, fixture, credential)
	result, err := webauthn.FinishAuthentication(context.Background(), options)
	if err != nil {
		t.Fatalf("FinishAuthentication() error = %v", err)
	}
	if result.Counter.Status != webauthn.CounterStatusIncremented {
		t.Fatalf("Counter.Status = %q, want incremented", result.Counter.Status)
	}

	return result
}

func browserFixtureAuthenticationOptions(t *testing.T, fixture browserFixture, credential webauthn.CredentialRecord) webauthn.AuthenticationFinishOptions {
	t.Helper()

	challenge := mustChallengeFromBase64URL(t, fixture.Authentication.Challenge)
	startOptions := webauthn.AuthenticationStartOptions{
		RPID:             fixture.RPID,
		AllowedOrigins:   []string{fixture.Origin},
		Challenge:        challenge,
		UserVerification: fixture.Authentication.UserVerification,
	}
	if fixture.Authentication.AllowCredentials {
		startOptions.ExpectedUserHandle = credential.UserHandle
		startOptions.AllowCredentials = []protocol.CredentialDescriptor{{
			Type:       protocol.CredentialTypePublicKey,
			ID:         credential.ID,
			Transports: fixture.Registration.Transports,
		}}
	}
	start, err := webauthn.StartAuthentication(context.Background(), startOptions)
	if err != nil {
		t.Fatalf("StartAuthentication() error = %v", err)
	}

	return webauthn.AuthenticationFinishOptions{
		State: start.State,
		Response: webauthn.AuthenticationResponse{
			Type:                   fixture.Authentication.Type,
			RawID:                  mustRawIDFromBase64URL(t, fixture.Authentication.RawID),
			ClientDataJSON:         mustClientDataJSONFromBase64URL(t, fixture.Authentication.ClientDataJSON),
			AuthenticatorData:      mustAuthenticatorDataFromBase64URL(t, fixture.Authentication.AuthenticatorData),
			Signature:              mustSignatureFromBase64URL(t, fixture.Authentication.Signature),
			UserHandle:             mustOptionalUserHandleFromBase64URL(t, fixture.Authentication.UserHandle),
			ClientExtensionResults: fixture.Authentication.ClientExtensionResults,
		},
		Credential:        credential,
		SignatureVerifier: browserFixtureSignatureVerifier{publicKey: credential.PublicKey},
		AlgorithmPolicy:   browserFixtureAlgorithmPolicy{},
		ExtensionRegistry: mustLevel2Registry(t),
	}
}

type browserFixtureSignatureVerifier struct {
	publicKey codec.CredentialPublicKey
}

func (v browserFixtureSignatureVerifier) VerifySignature(_ context.Context, input webcrypto.SignatureInput) error {
	material := v.publicKey.PublicKeyMaterial()
	if material.EC2 == nil {
		return errors.New("fixture public key is not EC2")
	}

	curve, hashFactory, err := browserFixtureCurveAndHash(input.Algorithm, material.EC2.Curve)
	if err != nil {
		return err
	}
	x := new(big.Int).SetBytes(material.EC2.X)
	y := new(big.Int).SetBytes(material.EC2.Y)
	publicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if _, err := publicKey.ECDH(); err != nil {
		return fmt.Errorf("fixture public key coordinates are invalid: %w", err)
	}

	hash := hashFactory()
	if _, err := hash.Write(input.Signed); err != nil {
		return err
	}
	digest := hash.Sum(nil)
	if !ecdsa.VerifyASN1(publicKey, digest, input.Signature.Bytes()) {
		return errors.New("fixture signature rejected")
	}

	return nil
}

type browserFixtureAlgorithmPolicy struct{}

func (browserFixtureAlgorithmPolicy) AcceptsAlgorithm(algorithm protocol.COSEAlgorithmIdentifier) bool {
	return algorithm == -7
}

func browserFixtureCurveAndHash(algorithm protocol.COSEAlgorithmIdentifier, curveName string) (elliptic.Curve, func() hash.Hash, error) {
	switch {
	case algorithm == -7 && curveName == codec.EC2CurveP256:
		return elliptic.P256(), sha256.New, nil
	case algorithm == -35 && curveName == codec.EC2CurveP384:
		return elliptic.P384(), sha512.New384, nil
	case algorithm == -36 && curveName == codec.EC2CurveP521:
		return elliptic.P521(), sha512.New, nil
	default:
		return nil, nil, fmt.Errorf("unsupported fixture algorithm %d with curve %s", algorithm, curveName)
	}
}

func readBrowserFixtureFile(t *testing.T) browserFixtureFile {
	t.Helper()

	data, err := os.ReadFile("testdata/browser/virtual-authenticator/fixtures.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var fixtures browserFixtureFile
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(fixtures.Fixtures) == 0 {
		t.Fatalf("fixtures file has no fixtures")
	}

	return fixtures
}

func mustChallengeFromBase64URL(t *testing.T, value string) protocol.Challenge {
	t.Helper()

	challenge, err := protocol.NewChallenge(mustBase64URLBytes(t, value))
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}

	return challenge
}

func mustUserHandleFromBase64URL(t *testing.T, value string) protocol.UserHandle {
	t.Helper()

	userHandle, err := protocol.NewUserHandle(mustBase64URLBytes(t, value))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}

	return userHandle
}

func mustOptionalUserHandleFromBase64URL(t *testing.T, value string) protocol.UserHandle {
	t.Helper()

	if value == "" {
		return protocol.UserHandle{}
	}

	return mustUserHandleFromBase64URL(t, value)
}

func mustRawIDFromBase64URL(t *testing.T, value string) protocol.RawID {
	t.Helper()

	rawID, err := protocol.NewRawID(mustBase64URLBytes(t, value))
	if err != nil {
		t.Fatalf("NewRawID() error = %v", err)
	}

	return rawID
}

func mustClientDataJSONFromBase64URL(t *testing.T, value string) protocol.ClientDataJSON {
	t.Helper()

	clientDataJSON, err := protocol.NewClientDataJSON(mustBase64URLBytes(t, value))
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}

	return clientDataJSON
}

func mustAttestationObjectFromBase64URL(t *testing.T, value string) protocol.AttestationObject {
	t.Helper()

	attestationObject, err := protocol.NewAttestationObject(mustBase64URLBytes(t, value))
	if err != nil {
		t.Fatalf("NewAttestationObject() error = %v", err)
	}

	return attestationObject
}

func mustAuthenticatorDataFromBase64URL(t *testing.T, value string) protocol.AuthenticatorData {
	t.Helper()

	authenticatorData, err := protocol.NewAuthenticatorData(mustBase64URLBytes(t, value))
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}

	return authenticatorData
}

func mustSignatureFromBase64URL(t *testing.T, value string) protocol.Signature {
	t.Helper()

	signature, err := protocol.NewSignature(mustBase64URLBytes(t, value))
	if err != nil {
		t.Fatalf("NewSignature() error = %v", err)
	}

	return signature
}

func mustBase64URLBytes(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", value, err)
	}

	return decoded
}

type browserFixtureFile struct {
	Metadata browserFixtureMetadata `json:"metadata"`
	Fixtures []browserFixture       `json:"fixtures"`
}

type browserFixtureMetadata struct {
	GeneratedAt             string `json:"generatedAt"`
	ExternalConformanceData string `json:"externalConformanceData"`
}

type browserFixture struct {
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	RPID           string         `json:"rpID"`
	Origin         string         `json:"origin"`
	Flow           string         `json:"flow"`
	Authenticator  map[string]any `json:"authenticator"`
	User           browserUser    `json:"user"`
	Registration   browserRegistration
	Authentication browserAuthentication
}

type browserUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type browserRegistration struct {
	Challenge              string                                  `json:"challenge"`
	UserVerification       protocol.UserVerificationRequirement    `json:"userVerification"`
	AuthenticatorSelection protocol.AuthenticatorSelectionCriteria `json:"authenticatorSelection"`
	Type                   protocol.PublicKeyCredentialType        `json:"type"`
	RawID                  string                                  `json:"rawID"`
	ClientDataJSON         string                                  `json:"clientDataJSON"`
	AttestationObject      string                                  `json:"attestationObject"`
	Transports             []protocol.AuthenticatorTransport       `json:"transports"`
	ClientExtensionResults map[string]any                          `json:"clientExtensionResults"`
}

type browserAuthentication struct {
	Challenge              string                               `json:"challenge"`
	UserVerification       protocol.UserVerificationRequirement `json:"userVerification"`
	AllowCredentials       bool                                 `json:"allowCredentials"`
	Type                   protocol.PublicKeyCredentialType     `json:"type"`
	RawID                  string                               `json:"rawID"`
	ClientDataJSON         string                               `json:"clientDataJSON"`
	AuthenticatorData      string                               `json:"authenticatorData"`
	Signature              string                               `json:"signature"`
	UserHandle             string                               `json:"userHandle"`
	ClientExtensionResults map[string]any                       `json:"clientExtensionResults"`
}
