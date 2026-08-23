package webauthn_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	attapple "github.com/islishude/webauthn/attestation/apple"
	attnone "github.com/islishude/webauthn/attestation/none"
	attpacked "github.com/islishude/webauthn/attestation/packed"
	"github.com/islishude/webauthn/codec"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	webcrypto "github.com/islishude/webauthn/crypto"
	cryptostandard "github.com/islishude/webauthn/crypto/standard"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

func TestW3CLevel3AppleES256Vector(t *testing.T) {
	t.Parallel()

	var vector struct {
		RPID              string `json:"rpId"`
		Origin            string `json:"origin"`
		Challenge         string `json:"challenge"`
		CredentialID      string `json:"credentialId"`
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	}
	data, err := os.ReadFile("testdata/w3c/webauthn-level3/apple-es256.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	challenge := mustProtocolChallenge(t, decodeW3CHex(t, vector.Challenge))
	userHandle, err := protocol.NewUserHandle([]byte("w3c-apple-user"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	start, err := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
		RP:           protocol.RPEntity{ID: vector.RPID, Name: "W3C Test RP"},
		User:         protocol.UserEntity{ID: userHandle, Name: "w3c-user", DisplayName: ""},
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{vector.Origin}},
		Challenge:    challenge,
		PubKeyCredParams: []protocol.CredentialParameter{
			{Type: protocol.CredentialTypePublicKey, Algorithm: protocol.AlgorithmES256},
		},
		Attestation: protocol.AttestationDirect,
	})
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}
	rawID, err := protocol.NewRawID(decodeW3CHex(t, vector.CredentialID))
	if err != nil {
		t.Fatalf("NewRawID() error = %v", err)
	}
	clientDataJSON, err := protocol.NewClientDataJSON(decodeW3CHex(t, vector.ClientDataJSON))
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}
	attestationObject, err := protocol.NewAttestationObject(decodeW3CHex(t, vector.AttestationObject))
	if err != nil {
		t.Fatalf("NewAttestationObject() error = %v", err)
	}
	registry, err := attestation.NewRegistry(attapple.New())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	decoder := codeccbor.MustNewDecoder()
	result, err := webauthn.FinishRegistration(context.Background(), webauthn.RegistrationFinishOptions{
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
		AttestationTrustPolicy:     attestation.AllowTypes(attestation.TypeAnonymizationCA),
	})
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if result.Attestation.Type != attestation.TypeAnonymizationCA || result.Credential.PublicKey.Algorithm != protocol.AlgorithmES256 {
		t.Fatalf("result = %+v", result)
	}
}

func TestW3CLevel3ES256RelyingPartyVectors(t *testing.T) {
	t.Parallel()

	var fixture struct {
		RPID      string `json:"rpId"`
		Origin    string `json:"origin"`
		TopOrigin string `json:"topOrigin"`
		Vectors   []struct {
			Name                         string `json:"name"`
			RegistrationChallenge        string `json:"registrationChallenge"`
			CredentialID                 string `json:"credentialId"`
			RegistrationClientDataJSON   string `json:"registrationClientDataJSON"`
			AttestationObject            string `json:"attestationObject"`
			AuthenticationChallenge      string `json:"authenticationChallenge"`
			AuthenticationClientDataJSON string `json:"authenticationClientDataJSON"`
			AuthenticatorData            string `json:"authenticatorData"`
			Signature                    string `json:"signature"`
		} `json:"vectors"`
	}
	data, err := os.ReadFile("testdata/w3c/webauthn-level3/es256-rp-vectors.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			originPolicy := webauthn.OriginPolicy{AllowedOrigins: []string{fixture.Origin}}
			switch vector.Name {
			case "cross-origin":
				originPolicy.AllowCrossOriginWithoutTopOrigin = true
			case "top-origin":
				originPolicy.AllowedTopOrigins = []string{fixture.TopOrigin}
			}
			userHandle, err := protocol.NewUserHandle([]byte("w3c-" + vector.Name))
			if err != nil {
				t.Fatalf("NewUserHandle() error = %v", err)
			}
			start, err := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
				RP:           protocol.RPEntity{ID: fixture.RPID, Name: "W3C Test RP"},
				User:         protocol.UserEntity{ID: userHandle, Name: "w3c-user", DisplayName: ""},
				OriginPolicy: originPolicy,
				Challenge:    mustProtocolChallenge(t, decodeW3CHex(t, vector.RegistrationChallenge)),
				PubKeyCredParams: []protocol.CredentialParameter{
					{Type: protocol.CredentialTypePublicKey, Algorithm: protocol.AlgorithmES256},
				},
				Attestation: protocol.AttestationNone,
			})
			if err != nil {
				t.Fatalf("StartRegistration() error = %v", err)
			}
			rawID, err := protocol.NewRawID(decodeW3CHex(t, vector.CredentialID))
			if err != nil {
				t.Fatalf("NewRawID() error = %v", err)
			}
			registrationClientData, err := protocol.NewClientDataJSON(decodeW3CHex(t, vector.RegistrationClientDataJSON))
			if err != nil {
				t.Fatalf("NewClientDataJSON() error = %v", err)
			}
			attestationObject, err := protocol.NewAttestationObject(decodeW3CHex(t, vector.AttestationObject))
			if err != nil {
				t.Fatalf("NewAttestationObject() error = %v", err)
			}
			registry, err := attestation.NewRegistry(attnone.New())
			if err != nil {
				t.Fatalf("NewRegistry() error = %v", err)
			}
			decoder := codeccbor.MustNewDecoder()
			registration, err := webauthn.FinishRegistration(context.Background(), webauthn.RegistrationFinishOptions{
				State: start.State,
				Response: webauthn.RegistrationResponse{
					Type:              protocol.CredentialTypePublicKey,
					RawID:             rawID,
					ClientDataJSON:    registrationClientData,
					AttestationObject: attestationObject,
				},
				AttestationObjectDecoder:   decoder,
				CredentialPublicKeyDecoder: decoder,
				ExtensionMapDecoder:        decoder,
				AttestationRegistry:        registry,
				AttestationTrustPolicy:     attestation.AcceptNone(),
			})
			if err != nil {
				t.Fatalf("FinishRegistration() error = %v", err)
			}
			if vector.Name == "max-credential-id" && registration.Credential.ID.Len() != protocol.MaxCredentialIDLength {
				t.Fatalf("credential ID length = %d, want %d", registration.Credential.ID.Len(), protocol.MaxCredentialIDLength)
			}

			authenticationStart, err := webauthn.StartAuthentication(context.Background(), webauthn.AuthenticationStartOptions{
				RPID:               fixture.RPID,
				OriginPolicy:       originPolicy,
				Challenge:          mustProtocolChallenge(t, decodeW3CHex(t, vector.AuthenticationChallenge)),
				AllowCredentials:   []protocol.CredentialDescriptor{{Type: protocol.CredentialTypePublicKey, ID: registration.Credential.ID}},
				ExpectedUserHandle: registration.Credential.UserHandle,
			})
			if err != nil {
				t.Fatalf("StartAuthentication() error = %v", err)
			}
			authenticationClientData, err := protocol.NewClientDataJSON(decodeW3CHex(t, vector.AuthenticationClientDataJSON))
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
			signatureVerifier, err := cryptostandard.NewVerifier(protocol.AlgorithmES256)
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			if _, err := webauthn.FinishAuthentication(context.Background(), webauthn.AuthenticationFinishOptions{
				State: authenticationStart.State,
				Response: webauthn.AuthenticationResponse{
					Type:              protocol.CredentialTypePublicKey,
					RawID:             rawID,
					ClientDataJSON:    authenticationClientData,
					AuthenticatorData: authenticatorData,
					Signature:         signature,
				},
				Credential:          registration.Credential,
				SignatureVerifier:   signatureVerifier,
				AlgorithmPolicy:     signatureVerifier,
				ExtensionMapDecoder: decoder,
			}); err != nil {
				t.Fatalf("FinishAuthentication() error = %v", err)
			}
		})
	}
}

func TestW3CLevel3PackedEd448Vector(t *testing.T) {
	t.Parallel()

	var vector struct {
		RPID                         string `json:"rpId"`
		Origin                       string `json:"origin"`
		RegistrationChallenge        string `json:"registrationChallenge"`
		CredentialID                 string `json:"credentialId"`
		RegistrationClientDataJSON   string `json:"registrationClientDataJSON"`
		AttestationObject            string `json:"attestationObject"`
		AuthenticationChallenge      string `json:"authenticationChallenge"`
		AuthenticationClientDataJSON string `json:"authenticationClientDataJSON"`
		AuthenticatorData            string `json:"authenticatorData"`
		Signature                    string `json:"signature"`
	}
	data, err := os.ReadFile("testdata/w3c/webauthn-level3/packed-ed448.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	userHandle, err := protocol.NewUserHandle([]byte("w3c-ed448-user"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	start, err := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
		RP:           protocol.RPEntity{ID: vector.RPID, Name: "W3C Test RP"},
		User:         protocol.UserEntity{ID: userHandle, Name: "w3c-user", DisplayName: ""},
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{vector.Origin}},
		Challenge:    mustProtocolChallenge(t, decodeW3CHex(t, vector.RegistrationChallenge)),
		PubKeyCredParams: []protocol.CredentialParameter{
			{Type: protocol.CredentialTypePublicKey, Algorithm: protocol.AlgorithmEd448},
		},
		Attestation: protocol.AttestationDirect,
	})
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}
	attestationSignatureVerifier, err := cryptostandard.NewVerifier(protocol.AlgorithmES256)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	registry, err := attestation.NewRegistry(attpacked.New(attestationSignatureVerifier))
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	decoder := codeccbor.MustNewDecoder()
	rawID, err := protocol.NewRawID(decodeW3CHex(t, vector.CredentialID))
	if err != nil {
		t.Fatalf("NewRawID() error = %v", err)
	}
	registrationClientData, err := protocol.NewClientDataJSON(decodeW3CHex(t, vector.RegistrationClientDataJSON))
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}
	attestationObject, err := protocol.NewAttestationObject(decodeW3CHex(t, vector.AttestationObject))
	if err != nil {
		t.Fatalf("NewAttestationObject() error = %v", err)
	}
	registration, err := webauthn.FinishRegistration(context.Background(), webauthn.RegistrationFinishOptions{
		State: start.State,
		Response: webauthn.RegistrationResponse{
			Type:              protocol.CredentialTypePublicKey,
			RawID:             rawID,
			ClientDataJSON:    registrationClientData,
			AttestationObject: attestationObject,
		},
		AttestationObjectDecoder:   decoder,
		CredentialPublicKeyDecoder: decoder,
		ExtensionMapDecoder:        decoder,
		AttestationRegistry:        registry,
		AttestationTrustPolicy:     attestation.AllowTypes(attestation.TypeUncertain),
	})
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if registration.Credential.PublicKey.Algorithm != protocol.AlgorithmEd448 || registration.Credential.PublicKey.PublicKeyMaterial().OKP == nil || registration.Credential.PublicKey.PublicKeyMaterial().OKP.Curve != codec.OKPCurveEd448 {
		t.Fatalf("credential public key = %+v", registration.Credential.PublicKey.PublicKeyMaterial())
	}

	authenticationStart, err := webauthn.StartAuthentication(context.Background(), webauthn.AuthenticationStartOptions{
		RPID:               vector.RPID,
		OriginPolicy:       webauthn.OriginPolicy{AllowedOrigins: []string{vector.Origin}},
		Challenge:          mustProtocolChallenge(t, decodeW3CHex(t, vector.AuthenticationChallenge)),
		AllowCredentials:   []protocol.CredentialDescriptor{{Type: protocol.CredentialTypePublicKey, ID: registration.Credential.ID}},
		ExpectedUserHandle: registration.Credential.UserHandle,
	})
	if err != nil {
		t.Fatalf("StartAuthentication() error = %v", err)
	}
	authenticationClientData, err := protocol.NewClientDataJSON(decodeW3CHex(t, vector.AuthenticationClientDataJSON))
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
	clientDataHash := sha256.Sum256(authenticationClientData.Bytes())
	wantSigned := authenticatorData.AppendTo(make([]byte, 0, authenticatorData.Len()+len(clientDataHash)))
	wantSigned = append(wantSigned, clientDataHash[:]...)
	authentication, err := webauthn.FinishAuthentication(context.Background(), webauthn.AuthenticationFinishOptions{
		State: authenticationStart.State,
		Response: webauthn.AuthenticationResponse{
			Type:              protocol.CredentialTypePublicKey,
			RawID:             rawID,
			ClientDataJSON:    authenticationClientData,
			AuthenticatorData: authenticatorData,
			Signature:         signature,
		},
		Credential:          registration.Credential,
		SignatureVerifier:   ed448VectorVerifier{t: t, wantSigned: wantSigned, wantSignature: signature.Bytes()},
		ExtensionMapDecoder: decoder,
	})
	if err != nil {
		t.Fatalf("FinishAuthentication() error = %v", err)
	}
	if !authentication.AuthenticatedAs.Equal(registration.Credential.UserHandle) {
		t.Fatal("AuthenticatedAs does not match registered user")
	}
}

func TestW3CLevel3PRFVector(t *testing.T) {
	t.Parallel()

	var vector struct {
		CredentialID string `json:"credentialId"`
		Input        string `json:"input"`
		Output       string `json:"output"`
	}
	data, err := os.ReadFile("testdata/w3c/webauthn-level3/prf.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	input := decodeW3CHex(t, vector.Input)
	output := decodeW3CHex(t, vector.Output)
	handler := extension.PRFHandler{}
	request := extension.OutputRequest{
		Operation: extension.OperationAuthentication,
		ID:        extension.IDPRF,
		Requested: true,
		ClientInput: extension.PRFInput{
			EvalByCredential: map[string]extension.PRFValues{
				vector.CredentialID: {First: input, Second: input},
			},
			AllowCredentials: []string{vector.CredentialID},
		},
		ClientOutput: map[string]any{
			"results": map[string]any{"first": output, "second": output},
		},
	}
	if _, err := handler.VerifyOutput(context.Background(), request); err != nil {
		t.Fatalf("VerifyOutput() error = %v", err)
	}
	request.ClientOutput = map[string]any{
		"results": map[string]any{"first": output, "second": bytes.Repeat([]byte{0xff}, 32)},
	}
	if _, err := handler.VerifyOutput(context.Background(), request); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("VerifyOutput() unequal result error = %v, want ErrInvalidRequest", err)
	}
}

type ed448VectorVerifier struct {
	t             *testing.T
	wantSigned    []byte
	wantSignature []byte
}

func (v ed448VectorVerifier) VerifySignature(_ context.Context, input webcrypto.SignatureInput) error {
	v.t.Helper()
	if input.Algorithm != protocol.AlgorithmEd448 || input.PublicKey.OKP == nil || input.PublicKey.OKP.Curve != codec.OKPCurveEd448 || len(input.PublicKey.OKP.X) != 57 {
		v.t.Fatalf("signature input key = %+v algorithm = %d", input.PublicKey, input.Algorithm)
	}
	if !bytes.Equal(input.Signed, v.wantSigned) || !bytes.Equal(input.Signature.Bytes(), v.wantSignature) {
		v.t.Fatal("signature verifier input does not match W3C vector")
	}
	return nil
}

var _ webcrypto.SignatureVerifier = ed448VectorVerifier{}

func decodeW3CHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}
	return decoded
}
