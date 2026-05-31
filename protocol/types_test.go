package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/webauthn/protocol"
)

func TestDOMStringValuesPreserveUnknownsUntilValidation(t *testing.T) {
	t.Parallel()

	transport := protocol.AuthenticatorTransport("future-transport")
	if transport.Known() {
		t.Fatal("unknown transport Known() = true")
	}

	credentialType := protocol.PublicKeyCredentialType("future-type")
	if credentialType.Known() {
		t.Fatal("unknown credential type Known() = true")
	}

	err := credentialType.Validate()
	if !errors.Is(err, protocol.ErrUnsupportedValue) {
		t.Fatalf("Validate() error = %v, want ErrUnsupportedValue", err)
	}
}

func TestCreationOptionsValidateRequiredFields(t *testing.T) {
	t.Parallel()

	challenge, err := protocol.NewChallenge(bytes.Repeat([]byte{0x01}, protocol.RecommendedChallengeLength))
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}
	userHandle, err := protocol.NewUserHandle([]byte("user-1"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}

	options := protocol.PublicKeyCredentialCreationOptions{
		RP: protocol.RPEntity{
			ID:   "example.com",
			Name: "Example",
		},
		User: protocol.UserEntity{
			ID:          userHandle,
			Name:        "user@example.com",
			DisplayName: "Example User",
		},
		Challenge: challenge,
		PubKeyCredParams: []protocol.CredentialParameter{
			{
				Type:      protocol.CredentialTypePublicKey,
				Algorithm: protocol.COSEAlgorithmIdentifier(-7),
			},
		},
	}

	if err := options.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	options.PubKeyCredParams[0].Type = protocol.PublicKeyCredentialType("future-type")
	err = options.Validate()
	if !errors.Is(err, protocol.ErrUnsupportedValue) {
		t.Fatalf("Validate() error = %v, want ErrUnsupportedValue", err)
	}
}

func TestRequestOptionsAllowDiscoverableCredentials(t *testing.T) {
	t.Parallel()

	challenge, err := protocol.NewChallenge(bytes.Repeat([]byte{0x02}, protocol.RecommendedChallengeLength))
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}

	options := protocol.PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		RPID:             "example.com",
		AllowCredentials: nil,
		UserVerification: protocol.UserVerificationPreferred,
	}

	if err := options.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestCollectedClientDataValidateType(t *testing.T) {
	t.Parallel()

	clientData, err := protocol.NewClientDataJSON([]byte(`{"type":"webauthn.create"}`))
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}

	data := protocol.CollectedClientData{
		Type:      protocol.ClientDataTypeCreate,
		Challenge: "challenge",
		Origin:    "https://example.com",
		Raw:       clientData,
	}

	if err := data.ValidateType(protocol.ClientDataTypeCreate); err != nil {
		t.Fatalf("ValidateType() error = %v", err)
	}

	err = data.ValidateType(protocol.ClientDataTypeGet)
	if !errors.Is(err, protocol.ErrUnsupportedValue) {
		t.Fatalf("ValidateType() error = %v, want ErrUnsupportedValue", err)
	}
}
