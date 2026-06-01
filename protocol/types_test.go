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
	if !protocol.TransportHybrid.Known() || !protocol.TransportSmartCard.Known() {
		t.Fatalf("Level 3 transports not known")
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

func TestLevel3EnumerationsAndRecommendedParameters(t *testing.T) {
	t.Parallel()

	if !protocol.HintSecurityKey.Known() || !protocol.HintClientDevice.Known() || !protocol.HintHybrid.Known() {
		t.Fatal("Level 3 credential hints are not known")
	}
	if !protocol.ClientCapabilityRelatedOrigins.Known() ||
		!protocol.ClientCapabilitySignalUnknownCredential.Known() ||
		!protocol.ClientCapabilityUserVerifyingPlatformAuthenticator.Known() {
		t.Fatal("Level 3 client capabilities are not known")
	}

	parameters := protocol.RecommendedLevel3CredentialParameters()
	if len(parameters) != 3 {
		t.Fatalf("RecommendedLevel3CredentialParameters() length = %d, want 3", len(parameters))
	}
	if parameters[0].Algorithm != protocol.AlgorithmEdDSA ||
		parameters[1].Algorithm != protocol.AlgorithmES256 ||
		parameters[2].Algorithm != protocol.AlgorithmRS256 {
		t.Fatalf("recommended algorithms = %#v", parameters)
	}
	parameters[0].Algorithm = 0
	if protocol.RecommendedLevel3CredentialParameters()[0].Algorithm != protocol.AlgorithmEdDSA {
		t.Fatal("RecommendedLevel3CredentialParameters() returned aliased slice")
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
