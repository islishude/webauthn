package consumer_test

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/preset"
	"github.com/islishude/webauthn/protocol"
	storagejson "github.com/islishude/webauthn/storage/json"
)

func TestPublicConsumer(t *testing.T) {
	ctx := context.Background()
	config, err := preset.PasskeyConfig(protocol.RPEntity{ID: "example.com", Name: "Consumer"}, webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	rp, err := webauthn.New(config)
	if err != nil {
		t.Fatal(err)
	}
	user, err := protocol.NewUserHandle([]byte("opaque-account"))
	if err != nil {
		t.Fatal(err)
	}
	registration, err := rp.StartRegistration(ctx, webauthn.RegistrationRequest{User: protocol.UserEntity{ID: user, Name: "account"}})
	if err != nil {
		t.Fatal(err)
	}
	if browser.CredentialCreationOptionsFromProtocol(registration.Options).Challenge == "" {
		t.Fatal("missing challenge")
	}
	raw, err := storagejson.MarshalRegistrationState(registration.State)
	if err != nil {
		t.Fatal(err)
	}
	regState, err := storagejson.UnmarshalRegistrationState(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rp.FinishRegistration(ctx, webauthn.RegistrationVerification{State: regState})
	if !errors.Is(err, webauthn.ErrMalformedResponse) {
		t.Fatal(err)
	}
	authentication, err := rp.StartAuthentication(ctx, webauthn.AuthenticationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if browser.CredentialRequestOptionsFromProtocol(authentication.Options).RPID != "example.com" {
		t.Fatal("wrong RP")
	}
	raw, err = storagejson.MarshalAuthenticationState(authentication.State)
	if err != nil {
		t.Fatal(err)
	}
	authState, err := storagejson.UnmarshalAuthenticationState(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rp.FinishAuthentication(ctx, webauthn.AuthenticationVerification{State: authState})
	if !errors.Is(err, webauthn.ErrUnsupportedAlgorithm) {
		t.Fatal(err)
	}
	// Credential persistence APIs also remain available without an internal import.
	if _, err = storagejson.MarshalCredentialRecord(webauthn.CredentialRecord{}); err == nil {
		t.Fatal("empty credential accepted")
	}
	if _, err = storagejson.UnmarshalCredentialRecord([]byte(`{}`), config.CredentialPublicKeyDecoder); err == nil {
		t.Fatal("empty envelope accepted")
	}
}
