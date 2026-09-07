package consumer_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/preset"
	"github.com/islishude/webauthn/protocol"
	storagejson "github.com/islishude/webauthn/storage/json"
)

// Reuse only this project's committed, independently collected browser output;
// metadata in the fixture records browser version, generator and provenance.
func TestPublicBrowserFixtureLifecycle(t *testing.T) {
	data, err := os.ReadFile("../../testdata/browser/virtual-authenticator/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	type response struct{ Challenge, RawID, ClientDataJSON, AttestationObject, AuthenticatorData, Signature, UserHandle string }
	var document struct {
		Fixtures []struct {
			Name, RPID, Origin           string
			User                         struct{ ID, Name string }
			Registration, Authentication response
		}
	}
	if err = json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range document.Fixtures {
		if fixture.Name != "platform-discoverable-uv-required" {
			continue
		}
		decode := func(value string) []byte {
			t.Helper()
			raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		user, err := protocol.NewUserHandle(decode(fixture.User.ID))
		if err != nil {
			t.Fatal(err)
		}
		challenge, err := protocol.NewChallenge(decode(fixture.Registration.Challenge))
		if err != nil {
			t.Fatal(err)
		}
		config, err := preset.PasskeyConfig(protocol.RPEntity{ID: fixture.RPID, Name: "Consumer"}, webauthn.OriginPolicy{AllowedOrigins: []string{fixture.Origin}})
		if err != nil {
			t.Fatal(err)
		}
		config.ChallengeGenerator = webauthn.ChallengeGeneratorFunc(func(context.Context) (protocol.Challenge, error) { return challenge, nil })
		rp, err := webauthn.New(config)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		start, err := rp.StartRegistration(ctx, webauthn.RegistrationRequest{User: protocol.UserEntity{ID: user, Name: fixture.User.Name}})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := storagejson.MarshalRegistrationState(start.State)
		if err != nil {
			t.Fatal(err)
		}
		state, err := storagejson.UnmarshalRegistrationState(raw)
		if err != nil {
			t.Fatal(err)
		}
		id, err := protocol.NewRawID(decode(fixture.Registration.RawID))
		if err != nil {
			t.Fatal(err)
		}
		client, err := protocol.NewClientDataJSON(decode(fixture.Registration.ClientDataJSON))
		if err != nil {
			t.Fatal(err)
		}
		object, err := protocol.NewAttestationObject(decode(fixture.Registration.AttestationObject))
		if err != nil {
			t.Fatal(err)
		}
		registration, err := rp.FinishRegistration(ctx, webauthn.RegistrationVerification{State: state, Response: webauthn.RegistrationResponse{Type: protocol.CredentialTypePublicKey, RawID: id, ClientDataJSON: client, AttestationObject: object}})
		if err != nil {
			t.Fatal(err)
		}
		raw, err = storagejson.MarshalCredentialRecord(registration.Credential)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := storagejson.UnmarshalCredentialRecord(raw, config.CredentialPublicKeyDecoder)
		if err != nil {
			t.Fatal(err)
		}
		challenge, err = protocol.NewChallenge(decode(fixture.Authentication.Challenge))
		if err != nil {
			t.Fatal(err)
		}
		auth, err := rp.StartAuthentication(ctx, webauthn.AuthenticationRequest{})
		if err != nil {
			t.Fatal(err)
		}
		raw, err = storagejson.MarshalAuthenticationState(auth.State)
		if err != nil {
			t.Fatal(err)
		}
		authState, err := storagejson.UnmarshalAuthenticationState(raw)
		if err != nil {
			t.Fatal(err)
		}
		id, err = protocol.NewRawID(decode(fixture.Authentication.RawID))
		if err != nil {
			t.Fatal(err)
		}
		client, err = protocol.NewClientDataJSON(decode(fixture.Authentication.ClientDataJSON))
		if err != nil {
			t.Fatal(err)
		}
		authData, err := protocol.NewAuthenticatorData(decode(fixture.Authentication.AuthenticatorData))
		if err != nil {
			t.Fatal(err)
		}
		signature, err := protocol.NewSignature(decode(fixture.Authentication.Signature))
		if err != nil {
			t.Fatal(err)
		}
		result, err := rp.FinishAuthentication(ctx, webauthn.AuthenticationVerification{State: authState, Credential: credential, Response: webauthn.AuthenticationResponse{Type: protocol.CredentialTypePublicKey, RawID: id, ClientDataJSON: client, AuthenticatorData: authData, Signature: signature, UserHandle: user}})
		if err != nil {
			t.Fatal(err)
		}
		if !result.AuthenticatedAs.Equal(user) || !result.UserVerified || !result.Update.SignCountChanged {
			t.Fatal("incomplete verified result")
		}
		return
	}
	t.Fatal("required browser fixture missing")
}
