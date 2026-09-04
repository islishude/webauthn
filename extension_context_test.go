package webauthn_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

func TestStartRegistrationValidatesRemoteClientDataChallenge(t *testing.T) {
	t.Parallel()

	challenge := mustProtocolChallenge(t, bytes.Repeat([]byte{0x31}, protocol.RecommendedChallengeLength))
	userHandle, err := protocol.NewUserHandle([]byte("remote-user"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	registry, err := extension.NewRegistry(extension.Register(extension.RemoteClientDataJSONHandler{}))
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	options := webauthn.RegistrationStartOptions{
		RP:           protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:         protocol.UserEntity{ID: userHandle, Name: "remote-user", DisplayName: ""},
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://remote.example"}, AllowRelatedOrigins: true},
		Challenge:    challenge,
		PubKeyCredParams: []protocol.CredentialParameter{
			{Type: protocol.CredentialTypePublicKey, Algorithm: protocol.AlgorithmES256},
		},
		Extensions: protocol.ExtensionInputs{
			extension.IDRemoteClientDataJSON: string(registrationClientData(t, challenge.Bytes(), "https://remote.example", false)),
		},
		ExtensionRegistry: registry,
	}
	if _, err := webauthn.StartRegistration(context.Background(), options); err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}

	options.Extensions[extension.IDRemoteClientDataJSON] = string(registrationClientData(t, bytes.Repeat([]byte{0x32}, protocol.RecommendedChallengeLength), "https://remote.example", false))
	if _, err := webauthn.StartRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("StartRegistration() error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestFinishRegistrationBindsRemoteClientDataBytes(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	registry, err := extension.NewRegistry(extension.Register(extension.RemoteClientDataJSONHandler{}))
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	serialized := string(fixture.response.ClientDataJSON.Bytes())
	fixture.start.State.RequestedExtensions = protocol.ExtensionInputs{extension.IDRemoteClientDataJSON: serialized}
	fixture.start.State.ExtensionBindings = mustExtensionBindings(t, registry, extension.IDRemoteClientDataJSON)
	fixture.response.ClientExtensionResults = map[string]any{extension.IDRemoteClientDataJSON: true}
	options := fixture.finishOptions()
	options.ExtensionRegistry = registry
	if _, err := webauthn.FinishRegistration(context.Background(), options); err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}

	options.Response.ClientExtensionResults = nil
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrExtensionPolicy) {
		t.Fatalf("FinishRegistration() missing remote output error = %v, want ErrExtensionPolicy", err)
	}
	options.Response.ClientExtensionResults = map[string]any{extension.IDRemoteClientDataJSON: true}

	changed := append([]byte{}, serialized[:len(serialized)-1]...)
	changed = append(changed, []byte(`,"future":true}`)...)
	options.Response.ClientDataJSON = mustClientDataJSON(t, changed)
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrExtensionPolicy) {
		t.Fatalf("FinishRegistration() changed remote data error = %v, want ErrExtensionPolicy", err)
	}
}

func TestFinishRegistrationStopsExtensionWorkWhenContextCanceled(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.Response.ClientExtensionResults = map[string]any{"future": true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := webauthn.FinishRegistration(ctx, options); !errors.Is(err, context.Canceled) {
		t.Fatalf("FinishRegistration() error = %v, want context.Canceled", err)
	}
}

func TestStartAuthenticationLargeBlobWriteRequiresOneCredential(t *testing.T) {
	t.Parallel()

	registry, err := extension.NewLevel3Registry()
	if err != nil {
		t.Fatalf("NewLevel3Registry() error = %v", err)
	}
	credentialOne, err := protocol.NewCredentialID([]byte("credential-one"))
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}
	credentialTwo, err := protocol.NewCredentialID([]byte("credential-two"))
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}
	base := webauthn.AuthenticationStartOptions{
		RPID:              "example.com",
		OriginPolicy:      webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		Challenge:         mustProtocolChallenge(t, bytes.Repeat([]byte{0x41}, protocol.RecommendedChallengeLength)),
		ExtensionRegistry: registry,
		Extensions: protocol.ExtensionInputs{
			extension.IDLargeBlob: extension.LargeBlobInput{Write: []byte("blob")},
		},
	}
	for _, descriptors := range [][]protocol.CredentialDescriptor{
		nil,
		{
			{Type: protocol.CredentialTypePublicKey, ID: credentialOne},
			{Type: protocol.CredentialTypePublicKey, ID: credentialTwo},
		},
	} {
		options := base
		options.AllowCredentials = descriptors
		if _, err := webauthn.StartAuthentication(context.Background(), options); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
			t.Fatalf("StartAuthentication(%d credentials) error = %v, want ErrInvalidConfiguration", len(descriptors), err)
		}
	}

	base.AllowCredentials = []protocol.CredentialDescriptor{{Type: protocol.CredentialTypePublicKey, ID: credentialOne}}
	if _, err := webauthn.StartAuthentication(context.Background(), base); err != nil {
		t.Fatalf("StartAuthentication(one credential) error = %v", err)
	}
}

func TestFinishAuthenticationRevalidatesLargeBlobCredentialContext(t *testing.T) {
	t.Parallel()

	registry, err := extension.NewLevel3Registry()
	if err != nil {
		t.Fatalf("NewLevel3Registry() error = %v", err)
	}
	for _, descriptors := range [][]protocol.CredentialDescriptor{
		nil,
		{
			{Type: protocol.CredentialTypePublicKey, ID: mustCredentialID(t, []byte("credential-one"))},
			{Type: protocol.CredentialTypePublicKey, ID: mustCredentialID(t, []byte("credential-two"))},
		},
	} {
		fixture := newAuthenticationFixture(t, true)
		options := fixture.finishOptions()
		options.State.AllowCredentials = descriptors
		options.State.RequestedExtensions = protocol.ExtensionInputs{
			extension.IDLargeBlob: extension.LargeBlobInput{Write: []byte("blob")},
		}
		options.ExtensionRegistry = registry
		options.State.ExtensionBindings = mustExtensionBindings(t, registry, extension.IDLargeBlob)
		if _, err := webauthn.FinishAuthentication(context.Background(), options); !errors.Is(err, webauthn.ErrInvalidCeremonyState) {
			t.Fatalf("FinishAuthentication(%d credentials) error = %v, want ErrInvalidCeremonyState", len(descriptors), err)
		}
	}
}

func mustProtocolChallenge(t *testing.T, value []byte) protocol.Challenge {
	t.Helper()
	challenge, err := protocol.NewChallenge(value)
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}
	return challenge
}
