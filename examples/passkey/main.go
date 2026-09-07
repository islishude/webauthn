package main

import (
	"context"
	"errors"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/preset"
	"github.com/islishude/webauthn/protocol"
)

type passkeyStore interface {
	LookupByUserHandleAndCredentialID(protocol.UserHandle, protocol.RawID) (webauthn.CredentialRecord, error)
	UpdateCredential(webauthn.CredentialUpdate) error
}

func newPasskeyRP() (*webauthn.RelyingParty, error) {
	config, err := preset.PasskeyConfig(protocol.RPEntity{ID: "example.com", Name: "Example"}, webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}})
	if err != nil {
		return nil, err
	}
	return webauthn.New(config)
}

func beginPasskeyAuthentication(ctx context.Context, rp *webauthn.RelyingParty) (browser.CredentialRequestOptionsJSON, webauthn.AuthenticationState, error) {
	start, err := rp.StartAuthentication(ctx, webauthn.AuthenticationRequest{})
	if err != nil {
		return browser.CredentialRequestOptionsJSON{}, webauthn.AuthenticationState{}, err
	}

	return browser.CredentialRequestOptionsFromProtocol(start.Options), start.State, nil
}

// The caller atomically consumes state before calling this function. UpdateCredential
// must compare all four previous fields and report conflicts before session creation.
func finishPasskeyAuthentication(ctx context.Context, store passkeyStore, rp *webauthn.RelyingParty, state webauthn.AuthenticationState, body []byte) (webauthn.AuthenticationResult, error) {
	response, err := browser.AuthenticationResponseFromJSON(body)
	if err != nil {
		return webauthn.AuthenticationResult{}, err
	}
	if response.UserHandle.Len() == 0 {
		return webauthn.AuthenticationResult{}, errors.New("discoverable credential response did not include a user handle")
	}

	credential, err := store.LookupByUserHandleAndCredentialID(response.UserHandle, response.RawID)
	if err != nil {
		return webauthn.AuthenticationResult{}, err
	}
	result, err := rp.FinishAuthentication(ctx, webauthn.AuthenticationVerification{
		State:      state,
		Response:   response,
		Credential: credential,
	})
	if err != nil {
		return webauthn.AuthenticationResult{}, err
	}
	if err := store.UpdateCredential(result.Update); err != nil {
		return webauthn.AuthenticationResult{}, err
	}

	return result, nil
}

func main() {
	_ = newPasskeyRP
	_ = beginPasskeyAuthentication
	_ = finishPasskeyAuthentication
}
