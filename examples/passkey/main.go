package main

import (
	"context"
	"errors"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/crypto/standard"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

type passkeyStore interface {
	LookupByUserHandleAndCredentialID(protocol.UserHandle, protocol.RawID) (webauthn.CredentialRecord, error)
	UpdateCredential(webauthn.CredentialUpdate) error
}

func beginPasskeyAuthentication(ctx context.Context, extensions *extension.Registry) (browser.CredentialRequestOptionsJSON, webauthn.AuthenticationState, error) {
	start, err := webauthn.StartAuthentication(ctx, webauthn.AuthenticationStartOptions{
		RPID:              "example.com",
		OriginPolicy:      webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		UserVerification:  protocol.UserVerificationRequired,
		Extensions:        protocol.ExtensionInputs{extension.IDUVM: true},
		ExtensionRegistry: extensions,
	})
	if err != nil {
		return browser.CredentialRequestOptionsJSON{}, webauthn.AuthenticationState{}, err
	}

	return browser.CredentialRequestOptionsFromProtocol(start.Options), start.State, nil
}

func finishPasskeyAuthentication(ctx context.Context, store passkeyStore, verifier *standard.Verifier, extensions *extension.Registry, state webauthn.AuthenticationState, body []byte) (webauthn.AuthenticationResult, error) {
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
	result, err := webauthn.FinishAuthentication(ctx, webauthn.AuthenticationFinishOptions{
		State:             state,
		Response:          response,
		Credential:        credential,
		SignatureVerifier: verifier,
		AlgorithmPolicy:   verifier,
		ExtensionRegistry: extensions,
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
	_ = beginPasskeyAuthentication
	_ = finishPasskeyAuthentication
}
