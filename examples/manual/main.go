package main

import (
	"context"
	"errors"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	"github.com/islishude/webauthn/browser"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

type server struct {
	registrationStates   map[string]webauthn.RegistrationState
	authenticationStates map[string]webauthn.AuthenticationState
	credentials          map[string]webauthn.CredentialRecord
	attestations         *attestation.Registry
	extensions           *extension.Registry
	signatures           webcrypto.SignatureVerifier
}

func newServer(signatureVerifier webcrypto.SignatureVerifier) (*server, error) {
	attestations, err := attestation.NewRegistry(attnone.New())
	if err != nil {
		return nil, err
	}
	extensions, err := extension.NewLevel2Registry()
	if err != nil {
		return nil, err
	}

	return &server{
		registrationStates:   make(map[string]webauthn.RegistrationState),
		authenticationStates: make(map[string]webauthn.AuthenticationState),
		credentials:          make(map[string]webauthn.CredentialRecord),
		attestations:         attestations,
		extensions:           extensions,
		signatures:           signatureVerifier,
	}, nil
}

func (s *server) beginRegistration(ctx context.Context, sessionID string, user protocol.UserEntity) (browser.CredentialCreationOptionsJSON, error) {
	start, err := webauthn.StartRegistration(ctx, webauthn.RegistrationStartOptions{
		RP:             protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:           user,
		AllowedOrigins: []string{"https://example.com"},
		PubKeyCredParams: []protocol.CredentialParameter{
			{Type: protocol.CredentialTypePublicKey, Algorithm: -7},
			{Type: protocol.CredentialTypePublicKey, Algorithm: -257},
		},
		Attestation:      protocol.AttestationNone,
		UserVerification: protocol.UserVerificationPreferred,
		Extensions:       protocol.ExtensionInputs{extension.IDCredProps: true},
	})
	if err != nil {
		return browser.CredentialCreationOptionsJSON{}, err
	}

	s.registrationStates[sessionID] = start.State
	return browser.CredentialCreationOptionsFromProtocol(start.Options), nil
}

func (s *server) finishRegistration(ctx context.Context, sessionID string, body []byte) (webauthn.CredentialRecord, error) {
	state, ok := s.registrationStates[sessionID]
	if !ok {
		return webauthn.CredentialRecord{}, errors.New("registration state not found")
	}
	response, err := browser.RegistrationResponseFromJSON(body)
	if err != nil {
		return webauthn.CredentialRecord{}, err
	}

	result, err := webauthn.FinishRegistration(ctx, webauthn.RegistrationFinishOptions{
		State:               state,
		Response:            response,
		Decoders:            codeccbor.MustNewDecoder(),
		AttestationRegistry: s.attestations,
		AttestationPolicy:   webauthn.RegistrationAttestationPolicy{AllowNone: true},
		ExtensionRegistry:   s.extensions,
	})
	if err != nil {
		return webauthn.CredentialRecord{}, err
	}

	s.credentials[string(result.Credential.ID.Bytes())] = result.Credential
	delete(s.registrationStates, sessionID)
	return result.Credential, nil
}

func (s *server) beginAuthentication(ctx context.Context, sessionID string, credential webauthn.CredentialRecord) (browser.CredentialRequestOptionsJSON, error) {
	start, err := webauthn.StartAuthentication(ctx, webauthn.AuthenticationStartOptions{
		RPID:           credential.RPID,
		AllowedOrigins: []string{"https://example.com"},
		AllowCredentials: []protocol.CredentialDescriptor{{
			Type:       protocol.CredentialTypePublicKey,
			ID:         credential.ID,
			Transports: credential.Transports,
		}},
		UserVerification:   protocol.UserVerificationPreferred,
		ExpectedUserHandle: credential.UserHandle,
	})
	if err != nil {
		return browser.CredentialRequestOptionsJSON{}, err
	}

	s.authenticationStates[sessionID] = start.State
	return browser.CredentialRequestOptionsFromProtocol(start.Options), nil
}

func (s *server) finishAuthentication(ctx context.Context, sessionID string, body []byte) (webauthn.AuthenticationResult, error) {
	state, ok := s.authenticationStates[sessionID]
	if !ok {
		return webauthn.AuthenticationResult{}, errors.New("authentication state not found")
	}
	response, err := browser.AuthenticationResponseFromJSON(body)
	if err != nil {
		return webauthn.AuthenticationResult{}, err
	}
	credential, ok := s.credentials[string(response.RawID.Bytes())]
	if !ok {
		return webauthn.AuthenticationResult{}, errors.New("credential not found")
	}

	result, err := webauthn.FinishAuthentication(ctx, webauthn.AuthenticationFinishOptions{
		State:             state,
		Response:          response,
		Credential:        credential,
		SignatureVerifier: s.signatures,
		ExtensionRegistry: s.extensions,
	})
	if err != nil {
		return webauthn.AuthenticationResult{}, err
	}

	s.credentials[string(result.Update.ID.Bytes())] = result.Credential
	delete(s.authenticationStates, sessionID)
	return result, nil
}

func main() {
	_ = newServer
	_ = (*server).beginRegistration
	_ = (*server).finishRegistration
	_ = (*server).beginAuthentication
	_ = (*server).finishAuthentication
}
