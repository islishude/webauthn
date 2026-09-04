package main

import (
	"context"
	"errors"
	"sync"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	"github.com/islishude/webauthn/browser"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/crypto/standard"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

type server struct {
	mu                   sync.Mutex
	registrationStates   map[string]webauthn.RegistrationState
	authenticationStates map[string]webauthn.AuthenticationState
	credentials          map[string]webauthn.CredentialRecord
	attestations         *attestation.Registry
	extensions           *extension.Registry
	signatures           *standard.Verifier
	decoder              *codeccbor.Decoder
}

func newServer() (*server, error) {
	attestations, err := attestation.NewRegistry(attnone.New())
	if err != nil {
		return nil, err
	}
	signatures, err := standard.NewVerifier(protocol.AlgorithmEdDSA, protocol.AlgorithmES256, protocol.AlgorithmRS256)
	if err != nil {
		return nil, err
	}
	extensions, err := extension.NewLevel3RegistryWithDeprecated()
	if err != nil {
		return nil, err
	}
	decoder, err := codeccbor.NewDecoder()
	if err != nil {
		return nil, err
	}

	return &server{
		registrationStates:   make(map[string]webauthn.RegistrationState),
		authenticationStates: make(map[string]webauthn.AuthenticationState),
		credentials:          make(map[string]webauthn.CredentialRecord),
		attestations:         attestations,
		extensions:           extensions,
		signatures:           signatures,
		decoder:              decoder,
	}, nil
}

func (s *server) beginRegistration(ctx context.Context, sessionID string, user protocol.UserEntity) (browser.CredentialCreationOptionsJSON, error) {
	start, err := webauthn.StartRegistration(ctx, webauthn.RegistrationStartOptions{
		RP:                protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:              user,
		OriginPolicy:      webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		PubKeyCredParams:  protocol.RecommendedLevel3CredentialParameters(),
		Attestation:       protocol.AttestationNone,
		Extensions:        protocol.ExtensionInputs{extension.IDCredProps: true},
		ExtensionRegistry: s.extensions,
	})
	if err != nil {
		return browser.CredentialCreationOptionsJSON{}, err
	}

	s.mu.Lock()
	s.registrationStates[sessionID] = start.State
	s.mu.Unlock()
	return browser.CredentialCreationOptionsFromProtocol(start.Options), nil
}

func (s *server) finishRegistration(ctx context.Context, sessionID string, body []byte) (webauthn.CredentialRecord, error) {
	s.mu.Lock()
	state, ok := s.registrationStates[sessionID]
	delete(s.registrationStates, sessionID)
	s.mu.Unlock()
	if !ok {
		return webauthn.CredentialRecord{}, errors.New("registration state not found")
	}
	response, err := browser.RegistrationResponseFromJSON(body)
	if err != nil {
		return webauthn.CredentialRecord{}, err
	}

	result, err := webauthn.FinishRegistration(ctx, webauthn.RegistrationFinishOptions{
		State:                      state,
		Response:                   response,
		AttestationObjectDecoder:   s.decoder,
		CredentialPublicKeyDecoder: s.decoder,
		ExtensionMapDecoder:        s.decoder,
		AttestationRegistry:        s.attestations,
		AttestationTrustPolicy:     attestation.AcceptNone(),
		ExtensionRegistry:          s.extensions,
	})
	if err != nil {
		return webauthn.CredentialRecord{}, err
	}

	key := string(result.Credential.ID.Bytes())
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.credentials[key]; exists {
		return webauthn.CredentialRecord{}, errors.New("credential already registered")
	}
	s.credentials[key] = result.Credential.Clone()
	return result.Credential, nil
}

func (s *server) beginAuthentication(ctx context.Context, sessionID string, credential webauthn.CredentialRecord) (browser.CredentialRequestOptionsJSON, error) {
	start, err := webauthn.StartAuthentication(ctx, webauthn.AuthenticationStartOptions{
		RPID:         credential.RPID,
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
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

	s.mu.Lock()
	s.authenticationStates[sessionID] = start.State
	s.mu.Unlock()
	return browser.CredentialRequestOptionsFromProtocol(start.Options), nil
}

func (s *server) finishAuthentication(ctx context.Context, sessionID string, body []byte) (webauthn.AuthenticationResult, error) {
	s.mu.Lock()
	state, ok := s.authenticationStates[sessionID]
	delete(s.authenticationStates, sessionID)
	s.mu.Unlock()
	if !ok {
		return webauthn.AuthenticationResult{}, errors.New("authentication state not found")
	}
	response, err := browser.AuthenticationResponseFromJSON(body)
	if err != nil {
		return webauthn.AuthenticationResult{}, err
	}
	s.mu.Lock()
	credential, ok := s.credentials[string(response.RawID.Bytes())]
	credential = credential.Clone()
	s.mu.Unlock()
	if !ok {
		return webauthn.AuthenticationResult{}, errors.New("credential not found")
	}

	result, err := webauthn.FinishAuthentication(ctx, webauthn.AuthenticationFinishOptions{
		State:             state,
		Response:          response,
		Credential:        credential,
		SignatureVerifier: s.signatures,
		AlgorithmPolicy:   s.signatures,
		ExtensionRegistry: s.extensions,
	})
	if err != nil {
		return webauthn.AuthenticationResult{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.credentials[string(result.Update.ID.Bytes())]
	if !ok || current.SignCount != result.Update.PreviousSignCount ||
		current.BackupState != result.Update.PreviousBackupState ||
		current.UVInitialized != result.Update.PreviousUVInitialized ||
		current.AuthenticatorAttachment != result.Update.PreviousAuthenticatorAttachment {
		return webauthn.AuthenticationResult{}, errors.New("credential changed concurrently")
	}
	if result.Update.SignCountChanged {
		current.SignCount = result.Update.SignCount
	}
	if result.Update.BackupStateChanged {
		current.BackupState = result.Update.BackupState
	}
	if result.Update.UVInitializedChanged {
		current.UVInitialized = result.Update.UVInitialized
	}
	if result.Update.AuthenticatorAttachmentChanged {
		current.AuthenticatorAttachment = result.Update.AuthenticatorAttachment
	}
	s.credentials[string(result.Update.ID.Bytes())] = current
	return result, nil
}

func main() {
	_ = newServer
	_ = (*server).beginRegistration
	_ = (*server).finishRegistration
	_ = (*server).beginAuthentication
	_ = (*server).finishAuthentication
}
