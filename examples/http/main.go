package main

import (
	"errors"
	"net/http"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
	webauthnhttp "github.com/islishude/webauthn/transport/http"
)

type handler struct {
	state      webauthn.RegistrationState
	authState  webauthn.AuthenticationState
	records    map[string]webauthn.CredentialRecord
	verifiers  *attestation.Registry
	extensions *extension.Registry
	signatures webcrypto.SignatureVerifier
}

func newHandler(signatureVerifier webcrypto.SignatureVerifier) (*handler, error) {
	verifiers, err := attestation.NewRegistry(attnone.New())
	if err != nil {
		return nil, err
	}
	extensions, err := extension.NewLevel3RegistryWithDeprecated()
	if err != nil {
		return nil, err
	}

	return &handler{
		records:    make(map[string]webauthn.CredentialRecord),
		verifiers:  verifiers,
		extensions: extensions,
		signatures: signatureVerifier,
	}, nil
}

func (h *handler) beginRegistration(response http.ResponseWriter, request *http.Request) {
	userHandle, err := protocol.NewUserHandle([]byte("demo-user"))
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusInternalServerError, err)
		return
	}

	start, err := webauthn.StartRegistration(request.Context(), webauthn.RegistrationStartOptions{
		RP:               protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:             protocol.UserEntity{ID: userHandle, Name: "demo@example.com", DisplayName: "Demo User"},
		OriginPolicy:     webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		PubKeyCredParams: protocol.RecommendedLevel3CredentialParameters(),
		Attestation:      protocol.AttestationNone,
	})
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusBadRequest, err)
		return
	}

	h.state = start.State
	_ = webauthnhttp.WriteCreationOptions(response, start.Options)
}

func (h *handler) finishRegistration(response http.ResponseWriter, request *http.Request) {
	credentialResponse, err := webauthnhttp.ReadRegistrationResponse(request, 0)
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusBadRequest, err)
		return
	}

	decoder := codeccbor.MustNewDecoder()
	result, err := webauthn.FinishRegistration(request.Context(), webauthn.RegistrationFinishOptions{
		State:                      h.state,
		Response:                   credentialResponse,
		AttestationObjectDecoder:   decoder,
		CredentialPublicKeyDecoder: decoder,
		ExtensionMapDecoder:        decoder,
		AttestationRegistry:        h.verifiers,
		AttestationTrustPolicy:     attestation.AcceptNone(),
		ExtensionRegistry:          h.extensions,
	})
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusBadRequest, err)
		return
	}

	h.records[string(result.Credential.ID.Bytes())] = result.Credential
	_ = webauthnhttp.WriteJSON(response, http.StatusCreated, map[string]string{"status": "registered"})
}

func (h *handler) beginAuthentication(response http.ResponseWriter, request *http.Request) {
	credential, ok := h.firstCredential()
	if !ok {
		_ = webauthnhttp.WriteError(response, http.StatusUnauthorized, errors.New("credential not found"))
		return
	}

	start, err := webauthn.StartAuthentication(request.Context(), webauthn.AuthenticationStartOptions{
		RPID:         credential.RPID,
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		AllowCredentials: []protocol.CredentialDescriptor{{
			Type:       protocol.CredentialTypePublicKey,
			ID:         credential.ID,
			Transports: credential.Transports,
		}},
		ExpectedUserHandle: credential.UserHandle,
		UserVerification:   protocol.UserVerificationPreferred,
	})
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusBadRequest, err)
		return
	}

	h.authState = start.State
	_ = webauthnhttp.WriteRequestOptions(response, start.Options)
}

func (h *handler) finishAuthentication(response http.ResponseWriter, request *http.Request) {
	assertion, err := webauthnhttp.ReadAuthenticationResponse(request, 0)
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusBadRequest, err)
		return
	}
	credential, ok := h.records[string(assertion.RawID.Bytes())]
	if !ok {
		_ = webauthnhttp.WriteError(response, http.StatusUnauthorized, errors.New("credential not found"))
		return
	}

	_, err = webauthn.FinishAuthentication(request.Context(), webauthn.AuthenticationFinishOptions{
		State:             h.authState,
		Response:          assertion,
		Credential:        credential,
		SignatureVerifier: h.signatures,
		ExtensionRegistry: h.extensions,
	})
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusUnauthorized, err)
		return
	}

	_ = webauthnhttp.WriteJSON(response, http.StatusOK, map[string]string{"status": "authenticated"})
}

func (h *handler) firstCredential() (webauthn.CredentialRecord, bool) {
	for _, credential := range h.records {
		return credential, true
	}

	return webauthn.CredentialRecord{}, false
}

func routes(h *handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register/options", h.beginRegistration)
	mux.HandleFunc("POST /register/finish", h.finishRegistration)
	mux.HandleFunc("POST /login/options", h.beginAuthentication)
	mux.HandleFunc("POST /login/finish", h.finishAuthentication)
	return mux
}

func main() {
	_ = newHandler
	_ = routes
	_ = (*handler).beginRegistration
	_ = (*handler).finishRegistration
	_ = (*handler).beginAuthentication
	_ = (*handler).finishAuthentication
	_ = (*handler).firstCredential
}
