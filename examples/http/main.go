package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/crypto/standard"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
	webauthnhttp "github.com/islishude/webauthn/transport/http"
)

const (
	registrationStateCookie   = "webauthn-registration-state"
	authenticationStateCookie = "webauthn-authentication-state"
)

type handler struct {
	mu sync.Mutex

	registrationStates   map[string]webauthn.RegistrationState
	authenticationStates map[string]webauthn.AuthenticationState
	records              map[string]webauthn.CredentialRecord

	verifiers  *attestation.Registry
	extensions *extension.Registry
	decoder    *codeccbor.Decoder
	signatures *standard.Verifier
	random     io.Reader
	now        func() time.Time
}

func newHandler() (*handler, error) {
	verifiers, err := attestation.NewRegistry(attnone.New())
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
	signatures, err := standard.NewVerifier(
		protocol.AlgorithmEdDSA,
		protocol.AlgorithmES256,
		protocol.AlgorithmRS256,
	)
	if err != nil {
		return nil, err
	}

	return &handler{
		registrationStates:   make(map[string]webauthn.RegistrationState),
		authenticationStates: make(map[string]webauthn.AuthenticationState),
		records:              make(map[string]webauthn.CredentialRecord),
		verifiers:            verifiers,
		extensions:           extensions,
		decoder:              decoder,
		signatures:           signatures,
		random:               rand.Reader,
		now:                  time.Now,
	}, nil
}

func (h *handler) beginRegistration(response http.ResponseWriter, request *http.Request) {
	userHandle, err := protocol.NewUserHandle([]byte("demo-user"))
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusInternalServerError, err)
		return
	}
	start, err := webauthn.StartRegistration(request.Context(), webauthn.RegistrationStartOptions{
		RP:                protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:              protocol.UserEntity{ID: userHandle, Name: "demo@example.com", DisplayName: "Demo User"},
		OriginPolicy:      webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		PubKeyCredParams:  protocol.RecommendedLevel3CredentialParameters(),
		Attestation:       protocol.AttestationNone,
		Extensions:        protocol.ExtensionInputs{extension.IDCredProps: true},
		ExtensionRegistry: h.extensions,
		Now:               h.now,
	})
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusBadRequest, err)
		return
	}
	stateID, err := h.newStateID()
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusInternalServerError, err)
		return
	}
	h.saveRegistrationState(stateID, start.State)
	h.setStateCookie(response, registrationStateCookie, stateID)
	_ = webauthnhttp.WriteCreationOptions(response, start.Options)
}

func (h *handler) finishRegistration(response http.ResponseWriter, request *http.Request) {
	stateID, ok := stateCookie(request, registrationStateCookie)
	if !ok {
		_ = webauthnhttp.WriteError(response, http.StatusUnauthorized, errors.New("registration state not found"))
		return
	}
	state, ok := h.consumeRegistrationState(stateID)
	h.clearStateCookie(response, registrationStateCookie)
	if !ok {
		_ = webauthnhttp.WriteError(response, http.StatusUnauthorized, errors.New("registration state not found"))
		return
	}
	credentialResponse, err := webauthnhttp.ReadRegistrationResponse(request, 0)
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusBadRequest, err)
		return
	}
	result, err := webauthn.FinishRegistration(request.Context(), webauthn.RegistrationFinishOptions{
		State:                      state,
		Response:                   credentialResponse,
		AttestationObjectDecoder:   h.decoder,
		CredentialPublicKeyDecoder: h.decoder,
		ExtensionMapDecoder:        h.decoder,
		AttestationRegistry:        h.verifiers,
		AttestationTrustPolicy:     attestation.AcceptNone(),
		ExtensionRegistry:          h.extensions,
		Now:                        h.now,
	})
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusUnauthorized, err)
		return
	}
	if !h.insertCredential(result.Credential) {
		_ = webauthnhttp.WriteError(response, http.StatusConflict, webauthn.ErrDuplicateCredential)
		return
	}
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
		Now:                h.now,
	})
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusBadRequest, err)
		return
	}
	stateID, err := h.newStateID()
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusInternalServerError, err)
		return
	}
	h.saveAuthenticationState(stateID, start.State)
	h.setStateCookie(response, authenticationStateCookie, stateID)
	_ = webauthnhttp.WriteRequestOptions(response, start.Options)
}

func (h *handler) finishAuthentication(response http.ResponseWriter, request *http.Request) {
	stateID, ok := stateCookie(request, authenticationStateCookie)
	if !ok {
		_ = webauthnhttp.WriteError(response, http.StatusUnauthorized, errors.New("authentication state not found"))
		return
	}
	state, ok := h.consumeAuthenticationState(stateID)
	h.clearStateCookie(response, authenticationStateCookie)
	if !ok {
		_ = webauthnhttp.WriteError(response, http.StatusUnauthorized, errors.New("authentication state not found"))
		return
	}
	assertion, err := webauthnhttp.ReadAuthenticationResponse(request, 0)
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusBadRequest, err)
		return
	}
	credential, ok := h.credentialByRawID(assertion.RawID)
	if !ok {
		_ = webauthnhttp.WriteError(response, http.StatusUnauthorized, errors.New("credential not found"))
		return
	}
	result, err := webauthn.FinishAuthentication(request.Context(), webauthn.AuthenticationFinishOptions{
		State:               state,
		Response:            assertion,
		Credential:          credential,
		SignatureVerifier:   h.signatures,
		AlgorithmPolicy:     h.signatures,
		ExtensionMapDecoder: h.decoder,
		ExtensionRegistry:   h.extensions,
		Now:                 h.now,
	})
	if err != nil {
		_ = webauthnhttp.WriteError(response, http.StatusUnauthorized, err)
		return
	}
	if !h.applyCredentialUpdate(result.Update) {
		_ = webauthnhttp.WriteError(response, http.StatusConflict, errors.New("credential changed concurrently"))
		return
	}
	_ = webauthnhttp.WriteJSON(response, http.StatusOK, map[string]string{"status": "authenticated"})
}

func (h *handler) newStateID() (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(h.random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (h *handler) saveRegistrationState(id string, state webauthn.RegistrationState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneExpiredLocked(h.now())
	h.registrationStates[id] = state
}

func (h *handler) consumeRegistrationState(id string) (webauthn.RegistrationState, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneExpiredLocked(h.now())
	state, ok := h.registrationStates[id]
	delete(h.registrationStates, id)
	return state, ok
}

func (h *handler) saveAuthenticationState(id string, state webauthn.AuthenticationState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneExpiredLocked(h.now())
	h.authenticationStates[id] = state
}

func (h *handler) consumeAuthenticationState(id string) (webauthn.AuthenticationState, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneExpiredLocked(h.now())
	state, ok := h.authenticationStates[id]
	delete(h.authenticationStates, id)
	return state, ok
}

func (h *handler) pruneExpiredLocked(now time.Time) {
	for id, state := range h.registrationStates {
		if !state.ExpiresAt.IsZero() && !now.Before(state.ExpiresAt) {
			delete(h.registrationStates, id)
		}
	}
	for id, state := range h.authenticationStates {
		if !state.ExpiresAt.IsZero() && !now.Before(state.ExpiresAt) {
			delete(h.authenticationStates, id)
		}
	}
}

func (h *handler) insertCredential(record webauthn.CredentialRecord) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := credentialKey(record.ID.Bytes())
	if _, exists := h.records[key]; exists {
		return false
	}
	h.records[key] = record
	return true
}

func (h *handler) credentialByRawID(id protocol.RawID) (webauthn.CredentialRecord, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	record, ok := h.records[credentialKey(id.Bytes())]
	return record, ok
}

func (h *handler) firstCredential() (webauthn.CredentialRecord, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, credential := range h.records {
		return credential, true
	}
	return webauthn.CredentialRecord{}, false
}

func (h *handler) applyCredentialUpdate(update webauthn.CredentialUpdate) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := credentialKey(update.ID.Bytes())
	record, ok := h.records[key]
	if !ok || record.SignCount != update.PreviousSignCount {
		return false
	}
	if update.SignCountChanged {
		record.SignCount = update.SignCount
	}
	if update.BackupStateChanged {
		record.BackupState = update.BackupState
	}
	if update.UVInitializedChanged {
		record.UVInitialized = update.UVInitialized
	}
	h.records[key] = record
	return true
}

func credentialKey(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func stateCookie(request *http.Request, name string) (string, bool) {
	cookie, err := request.Cookie(name)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func (h *handler) setStateCookie(response http.ResponseWriter, name string, value string) {
	http.SetCookie(response, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(webauthn.DefaultCeremonyTimeout / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *handler) clearStateCookie(response http.ResponseWriter, name string) {
	http.SetCookie(response, &http.Cookie{
		Name:     name,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
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
}
