package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/protocol"
	webauthnhttp "github.com/islishude/webauthn/transport/http"
)

type loginOptionsRequest struct {
	Email string `json:"email"`
	Mode  string `json:"mode"`
}

type loginFinishRequest struct {
	Email      string          `json:"email"`
	Credential json.RawMessage `json:"credential"`
}

func (a *app) loginOptions(response http.ResponseWriter, request *http.Request) {
	var input loginOptionsRequest
	if err := decodeJSON(request, &input); err != nil {
		writeGenericError(response, http.StatusBadRequest)
		return
	}

	var email string
	var allowCredentials []protocol.CredentialDescriptor
	var expectedUserHandle protocol.UserHandle
	if input.Mode == "roaming" {
		user, ok := a.store.userByEmail(input.Email)
		if !ok {
			writeGenericError(response, http.StatusUnauthorized)
			return
		}
		email = user.Email
		expectedUserHandle = user.Handle
		credentials := a.store.credentialsForUser(user.Handle)
		if len(credentials) == 0 {
			writeGenericError(response, http.StatusUnauthorized)
			return
		}
		allowCredentials = descriptorsFromCredentials(credentials)
	}

	start, err := webauthn.StartAuthentication(request.Context(), webauthn.AuthenticationStartOptions{
		RPID:               a.rpID,
		OriginPolicy:       a.originPolicy(),
		AllowCredentials:   allowCredentials,
		ExpectedUserHandle: expectedUserHandle,
		UserVerification:   userVerificationForMode(input.Mode),
	})
	if err != nil {
		writeGenericError(response, http.StatusBadRequest)
		return
	}
	stateID, err := randomToken()
	if err != nil {
		writeGenericError(response, http.StatusInternalServerError)
		return
	}
	a.store.saveAuthenticationState(stateID, authenticationState{Email: email, State: start.State})
	http.SetCookie(response, a.cookie(authenticationCookie, stateID, 300))
	_ = webauthnhttp.WriteRequestOptions(response, start.Options)
}

func (a *app) loginFinish(response http.ResponseWriter, request *http.Request) {
	var input loginFinishRequest
	if err := decodeJSON(request, &input); err != nil || len(input.Credential) == 0 {
		writeGenericError(response, http.StatusBadRequest)
		return
	}
	cookie, err := request.Cookie(authenticationCookie)
	if err != nil {
		writeGenericError(response, http.StatusUnauthorized)
		return
	}
	state, ok := a.store.consumeAuthenticationState(cookie.Value)
	http.SetCookie(response, a.clearCookie(authenticationCookie))
	if !ok || (state.Email != "" && state.Email != input.Email) {
		writeGenericError(response, http.StatusUnauthorized)
		return
	}

	assertion, err := browser.AuthenticationResponseFromJSON(input.Credential)
	if err != nil {
		writeGenericError(response, http.StatusBadRequest)
		return
	}
	credential, ok := a.store.credentialByID(assertion.RawID.Bytes())
	if !ok {
		writeGenericError(response, http.StatusUnauthorized)
		return
	}
	result, err := webauthn.FinishAuthentication(request.Context(), webauthn.AuthenticationFinishOptions{
		State:               state.State,
		Response:            assertion,
		Credential:          credential,
		SignatureVerifier:   signatureVerifier{publicKey: credential.PublicKey},
		ExtensionMapDecoder: a.decoder,
		ExtensionRegistry:   a.extensions,
		CounterPolicy:       webauthn.CounterPolicy{RejectCloneRisk: true},
	})
	if err != nil {
		writeGenericError(response, http.StatusUnauthorized)
		return
	}
	a.store.updateCredential(result.Update)
	if err := a.setSession(response, result.AuthenticatedAs); err != nil {
		writeGenericError(response, http.StatusInternalServerError)
		return
	}
	user, ok := a.store.userByHandle(result.AuthenticatedAs)
	if !ok {
		writeGenericError(response, http.StatusInternalServerError)
		return
	}
	_ = webauthnhttp.WriteJSON(response, http.StatusOK, map[string]any{
		"ok":   true,
		"user": map[string]string{"email": user.Email},
	})
}

func descriptorsFromCredentials(credentials []webauthn.CredentialRecord) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, credential := range credentials {
		out = append(out, protocol.CredentialDescriptor{
			Type:       protocol.CredentialTypePublicKey,
			ID:         credential.ID,
			Transports: credential.Transports,
		})
	}
	return out
}

func userVerificationForMode(mode string) protocol.UserVerificationRequirement {
	if mode == "roaming" {
		return protocol.UserVerificationPreferred
	}
	return protocol.UserVerificationRequired
}

func credentialIDQuery(request *http.Request) ([]byte, bool) {
	id := request.URL.Query().Get("id")
	if id == "" {
		return nil, false
	}
	bytes, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return nil, false
	}
	return bytes, true
}
