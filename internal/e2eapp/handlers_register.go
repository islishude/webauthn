package main

import (
	"encoding/json"
	"net/http"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/protocol"
	webauthnhttp "github.com/islishude/webauthn/transport/http"
)

type registerOptionsRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Mode        string `json:"mode"`
}

type registerFinishRequest struct {
	Email      string          `json:"email"`
	Credential json.RawMessage `json:"credential"`
}

func (a *app) registerOptions(response http.ResponseWriter, request *http.Request) {
	var input registerOptionsRequest
	if err := decodeJSON(request, &input); err != nil || input.Email == "" {
		writeGenericError(response, http.StatusBadRequest)
		return
	}
	user, err := a.store.getOrCreateUser(input.Email, input.DisplayName)
	if err != nil {
		writeGenericError(response, http.StatusInternalServerError)
		return
	}

	selection := &protocol.AuthenticatorSelectionCriteria{
		AuthenticatorAttachment: protocol.AuthenticatorAttachmentPlatform,
		ResidentKey:             protocol.ResidentKeyRequired,
		RequireResidentKey:      true,
		UserVerification:        protocol.UserVerificationRequired,
	}
	hints := []protocol.PublicKeyCredentialHint{protocol.HintClientDevice}
	if input.Mode == "roaming" {
		selection = &protocol.AuthenticatorSelectionCriteria{
			AuthenticatorAttachment: protocol.AuthenticatorAttachmentCrossPlatform,
			ResidentKey:             protocol.ResidentKeyDiscouraged,
			UserVerification:        protocol.UserVerificationPreferred,
		}
		hints = []protocol.PublicKeyCredentialHint{protocol.HintSecurityKey}
	}

	start, err := webauthn.StartRegistration(request.Context(), webauthn.RegistrationStartOptions{
		RP:                     protocol.RPEntity{ID: a.rpID, Name: "WebAuthn E2E"},
		User:                   protocol.UserEntity{ID: user.Handle, Name: user.Email, DisplayName: user.DisplayName},
		OriginPolicy:           a.originPolicy(),
		PubKeyCredParams:       []protocol.CredentialParameter{{Type: protocol.CredentialTypePublicKey, Algorithm: protocol.AlgorithmES256}},
		Timeout:                30_000_000_000,
		AuthenticatorSelection: selection,
		Hints:                  hints,
		Attestation:            protocol.AttestationNone,
		UserVerification:       selection.UserVerification,
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
	a.store.saveRegistrationState(stateID, registrationState{Email: user.Email, State: start.State})
	http.SetCookie(response, a.cookie(registrationCookie, stateID, 300))
	_ = webauthnhttp.WriteCreationOptions(response, start.Options)
}

func (a *app) registerFinish(response http.ResponseWriter, request *http.Request) {
	var input registerFinishRequest
	if err := decodeJSON(request, &input); err != nil || input.Email == "" || len(input.Credential) == 0 {
		writeGenericError(response, http.StatusBadRequest)
		return
	}
	cookie, err := request.Cookie(registrationCookie)
	if err != nil {
		writeGenericError(response, http.StatusUnauthorized)
		return
	}
	state, ok := a.store.consumeRegistrationState(cookie.Value)
	http.SetCookie(response, a.clearCookie(registrationCookie))
	if !ok || state.Email != input.Email {
		writeGenericError(response, http.StatusUnauthorized)
		return
	}
	credentialResponse, err := browser.RegistrationResponseFromJSON(input.Credential)
	if err != nil {
		writeGenericError(response, http.StatusBadRequest)
		return
	}
	result, err := webauthn.FinishRegistration(request.Context(), webauthn.RegistrationFinishOptions{
		State:                       state.State,
		Response:                    credentialResponse,
		AttestationObjectDecoder:    a.decoder,
		CredentialPublicKeyDecoder:  a.decoder,
		ExtensionMapDecoder:         a.decoder,
		AttestationRegistry:         a.attesters,
		AttestationTrustPolicy:      attestation.AcceptNone(),
		ExtensionRegistry:           a.extensions,
		CredentialAlreadyRegistered: a.store.credentialExists(credentialIDFromRawID(credentialResponse.RawID.Bytes())),
	})
	if err != nil {
		writeGenericError(response, http.StatusUnauthorized)
		return
	}
	a.store.saveCredential(result.Credential)
	if err := a.setSession(response, result.Credential.UserHandle); err != nil {
		writeGenericError(response, http.StatusInternalServerError)
		return
	}
	_ = webauthnhttp.WriteJSON(response, http.StatusOK, map[string]any{
		"ok":   true,
		"user": map[string]string{"email": input.Email},
	})
}

func credentialIDFromRawID(bytes []byte) protocol.CredentialID {
	id, _ := protocol.NewCredentialID(bytes)
	return id
}
