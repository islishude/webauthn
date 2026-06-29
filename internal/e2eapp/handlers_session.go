package main

import (
	"net/http"

	webauthnhttp "github.com/islishude/webauthn/transport/http"
)

func (a *app) me(response http.ResponseWriter, request *http.Request) {
	cookie, err := request.Cookie(sessionCookie)
	if err != nil {
		_ = webauthnhttp.WriteJSON(response, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	user, ok := a.store.sessionUser(cookie.Value)
	if !ok {
		_ = webauthnhttp.WriteJSON(response, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	_ = webauthnhttp.WriteJSON(response, http.StatusOK, map[string]any{
		"authenticated": true,
		"user":          map[string]string{"email": user.Email},
	})
}

func (a *app) logout(response http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie(sessionCookie); err == nil {
		a.store.deleteSession(cookie.Value)
	}
	http.SetCookie(response, a.clearCookie(sessionCookie))
	_ = webauthnhttp.WriteJSON(response, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) debugCredential(response http.ResponseWriter, request *http.Request) {
	id, ok := credentialIDQuery(request)
	if !ok {
		writeGenericError(response, http.StatusBadRequest)
		return
	}
	credential, ok := a.store.debugCredential(id)
	if !ok {
		writeGenericError(response, http.StatusNotFound)
		return
	}
	user, _ := a.store.userByHandle(credential.UserHandle)
	email := ""
	if user != nil {
		email = user.Email
	}
	_ = webauthnhttp.WriteJSON(response, http.StatusOK, map[string]any{
		"ok":        true,
		"email":     email,
		"signCount": credential.SignCount,
	})
}
