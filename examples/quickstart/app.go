package main

import (
	"crypto/rand"
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"time"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/preset"
	"github.com/islishude/webauthn/protocol"
	webauthnhttp "github.com/islishude/webauthn/transport/http"
)

//go:embed static/*
var assets embed.FS

const demoOrigin = "http://localhost:8080"
const registrationCookie = "demo-registration"
const authenticationCookie = "demo-authentication"
const sessionCookie = "demo-session"

type app struct {
	rp    *webauthn.RelyingParty
	store *memoryStore
	user  protocol.UserEntity
}

func newApp() (*app, error) {
	config, err := preset.PasskeyConfig(protocol.RPEntity{ID: "localhost", Name: "Passkey demo"}, webauthn.OriginPolicy{AllowedOrigins: []string{demoOrigin}})
	if err != nil {
		return nil, err
	}
	rp, err := webauthn.New(config)
	if err != nil {
		return nil, err
	}
	var raw [32]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return nil, err
	}
	handle, err := protocol.NewUserHandle(raw[:])
	if err != nil {
		return nil, err
	}
	return &app{rp: rp, store: newMemoryStore(), user: protocol.UserEntity{ID: handle, Name: "demo", DisplayName: "Local demo account"}}, nil
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register/options", a.beginRegistration)
	mux.HandleFunc("POST /register/finish", a.finishRegistration)
	mux.HandleFunc("POST /login/options", a.beginAuthentication)
	mux.HandleFunc("POST /login/finish", a.finishAuthentication)
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("GET /me", a.me)
	files, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(files)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		// Fixed host and Origin protect this localhost demo, including against DNS rebinding.
		if r.Host != "localhost:8080" {
			fail(w, http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if r.Header.Get("Origin") != demoOrigin || err != nil || media != "application/json" {
				fail(w, http.StatusForbidden)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func fail(w http.ResponseWriter, status int) { _ = webauthnhttp.WriteError(w, status, nil) }
func cookieID(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
func setCookie(w http.ResponseWriter, name, id string, seconds int) {
	// Secure is false only because this demo is fixed to loopback HTTP.
	http.SetCookie(w, &http.Cookie{Name: name, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: seconds}) //nolint:gosec // This example only serves fixed-host loopback HTTP, never production HTTPS.
}

func (a *app) beginRegistration(w http.ResponseWriter, r *http.Request) {
	start, err := a.rp.StartRegistration(r.Context(), webauthn.RegistrationRequest{User: a.user, ExcludeCredentials: a.store.descriptors()})
	if err != nil {
		fail(w, http.StatusInternalServerError)
		return
	}
	id, err := token()
	if err != nil {
		fail(w, http.StatusInternalServerError)
		return
	}
	a.store.mu.Lock()
	a.store.prune(time.Now())
	delete(a.store.registration, cookieID(r, registrationCookie))
	if len(a.store.registration) >= 128 {
		a.store.mu.Unlock()
		fail(w, http.StatusTooManyRequests)
		return
	}
	a.store.registration[id] = start.State
	a.store.mu.Unlock()
	setCookie(w, registrationCookie, id, int(webauthn.DefaultChallengeTTL/time.Second))
	_ = webauthnhttp.WriteCreationOptions(w, start.Options)
}

func (a *app) finishRegistration(w http.ResponseWriter, r *http.Request) {
	id := cookieID(r, registrationCookie)
	a.store.mu.Lock()
	a.store.prune(time.Now())
	state, ok := a.store.registration[id]
	delete(a.store.registration, id)
	a.store.mu.Unlock()
	setCookie(w, registrationCookie, "", -1)
	if !ok {
		fail(w, http.StatusUnauthorized)
		return
	}
	response, err := webauthnhttp.ReadRegistrationResponse(r, 0)
	if err != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	result, err := a.rp.FinishRegistration(r.Context(), webauthn.RegistrationVerification{State: state, Response: response})
	if err != nil {
		fail(w, http.StatusUnauthorized)
		return
	}
	if !a.store.insert(result.Credential) {
		fail(w, http.StatusConflict)
		return
	}
	_ = webauthnhttp.WriteJSON(w, http.StatusCreated, map[string]bool{"registered": true})
}

func (a *app) beginAuthentication(w http.ResponseWriter, r *http.Request) {
	start, err := a.rp.StartAuthentication(r.Context(), webauthn.AuthenticationRequest{})
	if err != nil {
		fail(w, http.StatusInternalServerError)
		return
	}
	id, err := token()
	if err != nil {
		fail(w, http.StatusInternalServerError)
		return
	}
	a.store.mu.Lock()
	a.store.prune(time.Now())
	delete(a.store.authentication, cookieID(r, authenticationCookie))
	if len(a.store.authentication) >= 128 {
		a.store.mu.Unlock()
		fail(w, http.StatusTooManyRequests)
		return
	}
	a.store.authentication[id] = start.State
	a.store.mu.Unlock()
	setCookie(w, authenticationCookie, id, int(webauthn.DefaultChallengeTTL/time.Second))
	_ = webauthnhttp.WriteRequestOptions(w, start.Options)
}

func (a *app) finishAuthentication(w http.ResponseWriter, r *http.Request) {
	id := cookieID(r, authenticationCookie)
	a.store.mu.Lock()
	a.store.prune(time.Now())
	state, ok := a.store.authentication[id]
	delete(a.store.authentication, id)
	a.store.mu.Unlock()
	setCookie(w, authenticationCookie, "", -1)
	if !ok {
		fail(w, http.StatusUnauthorized)
		return
	}
	response, err := webauthnhttp.ReadAuthenticationResponse(r, 0)
	if err != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	credential, ok := a.store.lookup(response.RawID, response.UserHandle)
	if !ok {
		fail(w, http.StatusUnauthorized)
		return
	}
	result, err := a.rp.FinishAuthentication(r.Context(), webauthn.AuthenticationVerification{State: state, Response: response, Credential: credential})
	if err != nil {
		fail(w, http.StatusUnauthorized)
		return
	}
	if !a.store.update(result.Update) {
		fail(w, http.StatusConflict)
		return
	}
	// Identity is trusted only after verification and successful conditional persistence.
	id, err = token()
	if err != nil {
		fail(w, http.StatusInternalServerError)
		return
	}
	a.store.mu.Lock()
	a.store.prune(time.Now())
	delete(a.store.sessions, cookieID(r, sessionCookie))
	if len(a.store.sessions) >= 128 {
		a.store.mu.Unlock()
		fail(w, http.StatusTooManyRequests)
		return
	}
	a.store.sessions[id] = time.Now().Add(time.Hour)
	a.store.mu.Unlock()
	setCookie(w, sessionCookie, id, 3600)
	_ = webauthnhttp.WriteJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (a *app) me(w http.ResponseWriter, r *http.Request) {
	a.store.mu.Lock()
	a.store.prune(time.Now())
	_, ok := a.store.sessions[cookieID(r, sessionCookie)]
	a.store.mu.Unlock()
	_ = webauthnhttp.WriteJSON(w, http.StatusOK, map[string]bool{"authenticated": ok})
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	a.store.mu.Lock()
	delete(a.store.sessions, cookieID(r, sessionCookie))
	a.store.mu.Unlock()
	setCookie(w, sessionCookie, "", -1)
	_ = webauthnhttp.WriteJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}
