package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/internal/testceremony"
)

func request(t *testing.T, h http.Handler, path string, body []byte, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, demoOrigin+path, bytes.NewReader(body))
	r.Header.Set("Origin", demoOrigin)
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func findCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("missing cookie %s", name)
	return nil
}

func TestQuickstartLifecycleAndReplay(t *testing.T) {
	a, err := newApp()
	if err != nil {
		t.Fatal(err)
	}
	h := a.routes()
	f := testceremony.New(t, "localhost", a.user.ID)
	begin := request(t, h, "/register/options", []byte(`{}`))
	c := findCookie(t, begin, registrationCookie)
	body := f.RegistrationJSON(t, a.store.registration[c.Value])
	if w := request(t, h, "/register/finish", body, c); w.Code != 201 {
		t.Fatalf("register %d %s", w.Code, w.Body)
	}
	if w := request(t, h, "/register/finish", body, c); w.Code != 401 {
		t.Fatal("replay accepted")
	}
	begin = request(t, h, "/login/options", []byte(`{}`))
	c = findCookie(t, begin, authenticationCookie)
	body = f.AuthenticationJSON(t, a.store.authentication[c.Value])
	w := request(t, h, "/login/finish", body, c)
	if w.Code != 200 {
		t.Fatalf("login %d %s", w.Code, w.Body)
	}
	session := findCookie(t, w, sessionCookie)
	if w = request(t, h, "/login/finish", body, c); w.Code != 401 {
		t.Fatal("login replay accepted")
	}
	if w = request(t, h, "/logout", []byte(`{}`), session); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if len(a.store.sessions) != 0 {
		t.Fatal("logout retained session")
	}
	begin = request(t, h, "/register/options", []byte(`{}`))
	c = findCookie(t, begin, registrationCookie)
	if w = request(t, h, "/register/finish", []byte(`{}`), c); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w = request(t, h, "/register/finish", []byte(`{}`), c); w.Code != 401 {
		t.Fatal("failed state retained")
	}
}

func TestQuickstartStoreCASAndUniqueInsert(t *testing.T) {
	a, err := newApp()
	if err != nil {
		t.Fatal(err)
	}
	f := testceremony.New(t, "localhost", a.user.ID)
	f.Record.BackupEligible = true
	if !a.store.insert(f.Record) || a.store.insert(f.Record) {
		t.Fatal("insert not unique")
	}
	u := webauthn.CredentialUpdate{ID: f.Record.ID, PreviousUVInitialized: true, BackupStateChanged: true, BackupState: true}
	if !a.store.update(u) || a.store.update(u) {
		t.Fatal("zero-counter backup CAS failed")
	}
	u.PreviousBackupState = true
	u.PreviousUVInitialized = false
	if a.store.update(u) {
		t.Fatal("stale UV accepted")
	}
	u.PreviousUVInitialized = true
	u.PreviousAuthenticatorAttachment = "platform"
	if a.store.update(u) {
		t.Fatal("stale attachment accepted")
	}
}

func TestQuickstartRejectsCrossOrigin(t *testing.T) {
	a, err := newApp()
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, demoOrigin+"/register/options", nil)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}

func TestQuickstartRejectsRiskBeforePersistence(t *testing.T) {
	for _, risk := range []string{"clone", "uv"} {
		t.Run(risk, func(t *testing.T) {
			a, err := newApp()
			if err != nil {
				t.Fatal(err)
			}
			f := testceremony.New(t, "localhost", a.user.ID)
			if risk == "clone" {
				f.Record.SignCount = 1
			} else {
				f.Record.UVInitialized = false
			}
			if !a.store.insert(f.Record) {
				t.Fatal("insert failed")
			}
			begin := request(t, a.routes(), "/login/options", []byte(`{}`))
			c := findCookie(t, begin, authenticationCookie)
			body := f.AuthenticationJSON(t, a.store.authentication[c.Value])
			result := request(t, a.routes(), "/login/finish", body, c)
			if result.Code != http.StatusUnauthorized || len(a.store.sessions) != 0 {
				t.Fatal("risk created session")
			}
			stored := a.store.credentials[string(f.Record.ID.Bytes())]
			if stored.SignCount != f.Record.SignCount || stored.UVInitialized != f.Record.UVInitialized {
				t.Fatal("risk wrote credential")
			}
			if _, exists := a.store.authentication[c.Value]; exists {
				t.Fatal("risk retained ceremony")
			}
		})
	}
}
