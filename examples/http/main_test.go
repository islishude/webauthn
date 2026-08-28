package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/protocol"
)

func TestHTTPExampleIsolatesAndConsumesRegistrationState(t *testing.T) {
	t.Parallel()

	h := mustHandler(t)
	h.now = func() time.Time { return time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC) }
	router := routes(h)

	first := beginRegistrationRequest(t, router)
	second := beginRegistrationRequest(t, router)
	if first.Value == second.Value {
		t.Fatal("two ceremonies received the same state id")
	}

	badFinish := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/register/finish", strings.NewReader(`{}`))
	badFinish.AddCookie(first)
	badRecorder := httptest.NewRecorder()
	router.ServeHTTP(badRecorder, badFinish)
	if badRecorder.Code != http.StatusBadRequest {
		t.Fatalf("first finish status = %d, want 400", badRecorder.Code)
	}

	replay := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/register/finish", strings.NewReader(`{}`))
	replay.AddCookie(first)
	replayRecorder := httptest.NewRecorder()
	router.ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", replayRecorder.Code)
	}

	h.mu.Lock()
	_, secondStillPresent := h.registrationStates[second.Value]
	h.mu.Unlock()
	if !secondStillPresent {
		t.Fatal("consuming one ceremony removed another session's state")
	}
}

func TestHTTPExampleExpiresStateAtDeadline(t *testing.T) {
	t.Parallel()

	h := mustHandler(t)
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	router := routes(h)
	cookie := beginRegistrationRequest(t, router)
	now = now.Add(webauthn.DefaultChallengeTTL)

	finish := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/register/finish", strings.NewReader(`{}`))
	finish.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, finish)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expired finish status = %d, want 401", recorder.Code)
	}
}

func TestHTTPExampleConcurrentStartsAndConditionalCredentialUpdate(t *testing.T) {
	t.Parallel()

	h := mustHandler(t)
	router := routes(h)
	const requests = 24
	var wait sync.WaitGroup
	wait.Add(requests)
	for range requests {
		go func() {
			defer wait.Done()
			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/register/options", nil)
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Errorf("registration start status = %d", recorder.Code)
			}
		}()
	}
	wait.Wait()

	credentialID, err := protocol.NewCredentialID([]byte("credential-id"))
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}
	userHandle, err := protocol.NewUserHandle([]byte("user-handle"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	record := webauthn.CredentialRecord{Type: protocol.CredentialTypePublicKey, ID: credentialID, UserHandle: userHandle, RPID: "example.com", SignCount: 7}
	if !h.insertCredential(record) || h.insertCredential(record) {
		t.Fatal("credential insertion was not atomic and unique")
	}
	if h.applyCredentialUpdate(webauthn.CredentialUpdate{ID: credentialID, PreviousSignCount: 6, SignCount: 8, SignCountChanged: true}) {
		t.Fatal("stale credential update succeeded")
	}
	if !h.applyCredentialUpdate(webauthn.CredentialUpdate{
		ID:                             credentialID,
		PreviousSignCount:              7,
		SignCount:                      8,
		SignCountChanged:               true,
		BackupState:                    true,
		BackupStateChanged:             true,
		UVInitialized:                  true,
		UVInitializedChanged:           true,
		AuthenticatorAttachment:        protocol.AuthenticatorAttachmentCrossPlatform,
		AuthenticatorAttachmentChanged: true,
	}) {
		t.Fatal("current credential update failed")
	}
	rawID, err := protocol.NewRawID(credentialID.Bytes())
	if err != nil {
		t.Fatalf("NewRawID() error = %v", err)
	}
	updated, ok := h.credentialByRawID(rawID)
	if !ok || updated.SignCount != 8 || !updated.BackupState || !updated.UVInitialized || updated.AuthenticatorAttachment != protocol.AuthenticatorAttachmentCrossPlatform {
		t.Fatalf("updated credential = %+v", updated)
	}
}

func TestHTTPExampleUsesOpaqueHandleAndExistingCredentialExclusions(t *testing.T) {
	t.Parallel()

	h := mustHandler(t)
	credentialID, err := protocol.NewCredentialID([]byte("existing-credential"))
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}
	if !h.insertCredential(webauthn.CredentialRecord{
		Type:       protocol.CredentialTypePublicKey,
		ID:         credentialID,
		UserHandle: h.userHandle,
		RPID:       "example.com",
	}) {
		t.Fatal("insertCredential() = false")
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/register/options", nil)
	routes(h).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("registration status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var options browser.CredentialCreationOptionsJSON
	if err := json.Unmarshal(recorder.Body.Bytes(), &options); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	handle, err := base64.RawURLEncoding.DecodeString(options.User.ID)
	if err != nil {
		t.Fatalf("user handle decode error = %v", err)
	}
	if len(handle) != protocol.MaxUserHandleLength {
		t.Fatalf("user handle length = %d, want %d", len(handle), protocol.MaxUserHandleLength)
	}
	if len(options.ExcludeCredentials) != 1 || options.ExcludeCredentials[0].ID != base64.RawURLEncoding.EncodeToString(credentialID.Bytes()) {
		t.Fatalf("ExcludeCredentials = %#v", options.ExcludeCredentials)
	}
}

func beginRegistrationRequest(t *testing.T, router http.Handler) *http.Cookie {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/register/options", nil)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("registration start status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == registrationStateCookie {
			return cookie
		}
	}
	t.Fatal("registration state cookie missing")
	return nil
}

func mustHandler(t *testing.T) *handler {
	t.Helper()
	h, err := newHandler()
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	return h
}
