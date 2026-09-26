package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/internal/testceremony"
	"github.com/islishude/webauthn/preset"
	"github.com/islishude/webauthn/protocol"
	storagejson "github.com/islishude/webauthn/storage/json"
)

type harness struct {
	app         *application
	accounts    *memoryAccounts
	ceremonies  *memoryCeremonies
	credentials *memoryCredentials
	sessions    *memorySessions
	now         time.Time
	alice, bob  testceremony.Fixture
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{now: time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)}
	users := make(map[string]protocol.UserEntity)
	for _, name := range []string{"alice", "bob", "empty"} {
		id, err := protocol.NewUserHandle([]byte("opaque-" + name))
		if err != nil {
			t.Fatal(err)
		}
		users[name] = protocol.UserEntity{ID: id, Name: name}
	}
	config, err := preset.PasskeyConfig(protocol.RPEntity{ID: "example.com", Name: "Integration"}, webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	config.Now = func() time.Time { return h.now }
	rp, err := webauthn.New(config)
	if err != nil {
		t.Fatal(err)
	}
	h.accounts = &memoryAccounts{users: users, grants: map[string]string{"enroll-alice": "alice", "enroll-bob": "bob"}}
	h.ceremonies = &memoryCeremonies{entries: make(map[string]savedCeremony), now: config.Now}
	h.credentials = &memoryCredentials{entries: make(map[string]savedCredential), decoder: config.CredentialPublicKeyDecoder}
	h.sessions = &memorySessions{entries: make(map[string]protocol.UserHandle)}
	h.app = &application{rp: rp, accounts: h.accounts, ceremonies: h.ceremonies, credentials: h.credentials, sessions: h.sessions}
	h.alice = testceremony.New(t, "example.com", users["alice"].ID)
	h.bob = testceremony.New(t, "example.com", users["bob"].ID)
	return h
}

func (h *harness) registrationState(t *testing.T, id string) webauthn.RegistrationState {
	t.Helper()
	state, err := storagejson.UnmarshalRegistrationState(h.ceremonies.entries[id].payload)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func (h *harness) authenticationState(t *testing.T, id string) webauthn.AuthenticationState {
	t.Helper()
	state, err := storagejson.UnmarshalAuthenticationState(h.ceremonies.entries[id].payload)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func (h *harness) enroll(t *testing.T, name string, f testceremony.Fixture) {
	t.Helper()
	id, _, err := h.app.beginEnrollment(context.Background(), "enroll-"+name)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.app.finishEnrollment(context.Background(), "enroll-"+name, id, f.RegistrationJSON(t, h.registrationState(t, id))); err != nil {
		t.Fatal(err)
	}
}

func TestBusinessLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.enroll(t, "alice", h.alice)
	h.enroll(t, "bob", h.bob)
	_, options, err := h.app.beginEnrollment(ctx, "enroll-alice")
	if err != nil || len(options.ExcludeCredentials) != 1 {
		t.Fatalf("exclusions: %v", err)
	}
	for _, name := range []string{"alice", ""} {
		id, dto, err := h.app.beginLogin(ctx, "browser", name)
		if err != nil {
			t.Fatal(err)
		}
		if (len(dto.AllowCredentials) == 0) != (name == "") {
			t.Fatal("wrong login mode")
		}
		body := h.alice.AuthenticationJSON(t, h.authenticationState(t, id))
		session, err := h.app.finishLogin(ctx, "browser", id, body)
		if err != nil {
			t.Fatal(err)
		}
		if !h.sessions.entries[session].Equal(h.alice.Record.UserHandle) {
			t.Fatal("wrong session identity")
		}
		if _, err = h.app.finishLogin(ctx, "browser", id, body); !errors.Is(err, errDenied) {
			t.Fatal("replay accepted")
		}
	}
	for _, name := range []string{"missing", "empty"} {
		if _, _, err = h.app.beginLogin(ctx, "browser", name); !errors.Is(err, errDenied) {
			t.Fatal("empty account became discoverable login")
		}
	}
}

func TestEnrollmentBindingsAndConsumption(t *testing.T) {
	ctx := context.Background()
	for _, scenario := range []string{"cross-session", "changed-account", "revoked", "wrong-kind", "expired", "malformed", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			h := newHarness(t)
			if scenario == "duplicate" {
				h.enroll(t, "alice", h.alice)
			}
			id, _, err := h.app.beginEnrollment(ctx, "enroll-alice")
			if err != nil {
				t.Fatal(err)
			}
			body := h.alice.RegistrationJSON(t, h.registrationState(t, id))
			session := "enroll-alice"
			switch scenario {
			case "cross-session":
				session = "enroll-bob"
			case "changed-account":
				h.accounts.grants[session] = "bob"
			case "revoked":
				delete(h.accounts.grants, session)
			case "wrong-kind":
				entry := h.ceremonies.entries[id]
				entry.kind = authentication
				h.ceremonies.entries[id] = entry
			case "expired":
				h.now = h.now.Add(webauthn.DefaultChallengeTTL)
			case "malformed":
				body = []byte(`{}`)
			}
			if err = h.app.finishEnrollment(ctx, session, id, body); err == nil {
				t.Fatal("invalid enrollment accepted")
			}
			if scenario == "malformed" || scenario == "expired" || scenario == "duplicate" {
				if _, ok := h.ceremonies.entries[id]; ok {
					t.Fatal("consumed state retained")
				}
			}
			if scenario == "cross-session" || scenario == "changed-account" || scenario == "revoked" || scenario == "wrong-kind" {
				if _, ok := h.ceremonies.entries[id]; !ok {
					t.Fatal("unmatched binding consumed state")
				}
			}
		})
	}
}

type failingUpdates struct {
	credentialStore
	err error
}

func (s failingUpdates) Update(context.Context, webauthn.CredentialUpdate, uint64) error {
	return s.err
}

type interveningWrite struct{ credentialStore }

func (s interveningWrite) Update(ctx context.Context, u webauthn.CredentialUpdate, v uint64) error {
	if err := s.credentialStore.Update(ctx, u, v); err != nil {
		return err
	}
	return s.credentialStore.Update(ctx, u, v)
}

func TestLoginFailuresDoNotCreateSessions(t *testing.T) {
	ctx := context.Background()
	for _, scenario := range []string{"cross-session", "other-account", "malformed", "expired", "clone-risk", "pending-uv", "storage-error", "concurrent-write", "invalid-storage"} {
		t.Run(scenario, func(t *testing.T) {
			h := newHarness(t)
			record := h.alice.Record
			if scenario == "clone-risk" {
				record.SignCount = 8
			}
			if scenario == "pending-uv" {
				record.UVInitialized = false
			}
			if err := h.credentials.Insert(ctx, record); err != nil {
				t.Fatal(err)
			}
			if err := h.credentials.Insert(ctx, h.bob.Record); err != nil {
				t.Fatal(err)
			}
			id, _, err := h.app.beginLogin(ctx, "browser", "alice")
			if err != nil {
				t.Fatal(err)
			}
			state := h.authenticationState(t, id)
			body := h.alice.AuthenticationJSON(t, state)
			session := "browser"
			switch scenario {
			case "cross-session":
				session = "other-browser"
			case "other-account":
				body = h.bob.AuthenticationJSON(t, state)
			case "malformed":
				body = []byte(`{}`)
			case "expired":
				h.now = h.now.Add(webauthn.DefaultChallengeTTL)
			case "storage-error":
				h.app.credentials = failingUpdates{credentialStore: h.credentials, err: errors.New("storage unavailable")}
			case "concurrent-write":
				h.app.credentials = interveningWrite{credentialStore: h.credentials}
			case "invalid-storage":
				h.credentials.entries[string(record.ID.Bytes())] = savedCredential{payload: []byte(`{}`), version: 1}
			}
			_, err = h.app.finishLogin(ctx, session, id, body)
			if err == nil || len(h.sessions.entries) != 0 {
				t.Fatal("failed login created a session")
			}
			if scenario == "clone-risk" || scenario == "pending-uv" {
				if !errors.Is(err, errRisk) {
					t.Fatalf("wrong risk classification: %v", err)
				}
				if h.credentials.entries[string(record.ID.Bytes())].version != 1 {
					t.Fatal("risk decision wrote credential")
				}
			}
			if scenario == "concurrent-write" && !errors.Is(err, webauthn.ErrCredentialUpdateConflict) {
				t.Fatal(err)
			}
			if scenario != "cross-session" {
				if _, ok := h.ceremonies.entries[id]; ok {
					t.Fatal("failed attempt retained state")
				}
			}
		})
	}
}

func TestAtomicStorageContracts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var inserted atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if h.credentials.Insert(ctx, h.alice.Record) == nil {
				inserted.Add(1)
			}
		})
	}
	wg.Wait()
	if inserted.Load() != 1 {
		t.Fatal("duplicate insertion raced")
	}
	update := webauthn.CredentialUpdate{ID: h.alice.Record.ID, PreviousUVInitialized: true}
	var updated atomic.Int32
	for range 12 {
		wg.Go(func() {
			if h.credentials.Update(ctx, update, 1) == nil {
				updated.Add(1)
			}
		})
	}
	wg.Wait()
	if updated.Load() != 1 {
		t.Fatal("row version did not protect no-op updates")
	}
	id, _, err := h.app.beginLogin(ctx, "browser", "")
	if err != nil {
		t.Fatal(err)
	}
	var consumed atomic.Int32
	for range 12 {
		wg.Go(func() {
			if _, err := h.ceremonies.Consume(ctx, id, "browser", authentication, nil); err == nil {
				consumed.Add(1)
			}
		})
	}
	wg.Wait()
	if consumed.Load() != 1 {
		t.Fatal("state consumed more than once")
	}
}
