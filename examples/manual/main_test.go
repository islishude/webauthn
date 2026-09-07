package main

import (
	"context"
	"testing"

	"github.com/islishude/webauthn/internal/testceremony"
	"github.com/islishude/webauthn/protocol"
)

func TestManualLifecycle(t *testing.T) {
	s, err := newServer()
	if err != nil {
		t.Fatal(err)
	}
	user, err := protocol.NewUserHandle([]byte("account"))
	if err != nil {
		t.Fatal(err)
	}
	f := testceremony.New(t, "example.com", user)
	ctx := context.Background()
	if _, err = s.beginRegistration(ctx, "register", protocol.UserEntity{ID: user, Name: "account"}); err != nil {
		t.Fatal(err)
	}
	body := f.RegistrationJSON(t, s.registrationStates["register"])
	record, err := s.finishRegistration(ctx, "register", body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.finishRegistration(ctx, "register", body); err == nil {
		t.Fatal("registration replay accepted")
	}
	if _, err = s.beginRegistration(ctx, "duplicate", protocol.UserEntity{ID: user, Name: "account"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.finishRegistration(ctx, "duplicate", f.RegistrationJSON(t, s.registrationStates["duplicate"])); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err = s.beginAuthentication(ctx, "login", record); err != nil {
		t.Fatal(err)
	}
	body = f.AuthenticationJSON(t, s.authenticationStates["login"])
	if _, err = s.finishAuthentication(ctx, "login", body); err != nil {
		t.Fatal(err)
	}
	if _, err = s.finishAuthentication(ctx, "login", body); err == nil {
		t.Fatal("login replay accepted")
	}
	if _, err = s.beginAuthentication(ctx, "bad", record); err != nil {
		t.Fatal(err)
	}
	if _, err = s.finishAuthentication(ctx, "bad", []byte(`{}`)); err == nil {
		t.Fatal("malformed accepted")
	}
	if _, ok := s.authenticationStates["bad"]; ok {
		t.Fatal("failed state retained")
	}
}
