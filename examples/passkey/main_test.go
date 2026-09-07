package main

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/internal/testceremony"
	"github.com/islishude/webauthn/protocol"
)

type testStore struct {
	record   webauthn.CredentialRecord
	conflict bool
	updated  bool
}

func (s *testStore) LookupByUserHandleAndCredentialID(user protocol.UserHandle, id protocol.RawID) (webauthn.CredentialRecord, error) {
	if !s.record.ID.EqualRawID(id) || !s.record.UserHandle.Equal(user) {
		return webauthn.CredentialRecord{}, errors.New("unknown credential")
	}
	return s.record, nil
}
func (s *testStore) UpdateCredential(webauthn.CredentialUpdate) error {
	if s.conflict {
		return errors.New("conflict")
	}
	s.updated = true
	return nil
}

func TestPasskeySignedExtensionAndPersistence(t *testing.T) {
	rp, err := newPasskeyRP()
	if err != nil {
		t.Fatal(err)
	}
	user, err := protocol.NewUserHandle([]byte("account"))
	if err != nil {
		t.Fatal(err)
	}
	f := testceremony.New(t, "example.com", user)
	_, state, err := beginPasskeyAuthentication(context.Background(), rp)
	if err != nil {
		t.Fatal(err)
	}
	store := &testStore{record: f.Record}
	body := f.AuthenticationJSON(t, state)
	if _, err = finishPasskeyAuthentication(context.Background(), store, rp, state, body); err != nil || !store.updated {
		t.Fatalf("verification/persistence: %v", err)
	}
	store.conflict = true
	if _, err = finishPasskeyAuthentication(context.Background(), store, rp, state, body); err == nil {
		t.Fatal("storage conflict ignored")
	}
}
