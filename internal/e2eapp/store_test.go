package main

import (
	"sync"
	"sync/atomic"
	"testing"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/protocol"
)

func TestStoreInsertCredentialIsAtomic(t *testing.T) {
	t.Parallel()

	store := newStore()
	credentialID, err := protocol.NewCredentialID([]byte("shared-credential"))
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}
	userHandle, err := protocol.NewUserHandle([]byte("user-handle"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	record := webauthn.CredentialRecord{ID: credentialID, UserHandle: userHandle, RPID: "localhost"}

	const workers = 32
	var successes atomic.Int64
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			if store.insertCredential(record) {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("successful inserts = %d, want 1", got)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.credentialsByID) != 1 || len(store.credentialsByUserHandle[handleKey(userHandle)]) != 1 {
		t.Fatalf("credential indexes contain duplicates: by-id=%d by-user=%d", len(store.credentialsByID), len(store.credentialsByUserHandle[handleKey(userHandle)]))
	}
}

func TestStoreAppliesAuthenticatorAttachmentUpdate(t *testing.T) {
	t.Parallel()

	store := newStore()
	credentialID, err := protocol.NewCredentialID([]byte("credential"))
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}
	userHandle, err := protocol.NewUserHandle([]byte("user-handle"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	record := webauthn.CredentialRecord{
		ID:                      credentialID,
		UserHandle:              userHandle,
		RPID:                    "localhost",
		AuthenticatorAttachment: protocol.AuthenticatorAttachmentPlatform,
	}
	if !store.insertCredential(record) {
		t.Fatal("insertCredential() = false")
	}
	if !store.updateCredential(webauthn.CredentialUpdate{
		ID:                             credentialID,
		PreviousSignCount:              0,
		AuthenticatorAttachment:        protocol.AuthenticatorAttachmentCrossPlatform,
		AuthenticatorAttachmentChanged: true,
	}) {
		t.Fatal("updateCredential() = false")
	}
	updated, ok := store.credentialByID(credentialID.Bytes())
	if !ok || updated.AuthenticatorAttachment != protocol.AuthenticatorAttachmentCrossPlatform {
		t.Fatalf("updated credential = %+v, found=%t", updated, ok)
	}
}
