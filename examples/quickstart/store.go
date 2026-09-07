package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/protocol"
)

// Production applications replace these maps with their own account database
// and atomic ceremony/session store. Every stored record crosses a copy boundary.
type memoryStore struct {
	mu             sync.Mutex
	registration   map[string]webauthn.RegistrationState
	authentication map[string]webauthn.AuthenticationState
	credentials    map[string]webauthn.CredentialRecord
	sessions       map[string]time.Time
}

func newMemoryStore() *memoryStore {
	return &memoryStore{registration: make(map[string]webauthn.RegistrationState), authentication: make(map[string]webauthn.AuthenticationState), credentials: make(map[string]webauthn.CredentialRecord), sessions: make(map[string]time.Time)}
}

func token() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (s *memoryStore) prune(now time.Time) {
	for id, state := range s.registration {
		if !now.Before(state.ExpiresAt) {
			delete(s.registration, id)
		}
	}
	for id, state := range s.authentication {
		if !now.Before(state.ExpiresAt) {
			delete(s.authentication, id)
		}
	}
	for id, expiry := range s.sessions {
		if !now.Before(expiry) {
			delete(s.sessions, id)
		}
	}
}

func (s *memoryStore) insert(record webauthn.CredentialRecord) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(record.ID.Bytes())
	if _, ok := s.credentials[key]; ok || len(s.credentials) >= 64 {
		return false
	}
	s.credentials[key] = record.Clone()
	return true
}

func (s *memoryStore) lookup(id protocol.RawID, user protocol.UserHandle) (webauthn.CredentialRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.credentials[string(id.Bytes())]
	return record.Clone(), ok && record.UserHandle.Equal(user)
}

func (s *memoryStore) descriptors() []protocol.CredentialDescriptor {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]protocol.CredentialDescriptor, 0, len(s.credentials))
	for _, c := range s.credentials {
		out = append(out, protocol.CredentialDescriptor{Type: c.Type, ID: c.ID, Transports: c.Clone().Transports})
	}
	return out
}

func (s *memoryStore) update(u webauthn.CredentialUpdate) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(u.ID.Bytes())
	c, ok := s.credentials[key]
	if !ok || c.SignCount != u.PreviousSignCount || c.BackupState != u.PreviousBackupState || c.UVInitialized != u.PreviousUVInitialized || c.AuthenticatorAttachment != u.PreviousAuthenticatorAttachment {
		return false
	}
	if u.SignCountChanged {
		c.SignCount = u.SignCount
	}
	if u.BackupStateChanged {
		c.BackupState = u.BackupState
	}
	if u.UVInitializedChanged {
		c.UVInitialized = u.UVInitialized
	}
	if u.AuthenticatorAttachmentChanged {
		c.AuthenticatorAttachment = u.AuthenticatorAttachment
	}
	s.credentials[key] = c
	return true
}
