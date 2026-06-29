package main

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"sync"
	"time"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/protocol"
)

type user struct {
	Handle      protocol.UserHandle
	Email       string
	DisplayName string
	CreatedAt   time.Time
}

type credentialRecord struct {
	Credential webauthn.CredentialRecord
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type registrationState struct {
	Email string
	State webauthn.RegistrationState
}

type authenticationState struct {
	Email string
	State webauthn.AuthenticationState
}

type store struct {
	mu sync.Mutex

	usersByEmail  map[string]*user
	usersByHandle map[string]*user

	credentialsByID         map[string]*credentialRecord
	credentialsByUserHandle map[string][]*credentialRecord

	registrationStates   map[string]registrationState
	authenticationStates map[string]authenticationState
	sessions             map[string]string
}

func newStore() *store {
	return &store{
		usersByEmail:            make(map[string]*user),
		usersByHandle:           make(map[string]*user),
		credentialsByID:         make(map[string]*credentialRecord),
		credentialsByUserHandle: make(map[string][]*credentialRecord),
		registrationStates:      make(map[string]registrationState),
		authenticationStates:    make(map[string]authenticationState),
		sessions:                make(map[string]string),
	}
}

func (s *store) getOrCreateUser(email, displayName string) (*user, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user, ok := s.usersByEmail[email]; ok {
		return user, nil
	}
	handleBytes, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	handle, err := protocol.NewUserHandle(handleBytes)
	if err != nil {
		return nil, err
	}
	if displayName == "" {
		displayName = email
	}
	user := &user{
		Handle:      handle,
		Email:       email,
		DisplayName: displayName,
		CreatedAt:   time.Now(),
	}
	s.usersByEmail[email] = user
	s.usersByHandle[handleKey(handle)] = user
	return user, nil
}

func (s *store) userByEmail(email string) (*user, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.usersByEmail[email]
	return user, ok
}

func (s *store) userByHandle(handle protocol.UserHandle) (*user, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.usersByHandle[handleKey(handle)]
	return user, ok
}

func (s *store) saveRegistrationState(id string, state registrationState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registrationStates[id] = state
}

func (s *store) consumeRegistrationState(id string) (registrationState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.registrationStates[id]
	if ok {
		delete(s.registrationStates, id)
	}
	return state, ok
}

func (s *store) saveAuthenticationState(id string, state authenticationState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authenticationStates[id] = state
}

func (s *store) consumeAuthenticationState(id string) (authenticationState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.authenticationStates[id]
	if ok {
		delete(s.authenticationStates, id)
	}
	return state, ok
}

func (s *store) credentialExists(id protocol.CredentialID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.credentialsByID[credentialKey(id.Bytes())]
	return ok
}

func (s *store) saveCredential(record webauthn.CredentialRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	key := credentialKey(record.ID.Bytes())
	credential := &credentialRecord{Credential: record, CreatedAt: now, UpdatedAt: now}
	s.credentialsByID[key] = credential
	userKey := handleKey(record.UserHandle)
	s.credentialsByUserHandle[userKey] = append(s.credentialsByUserHandle[userKey], credential)
}

func (s *store) credentialByID(id []byte) (webauthn.CredentialRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.credentialsByID[credentialKey(id)]
	if !ok {
		return webauthn.CredentialRecord{}, false
	}
	return credential.Credential, true
}

func (s *store) credentialsForUser(handle protocol.UserHandle) []webauthn.CredentialRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.credentialsByUserHandle[handleKey(handle)]
	out := make([]webauthn.CredentialRecord, 0, len(records))
	for _, record := range records {
		out = append(out, record.Credential)
	}
	return out
}

func (s *store) updateCredential(update webauthn.CredentialUpdate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.credentialsByID[credentialKey(update.ID.Bytes())]
	if !ok {
		return
	}
	record.Credential.SignCount = update.SignCount
	record.Credential.BackupEligible = update.BackupEligible
	record.Credential.BackupState = update.BackupState
	record.UpdatedAt = time.Now()
}

func (s *store) createSession(handle protocol.UserHandle) (string, error) {
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = handleKey(handle)
	return id, nil
}

func (s *store) deleteSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *store) sessionUser(id string) (*user, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	handle, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	user, ok := s.usersByHandle[handle]
	return user, ok
}

func (s *store) debugCredential(id []byte) (webauthn.CredentialRecord, bool) {
	return s.credentialByID(id)
}

func randomToken() (string, error) {
	bytes, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func randomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

func credentialKey(bytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func handleKey(handle protocol.UserHandle) string {
	return base64.RawURLEncoding.EncodeToString(handle.Bytes())
}
