package main

import (
	"context"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/protocol"
	storagejson "github.com/islishude/webauthn/storage/json"
)

// The maps model application storage contracts, not a deployable account system.
// Account enrollment grants are provisioned by the host's existing authentication.
type memoryAccounts struct {
	mu     sync.Mutex
	users  map[string]protocol.UserEntity
	grants map[string]string
}

func (s *memoryAccounts) EnrollmentUser(ctx context.Context, session string) (protocol.UserEntity, error) {
	if err := ctx.Err(); err != nil {
		return protocol.UserEntity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, granted := s.grants[session]
	user, exists := s.users[name]
	if session == "" || !granted || !exists {
		return protocol.UserEntity{}, errDenied
	}
	return user, nil
}

func (s *memoryAccounts) UserByName(ctx context.Context, name string) (protocol.UserEntity, error) {
	if err := ctx.Err(); err != nil {
		return protocol.UserEntity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[name]
	if !ok {
		return protocol.UserEntity{}, errDenied
	}
	return user, nil
}

type memoryCeremonies struct {
	mu      sync.Mutex
	entries map[string]savedCeremony
	now     func() time.Time
}

func (s *memoryCeremonies) Save(ctx context.Context, id string, saved savedCeremony) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, entry := range s.entries {
		if !now.Before(entry.expires) {
			delete(s.entries, key)
		}
	}
	if _, exists := s.entries[id]; exists {
		return errDenied
	}
	if id == "" || saved.session == "" || !now.Before(saved.expires) || len(s.entries) >= 128 {
		return errDenied
	}
	saved.payload = slices.Clone(saved.payload)
	s.entries[id] = saved
	return nil
}

func (s *memoryCeremonies) Consume(ctx context.Context, id, session string, kind ceremonyKind, account *protocol.UserHandle) (savedCeremony, error) {
	if err := ctx.Err(); err != nil {
		return savedCeremony{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, ok := s.entries[id]
	if !ok || session == "" || saved.session != session || saved.kind != kind || (account != nil && !saved.account.Equal(*account)) {
		return savedCeremony{}, errDenied
	}
	delete(s.entries, id)
	if !s.now().Before(saved.expires) {
		return savedCeremony{}, webauthn.ErrCeremonyExpired
	}
	saved.payload = slices.Clone(saved.payload)
	return saved, nil
}

type savedCredential struct {
	payload []byte
	version uint64
}

type memoryCredentials struct {
	mu      sync.Mutex
	entries map[string]savedCredential
	decoder codec.COSEKeyDecoder
}

func (s *memoryCredentials) List(ctx context.Context, user protocol.UserHandle) ([]protocol.CredentialDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []protocol.CredentialDescriptor
	for _, entry := range s.entries {
		record, err := storagejson.UnmarshalCredentialRecord(entry.payload, s.decoder)
		if err != nil {
			return nil, err
		}
		if record.UserHandle.Equal(user) {
			out = append(out, record.Descriptor())
		}
	}
	return out, nil
}

func (s *memoryCredentials) Lookup(ctx context.Context, id protocol.RawID, user protocol.UserHandle) (credentialSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return credentialSnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[string(id.Bytes())]
	if !ok {
		return credentialSnapshot{}, errDenied
	}
	record, err := storagejson.UnmarshalCredentialRecord(entry.payload, s.decoder)
	if err != nil {
		return credentialSnapshot{}, err
	}
	if !record.UserHandle.Equal(user) {
		return credentialSnapshot{}, errDenied
	}
	return credentialSnapshot{record: record, version: entry.version}, nil
}

func (s *memoryCredentials) Insert(ctx context.Context, record webauthn.CredentialRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := storagejson.MarshalCredentialRecord(record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(record.ID.Bytes())
	if _, exists := s.entries[key]; exists {
		return errDuplicate
	}
	s.entries[key] = savedCredential{payload: payload, version: 1}
	return nil
}

func (s *memoryCredentials) Update(ctx context.Context, update webauthn.CredentialUpdate, version uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(update.ID.Bytes())
	entry, ok := s.entries[key]
	if !ok || entry.version != version || version == math.MaxUint64 {
		return webauthn.ErrCredentialUpdateConflict
	}
	record, err := storagejson.UnmarshalCredentialRecord(entry.payload, s.decoder)
	if err != nil {
		return err
	}
	next, err := update.ApplyTo(record)
	if err != nil {
		return err
	}
	payload, err := storagejson.MarshalCredentialRecord(next)
	if err != nil {
		return err
	}
	// Increment even for no-op updates: this application's row version detects
	// intervening writes that the library's value-only predicate cannot detect.
	s.entries[key] = savedCredential{payload: payload, version: version + 1}
	return nil
}

type memorySessions struct {
	mu      sync.Mutex
	entries map[string]protocol.UserHandle
}

func (s *memorySessions) Create(ctx context.Context, user protocol.UserHandle) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	id, err := ceremonyID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[id] = user
	return id, nil
}
