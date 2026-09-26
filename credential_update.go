package webauthn

import (
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/webauthn/protocol"
)

var (
	// ErrCredentialUpdateConflict reports a credential that no longer matches
	// the verified update's ID and previous mutable values.
	ErrCredentialUpdateConflict = errors.New("webauthn: credential update conflict")
	// ErrInvalidCredentialUpdate reports an update that produces an invalid record.
	ErrInvalidCredentialUpdate = errors.New("webauthn: invalid credential update")
)

// Descriptor returns a browser selection descriptor with copied transport hints.
func (record CredentialRecord) Descriptor() protocol.CredentialDescriptor {
	return protocol.CredentialDescriptor{Type: record.Type, ID: record.ID, Transports: slices.Clone(record.Transports)}
}

// ApplyTo compares ID and all four previous values, then applies changed fields
// to a copy. Use only updates returned by successful authentication verification.
// It does not perform storage I/O or enforce atomicity: callers must hold their
// storage lock or use an equivalent database transaction/conditional update.
// Value comparisons do not detect intervening writes that restore the same values.
func (update CredentialUpdate) ApplyTo(record CredentialRecord) (CredentialRecord, error) {
	if err := record.Validate(); err != nil {
		return CredentialRecord{}, err
	}
	if !record.ID.Equal(update.ID) || record.SignCount != update.PreviousSignCount ||
		record.BackupState != update.PreviousBackupState ||
		record.UVInitialized != update.PreviousUVInitialized ||
		record.AuthenticatorAttachment != update.PreviousAuthenticatorAttachment {
		return CredentialRecord{}, ErrCredentialUpdateConflict
	}
	next := record.Clone()
	if update.SignCountChanged {
		next.SignCount = update.SignCount
	}
	if update.BackupStateChanged {
		next.BackupState = update.BackupState
	}
	if update.UVInitializedChanged {
		next.UVInitialized = update.UVInitialized
	}
	if update.AuthenticatorAttachmentChanged {
		next.AuthenticatorAttachment = update.AuthenticatorAttachment
	}
	if err := next.Validate(); err != nil {
		return CredentialRecord{}, fmt.Errorf("%w: %w", ErrInvalidCredentialUpdate, err)
	}
	return next, nil
}
