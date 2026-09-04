package webauthn

import (
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/internal/protocolidentifier"
)

var (
	// ErrInvalidCredentialRecord reports incomplete or internally inconsistent
	// caller-stored credential material.
	ErrInvalidCredentialRecord = errors.New("webauthn: invalid credential record")
)

// Validate checks registration state invariants that must hold independently
// of the caller's persistence representation.
func (state RegistrationState) Validate() error {
	if state.Challenge.Len() == 0 || state.RPID == "" {
		return ErrInvalidCeremonyState
	}
	if err := validateOriginPolicy(state.OriginPolicy); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}
	if err := validateRPIDOriginPolicy(state.RPID, state.OriginPolicy); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}
	if state.UserHandle.Len() == 0 {
		return fmt.Errorf("%w: user handle is required", ErrInvalidCeremonyState)
	}
	if state.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: expiry is required", ErrInvalidCeremonyState)
	}
	if len(state.AllowedAlgorithms) == 0 {
		return fmt.Errorf("%w: allowed algorithms are required", ErrInvalidCeremonyState)
	}
	for _, algorithm := range state.AllowedAlgorithms {
		if err := algorithm.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
		}
	}
	if !state.Attestation.Known() {
		return fmt.Errorf("%w: invalid attestation conveyance", ErrInvalidCeremonyState)
	}
	if err := validateUserVerification(state.RequestedUserVerification); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}
	if err := validateRequestedExtensionIDs(state.RequestedExtensions); err != nil {
		return err
	}
	return validateExtensionBindingState(state.RequestedExtensions, state.ExtensionBindings)
}

// Validate checks authentication state invariants that must hold independently
// of the caller's persistence representation.
func (state AuthenticationState) Validate() error {
	if state.Challenge.Len() == 0 || state.RPID == "" {
		return ErrInvalidCeremonyState
	}
	if err := validateOriginPolicy(state.OriginPolicy); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}
	if err := validateRPIDOriginPolicy(state.RPID, state.OriginPolicy); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}
	if state.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: expiry is required", ErrInvalidCeremonyState)
	}
	if err := validateUserVerification(state.RequestedUserVerification); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}
	for _, descriptor := range state.AllowCredentials {
		if err := descriptor.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
		}
	}
	if err := validateRequestedExtensionIDs(state.RequestedExtensions); err != nil {
		return err
	}
	if err := validateExtensionBindingState(state.RequestedExtensions, state.ExtensionBindings); err != nil {
		return err
	}
	if err := validateStoredAuthenticationExtensionContext(state.RequestedExtensions, state.AllowCredentials); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}
	return nil
}

func validateExtensionBindingState(inputs map[string]any, bindings []extension.Binding) error {
	if len(bindings) > extension.MaxEntries {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, extension.ErrTooManyEntries)
	}
	if !slices.IsSortedFunc(bindings, func(a, b extension.Binding) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	}) {
		return fmt.Errorf("%w: extension bindings are not sorted", ErrInvalidCeremonyState)
	}
	bound := make(map[string]extension.Binding, len(bindings))
	previous := ""
	for _, binding := range bindings {
		if !binding.Valid() || binding.ID == previous {
			return fmt.Errorf("%w: extension binding is invalid", ErrInvalidCeremonyState)
		}
		if _, requested := inputs[binding.ID]; !requested {
			return fmt.Errorf("%w: extension binding was not requested", ErrInvalidCeremonyState)
		}
		bound[binding.ID] = binding
		previous = binding.ID
	}
	for id := range inputs {
		expected, builtIn := extension.BuiltInBinding(id)
		if builtIn && bound[id] != expected {
			return fmt.Errorf("%w: %w: %s", ErrInvalidCeremonyState, extension.ErrBindingMismatch, id)
		}
	}
	return nil
}

func validateRequestedExtensionIDs(inputs map[string]any) error {
	if len(inputs) > extension.MaxEntries {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, extension.ErrTooManyEntries)
	}
	for id := range inputs {
		if !protocolidentifier.Valid(id) {
			return fmt.Errorf("%w: invalid extension id", ErrInvalidCeremonyState)
		}
	}
	return nil
}

// Validate checks credential record invariants expected by authentication and
// optional storage adapters.
func (record CredentialRecord) Validate() error {
	if err := record.Type.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCredentialRecord, err)
	}
	if record.ID.Len() == 0 || record.UserHandle.Len() == 0 || record.RPID == "" {
		return fmt.Errorf("%w: required field is missing", ErrInvalidCredentialRecord)
	}
	if err := record.PublicKey.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCredentialRecord, err)
	}
	if record.BackupState && !record.BackupEligible {
		return fmt.Errorf("%w: %w", ErrInvalidCredentialRecord, ErrInvalidBackupState)
	}
	if record.AuthenticatorAttachment != "" && !record.AuthenticatorAttachment.Known() {
		return fmt.Errorf("%w: authenticator attachment", ErrInvalidCredentialRecord)
	}
	if !record.AttestationType.Known() {
		return fmt.Errorf("%w: attestation type", ErrInvalidCredentialRecord)
	}
	return nil
}

// Clone returns a credential record whose mutable slices do not alias record.
func (record CredentialRecord) Clone() CredentialRecord {
	record.Transports = slices.Clone(record.Transports)
	return record
}
