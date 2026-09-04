// Package storagejson provides versioned JSON encoding for trusted server-side
// WebAuthn ceremony state and credential records. It does not authenticate,
// encrypt, store, or expose state to clients.
package storagejson

import (
	"bytes"
	"encoding/base64"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/internal/interfaceutil"
	"github.com/islishude/webauthn/protocol"
)

const (
	// EnvelopeVersion is the current storage envelope version.
	EnvelopeVersion = 3
	// MaxEnvelopeBytes bounds storage input before JSON decoding.
	MaxEnvelopeBytes = 1 << 20
	// MaxStoredPublicKeyBytes bounds a persisted raw COSE credential key.
	MaxStoredPublicKeyBytes = codec.MaxCredentialPublicKeyBytes

	kindRegistrationState   = "registration-state"
	kindAuthenticationState = "authentication-state"
	kindCredentialRecord    = "credential-record" //nolint:gosec // Public envelope discriminator, not a credential secret.
	legacyEnvelopeVersion   = 1
	previousEnvelopeVersion = 2
)

var (
	// ErrInvalidEnvelope reports malformed or internally inconsistent storage JSON.
	ErrInvalidEnvelope = errors.New("webauthn storage json envelope invalid")
	// ErrUnsupportedVersion reports a storage envelope version this package cannot decode.
	ErrUnsupportedVersion = errors.New("webauthn storage json version unsupported")
	// ErrUnsupportedExtensionValue reports an extension state value that cannot be represented losslessly.
	ErrUnsupportedExtensionValue = errors.New("webauthn storage json extension value unsupported")
)

type envelope struct {
	Version             int                     `json:"version"`
	Kind                string                  `json:"kind"`
	RegistrationState   *registrationStateDTO   `json:"registrationState,omitempty"`
	AuthenticationState *authenticationStateDTO `json:"authenticationState,omitempty"`
	CredentialRecord    *credentialRecordDTO    `json:"credentialRecord,omitempty"`
}

type originPolicyDTO struct {
	AllowedOrigins                   []string `json:"allowedOrigins"`
	AllowedTopOrigins                []string `json:"allowedTopOrigins,omitempty"`
	AllowCrossOriginWithoutTopOrigin bool     `json:"allowCrossOriginWithoutTopOrigin,omitempty"`
	AllowRelatedOrigins              bool     `json:"allowRelatedOrigins,omitempty"`
}

type registrationStateDTO struct {
	Challenge                 string                  `json:"challenge"`
	RPID                      string                  `json:"rpId"`
	OriginPolicy              originPolicyDTO         `json:"originPolicy"`
	ConditionalMediation      bool                    `json:"conditionalMediation,omitempty"`
	UserHandle                string                  `json:"userHandle"`
	RequestedUserVerification string                  `json:"requestedUserVerification"`
	RequestedExtensions       map[string]encodedValue `json:"requestedExtensions,omitempty"`
	ExtensionBindings         []extensionBindingDTO   `json:"extensionBindings,omitempty"`
	AllowedAlgorithms         []int64                 `json:"allowedAlgorithms"`
	Attestation               string                  `json:"attestation"`
	ExpiresAt                 string                  `json:"expiresAt"`
}

type credentialDescriptorDTO struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

type authenticationStateDTO struct {
	Challenge                 string                    `json:"challenge"`
	RPID                      string                    `json:"rpId"`
	OriginPolicy              originPolicyDTO           `json:"originPolicy"`
	RequestedUserVerification string                    `json:"requestedUserVerification"`
	RequestedExtensions       map[string]encodedValue   `json:"requestedExtensions,omitempty"`
	ExtensionBindings         []extensionBindingDTO     `json:"extensionBindings,omitempty"`
	AllowCredentials          []credentialDescriptorDTO `json:"allowCredentials,omitempty"`
	ExpectedUserHandle        string                    `json:"expectedUserHandle,omitempty"`
	ExpiresAt                 string                    `json:"expiresAt"`
}

type extensionBindingDTO struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

type credentialRecordDTO struct {
	Type                    stdjson.RawMessage `json:"type,omitempty"`
	ID                      string             `json:"id"`
	PublicKeyCOSE           string             `json:"publicKeyCose"`
	UserHandle              string             `json:"userHandle"`
	RPID                    string             `json:"rpId"`
	AAGUID                  string             `json:"aaguid"`
	SignCount               uint32             `json:"signCount"`
	Transports              []string           `json:"transports,omitempty"`
	BackupEligible          bool               `json:"backupEligible"`
	BackupState             bool               `json:"backupState"`
	UVInitialized           bool               `json:"uvInitialized"`
	AuthenticatorAttachment string             `json:"authenticatorAttachment,omitempty"`
	AttestationType         string             `json:"attestationType"`
}

// MarshalRegistrationState encodes registration state for trusted server-side storage.
func MarshalRegistrationState(state webauthn.RegistrationState) ([]byte, error) {
	if err := validateRegistrationState(state); err != nil {
		return nil, err
	}
	extensions, err := encodeExtensionValues(state.RequestedExtensions)
	if err != nil {
		return nil, err
	}
	algorithms := make([]int64, len(state.AllowedAlgorithms))
	for i, algorithm := range state.AllowedAlgorithms {
		algorithms[i] = int64(algorithm)
	}
	payload := &registrationStateDTO{
		Challenge:                 encodeBytes(state.Challenge.Bytes()),
		RPID:                      state.RPID,
		OriginPolicy:              originPolicyToDTO(state.OriginPolicy),
		ConditionalMediation:      state.ConditionalMediation,
		UserHandle:                encodeBytes(state.UserHandle.Bytes()),
		RequestedUserVerification: string(state.RequestedUserVerification),
		RequestedExtensions:       extensions,
		ExtensionBindings:         extensionBindingsToDTO(state.ExtensionBindings),
		AllowedAlgorithms:         algorithms,
		Attestation:               string(state.Attestation),
		ExpiresAt:                 formatTime(state.ExpiresAt),
	}
	return marshalEnvelope(envelope{Version: EnvelopeVersion, Kind: kindRegistrationState, RegistrationState: payload})
}

// UnmarshalRegistrationState decodes and validates registration state.
func UnmarshalRegistrationState(data []byte) (webauthn.RegistrationState, error) {
	envelope, err := unmarshalEnvelope(data, kindRegistrationState)
	if err != nil {
		return webauthn.RegistrationState{}, err
	}
	payload := envelope.RegistrationState
	challenge, err := decodeChallenge(payload.Challenge)
	if err != nil {
		return webauthn.RegistrationState{}, err
	}
	userHandle, err := decodeUserHandle("userHandle", payload.UserHandle, true)
	if err != nil {
		return webauthn.RegistrationState{}, err
	}
	expiresAt, err := parseTime(payload.ExpiresAt)
	if err != nil {
		return webauthn.RegistrationState{}, err
	}
	extensions, err := decodeExtensionValues(payload.RequestedExtensions)
	if err != nil {
		return webauthn.RegistrationState{}, err
	}
	if envelope.Version < EnvelopeVersion && (len(extensions) != 0 || len(payload.ExtensionBindings) != 0 || payload.OriginPolicy.AllowRelatedOrigins) {
		return webauthn.RegistrationState{}, fmt.Errorf("%w: legacy state contains v3-only policy or extension bindings", ErrInvalidEnvelope)
	}
	algorithms := make([]protocol.COSEAlgorithmIdentifier, len(payload.AllowedAlgorithms))
	for i, algorithm := range payload.AllowedAlgorithms {
		algorithms[i] = protocol.COSEAlgorithmIdentifier(algorithm)
	}
	state := webauthn.RegistrationState{
		Challenge:                 challenge,
		RPID:                      payload.RPID,
		OriginPolicy:              originPolicyFromDTO(payload.OriginPolicy),
		ConditionalMediation:      payload.ConditionalMediation,
		UserHandle:                userHandle,
		RequestedUserVerification: protocol.UserVerificationRequirement(payload.RequestedUserVerification),
		RequestedExtensions:       protocol.ExtensionInputs(extensions),
		ExtensionBindings:         extensionBindingsFromDTO(payload.ExtensionBindings),
		AllowedAlgorithms:         algorithms,
		Attestation:               protocol.AttestationConveyancePreference(payload.Attestation),
		ExpiresAt:                 expiresAt,
	}
	if err := validateRegistrationState(state); err != nil {
		return webauthn.RegistrationState{}, err
	}
	return state, nil
}

// MarshalAuthenticationState encodes authentication state for trusted server-side storage.
func MarshalAuthenticationState(state webauthn.AuthenticationState) ([]byte, error) {
	if err := validateAuthenticationState(state); err != nil {
		return nil, err
	}
	extensions, err := encodeExtensionValues(state.RequestedExtensions)
	if err != nil {
		return nil, err
	}
	payload := &authenticationStateDTO{
		Challenge:                 encodeBytes(state.Challenge.Bytes()),
		RPID:                      state.RPID,
		OriginPolicy:              originPolicyToDTO(state.OriginPolicy),
		RequestedUserVerification: string(state.RequestedUserVerification),
		RequestedExtensions:       extensions,
		ExtensionBindings:         extensionBindingsToDTO(state.ExtensionBindings),
		AllowCredentials:          descriptorsToDTO(state.AllowCredentials),
		ExpiresAt:                 formatTime(state.ExpiresAt),
	}
	if state.ExpectedUserHandle.Len() != 0 {
		payload.ExpectedUserHandle = encodeBytes(state.ExpectedUserHandle.Bytes())
	}
	return marshalEnvelope(envelope{Version: EnvelopeVersion, Kind: kindAuthenticationState, AuthenticationState: payload})
}

// UnmarshalAuthenticationState decodes and validates authentication state.
func UnmarshalAuthenticationState(data []byte) (webauthn.AuthenticationState, error) {
	envelope, err := unmarshalEnvelope(data, kindAuthenticationState)
	if err != nil {
		return webauthn.AuthenticationState{}, err
	}
	payload := envelope.AuthenticationState
	challenge, err := decodeChallenge(payload.Challenge)
	if err != nil {
		return webauthn.AuthenticationState{}, err
	}
	expectedUserHandle, err := decodeUserHandle("expectedUserHandle", payload.ExpectedUserHandle, false)
	if err != nil {
		return webauthn.AuthenticationState{}, err
	}
	expiresAt, err := parseTime(payload.ExpiresAt)
	if err != nil {
		return webauthn.AuthenticationState{}, err
	}
	extensions, err := decodeExtensionValues(payload.RequestedExtensions)
	if err != nil {
		return webauthn.AuthenticationState{}, err
	}
	if envelope.Version < EnvelopeVersion && (len(extensions) != 0 || len(payload.ExtensionBindings) != 0 || payload.OriginPolicy.AllowRelatedOrigins) {
		return webauthn.AuthenticationState{}, fmt.Errorf("%w: legacy state contains v3-only policy or extension bindings", ErrInvalidEnvelope)
	}
	descriptors, err := descriptorsFromDTO(payload.AllowCredentials)
	if err != nil {
		return webauthn.AuthenticationState{}, err
	}
	state := webauthn.AuthenticationState{
		Challenge:                 challenge,
		RPID:                      payload.RPID,
		OriginPolicy:              originPolicyFromDTO(payload.OriginPolicy),
		RequestedUserVerification: protocol.UserVerificationRequirement(payload.RequestedUserVerification),
		RequestedExtensions:       protocol.ExtensionInputs(extensions),
		ExtensionBindings:         extensionBindingsFromDTO(payload.ExtensionBindings),
		AllowCredentials:          descriptors,
		ExpectedUserHandle:        expectedUserHandle,
		ExpiresAt:                 expiresAt,
	}
	if err := validateAuthenticationState(state); err != nil {
		return webauthn.AuthenticationState{}, err
	}
	return state, nil
}

// MarshalCredentialRecord encodes a credential record, including its raw COSE key.
func MarshalCredentialRecord(record webauthn.CredentialRecord) ([]byte, error) {
	if err := validateCredentialRecord(record); err != nil {
		return nil, err
	}
	credentialType, err := stdjson.Marshal(record.Type)
	if err != nil {
		return nil, fmt.Errorf("%w: credential type", ErrInvalidEnvelope)
	}
	payload := &credentialRecordDTO{
		Type:                    credentialType,
		ID:                      encodeBytes(record.ID.Bytes()),
		PublicKeyCOSE:           encodeBytes(record.PublicKey.Raw()),
		UserHandle:              encodeBytes(record.UserHandle.Bytes()),
		RPID:                    record.RPID,
		AAGUID:                  encodeBytes(record.AAGUID.Bytes()),
		SignCount:               record.SignCount,
		Transports:              transportsToStrings(record.Transports),
		BackupEligible:          record.BackupEligible,
		BackupState:             record.BackupState,
		UVInitialized:           record.UVInitialized,
		AuthenticatorAttachment: string(record.AuthenticatorAttachment),
		AttestationType:         string(record.AttestationType),
	}
	return marshalEnvelope(envelope{Version: EnvelopeVersion, Kind: kindCredentialRecord, CredentialRecord: payload})
}

// UnmarshalCredentialRecord decodes a credential record and reconstructs its
// typed public key with decoder.
func UnmarshalCredentialRecord(data []byte, decoder codec.COSEKeyDecoder) (webauthn.CredentialRecord, error) {
	if interfaceutil.IsNil(decoder) {
		return webauthn.CredentialRecord{}, fmt.Errorf("%w: credential key decoder is required", ErrInvalidEnvelope)
	}
	envelope, err := unmarshalEnvelope(data, kindCredentialRecord)
	if err != nil {
		return webauthn.CredentialRecord{}, err
	}
	payload := envelope.CredentialRecord
	credentialType, err := credentialRecordType(envelope.Version, payload.Type)
	if err != nil {
		return webauthn.CredentialRecord{}, err
	}
	idBytes, err := decodeBytes("id", payload.ID, 1, protocol.MaxCredentialIDLength)
	if err != nil {
		return webauthn.CredentialRecord{}, err
	}
	id, err := protocol.NewCredentialID(idBytes)
	if err != nil {
		return webauthn.CredentialRecord{}, invalid(err)
	}
	userHandle, err := decodeUserHandle("userHandle", payload.UserHandle, true)
	if err != nil {
		return webauthn.CredentialRecord{}, err
	}
	publicKeyBytes, err := decodeBytes("publicKeyCose", payload.PublicKeyCOSE, 1, MaxStoredPublicKeyBytes)
	if err != nil {
		return webauthn.CredentialRecord{}, err
	}
	publicKey, err := decoder.DecodeCredentialPublicKey(publicKeyBytes)
	if err != nil || !bytes.Equal(publicKey.Raw(), publicKeyBytes) {
		return webauthn.CredentialRecord{}, fmt.Errorf("%w: invalid credential public key", ErrInvalidEnvelope)
	}
	aaguidBytes, err := decodeBytes("aaguid", payload.AAGUID, protocol.AAGUIDLength, protocol.AAGUIDLength)
	if err != nil {
		return webauthn.CredentialRecord{}, err
	}
	var aaguid protocol.AAGUID
	copy(aaguid[:], aaguidBytes)
	record := webauthn.CredentialRecord{
		Type:                    credentialType,
		ID:                      id,
		PublicKey:               publicKey,
		UserHandle:              userHandle,
		RPID:                    payload.RPID,
		AAGUID:                  aaguid,
		SignCount:               payload.SignCount,
		Transports:              stringsToTransports(payload.Transports),
		BackupEligible:          payload.BackupEligible,
		BackupState:             payload.BackupState,
		UVInitialized:           payload.UVInitialized,
		AuthenticatorAttachment: protocol.AuthenticatorAttachment(payload.AuthenticatorAttachment),
		AttestationType:         attestation.Type(payload.AttestationType),
	}
	if err := validateCredentialRecord(record); err != nil {
		return webauthn.CredentialRecord{}, err
	}
	return record, nil
}

func credentialRecordType(version int, raw stdjson.RawMessage) (protocol.PublicKeyCredentialType, error) {
	if len(raw) == 0 {
		if version == legacyEnvelopeVersion {
			return protocol.CredentialTypePublicKey, nil
		}
		return "", fmt.Errorf("%w: credential type is required", ErrInvalidEnvelope)
	}

	var value string
	if err := stdjson.Unmarshal(raw, &value); err != nil || value == "" {
		return "", fmt.Errorf("%w: credential type", ErrInvalidEnvelope)
	}
	return protocol.PublicKeyCredentialType(value), nil
}

func marshalEnvelope(value envelope) ([]byte, error) {
	encoded, err := stdjson.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	if len(encoded) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: envelope too large", ErrInvalidEnvelope)
	}
	return encoded, nil
}

func unmarshalEnvelope(data []byte, expectedKind string) (envelope, error) {
	if len(data) == 0 || len(data) > MaxEnvelopeBytes {
		return envelope{}, fmt.Errorf("%w: envelope size", ErrInvalidEnvelope)
	}
	decoder := stdjson.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value envelope
	if err := decoder.Decode(&value); err != nil {
		return envelope{}, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return envelope{}, fmt.Errorf("%w: trailing data", ErrInvalidEnvelope)
	}
	if value.Version != EnvelopeVersion && value.Version != previousEnvelopeVersion && value.Version != legacyEnvelopeVersion {
		return envelope{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, value.Version)
	}
	if value.Kind != expectedKind {
		return envelope{}, fmt.Errorf("%w: envelope kind", ErrInvalidEnvelope)
	}
	payloads := 0
	for _, present := range []bool{value.RegistrationState != nil, value.AuthenticationState != nil, value.CredentialRecord != nil} {
		if present {
			payloads++
		}
	}
	if payloads != 1 ||
		(expectedKind == kindRegistrationState && value.RegistrationState == nil) ||
		(expectedKind == kindAuthenticationState && value.AuthenticationState == nil) ||
		(expectedKind == kindCredentialRecord && value.CredentialRecord == nil) {
		return envelope{}, fmt.Errorf("%w: envelope payload", ErrInvalidEnvelope)
	}
	return value, nil
}

func extensionBindingsToDTO(bindings []extension.Binding) []extensionBindingDTO {
	if bindings == nil {
		return nil
	}
	out := make([]extensionBindingDTO, len(bindings))
	for i, binding := range bindings {
		out[i] = extensionBindingDTO{ID: binding.ID, Revision: binding.Revision}
	}
	return out
}

func extensionBindingsFromDTO(bindings []extensionBindingDTO) []extension.Binding {
	if bindings == nil {
		return nil
	}
	out := make([]extension.Binding, len(bindings))
	for i, binding := range bindings {
		out[i] = extension.Binding{ID: binding.ID, Revision: binding.Revision}
	}
	return out
}

func validateRegistrationState(state webauthn.RegistrationState) error {
	if err := state.Validate(); err != nil {
		return invalid(err)
	}
	return nil
}

func validateAuthenticationState(state webauthn.AuthenticationState) error {
	if err := state.Validate(); err != nil {
		return invalid(err)
	}
	return nil
}

func validateCredentialRecord(record webauthn.CredentialRecord) error {
	if err := record.Validate(); err != nil {
		return invalid(err)
	}
	return nil
}

func originPolicyToDTO(policy webauthn.OriginPolicy) originPolicyDTO {
	return originPolicyDTO{
		AllowedOrigins:                   slices.Clone(policy.AllowedOrigins),
		AllowedTopOrigins:                slices.Clone(policy.AllowedTopOrigins),
		AllowCrossOriginWithoutTopOrigin: policy.AllowCrossOriginWithoutTopOrigin,
		AllowRelatedOrigins:              policy.AllowRelatedOrigins,
	}
}

func originPolicyFromDTO(policy originPolicyDTO) webauthn.OriginPolicy {
	return webauthn.OriginPolicy{
		AllowedOrigins:                   slices.Clone(policy.AllowedOrigins),
		AllowedTopOrigins:                slices.Clone(policy.AllowedTopOrigins),
		AllowCrossOriginWithoutTopOrigin: policy.AllowCrossOriginWithoutTopOrigin,
		AllowRelatedOrigins:              policy.AllowRelatedOrigins,
	}
}

func descriptorsToDTO(descriptors []protocol.CredentialDescriptor) []credentialDescriptorDTO {
	if descriptors == nil {
		return nil
	}
	out := make([]credentialDescriptorDTO, len(descriptors))
	for i, descriptor := range descriptors {
		out[i] = credentialDescriptorDTO{
			Type:       string(descriptor.Type),
			ID:         encodeBytes(descriptor.ID.Bytes()),
			Transports: transportsToStrings(descriptor.Transports),
		}
	}
	return out
}

func descriptorsFromDTO(descriptors []credentialDescriptorDTO) ([]protocol.CredentialDescriptor, error) {
	if descriptors == nil {
		return nil, nil
	}
	out := make([]protocol.CredentialDescriptor, len(descriptors))
	for i, descriptor := range descriptors {
		idBytes, err := decodeBytes("allowCredentials.id", descriptor.ID, 1, protocol.MaxCredentialIDLength)
		if err != nil {
			return nil, err
		}
		id, err := protocol.NewCredentialID(idBytes)
		if err != nil {
			return nil, invalid(err)
		}
		out[i] = protocol.CredentialDescriptor{
			Type:       protocol.PublicKeyCredentialType(descriptor.Type),
			ID:         id,
			Transports: stringsToTransports(descriptor.Transports),
		}
		if err := out[i].Validate(); err != nil {
			return nil, invalid(err)
		}
	}
	return out, nil
}

func transportsToStrings(transports []protocol.AuthenticatorTransport) []string {
	if transports == nil {
		return nil
	}
	out := make([]string, len(transports))
	for i, transport := range transports {
		out[i] = string(transport)
	}
	return out
}

func stringsToTransports(transports []string) []protocol.AuthenticatorTransport {
	if transports == nil {
		return nil
	}
	out := make([]protocol.AuthenticatorTransport, len(transports))
	for i, transport := range transports {
		out[i] = protocol.AuthenticatorTransport(transport)
	}
	return out
}

func decodeChallenge(encoded string) (protocol.Challenge, error) {
	raw, err := decodeBytes("challenge", encoded, protocol.MinChallengeLength, 0)
	if err != nil {
		return protocol.Challenge{}, err
	}
	challenge, err := protocol.NewChallenge(raw)
	if err != nil {
		return protocol.Challenge{}, invalid(err)
	}
	return challenge, nil
}

func decodeUserHandle(field string, encoded string, required bool) (protocol.UserHandle, error) {
	if encoded == "" && !required {
		return protocol.UserHandle{}, nil
	}
	raw, err := decodeBytes(field, encoded, 1, protocol.MaxUserHandleLength)
	if err != nil {
		return protocol.UserHandle{}, err
	}
	handle, err := protocol.NewUserHandle(raw)
	if err != nil {
		return protocol.UserHandle{}, invalid(err)
	}
	return handle, nil
}

func encodeBytes(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeBytes(field string, encoded string, min int, max int) ([]byte, error) {
	encoding := base64.RawURLEncoding.Strict()
	raw, err := encoding.DecodeString(encoded)
	if err != nil || encoding.EncodeToString(raw) != encoded || len(raw) < min || (max > 0 && len(raw) > max) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidEnvelope, field)
	}
	return raw, nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(encoded string) (time.Time, error) {
	value, err := time.Parse(time.RFC3339Nano, encoded)
	if err != nil || value.IsZero() || value.UTC().Format(time.RFC3339Nano) != encoded {
		return time.Time{}, fmt.Errorf("%w: expiresAt", ErrInvalidEnvelope)
	}
	return value.UTC(), nil
}

func invalid(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
}
