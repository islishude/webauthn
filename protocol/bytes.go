package protocol

import (
	"crypto/subtle"
	"fmt"
	"slices"
)

const (
	// MinChallengeLength is the minimum accepted challenge length in bytes.
	MinChallengeLength = 16
	// RecommendedChallengeLength is the target default challenge length.
	RecommendedChallengeLength = 32
	// MaxCredentialIDLength is the maximum credential ID length carried by
	// authenticator data's uint16 length field.
	MaxCredentialIDLength = 65535
	// MaxUserHandleLength is the WebAuthn user handle size limit in bytes.
	MaxUserHandleLength = 64
	// MinAuthenticatorDataLength is rpIdHash(32) + flags(1) + signCount(4).
	MinAuthenticatorDataLength = 37
)

// ByteLengthError reports a byte-oriented protocol value with an invalid size.
type ByteLengthError struct {
	Field  string
	Length int
	Min    int
	Max    int
}

func (e ByteLengthError) Error() string {
	switch {
	case e.Max > 0:
		return fmt.Sprintf("%s length %d is outside %d..%d bytes", e.Field, e.Length, e.Min, e.Max)
	default:
		return fmt.Sprintf("%s length %d is below %d bytes", e.Field, e.Length, e.Min)
	}
}

type byteValue struct {
	value []byte
}

func newByteValue(field string, value []byte, minLength int, maxLength int) (byteValue, error) {
	if len(value) < minLength || (maxLength > 0 && len(value) > maxLength) {
		return byteValue{}, ByteLengthError{
			Field:  field,
			Length: len(value),
			Min:    minLength,
			Max:    maxLength,
		}
	}

	return byteValue{value: slices.Clone(value)}, nil
}

func (v byteValue) bytes() []byte {
	return slices.Clone(v.value)
}

func (v byteValue) len() int {
	return len(v.value)
}

func (v byteValue) equalBytes(other []byte) bool {
	return subtle.ConstantTimeCompare(v.value, other) == 1
}

func (v byteValue) Equal(other byteValue) bool {
	return v.equalBytes(other.value)
}

func (v byteValue) IsNil() bool {
	return v.value == nil
}

// Challenge is a server-generated WebAuthn challenge.
type Challenge struct {
	byteValue
}

// NewChallenge stores a defensive copy of value after length validation.
func NewChallenge(value []byte) (Challenge, error) {
	v, err := newByteValue("challenge", value, MinChallengeLength, 0)
	if err != nil {
		return Challenge{}, err
	}

	return Challenge{byteValue: v}, nil
}

// Bytes returns a defensive copy.
func (c Challenge) Bytes() []byte {
	return c.bytes()
}

// Len returns the byte length.
func (c Challenge) Len() int {
	return c.len()
}

// Equal compares challenges without data-dependent comparison work for equal
// length inputs.
func (c Challenge) Equal(other Challenge) bool {
	return c.equalBytes(other.value)
}

// EqualBytes compares the challenge with caller-provided bytes.
func (c Challenge) EqualBytes(other []byte) bool {
	return c.equalBytes(other)
}

// CredentialID is an authenticator-generated credential identifier.
type CredentialID struct {
	byteValue
}

// NewCredentialID stores a defensive copy of value after length validation.
func NewCredentialID(value []byte) (CredentialID, error) {
	v, err := newByteValue("credential id", value, 1, MaxCredentialIDLength)
	if err != nil {
		return CredentialID{}, err
	}

	return CredentialID{byteValue: v}, nil
}

// Bytes returns a defensive copy.
func (id CredentialID) Bytes() []byte {
	return id.bytes()
}

// Len returns the byte length.
func (id CredentialID) Len() int {
	return id.len()
}

// UserHandle is an opaque relying-party user handle.
type UserHandle struct {
	byteValue
}

// NewUserHandle stores a defensive copy of value after length validation.
func NewUserHandle(value []byte) (UserHandle, error) {
	v, err := newByteValue("user handle", value, 1, MaxUserHandleLength)
	if err != nil {
		return UserHandle{}, err
	}

	return UserHandle{byteValue: v}, nil
}

// Bytes returns a defensive copy.
func (h UserHandle) Bytes() []byte {
	return h.bytes()
}

// Len returns the byte length.
func (h UserHandle) Len() int {
	return h.len()
}

// RawID is the browser credential raw ID as bytes.
type RawID struct {
	byteValue
}

// NewRawID stores a defensive copy of value after length validation.
func NewRawID(value []byte) (RawID, error) {
	v, err := newByteValue("raw id", value, 1, MaxCredentialIDLength)
	if err != nil {
		return RawID{}, err
	}

	return RawID{byteValue: v}, nil
}

// Bytes returns a defensive copy.
func (id RawID) Bytes() []byte {
	return id.bytes()
}

// AuthenticatorData is the raw authenticator data byte sequence.
type AuthenticatorData struct {
	byteValue
}

// NewAuthenticatorData stores a defensive copy of value after length validation.
func NewAuthenticatorData(value []byte) (AuthenticatorData, error) {
	v, err := newByteValue("authenticator data", value, MinAuthenticatorDataLength, 0)
	if err != nil {
		return AuthenticatorData{}, err
	}

	return AuthenticatorData{byteValue: v}, nil
}

// Bytes returns a defensive copy.
func (d AuthenticatorData) Bytes() []byte {
	return d.bytes()
}

// Len returns the byte length.
func (d AuthenticatorData) Len() int {
	return d.len()
}

// ClientDataJSON is the raw serialized client data JSON.
type ClientDataJSON struct {
	byteValue
}

// NewClientDataJSON stores a defensive copy of value after length validation.
func NewClientDataJSON(value []byte) (ClientDataJSON, error) {
	v, err := newByteValue("client data json", value, 1, 0)
	if err != nil {
		return ClientDataJSON{}, err
	}

	return ClientDataJSON{byteValue: v}, nil
}

// Bytes returns a defensive copy.
func (d ClientDataJSON) Bytes() []byte {
	return d.bytes()
}

// AttestationObject is the raw CBOR attestation object.
type AttestationObject struct {
	byteValue
}

// NewAttestationObject stores a defensive copy of value after length validation.
func NewAttestationObject(value []byte) (AttestationObject, error) {
	v, err := newByteValue("attestation object", value, 1, 0)
	if err != nil {
		return AttestationObject{}, err
	}

	return AttestationObject{byteValue: v}, nil
}

// Bytes returns a defensive copy.
func (o AttestationObject) Bytes() []byte {
	return o.bytes()
}

// Signature is a raw authenticator or attestation signature.
type Signature struct {
	byteValue
}

// NewSignature stores a defensive copy of value after length validation.
func NewSignature(value []byte) (Signature, error) {
	v, err := newByteValue("signature", value, 1, 0)
	if err != nil {
		return Signature{}, err
	}

	return Signature{byteValue: v}, nil
}

// Bytes returns a defensive copy.
func (s Signature) Bytes() []byte {
	return s.bytes()
}
