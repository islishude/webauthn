package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	// AAGUIDLength is the fixed authenticator attestation GUID length.
	AAGUIDLength = 16
	// RPIDHashLength is the SHA-256 output size used for rpIdHash.
	RPIDHashLength = 32

	authDataFlagUP = byte(0x01)
	authDataFlagUV = byte(0x04)
	authDataFlagBE = byte(0x08)
	authDataFlagBS = byte(0x10)
	authDataFlagAT = byte(0x40)
	authDataFlagED = byte(0x80)
)

var (
	// ErrMalformedAuthenticatorData reports authenticator data with an
	// inconsistent or truncated WebAuthn-specific structure.
	ErrMalformedAuthenticatorData = errors.New("malformed authenticator data")
	// ErrAttestedCredentialDataMissing reports registration authenticator data
	// without the AT flag and attested credential data.
	ErrAttestedCredentialDataMissing = errors.New("attested credential data missing")
)

// AAGUID is an authenticator attestation GUID.
type AAGUID [AAGUIDLength]byte

// Bytes returns a defensive copy.
func (a AAGUID) Bytes() []byte {
	return cloneBytes(a[:])
}

// AuthenticatorFlags exposes authenticator data flags.
type AuthenticatorFlags byte

// UserPresent reports whether the UP flag is set.
func (f AuthenticatorFlags) UserPresent() bool {
	return byte(f)&authDataFlagUP != 0
}

// UserVerified reports whether the UV flag is set.
func (f AuthenticatorFlags) UserVerified() bool {
	return byte(f)&authDataFlagUV != 0
}

// BackupEligible reports whether the BE flag is set.
func (f AuthenticatorFlags) BackupEligible() bool {
	return byte(f)&authDataFlagBE != 0
}

// BackupState reports whether the BS flag is set.
func (f AuthenticatorFlags) BackupState() bool {
	return byte(f)&authDataFlagBS != 0
}

// HasAttestedCredentialData reports whether the AT flag is set.
func (f AuthenticatorFlags) HasAttestedCredentialData() bool {
	return byte(f)&authDataFlagAT != 0
}

// HasExtensionData reports whether the ED flag is set.
func (f AuthenticatorFlags) HasExtensionData() bool {
	return byte(f)&authDataFlagED != 0
}

// AttestedCredentialData is the fixed WebAuthn attested credential data prefix
// plus the remaining credentialPublicKey and optional extensions bytes.
type AttestedCredentialData struct {
	AAGUID                           AAGUID
	CredentialID                     CredentialID
	CredentialPublicKeyAndExtensions []byte
}

// ParsedAuthenticatorData is authenticator data split into WebAuthn-specific
// fields. COSE key and extension CBOR decoding happen behind codec adapters.
type ParsedAuthenticatorData struct {
	Raw                    AuthenticatorData
	RPIDHash               []byte
	Flags                  AuthenticatorFlags
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	ExtensionData          []byte
}

// ParseAuthenticatorData parses the WebAuthn authenticator data layout.
func ParseAuthenticatorData(raw AuthenticatorData) (ParsedAuthenticatorData, error) {
	bytes := raw.Bytes()
	if len(bytes) < MinAuthenticatorDataLength {
		return ParsedAuthenticatorData{}, ErrMalformedAuthenticatorData
	}

	parsed := ParsedAuthenticatorData{
		Raw:       raw,
		RPIDHash:  cloneBytes(bytes[:RPIDHashLength]),
		Flags:     AuthenticatorFlags(bytes[RPIDHashLength]),
		SignCount: binary.BigEndian.Uint32(bytes[RPIDHashLength+1 : MinAuthenticatorDataLength]),
	}

	if !parsed.Flags.HasAttestedCredentialData() {
		extensionData := bytes[MinAuthenticatorDataLength:]
		switch {
		case parsed.Flags.HasExtensionData() && len(extensionData) == 0:
			return ParsedAuthenticatorData{}, ErrMalformedAuthenticatorData
		case parsed.Flags.HasExtensionData():
			parsed.ExtensionData = cloneBytes(extensionData)
		case len(extensionData) != 0:
			return ParsedAuthenticatorData{}, ErrMalformedAuthenticatorData
		}

		return parsed, nil
	}

	attested, err := parseAttestedCredentialData(bytes[MinAuthenticatorDataLength:])
	if err != nil {
		return ParsedAuthenticatorData{}, err
	}
	parsed.AttestedCredentialData = &attested

	return parsed, nil
}

func parseAttestedCredentialData(data []byte) (AttestedCredentialData, error) {
	if len(data) < AAGUIDLength+2 {
		return AttestedCredentialData{}, ErrMalformedAuthenticatorData
	}

	var aaguid AAGUID
	copy(aaguid[:], data[:AAGUIDLength])

	credentialIDLength := int(binary.BigEndian.Uint16(data[AAGUIDLength : AAGUIDLength+2]))
	credentialIDStart := AAGUIDLength + 2
	credentialIDEnd := credentialIDStart + credentialIDLength
	if credentialIDLength == 0 || len(data) < credentialIDEnd {
		return AttestedCredentialData{}, ErrMalformedAuthenticatorData
	}
	if len(data) == credentialIDEnd {
		return AttestedCredentialData{}, ErrMalformedAuthenticatorData
	}

	credentialID, err := NewCredentialID(data[credentialIDStart:credentialIDEnd])
	if err != nil {
		return AttestedCredentialData{}, err
	}

	return AttestedCredentialData{
		AAGUID:                           aaguid,
		CredentialID:                     credentialID,
		CredentialPublicKeyAndExtensions: cloneBytes(data[credentialIDEnd:]),
	}, nil
}
