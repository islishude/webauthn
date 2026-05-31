package protocol_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/islishude/webauthn/protocol"
)

func TestParseAuthenticatorDataWithAttestedCredentialData(t *testing.T) {
	t.Parallel()

	credentialID := []byte("credential-id")
	authData := buildProtocolAuthenticatorData(t, 0x01|0x04|0x40, credentialID, []byte{0xa1, 0x01, 0x02})

	raw, err := protocol.NewAuthenticatorData(authData)
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}

	parsed, err := protocol.ParseAuthenticatorData(raw)
	if err != nil {
		t.Fatalf("ParseAuthenticatorData() error = %v", err)
	}
	if !parsed.Flags.UserPresent() || !parsed.Flags.UserVerified() || !parsed.Flags.HasAttestedCredentialData() {
		t.Fatalf("flags not parsed correctly: %#x", parsed.Flags)
	}
	if parsed.SignCount != 7 {
		t.Fatalf("SignCount = %d, want 7", parsed.SignCount)
	}
	if !bytes.Equal(parsed.AttestedCredentialData.CredentialID.Bytes(), credentialID) {
		t.Fatalf("CredentialID = %x, want %x", parsed.AttestedCredentialData.CredentialID.Bytes(), credentialID)
	}
}

func TestParseAuthenticatorDataRejectsTruncatedAttestedCredentialData(t *testing.T) {
	t.Parallel()

	raw, err := protocol.NewAuthenticatorData(bytes.Repeat([]byte{0x01}, protocol.MinAuthenticatorDataLength))
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}

	bytes := raw.Bytes()
	bytes[32] = 0x40
	truncated, err := protocol.NewAuthenticatorData(bytes)
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}

	_, err = protocol.ParseAuthenticatorData(truncated)
	if !errors.Is(err, protocol.ErrMalformedAuthenticatorData) {
		t.Fatalf("ParseAuthenticatorData() error = %v, want ErrMalformedAuthenticatorData", err)
	}
}

func buildProtocolAuthenticatorData(t *testing.T, flags byte, credentialID []byte, credentialPublicKey []byte) []byte {
	t.Helper()

	rpIDHash := sha256.Sum256([]byte("example.com"))
	out := append([]byte{}, rpIDHash[:]...)
	out = append(out, flags)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 7)
	out = append(out, counter...)
	out = append(out, bytes.Repeat([]byte{0x01}, protocol.AAGUIDLength)...)
	credentialIDLength := make([]byte, 2)
	binary.BigEndian.PutUint16(credentialIDLength, checkedUint16Length(t, len(credentialID)))
	out = append(out, credentialIDLength...)
	out = append(out, credentialID...)
	out = append(out, credentialPublicKey...)
	return out
}

func checkedUint16Length(t *testing.T, length int) uint16 {
	t.Helper()

	if length < 0 || length > protocol.MaxCredentialIDLength {
		t.Fatalf("length %d is outside uint16 range", length)
	}

	return uint16(length) //nolint:gosec // length is bounded by MaxCredentialIDLength before conversion.
}
