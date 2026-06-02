package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/webauthn/protocol"
)

func TestChallengeCopiesInputAndOutput(t *testing.T) {
	t.Parallel()

	raw := bytes.Repeat([]byte{0x7a}, protocol.MinChallengeLength)
	challenge, err := protocol.NewChallenge(raw)
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}

	raw[0] = 0x01
	got := challenge.Bytes()
	if got[0] != 0x7a {
		t.Fatalf("challenge stored input alias, got first byte %#x", got[0])
	}

	got[1] = 0x02
	again := challenge.Bytes()
	if again[1] != 0x7a {
		t.Fatalf("challenge returned output alias, got second byte %#x", again[1])
	}
}

func TestByteValueLengthValidation(t *testing.T) {
	t.Parallel()

	_, err := protocol.NewChallenge(bytes.Repeat([]byte{0x01}, protocol.MinChallengeLength-1))
	assertByteLengthError(t, err)

	_, err = protocol.NewUserHandle(bytes.Repeat([]byte{0x01}, protocol.MaxUserHandleLength+1))
	assertByteLengthError(t, err)

	_, err = protocol.NewAuthenticatorData(bytes.Repeat([]byte{0x01}, protocol.MinAuthenticatorDataLength-1))
	assertByteLengthError(t, err)

	_, err = protocol.NewCredentialID(nil)
	assertByteLengthError(t, err)
}

func TestChallengeEqualUsesExactBytes(t *testing.T) {
	t.Parallel()

	raw := bytes.Repeat([]byte{0x01}, protocol.MinChallengeLength)
	same := bytes.Repeat([]byte{0x01}, protocol.MinChallengeLength)
	different := bytes.Repeat([]byte{0x02}, protocol.MinChallengeLength)

	challenge, err := protocol.NewChallenge(raw)
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}
	matching, err := protocol.NewChallenge(same)
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}
	nonmatching, err := protocol.NewChallenge(different)
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}

	if !challenge.Equal(matching) {
		t.Fatal("Equal() = false, want true")
	}
	if !challenge.EqualBytes(same) {
		t.Fatal("EqualBytes() = false, want true")
	}
	if challenge.Equal(nonmatching) {
		t.Fatal("Equal() = true for different bytes")
	}
	if challenge.EqualBytes(same[:len(same)-1]) {
		t.Fatal("EqualBytes() = true for truncated bytes")
	}
}

func TestCredentialIDTypedEqualityDoesNotUseDefensiveCopies(t *testing.T) {
	t.Parallel()

	raw := []byte("credential-1")
	credentialID, err := protocol.NewCredentialID(raw)
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}
	rawID, err := protocol.NewRawID(raw)
	if err != nil {
		t.Fatalf("NewRawID() error = %v", err)
	}
	other, err := protocol.NewCredentialID([]byte("credential-2"))
	if err != nil {
		t.Fatalf("NewCredentialID() other error = %v", err)
	}

	copyFromBytes := credentialID.Bytes()
	copyFromBytes[0] = 'x'
	if !credentialID.EqualRawID(rawID) {
		t.Fatal("EqualRawID() = false after mutating Bytes() copy")
	}
	if !credentialID.Equal(credentialID) {
		t.Fatal("Equal() = false for same credential ID")
	}
	if credentialID.Equal(other) {
		t.Fatal("Equal() = true for different credential IDs")
	}
}

func TestUserHandleTypedEqualityDoesNotUseDefensiveCopies(t *testing.T) {
	t.Parallel()

	handle, err := protocol.NewUserHandle([]byte("user-1"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	matching, err := protocol.NewUserHandle([]byte("user-1"))
	if err != nil {
		t.Fatalf("NewUserHandle() matching error = %v", err)
	}
	other, err := protocol.NewUserHandle([]byte("user-2"))
	if err != nil {
		t.Fatalf("NewUserHandle() other error = %v", err)
	}

	copyFromBytes := handle.Bytes()
	copyFromBytes[0] = 'x'
	if !handle.Equal(matching) {
		t.Fatal("Equal() = false after mutating Bytes() copy")
	}
	if handle.Equal(other) {
		t.Fatal("Equal() = true for different user handles")
	}
}

func TestAppendToAppendsWithoutExposingStoredBytes(t *testing.T) {
	t.Parallel()

	authenticatorData, err := protocol.NewAuthenticatorData(bytes.Repeat([]byte{0x03}, protocol.MinAuthenticatorDataLength))
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}

	out := authenticatorData.AppendTo([]byte{0x01, 0x02})
	if len(out) != protocol.MinAuthenticatorDataLength+2 || out[0] != 0x01 || out[2] != 0x03 {
		t.Fatalf("AppendTo() output = %#v", out)
	}
	out[2] = 0x7f

	again := authenticatorData.AppendTo(nil)
	if again[0] != 0x03 {
		t.Fatalf("AppendTo() exposed stored bytes, first byte %#x", again[0])
	}
}

func assertByteLengthError(t *testing.T, err error) {
	t.Helper()

	var lengthErr protocol.ByteLengthError
	if !errors.As(err, &lengthErr) {
		t.Fatalf("error = %v, want ByteLengthError", err)
	}
}
