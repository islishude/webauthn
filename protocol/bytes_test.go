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

func assertByteLengthError(t *testing.T, err error) {
	t.Helper()

	var lengthErr protocol.ByteLengthError
	if !errors.As(err, &lengthErr) {
		t.Fatalf("error = %v, want ByteLengthError", err)
	}
}
