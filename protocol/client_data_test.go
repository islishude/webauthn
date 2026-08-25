package protocol_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/islishude/webauthn/protocol"
)

func TestParseCollectedClientData(t *testing.T) {
	t.Parallel()

	challenge := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	raw, err := protocol.NewClientDataJSON([]byte(`{"type":"webauthn.create","challenge":"` + challenge + `","origin":"https://example.com","crossOrigin":true,"topOrigin":"https://top.example","unknown":true}`))
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}

	clientData, err := protocol.ParseCollectedClientData(raw)
	if err != nil {
		t.Fatalf("ParseCollectedClientData() error = %v", err)
	}
	if clientData.Type != protocol.ClientDataTypeCreate {
		t.Fatalf("Type = %q, want webauthn.create", clientData.Type)
	}
	gotChallenge, err := clientData.ChallengeBytes()
	if err != nil {
		t.Fatalf("ChallengeBytes() error = %v", err)
	}
	if string(gotChallenge) != "0123456789abcdef" {
		t.Fatalf("ChallengeBytes() = %q", gotChallenge)
	}
	if clientData.CrossOrigin == nil || !*clientData.CrossOrigin || clientData.TopOrigin != "https://top.example" {
		t.Fatalf("cross/top origin = %v %q", clientData.CrossOrigin, clientData.TopOrigin)
	}
	if !clientData.HasTopOrigin() {
		t.Fatal("HasTopOrigin() = false, want true")
	}
}

func TestParseCollectedClientDataRejectsInvalidOptionalMembers(t *testing.T) {
	t.Parallel()

	challenge := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	tests := []string{
		`"crossOrigin":null`,
		`"crossOrigin":"true"`,
		`"topOrigin":null`,
		`"topOrigin":""`,
		`"topOrigin":true`,
	}
	for _, member := range tests {
		raw, err := protocol.NewClientDataJSON([]byte(`{"type":"webauthn.create","challenge":"` + challenge + `","origin":"https://example.com",` + member + `}`))
		if err != nil {
			t.Fatalf("NewClientDataJSON() error = %v", err)
		}
		if _, err := protocol.ParseCollectedClientData(raw); !errors.Is(err, protocol.ErrMalformedClientData) {
			t.Fatalf("ParseCollectedClientData(%s) error = %v, want ErrMalformedClientData", member, err)
		}
	}
}

func TestParseCollectedClientDataRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	raw, err := protocol.NewClientDataJSON([]byte(`{"type":"webauthn.create"}`))
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}

	_, err = protocol.ParseCollectedClientData(raw)
	if !errors.Is(err, protocol.ErrMalformedClientData) {
		t.Fatalf("ParseCollectedClientData() error = %v, want ErrMalformedClientData", err)
	}
}

func TestCollectedClientDataChallengeBytesRejectsNonCanonicalBase64URL(t *testing.T) {
	t.Parallel()

	challenge := bytes.Repeat([]byte{0xff}, 16)
	canonical := base64.RawURLEncoding.EncodeToString(challenge)
	nonCanonical := canonical[:len(canonical)-1] + "x"
	decoded, err := base64.RawURLEncoding.DecodeString(nonCanonical)
	if err != nil || !bytes.Equal(decoded, challenge) {
		t.Fatalf("test input %q does not decode to the expected challenge", nonCanonical)
	}
	raw, err := protocol.NewClientDataJSON([]byte(`{"type":"webauthn.create","challenge":"` + nonCanonical + `","origin":"https://example.com"}`))
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}

	clientData, err := protocol.ParseCollectedClientData(raw)
	if err != nil {
		t.Fatalf("ParseCollectedClientData() error = %v", err)
	}
	if _, err := clientData.ChallengeBytes(); err == nil {
		t.Fatal("ChallengeBytes() accepted non-canonical base64url")
	}
}

func TestParseCollectedClientDataStripsBOMForParsing(t *testing.T) {
	t.Parallel()

	challenge := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	jsonText := []byte(`{"type":"webauthn.create","challenge":"` + challenge + `","origin":"https://example.com"}`)
	rawBytes := append([]byte{0xef, 0xbb, 0xbf}, jsonText...)
	raw, err := protocol.NewClientDataJSON(rawBytes)
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}

	clientData, err := protocol.ParseCollectedClientData(raw)
	if err != nil {
		t.Fatalf("ParseCollectedClientData() error = %v", err)
	}
	if !bytes.Equal(clientData.Raw.Bytes(), rawBytes) {
		t.Fatalf("Raw = %x, want original BOM-prefixed bytes", clientData.Raw.Bytes())
	}
	if clientData.HasTopOrigin() {
		t.Fatal("HasTopOrigin() = true for absent member")
	}
}
