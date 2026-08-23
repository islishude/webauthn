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
}
