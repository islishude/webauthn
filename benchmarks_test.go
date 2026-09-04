package webauthn_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	fxcbor "github.com/fxamacker/cbor/v2"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/browser"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

func BenchmarkParseCollectedClientData(b *testing.B) {
	challenge := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	raw, err := protocol.NewClientDataJSON([]byte(`{"type":"webauthn.get","challenge":"` + challenge + `","origin":"https://example.com","crossOrigin":false}`))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := protocol.ParseCollectedClientData(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeAttestationObject(b *testing.B) {
	decoder := codeccbor.MustNewDecoder()
	authenticatorData := bytes.Repeat([]byte{0x00}, protocol.MinAuthenticatorDataLength)
	encoded := benchmarkCBOR(b, map[string]any{
		"fmt": "none", "authData": authenticatorData, "attStmt": map[string]any{},
	})
	raw, err := protocol.NewAttestationObject(encoded)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := decoder.DecodeAttestationObject(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeBrowserRegistrationResponse(b *testing.B) {
	id := base64.RawURLEncoding.EncodeToString([]byte("credential-id"))
	payload, err := json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString([]byte("{}")),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x00}, protocol.MinAuthenticatorDataLength)),
			"transports":        []string{}, "publicKeyAlgorithm": -7, "attestationObject": "oA",
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := browser.RegistrationResponseFromJSON(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCloneExtensionValue(b *testing.B) {
	value := map[string]any{
		"nested": []any{map[string]any{"bytes": bytes.Repeat([]byte{0x01}, 256)}},
	}
	b.ReportAllocs()
	for range b.N {
		if _, err := extension.CloneValue(value); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStartRegistrationWithUnknownExtension(b *testing.B) {
	challenge, _ := protocol.NewChallenge(bytes.Repeat([]byte{0x01}, 32))
	userHandle, _ := protocol.NewUserHandle([]byte("benchmark-user"))
	registry, _ := extension.NewRegistry()
	options := webauthn.RegistrationStartOptions{
		RP:           protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:         protocol.UserEntity{ID: userHandle, Name: "benchmark", DisplayName: ""},
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		Challenge:    challenge,
		Extensions: protocol.ExtensionInputs{
			"benchmark": map[string]any{"bytes": bytes.Repeat([]byte{0x01}, 256)},
		},
		ExtensionRegistry: registry,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := webauthn.StartRegistration(context.Background(), options); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkCBOR(b *testing.B, value any) []byte {
	b.Helper()
	mode, err := fxcbor.CTAP2EncOptions().EncMode()
	if err != nil {
		b.Fatal(err)
	}
	encoded, err := mode.Marshal(value)
	if err != nil {
		b.Fatal(err)
	}
	return encoded
}
