package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	fxcbor "github.com/fxamacker/cbor/v2"

	"github.com/islishude/webauthn/browser"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/protocol"
)

func TestNormalizePlaywrightRegistrationJSONDerivesAuthenticatorData(t *testing.T) {
	t.Parallel()

	authenticatorData := bytes.Repeat([]byte{0x01}, protocol.MinAuthenticatorDataLength)
	mode, err := fxcbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("EncMode() error = %v", err)
	}
	attestationObject, err := mode.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authenticatorData,
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	id := base64.RawURLEncoding.EncodeToString([]byte("credential-id"))
	payload, err := json.Marshal(map[string]any{
		"id":                     id,
		"rawId":                  id,
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":     base64.RawURLEncoding.EncodeToString([]byte("{}")),
			"attestationObject":  base64.RawURLEncoding.EncodeToString(attestationObject),
			"transports":         []string{},
			"publicKeyAlgorithm": -7,
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	normalized, err := normalizePlaywrightRegistrationJSON(payload, codeccbor.MustNewDecoder())
	if err != nil {
		t.Fatalf("normalizePlaywrightRegistrationJSON() error = %v", err)
	}
	response, err := browser.RegistrationResponseFromJSON(normalized)
	if err != nil {
		t.Fatalf("RegistrationResponseFromJSON() error = %v", err)
	}
	if !bytes.Equal(response.AuthenticatorData.Bytes(), authenticatorData) {
		t.Fatalf("AuthenticatorData = %x, want %x", response.AuthenticatorData.Bytes(), authenticatorData)
	}
}
