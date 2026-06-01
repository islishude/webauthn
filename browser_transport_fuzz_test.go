package webauthn_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/islishude/webauthn/protocol"
)

func FuzzDecodeBrowserCredentialDescriptor(f *testing.F) {
	encodedID := base64.RawURLEncoding.EncodeToString([]byte("credential-id"))
	f.Add([]byte(`{"type":"public-key","id":"` + encodedID + `","transports":["internal"]}`))
	f.Add([]byte(`{"type":"public-key","id":"` + encodedID + `","transports":["usb","nfc","future-transport"]}`))
	f.Add([]byte(`{"type":"password","id":"` + encodedID + `"}`))
	f.Add([]byte(`{"type":"public-key","id":"%%%INVALID%%%"}`))
	f.Add([]byte{0xff, 0xfe, 0xfd})

	f.Fuzz(func(t *testing.T, data []byte) {
		descriptor, err := decodeBrowserCredentialDescriptor(data)
		if err != nil {
			return
		}
		if err := descriptor.Validate(); err != nil {
			t.Fatalf("decoded descriptor failed validation: %v", err)
		}
	})
}

func decodeBrowserCredentialDescriptor(data []byte) (protocol.CredentialDescriptor, error) {
	var dto struct {
		Type       protocol.PublicKeyCredentialType  `json:"type"`
		ID         string                            `json:"id"`
		Transports []protocol.AuthenticatorTransport `json:"transports"`
	}
	if err := json.Unmarshal(data, &dto); err != nil {
		return protocol.CredentialDescriptor{}, err
	}

	idBytes, err := base64.RawURLEncoding.DecodeString(dto.ID)
	if err != nil {
		return protocol.CredentialDescriptor{}, err
	}
	credentialID, err := protocol.NewCredentialID(idBytes)
	if err != nil {
		return protocol.CredentialDescriptor{}, err
	}

	descriptor := protocol.CredentialDescriptor{
		Type:       dto.Type,
		ID:         credentialID,
		Transports: dto.Transports,
	}
	if err := descriptor.Validate(); err != nil {
		return protocol.CredentialDescriptor{}, err
	}

	return descriptor, nil
}
