package browser_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

func TestCredentialCreationOptionsFromProtocolEncodesBinaryFields(t *testing.T) {
	t.Parallel()

	challenge := mustChallenge(t, []byte("0123456789abcdef"))
	userHandle := mustUserHandle(t, []byte("user-1"))
	credentialID := mustCredentialID(t, []byte("credential-1"))
	read := true
	options := protocol.PublicKeyCredentialCreationOptions{
		RP: protocol.RPEntity{ID: "example.com", Name: "Example"},
		User: protocol.UserEntity{
			ID:          userHandle,
			Name:        "user@example.com",
			DisplayName: "Example User",
		},
		Challenge: challenge,
		PubKeyCredParams: []protocol.CredentialParameter{{
			Type:      protocol.CredentialTypePublicKey,
			Algorithm: -7,
		}},
		ExcludeCredentials: []protocol.CredentialDescriptor{{
			Type:       protocol.CredentialTypePublicKey,
			ID:         credentialID,
			Transports: []protocol.AuthenticatorTransport{protocol.TransportInternal},
		}},
		AuthenticatorSelection: &protocol.AuthenticatorSelectionCriteria{
			ResidentKey:      protocol.ResidentKeyRequired,
			UserVerification: protocol.UserVerificationRequired,
		},
		Attestation: protocol.AttestationDirect,
		Extensions: protocol.ExtensionInputs{
			extension.IDLargeBlob: extension.LargeBlobInput{Read: &read, Write: []byte("blob")},
			"future":              map[string]any{"unchanged": true},
		},
	}

	dto := browser.CredentialCreationOptionsFromProtocol(options)
	if dto.Challenge != encode([]byte("0123456789abcdef")) {
		t.Fatalf("Challenge = %q", dto.Challenge)
	}
	if dto.User.ID != encode([]byte("user-1")) {
		t.Fatalf("User.ID = %q", dto.User.ID)
	}
	if dto.ExcludeCredentials[0].ID != encode([]byte("credential-1")) {
		t.Fatalf("ExcludeCredentials[0].ID = %q", dto.ExcludeCredentials[0].ID)
	}
	largeBlob, ok := dto.Extensions[extension.IDLargeBlob].(map[string]any)
	if !ok {
		t.Fatalf("largeBlob extension = %T", dto.Extensions[extension.IDLargeBlob])
	}
	if largeBlob["write"] != encode([]byte("blob")) || largeBlob["read"] != true {
		t.Fatalf("largeBlob extension = %#v", largeBlob)
	}
}

func TestCredentialRequestOptionsFromProtocolEncodesCredentialDescriptors(t *testing.T) {
	t.Parallel()

	challenge := mustChallenge(t, []byte("0123456789abcdef"))
	credentialID := mustCredentialID(t, []byte("credential-1"))
	options := protocol.PublicKeyCredentialRequestOptions{
		Challenge: challenge,
		RPID:      "example.com",
		AllowCredentials: []protocol.CredentialDescriptor{{
			Type:       protocol.CredentialTypePublicKey,
			ID:         credentialID,
			Transports: []protocol.AuthenticatorTransport{protocol.TransportUSB},
		}},
		UserVerification: protocol.UserVerificationPreferred,
	}

	dto := browser.CredentialRequestOptionsFromProtocol(options)
	if dto.Challenge != encode([]byte("0123456789abcdef")) {
		t.Fatalf("Challenge = %q", dto.Challenge)
	}
	if dto.AllowCredentials[0].ID != encode([]byte("credential-1")) {
		t.Fatalf("AllowCredentials[0].ID = %q", dto.AllowCredentials[0].ID)
	}
}

func TestCredentialDescriptorFromJSON(t *testing.T) {
	t.Parallel()

	descriptor, err := browser.CredentialDescriptorFromJSON(browser.CredentialDescriptorJSON{
		Type:       protocol.CredentialTypePublicKey,
		ID:         encode([]byte("credential-1")),
		Transports: []protocol.AuthenticatorTransport{protocol.TransportInternal, "future"},
	})
	if err != nil {
		t.Fatalf("CredentialDescriptorFromJSON() error = %v", err)
	}
	if string(descriptor.ID.Bytes()) != "credential-1" {
		t.Fatalf("descriptor.ID = %q", descriptor.ID.Bytes())
	}
	if descriptor.Transports[1] != "future" {
		t.Fatalf("descriptor.Transports = %#v", descriptor.Transports)
	}
}

func TestRegistrationResponseFromJSON(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"type":  protocol.CredentialTypePublicKey,
		"rawId": encode([]byte("credential-1")),
		"response": map[string]any{
			"clientDataJSON":    encode([]byte(`{"type":"webauthn.create"}`)),
			"attestationObject": encode([]byte{0xa0}),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]any{
			extension.IDLargeBlob: map[string]any{"blob": encode([]byte("blob"))},
			"future":              map[string]any{"unchanged": true},
		},
	}
	data := mustJSON(t, payload)

	response, err := browser.RegistrationResponseFromJSON(data)
	if err != nil {
		t.Fatalf("RegistrationResponseFromJSON() error = %v", err)
	}
	if string(response.RawID.Bytes()) != "credential-1" {
		t.Fatalf("RawID = %q", response.RawID.Bytes())
	}
	if string(response.ClientDataJSON.Bytes()) != `{"type":"webauthn.create"}` {
		t.Fatalf("ClientDataJSON = %q", response.ClientDataJSON.Bytes())
	}
	largeBlob := response.ClientExtensionResults[extension.IDLargeBlob].(map[string]any)
	if string(largeBlob["blob"].([]byte)) != "blob" {
		t.Fatalf("largeBlob blob = %#v", largeBlob["blob"])
	}
	if response.ClientExtensionResults["future"].(map[string]any)["unchanged"] != true {
		t.Fatalf("future extension = %#v", response.ClientExtensionResults["future"])
	}
}

func TestAuthenticationResponseFromJSON(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"type":  protocol.CredentialTypePublicKey,
		"rawId": encode([]byte("credential-1")),
		"response": map[string]any{
			"clientDataJSON":    encode([]byte(`{"type":"webauthn.get"}`)),
			"authenticatorData": encode(append(make([]byte, 37), 1)),
			"signature":         encode([]byte("signature")),
			"userHandle":        encode([]byte("user-1")),
		},
		"clientExtensionResults": map[string]any{
			extension.IDLargeBlob: map[string]any{"blob": encode([]byte("blob"))},
		},
	}
	data := mustJSON(t, payload)

	response, err := browser.AuthenticationResponseFromJSON(data)
	if err != nil {
		t.Fatalf("AuthenticationResponseFromJSON() error = %v", err)
	}
	if string(response.RawID.Bytes()) != "credential-1" {
		t.Fatalf("RawID = %q", response.RawID.Bytes())
	}
	if string(response.UserHandle.Bytes()) != "user-1" {
		t.Fatalf("UserHandle = %q", response.UserHandle.Bytes())
	}
	if string(response.Signature.Bytes()) != "signature" {
		t.Fatalf("Signature = %q", response.Signature.Bytes())
	}
}

func TestResponseDecodersRejectInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		err  error
	}{
		{
			name: "malformed json",
			data: []byte("{"),
			err:  browser.ErrMalformedJSON,
		},
		{
			name: "invalid base64url",
			data: []byte(`{"type":"public-key","rawId":"%%%","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`),
			err:  browser.ErrInvalidBase64URL,
		},
		{
			name: "empty raw id",
			data: []byte(`{"type":"public-key","rawId":"","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`),
			err:  browser.ErrInvalidProtocolValue,
		},
		{
			name: "invalid type",
			data: []byte(`{"type":"password","rawId":"Y3JlZGVudGlhbA","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`),
			err:  browser.ErrInvalidProtocolValue,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := browser.RegistrationResponseFromJSON(test.data)
			if !errors.Is(err, test.err) {
				t.Fatalf("RegistrationResponseFromJSON() error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestAuthenticationResponseRejectsOversizedUserHandle(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"type":  protocol.CredentialTypePublicKey,
		"rawId": encode([]byte("credential-1")),
		"response": map[string]any{
			"clientDataJSON":    encode([]byte(`{"type":"webauthn.get"}`)),
			"authenticatorData": encode(make([]byte, 37)),
			"signature":         encode([]byte("signature")),
			"userHandle":        encode([]byte(strings.Repeat("u", protocol.MaxUserHandleLength+1))),
		},
	}

	_, err := browser.AuthenticationResponseFromJSON(mustJSON(t, payload))
	if !errors.Is(err, browser.ErrInvalidProtocolValue) {
		t.Fatalf("AuthenticationResponseFromJSON() error = %v, want ErrInvalidProtocolValue", err)
	}
}

func mustChallenge(t *testing.T, value []byte) protocol.Challenge {
	t.Helper()

	out, err := protocol.NewChallenge(value)
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}

	return out
}

func mustCredentialID(t *testing.T, value []byte) protocol.CredentialID {
	t.Helper()

	out, err := protocol.NewCredentialID(value)
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}

	return out
}

func mustUserHandle(t *testing.T, value []byte) protocol.UserHandle {
	t.Helper()

	out, err := protocol.NewUserHandle(value)
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}

	return out
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	return data
}

func encode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
