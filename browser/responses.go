package browser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

// RegistrationCredentialJSON is the browser JSON shape for a registration credential response.
type RegistrationCredentialJSON struct {
	ID                      string                           `json:"id,omitempty"`
	RawID                   string                           `json:"rawId"`
	Type                    protocol.PublicKeyCredentialType `json:"type"`
	Response                AttestationResponseJSON          `json:"response"`
	AuthenticatorAttachment protocol.AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  map[string]any                   `json:"clientExtensionResults,omitempty"`
}

// AttestationResponseJSON is the browser JSON shape for an authenticator attestation response.
type AttestationResponseJSON struct {
	ClientDataJSON     string                            `json:"clientDataJSON"`
	AuthenticatorData  string                            `json:"authenticatorData"`
	Transports         []protocol.AuthenticatorTransport `json:"transports,omitempty"`
	PublicKey          *string                           `json:"publicKey,omitempty"`
	PublicKeyAlgorithm protocol.COSEAlgorithmIdentifier  `json:"publicKeyAlgorithm"`
	AttestationObject  string                            `json:"attestationObject"`
}

// AuthenticationCredentialJSON is the browser JSON shape for an authentication credential response.
type AuthenticationCredentialJSON struct {
	ID                      string                           `json:"id,omitempty"`
	RawID                   string                           `json:"rawId"`
	Type                    protocol.PublicKeyCredentialType `json:"type"`
	Response                AssertionResponseJSON            `json:"response"`
	AuthenticatorAttachment protocol.AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  map[string]any                   `json:"clientExtensionResults,omitempty"`
}

// AssertionResponseJSON is the browser JSON shape for an authenticator assertion response.
type AssertionResponseJSON struct {
	ClientDataJSON    string  `json:"clientDataJSON"`
	AuthenticatorData string  `json:"authenticatorData"`
	Signature         string  `json:"signature"`
	UserHandle        *string `json:"userHandle,omitempty"`
}

// RegistrationResponseFromJSON decodes browser registration JSON into transport-neutral input.
func RegistrationResponseFromJSON(data []byte) (webauthn.RegistrationResponse, error) {
	var dto RegistrationCredentialJSON
	if err := unmarshalBrowserJSON(data, &dto); err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	if err := dto.Type.Validate(); err != nil {
		return webauthn.RegistrationResponse{}, protocolValueError("type", err)
	}

	rawID, err := rawIDFromBase64URL("rawId", dto.RawID)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	clientDataJSON, err := clientDataJSONFromBase64URL("response.clientDataJSON", dto.Response.ClientDataJSON)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	authenticatorData, err := optionalAuthenticatorDataFromBase64URL("response.authenticatorData", dto.Response.AuthenticatorData)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	attestationObject, err := attestationObjectFromBase64URL("response.attestationObject", dto.Response.AttestationObject)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	publicKey, err := optionalBytesFromBase64URL("response.publicKey", dto.Response.PublicKey)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	clientExtensions, err := clientExtensionResultsFromJSON(dto.ClientExtensionResults)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}

	return webauthn.RegistrationResponse{
		Type:                    dto.Type,
		RawID:                   rawID,
		ClientDataJSON:          clientDataJSON,
		AuthenticatorData:       authenticatorData,
		AttestationObject:       attestationObject,
		PublicKey:               publicKey,
		PublicKeyAlgorithm:      dto.Response.PublicKeyAlgorithm,
		Transports:              append([]protocol.AuthenticatorTransport(nil), dto.Response.Transports...),
		AuthenticatorAttachment: dto.AuthenticatorAttachment,
		ClientExtensionResults:  clientExtensions,
	}, nil
}

// AuthenticationResponseFromJSON decodes browser authentication JSON into transport-neutral input.
func AuthenticationResponseFromJSON(data []byte) (webauthn.AuthenticationResponse, error) {
	var dto AuthenticationCredentialJSON
	if err := unmarshalBrowserJSON(data, &dto); err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	if err := dto.Type.Validate(); err != nil {
		return webauthn.AuthenticationResponse{}, protocolValueError("type", err)
	}

	rawID, err := rawIDFromBase64URL("rawId", dto.RawID)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	clientDataJSON, err := clientDataJSONFromBase64URL("response.clientDataJSON", dto.Response.ClientDataJSON)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	authenticatorData, err := authenticatorDataFromBase64URL("response.authenticatorData", dto.Response.AuthenticatorData)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	signature, err := signatureFromBase64URL("response.signature", dto.Response.Signature)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	userHandle, err := optionalUserHandleFromBase64URL("response.userHandle", dto.Response.UserHandle)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	clientExtensions, err := clientExtensionResultsFromJSON(dto.ClientExtensionResults)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}

	return webauthn.AuthenticationResponse{
		Type:                    dto.Type,
		RawID:                   rawID,
		ClientDataJSON:          clientDataJSON,
		AuthenticatorData:       authenticatorData,
		Signature:               signature,
		UserHandle:              userHandle,
		AuthenticatorAttachment: dto.AuthenticatorAttachment,
		ClientExtensionResults:  clientExtensions,
	}, nil
}

// CredentialDescriptorFromJSON decodes a browser JSON credential descriptor.
func CredentialDescriptorFromJSON(dto CredentialDescriptorJSON) (protocol.CredentialDescriptor, error) {
	credentialIDBytes, err := decodeBase64URL("id", dto.ID)
	if err != nil {
		return protocol.CredentialDescriptor{}, err
	}
	credentialID, err := protocol.NewCredentialID(credentialIDBytes)
	if err != nil {
		return protocol.CredentialDescriptor{}, protocolValueError("id", err)
	}

	descriptor := protocol.CredentialDescriptor{
		Type:       dto.Type,
		ID:         credentialID,
		Transports: append([]protocol.AuthenticatorTransport(nil), dto.Transports...),
	}
	if err := descriptor.Validate(); err != nil {
		return protocol.CredentialDescriptor{}, protocolValueError("credential descriptor", err)
	}

	return descriptor, nil
}

func unmarshalBrowserJSON(data []byte, target any) error {
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedJSON, err)
	}

	return nil
}

func rawIDFromBase64URL(field string, encoded string) (protocol.RawID, error) {
	bytes, err := decodeBase64URL(field, encoded)
	if err != nil {
		return protocol.RawID{}, err
	}
	value, err := protocol.NewRawID(bytes)
	if err != nil {
		return protocol.RawID{}, protocolValueError(field, err)
	}

	return value, nil
}

func clientDataJSONFromBase64URL(field string, encoded string) (protocol.ClientDataJSON, error) {
	bytes, err := decodeBase64URL(field, encoded)
	if err != nil {
		return protocol.ClientDataJSON{}, err
	}
	value, err := protocol.NewClientDataJSON(bytes)
	if err != nil {
		return protocol.ClientDataJSON{}, protocolValueError(field, err)
	}

	return value, nil
}

func attestationObjectFromBase64URL(field string, encoded string) (protocol.AttestationObject, error) {
	bytes, err := decodeBase64URL(field, encoded)
	if err != nil {
		return protocol.AttestationObject{}, err
	}
	value, err := protocol.NewAttestationObject(bytes)
	if err != nil {
		return protocol.AttestationObject{}, protocolValueError(field, err)
	}

	return value, nil
}

func authenticatorDataFromBase64URL(field string, encoded string) (protocol.AuthenticatorData, error) {
	bytes, err := decodeBase64URL(field, encoded)
	if err != nil {
		return protocol.AuthenticatorData{}, err
	}
	value, err := protocol.NewAuthenticatorData(bytes)
	if err != nil {
		return protocol.AuthenticatorData{}, protocolValueError(field, err)
	}

	return value, nil
}

func optionalAuthenticatorDataFromBase64URL(field string, encoded string) (protocol.AuthenticatorData, error) {
	if encoded == "" {
		return protocol.AuthenticatorData{}, nil
	}

	return authenticatorDataFromBase64URL(field, encoded)
}

func signatureFromBase64URL(field string, encoded string) (protocol.Signature, error) {
	bytes, err := decodeBase64URL(field, encoded)
	if err != nil {
		return protocol.Signature{}, err
	}
	value, err := protocol.NewSignature(bytes)
	if err != nil {
		return protocol.Signature{}, protocolValueError(field, err)
	}

	return value, nil
}

func optionalUserHandleFromBase64URL(field string, encoded *string) (protocol.UserHandle, error) {
	if encoded == nil {
		return protocol.UserHandle{}, nil
	}
	bytes, err := decodeBase64URL(field, *encoded)
	if err != nil {
		return protocol.UserHandle{}, err
	}
	value, err := protocol.NewUserHandle(bytes)
	if err != nil {
		return protocol.UserHandle{}, protocolValueError(field, err)
	}

	return value, nil
}

func optionalBytesFromBase64URL(field string, encoded *string) ([]byte, error) {
	if encoded == nil {
		return nil, nil
	}

	return decodeBase64URL(field, *encoded)
}

func decodeBase64URL(field string, encoded string) ([]byte, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidBase64URL, field, err)
	}

	return bytes, nil
}

func protocolValueError(field string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrInvalidProtocolValue, field, err)
}

func clientExtensionResultsFromJSON(results map[string]any) (map[string]any, error) {
	if len(results) == 0 {
		return nil, nil
	}

	out := make(map[string]any, len(results))
	for id, value := range results {
		if id != extension.IDLargeBlob {
			if id == extension.IDPRF {
				converted, err := prfOutputFromJSON(value)
				if err != nil {
					return nil, err
				}
				out[id] = converted
				continue
			}
			out[id] = value
			continue
		}
		converted, err := largeBlobOutputFromJSON(value)
		if err != nil {
			return nil, err
		}
		out[id] = converted
	}

	return out, nil
}

func prfOutputFromJSON(value any) (any, error) {
	fields, ok := value.(map[string]any)
	if !ok {
		return value, nil
	}

	out := maps.Clone(fields)
	rawResults, ok := out["results"]
	if !ok {
		return out, nil
	}
	results, ok := rawResults.(map[string]any)
	if !ok {
		return out, nil
	}
	converted := maps.Clone(results)
	for _, field := range []string{"first", "second"} {
		raw, ok := converted[field]
		if !ok {
			continue
		}
		encoded, ok := raw.(string)
		if !ok {
			continue
		}
		decoded, err := decodeBase64URL("clientExtensionResults.prf.results."+field, encoded)
		if err != nil {
			return nil, err
		}
		converted[field] = decoded
	}
	out["results"] = converted
	return out, nil
}

func largeBlobOutputFromJSON(value any) (any, error) {
	fields, ok := value.(map[string]any)
	if !ok {
		return value, nil
	}

	out := maps.Clone(fields)
	for _, field := range []string{"blob", "write"} {
		raw, ok := out[field]
		if !ok {
			continue
		}
		encoded, ok := raw.(string)
		if !ok {
			continue
		}
		decoded, err := decodeBase64URL("clientExtensionResults.largeBlob."+field, encoded)
		if err != nil {
			return nil, err
		}
		out[field] = decoded
	}

	return out, nil
}
