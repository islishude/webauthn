package browser

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

const (
	// MaxResponseJSONBytes bounds direct browser response decoding. The HTTP
	// adapter applies the same default before allocating the input slice.
	MaxResponseJSONBytes = 1 << 20
)

// RegistrationCredentialJSON is the browser JSON shape for a registration credential response.
type RegistrationCredentialJSON struct {
	ID                      string                           `json:"id"`
	RawID                   string                           `json:"rawId"`
	Type                    protocol.PublicKeyCredentialType `json:"type"`
	Response                AttestationResponseJSON          `json:"response"`
	AuthenticatorAttachment protocol.AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  map[string]any                   `json:"clientExtensionResults"`
}

// AttestationResponseJSON is the browser JSON shape for an authenticator attestation response.
type AttestationResponseJSON struct {
	ClientDataJSON     string                            `json:"clientDataJSON"`
	AuthenticatorData  string                            `json:"authenticatorData"`
	Transports         []protocol.AuthenticatorTransport `json:"transports"`
	PublicKey          *string                           `json:"publicKey,omitempty"`
	PublicKeyAlgorithm protocol.COSEAlgorithmIdentifier  `json:"publicKeyAlgorithm"`
	AttestationObject  string                            `json:"attestationObject"`
}

// AuthenticationCredentialJSON is the browser JSON shape for an authentication credential response.
type AuthenticationCredentialJSON struct {
	ID                      string                           `json:"id"`
	RawID                   string                           `json:"rawId"`
	Type                    protocol.PublicKeyCredentialType `json:"type"`
	Response                AssertionResponseJSON            `json:"response"`
	AuthenticatorAttachment protocol.AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  map[string]any                   `json:"clientExtensionResults"`
}

// AssertionResponseJSON is the browser JSON shape for an authenticator assertion response.
type AssertionResponseJSON struct {
	ClientDataJSON    string  `json:"clientDataJSON"`
	AuthenticatorData string  `json:"authenticatorData"`
	Signature         string  `json:"signature"`
	UserHandle        *string `json:"userHandle,omitempty"`
}

type registrationCredentialWire struct {
	ID                      *string                           `json:"id"`
	RawID                   *string                           `json:"rawId"`
	Type                    *protocol.PublicKeyCredentialType `json:"type"`
	Response                *attestationResponseWire          `json:"response"`
	AuthenticatorAttachment protocol.AuthenticatorAttachment  `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  *map[string]any                   `json:"clientExtensionResults"`
}

type attestationResponseWire struct {
	ClientDataJSON     *string                            `json:"clientDataJSON"`
	AuthenticatorData  *string                            `json:"authenticatorData"`
	Transports         *[]protocol.AuthenticatorTransport `json:"transports"`
	PublicKey          *string                            `json:"publicKey,omitempty"`
	PublicKeyAlgorithm *protocol.COSEAlgorithmIdentifier  `json:"publicKeyAlgorithm"`
	AttestationObject  *string                            `json:"attestationObject"`
}

type authenticationCredentialWire struct {
	ID                      *string                           `json:"id"`
	RawID                   *string                           `json:"rawId"`
	Type                    *protocol.PublicKeyCredentialType `json:"type"`
	Response                *assertionResponseWire            `json:"response"`
	AuthenticatorAttachment protocol.AuthenticatorAttachment  `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  *map[string]any                   `json:"clientExtensionResults"`
}

type assertionResponseWire struct {
	ClientDataJSON    *string `json:"clientDataJSON"`
	AuthenticatorData *string `json:"authenticatorData"`
	Signature         *string `json:"signature"`
	UserHandle        *string `json:"userHandle,omitempty"`
}

// RegistrationResponseFromJSON decodes browser registration JSON into transport-neutral input.
func RegistrationResponseFromJSON(data []byte) (webauthn.RegistrationResponse, error) {
	if err := validateResponseJSONSize(data); err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	var wire registrationCredentialWire
	if err := unmarshalBrowserJSON(data, &wire); err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	if wire.RawID == nil || wire.Type == nil {
		return webauthn.RegistrationResponse{}, requiredMemberError("registration response")
	}
	if err := wire.Type.Validate(); err != nil {
		return webauthn.RegistrationResponse{}, protocolValueError("type", err)
	}
	rawID, err := rawIDFromBase64URL("rawId", *wire.RawID)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	if wire.ID == nil || wire.Response == nil || wire.ClientExtensionResults == nil {
		return webauthn.RegistrationResponse{}, requiredMemberError("registration response")
	}
	response := wire.Response
	if response.ClientDataJSON == nil || response.AuthenticatorData == nil || response.Transports == nil || response.PublicKeyAlgorithm == nil || response.AttestationObject == nil {
		return webauthn.RegistrationResponse{}, requiredMemberError("response")
	}
	if *wire.ID != base64.RawURLEncoding.EncodeToString(rawID.Bytes()) {
		return webauthn.RegistrationResponse{}, protocolValueError("id", errors.New("id does not match rawId"))
	}
	clientDataJSON, err := clientDataJSONFromBase64URL("response.clientDataJSON", *response.ClientDataJSON)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	authenticatorData, err := authenticatorDataFromBase64URL("response.authenticatorData", *response.AuthenticatorData)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	attestationObject, err := attestationObjectFromBase64URL("response.attestationObject", *response.AttestationObject)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	_, err = optionalBytesFromBase64URL("response.publicKey", response.PublicKey)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}
	if *response.PublicKeyAlgorithm == 0 {
		return webauthn.RegistrationResponse{}, protocolValueError("response.publicKeyAlgorithm", errors.New("algorithm is required"))
	}
	clientExtensions, err := clientExtensionResultsFromJSON(*wire.ClientExtensionResults)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}

	return webauthn.RegistrationResponse{
		Type:                    *wire.Type,
		RawID:                   rawID,
		ClientDataJSON:          clientDataJSON,
		AuthenticatorData:       authenticatorData,
		AttestationObject:       attestationObject,
		PublicKeyAlgorithm:      *response.PublicKeyAlgorithm,
		Transports:              append([]protocol.AuthenticatorTransport(nil), (*response.Transports)...),
		AuthenticatorAttachment: wire.AuthenticatorAttachment,
		ClientExtensionResults:  clientExtensions,
	}, nil
}

// AuthenticationResponseFromJSON decodes browser authentication JSON into transport-neutral input.
func AuthenticationResponseFromJSON(data []byte) (webauthn.AuthenticationResponse, error) {
	if err := validateResponseJSONSize(data); err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	var wire authenticationCredentialWire
	if err := unmarshalBrowserJSON(data, &wire); err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	if wire.RawID == nil || wire.Type == nil {
		return webauthn.AuthenticationResponse{}, requiredMemberError("authentication response")
	}
	if err := wire.Type.Validate(); err != nil {
		return webauthn.AuthenticationResponse{}, protocolValueError("type", err)
	}
	rawID, err := rawIDFromBase64URL("rawId", *wire.RawID)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	if wire.ID == nil || wire.Response == nil || wire.ClientExtensionResults == nil {
		return webauthn.AuthenticationResponse{}, requiredMemberError("authentication response")
	}
	response := wire.Response
	if response.ClientDataJSON == nil || response.AuthenticatorData == nil || response.Signature == nil {
		return webauthn.AuthenticationResponse{}, requiredMemberError("response")
	}
	if *wire.ID != base64.RawURLEncoding.EncodeToString(rawID.Bytes()) {
		return webauthn.AuthenticationResponse{}, protocolValueError("id", errors.New("id does not match rawId"))
	}
	clientDataJSON, err := clientDataJSONFromBase64URL("response.clientDataJSON", *response.ClientDataJSON)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	authenticatorData, err := authenticatorDataFromBase64URL("response.authenticatorData", *response.AuthenticatorData)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	signature, err := signatureFromBase64URL("response.signature", *response.Signature)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	userHandle, err := optionalUserHandleFromBase64URL("response.userHandle", response.UserHandle)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}
	clientExtensions, err := clientExtensionResultsFromJSON(*wire.ClientExtensionResults)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}

	return webauthn.AuthenticationResponse{
		Type:                    *wire.Type,
		RawID:                   rawID,
		ClientDataJSON:          clientDataJSON,
		AuthenticatorData:       authenticatorData,
		Signature:               signature,
		UserHandle:              userHandle,
		AuthenticatorAttachment: wire.AuthenticatorAttachment,
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

func validateResponseJSONSize(data []byte) error {
	if len(data) == 0 || len(data) > MaxResponseJSONBytes {
		return fmt.Errorf("%w: response size", ErrMalformedJSON)
	}
	return nil
}

func requiredMemberError(field string) error {
	return protocolValueError(field, errors.New("required member is missing or null"))
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
	encoding := base64.RawURLEncoding.Strict()
	bytes, err := encoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidBase64URL, field, err)
	}
	if encoding.EncodeToString(bytes) != encoded {
		return nil, fmt.Errorf("%w: %s: non-canonical encoding", ErrInvalidBase64URL, field)
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
