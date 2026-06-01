package browser

import (
	"encoding/base64"
	"maps"

	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

// RPEntityJSON is the browser JSON shape for a relying-party entity.
type RPEntityJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserEntityJSON is the browser JSON shape for a user entity.
type UserEntityJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// CredentialParameterJSON is the browser JSON shape for a credential parameter.
type CredentialParameterJSON struct {
	Type      protocol.PublicKeyCredentialType `json:"type"`
	Algorithm protocol.COSEAlgorithmIdentifier `json:"alg"`
}

// CredentialDescriptorJSON is the browser JSON shape for a credential descriptor.
type CredentialDescriptorJSON struct {
	Type       protocol.PublicKeyCredentialType  `json:"type"`
	ID         string                            `json:"id"`
	Transports []protocol.AuthenticatorTransport `json:"transports,omitempty"`
}

// AuthenticatorSelectionCriteriaJSON is the browser JSON shape for authenticator selection.
type AuthenticatorSelectionCriteriaJSON struct {
	AuthenticatorAttachment protocol.AuthenticatorAttachment     `json:"authenticatorAttachment,omitempty"`
	ResidentKey             protocol.ResidentKeyRequirement      `json:"residentKey,omitempty"`
	RequireResidentKey      bool                                 `json:"requireResidentKey,omitempty"`
	UserVerification        protocol.UserVerificationRequirement `json:"userVerification,omitempty"`
}

// CredentialCreationOptionsJSON is the browser JSON shape for creation options.
type CredentialCreationOptionsJSON struct {
	RP                     RPEntityJSON                             `json:"rp"`
	User                   UserEntityJSON                           `json:"user"`
	Challenge              string                                   `json:"challenge"`
	PubKeyCredParams       []CredentialParameterJSON                `json:"pubKeyCredParams"`
	TimeoutMilliseconds    uint32                                   `json:"timeout,omitempty"`
	ExcludeCredentials     []CredentialDescriptorJSON               `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *AuthenticatorSelectionCriteriaJSON      `json:"authenticatorSelection,omitempty"`
	Attestation            protocol.AttestationConveyancePreference `json:"attestation,omitempty"`
	Extensions             map[string]any                           `json:"extensions,omitempty"`
}

// CredentialRequestOptionsJSON is the browser JSON shape for request options.
type CredentialRequestOptionsJSON struct {
	Challenge           string                               `json:"challenge"`
	TimeoutMilliseconds uint32                               `json:"timeout,omitempty"`
	RPID                string                               `json:"rpId,omitempty"`
	AllowCredentials    []CredentialDescriptorJSON           `json:"allowCredentials,omitempty"`
	UserVerification    protocol.UserVerificationRequirement `json:"userVerification,omitempty"`
	Extensions          map[string]any                       `json:"extensions,omitempty"`
}

// CredentialCreationOptionsFromProtocol converts transport-neutral creation options to browser JSON DTOs.
func CredentialCreationOptionsFromProtocol(options protocol.PublicKeyCredentialCreationOptions) CredentialCreationOptionsJSON {
	out := CredentialCreationOptionsJSON{
		RP: RPEntityJSON{
			ID:   options.RP.ID,
			Name: options.RP.Name,
		},
		User: UserEntityJSON{
			ID:          base64.RawURLEncoding.EncodeToString(options.User.ID.Bytes()),
			Name:        options.User.Name,
			DisplayName: options.User.DisplayName,
		},
		Challenge:           base64.RawURLEncoding.EncodeToString(options.Challenge.Bytes()),
		PubKeyCredParams:    credentialParametersToJSON(options.PubKeyCredParams),
		TimeoutMilliseconds: options.TimeoutMilliseconds,
		ExcludeCredentials:  credentialDescriptorsToJSON(options.ExcludeCredentials),
		Attestation:         options.Attestation,
		Extensions:          extensionInputsToJSON(options.Extensions),
	}
	if options.AuthenticatorSelection != nil {
		out.AuthenticatorSelection = &AuthenticatorSelectionCriteriaJSON{
			AuthenticatorAttachment: options.AuthenticatorSelection.AuthenticatorAttachment,
			ResidentKey:             options.AuthenticatorSelection.ResidentKey,
			RequireResidentKey:      options.AuthenticatorSelection.RequireResidentKey,
			UserVerification:        options.AuthenticatorSelection.UserVerification,
		}
	}

	return out
}

// CredentialRequestOptionsFromProtocol converts transport-neutral request options to browser JSON DTOs.
func CredentialRequestOptionsFromProtocol(options protocol.PublicKeyCredentialRequestOptions) CredentialRequestOptionsJSON {
	return CredentialRequestOptionsJSON{
		Challenge:           base64.RawURLEncoding.EncodeToString(options.Challenge.Bytes()),
		TimeoutMilliseconds: options.TimeoutMilliseconds,
		RPID:                options.RPID,
		AllowCredentials:    credentialDescriptorsToJSON(options.AllowCredentials),
		UserVerification:    options.UserVerification,
		Extensions:          extensionInputsToJSON(options.Extensions),
	}
}

// CredentialDescriptorToJSON converts a protocol credential descriptor to browser JSON.
func CredentialDescriptorToJSON(descriptor protocol.CredentialDescriptor) CredentialDescriptorJSON {
	return CredentialDescriptorJSON{
		Type:       descriptor.Type,
		ID:         base64.RawURLEncoding.EncodeToString(descriptor.ID.Bytes()),
		Transports: append([]protocol.AuthenticatorTransport(nil), descriptor.Transports...),
	}
}

func credentialParametersToJSON(parameters []protocol.CredentialParameter) []CredentialParameterJSON {
	if len(parameters) == 0 {
		return nil
	}

	out := make([]CredentialParameterJSON, len(parameters))
	for i, parameter := range parameters {
		out[i] = CredentialParameterJSON{
			Type:      parameter.Type,
			Algorithm: parameter.Algorithm,
		}
	}

	return out
}

func credentialDescriptorsToJSON(descriptors []protocol.CredentialDescriptor) []CredentialDescriptorJSON {
	if len(descriptors) == 0 {
		return nil
	}

	out := make([]CredentialDescriptorJSON, len(descriptors))
	for i, descriptor := range descriptors {
		out[i] = CredentialDescriptorToJSON(descriptor)
	}

	return out
}

func extensionInputsToJSON(inputs protocol.ExtensionInputs) map[string]any {
	if len(inputs) == 0 {
		return nil
	}

	out := make(map[string]any, len(inputs))
	for id, value := range inputs {
		if id == extension.IDLargeBlob {
			out[id] = largeBlobInputToJSON(value)
			continue
		}
		out[id] = value
	}

	return out
}

func largeBlobInputToJSON(value any) any {
	switch input := value.(type) {
	case extension.LargeBlobInput:
		out := make(map[string]any, 3)
		if input.Support != "" {
			out["support"] = input.Support
		}
		if input.Read != nil {
			out["read"] = *input.Read
		}
		if input.Write != nil {
			out["write"] = base64.RawURLEncoding.EncodeToString(input.Write)
		}
		return out
	case map[string]any:
		out := maps.Clone(input)
		encodeLargeBlobByteField(out, "write")
		return out
	default:
		return value
	}
}

func encodeLargeBlobByteField(fields map[string]any, name string) {
	value, ok := fields[name]
	if !ok {
		return
	}
	if bytes, ok := value.([]byte); ok {
		fields[name] = base64.RawURLEncoding.EncodeToString(bytes)
	}
}
