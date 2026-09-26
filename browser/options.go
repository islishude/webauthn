package browser

import (
	"encoding/base64"
	"encoding/json"
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
	Hints                  []protocol.PublicKeyCredentialHint       `json:"hints,omitempty"`
	Attestation            protocol.AttestationConveyancePreference `json:"attestation,omitempty"`
	AttestationFormats     []string                                 `json:"attestationFormats,omitempty"`
	Extensions             ExtensionJSON                            `json:"extensions,omitempty"`
}

// CredentialRequestOptionsJSON is the browser JSON shape for request options.
type CredentialRequestOptionsJSON struct {
	Challenge           string                               `json:"challenge"`
	TimeoutMilliseconds uint32                               `json:"timeout,omitempty"`
	RPID                string                               `json:"rpId,omitempty"`
	AllowCredentials    []CredentialDescriptorJSON           `json:"allowCredentials,omitempty"`
	UserVerification    protocol.UserVerificationRequirement `json:"userVerification,omitempty"`
	Hints               []protocol.PublicKeyCredentialHint   `json:"hints,omitempty"`
	Extensions          ExtensionJSON                        `json:"extensions,omitempty"`
}

// CredentialCreationOptionsFromProtocol converts transport-neutral creation options to browser JSON DTOs.
func CredentialCreationOptionsFromProtocol(options protocol.PublicKeyCredentialCreationOptions) (CredentialCreationOptionsJSON, error) {
	if err := options.AuthenticatorSelection.Validate(); err != nil {
		return CredentialCreationOptionsJSON{}, protocolValueError("authenticatorSelection", err)
	}
	extensions, err := extensionInputsToJSON(options.Extensions)
	if err != nil {
		return CredentialCreationOptionsJSON{}, err
	}
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
		Hints:               append([]protocol.PublicKeyCredentialHint(nil), options.Hints...),
		Attestation:         options.Attestation,
		AttestationFormats:  append([]string(nil), options.AttestationFormats...),
		Extensions:          extensions,
	}
	if options.AuthenticatorSelection != nil {
		out.AuthenticatorSelection = &AuthenticatorSelectionCriteriaJSON{
			AuthenticatorAttachment: options.AuthenticatorSelection.AuthenticatorAttachment,
			ResidentKey:             options.AuthenticatorSelection.ResidentKey,
			RequireResidentKey:      options.AuthenticatorSelection.RequireResidentKey,
			UserVerification:        options.AuthenticatorSelection.UserVerification,
		}
	}

	return out, nil
}

// CredentialRequestOptionsFromProtocol converts transport-neutral request options to browser JSON DTOs.
func CredentialRequestOptionsFromProtocol(options protocol.PublicKeyCredentialRequestOptions) (CredentialRequestOptionsJSON, error) {
	extensions, err := extensionInputsToJSON(options.Extensions)
	if err != nil {
		return CredentialRequestOptionsJSON{}, err
	}
	return CredentialRequestOptionsJSON{
		Challenge:           base64.RawURLEncoding.EncodeToString(options.Challenge.Bytes()),
		TimeoutMilliseconds: options.TimeoutMilliseconds,
		RPID:                options.RPID,
		AllowCredentials:    credentialDescriptorsToJSON(options.AllowCredentials),
		UserVerification:    options.UserVerification,
		Hints:               append([]protocol.PublicKeyCredentialHint(nil), options.Hints...),
		Extensions:          extensions,
	}, nil
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
		return []CredentialParameterJSON{}
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

func extensionInputsToJSON(inputs protocol.ExtensionInputs) (ExtensionJSON, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	if len(inputs) > extension.MaxEntries {
		return nil, protocolValueError("extensions", extension.ErrTooManyEntries)
	}
	out := make(ExtensionJSON, len(inputs))
	for id, input := range inputs {
		value, err := extension.InputValue(input)
		if err != nil {
			return nil, protocolValueError("extensions."+id, err)
		}
		switch id {
		case extension.IDLargeBlob:
			value = largeBlobInputToJSON(value)
		case extension.IDPRF:
			value = prfInputToJSON(value)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, protocolValueError("extensions."+id, err)
		}
		out[id] = encoded
	}
	return out, nil
}

func prfInputToJSON(value any) any {
	switch input := value.(type) {
	case extension.PRFInput:
		out := PRFInputJSON{}
		if input.Eval != nil {
			values := prfValuesToJSON(*input.Eval)
			out.Eval = &values
		}
		if input.EvalByCredential != nil {
			byCredential := make(map[string]PRFValuesJSON, len(input.EvalByCredential))
			for id, values := range input.EvalByCredential {
				byCredential[id] = prfValuesToJSON(values)
			}
			out.EvalByCredential = &byCredential
		}
		return out

	case map[string]any:
		out := maps.Clone(input)
		if raw, ok := out["eval"]; ok {
			out["eval"] = prfValuesAnyToJSON(raw)
		}
		if raw, ok := out["evalByCredential"]; ok {
			if byCredential, ok := raw.(map[string]any); ok {
				converted := make(map[string]any, len(byCredential))
				for id, values := range byCredential {
					converted[id] = prfValuesAnyToJSON(values)
				}
				out["evalByCredential"] = converted
			}
		}
		return out
	default:
		return value
	}
}

func prfValuesAnyToJSON(value any) any {
	switch values := value.(type) {
	case extension.PRFValues:
		return prfValuesToJSON(values)
	case map[string]any:
		out := maps.Clone(values)
		encodeLargeBlobByteField(out, "first")
		encodeLargeBlobByteField(out, "second")
		return out
	default:
		return value
	}
}

func prfValuesToJSON(values extension.PRFValues) PRFValuesJSON {
	out := PRFValuesJSON{First: base64.RawURLEncoding.EncodeToString(values.First)}
	if values.Second != nil {
		second := base64.RawURLEncoding.EncodeToString(values.Second)
		out.Second = &second
	}
	return out
}

func largeBlobInputToJSON(value any) any {
	switch input := value.(type) {
	case extension.LargeBlobInput:
		out := LargeBlobInputJSON{Support: input.Support, Read: input.Read}
		if input.Write != nil {
			encoded := base64.RawURLEncoding.EncodeToString(input.Write)
			out.Write = &encoded
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
