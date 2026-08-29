package webauthn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/internal/protocolidentifier"
	"github.com/islishude/webauthn/protocol"
)

type registrationExtensionInputs struct {
	state                   RegistrationState
	policy                  RegistrationExtensionPolicy
	registry                *extension.Registry
	clientExtensionResults  map[string]any
	authenticatorExtensions codec.ExtensionMap
	clientDataJSON          protocol.ClientDataJSON
}

func verifyRegistrationExtensions(ctx context.Context, inputs registrationExtensionInputs) (extension.Results, error) {
	if err := verifyRemoteClientDataBinding(inputs.state.RequestedExtensions, inputs.registry, inputs.clientDataJSON); err != nil {
		return nil, err
	}
	return verifyExtensions(ctx, extensionVerificationInputs{
		operation:               extension.OperationRegistration,
		requestedExtensions:     inputs.state.RequestedExtensions,
		policy:                  extensionOutputPolicy{rejectUnrequested: inputs.policy.RejectUnrequested, rejectUnknown: inputs.policy.RejectUnknown},
		registry:                inputs.registry,
		clientExtensionResults:  inputs.clientExtensionResults,
		authenticatorExtensions: inputs.authenticatorExtensions,
	})
}

func validateRemoteClientDataInput(operation extension.Operation, inputs protocol.ExtensionInputs, registry *extension.Registry, challenge protocol.Challenge) error {
	value, requested := inputs[extension.IDRemoteClientDataJSON]
	if !requested || registry == nil {
		return nil
	}
	if !registry.Contains(extension.IDRemoteClientDataJSON) {
		return nil
	}
	raw, err := extension.NewRawValue(value)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
	}
	normalized, err := (extension.RemoteClientDataJSONHandler{}).ValidateInput(extension.InputRequest{
		Operation: operation,
		ID:        extension.IDRemoteClientDataJSON,
		Input:     raw,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
	}
	clientDataJSON, err := protocol.NewClientDataJSON([]byte(normalized))
	if err != nil {
		return fmt.Errorf("%w: invalid remote client data", ErrExtensionPolicy)
	}
	clientData, err := protocol.ParseCollectedClientData(clientDataJSON)
	if err != nil {
		return fmt.Errorf("%w: invalid remote client data", ErrExtensionPolicy)
	}
	challengeBytes, err := clientData.ChallengeBytes()
	if err != nil || !challenge.EqualBytes(challengeBytes) {
		return fmt.Errorf("%w: remote client data challenge mismatch", ErrExtensionPolicy)
	}
	return nil
}

func verifyRemoteClientDataBinding(inputs protocol.ExtensionInputs, registry *extension.Registry, raw protocol.ClientDataJSON) error {
	value, requested := inputs[extension.IDRemoteClientDataJSON]
	if !requested || registry == nil {
		return nil
	}
	if !registry.Contains(extension.IDRemoteClientDataJSON) {
		return nil
	}
	serialized, ok := value.(string)
	if !ok || !bytes.Equal(raw.Bytes(), []byte(serialized)) {
		return fmt.Errorf("%w: remote client data changed", ErrExtensionPolicy)
	}
	return nil
}

func validateAuthenticationExtensionContext(inputs protocol.ExtensionInputs, registry *extension.Registry, allowCredentials []protocol.CredentialDescriptor) error {
	value, requested := inputs[extension.IDLargeBlob]
	if !requested {
		return nil
	}
	if registry == nil {
		return fmt.Errorf("%w: largeBlob handler is required", ErrExtensionPolicy)
	}
	if !registry.Contains(extension.IDLargeBlob) {
		return fmt.Errorf("%w: largeBlob handler is required", ErrExtensionPolicy)
	}
	if err := validateLargeBlobCredentialContext(value, allowCredentials); err != nil {
		return fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
	}
	return nil
}

func validateStoredAuthenticationExtensionContext(inputs protocol.ExtensionInputs, allowCredentials []protocol.CredentialDescriptor) error {
	value, requested := inputs[extension.IDLargeBlob]
	if !requested {
		return nil
	}
	return validateLargeBlobCredentialContext(value, allowCredentials)
}

func validateLargeBlobCredentialContext(value any, allowCredentials []protocol.CredentialDescriptor) error {
	raw, err := extension.NewRawValue(value)
	if err != nil {
		return err
	}
	normalized, err := (extension.LargeBlobHandler{}).ValidateInput(extension.InputRequest{
		Operation: extension.OperationAuthentication,
		ID:        extension.IDLargeBlob,
		Input:     raw,
	})
	if err != nil {
		return err
	}
	if normalized.Write != nil && len(allowCredentials) != 1 {
		return errors.New("largeBlob write requires exactly one allowed credential")
	}
	return nil
}

type extensionOutputPolicy struct {
	rejectUnrequested bool
	rejectUnknown     bool
}

type extensionVerificationInputs struct {
	operation               extension.Operation
	selectedCredentialID    protocol.CredentialID
	requestedExtensions     protocol.ExtensionInputs
	policy                  extensionOutputPolicy
	registry                *extension.Registry
	clientExtensionResults  map[string]any
	authenticatorExtensions codec.ExtensionMap
	clientInputTransform    func(string, any) any
}

func verifyExtensions(ctx context.Context, inputs extensionVerificationInputs) (extension.Results, error) {
	ids := map[string]struct{}{}
	for id := range inputs.requestedExtensions {
		if !protocolidentifier.Valid(id) {
			return nil, fmt.Errorf("%w: invalid extension id", ErrExtensionPolicy)
		}
		ids[id] = struct{}{}
	}
	for id := range inputs.clientExtensionResults {
		if !protocolidentifier.Valid(id) {
			return nil, fmt.Errorf("%w: invalid extension id", ErrExtensionPolicy)
		}
		ids[id] = struct{}{}
	}
	for id := range inputs.authenticatorExtensions {
		if !protocolidentifier.Valid(id) {
			return nil, fmt.Errorf("%w: invalid extension id", ErrExtensionPolicy)
		}
		ids[id] = struct{}{}
	}

	results := make(extension.Results, 0, len(ids))
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		clientInput, requested := inputs.requestedExtensions[id]
		clientOutput, hasClientOutput := inputs.clientExtensionResults[id]
		authenticatorOutput, hasAuthenticatorOutput := inputs.authenticatorExtensions[id]
		known := inputs.registry != nil && inputs.registry.Contains(id)
		hasOutput := hasClientOutput || hasAuthenticatorOutput
		if !known && hasOutput && inputs.policy.rejectUnknown {
			return nil, ErrExtensionPolicy
		}
		if !requested && hasOutput && inputs.policy.rejectUnrequested {
			return nil, ErrExtensionPolicy
		}

		if inputs.clientInputTransform != nil {
			clientInput = inputs.clientInputTransform(id, clientInput)
		}
		clientInputValue, err := rawExtensionValue(clientInput, requested)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		clientOutputValue, err := rawExtensionValue(clientOutput, hasClientOutput)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		authenticatorOutputValue, err := rawExtensionValue(authenticatorOutput, hasAuthenticatorOutput)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}

		if !requested && hasOutput {
			result, err := extension.PreserveRaw(id, extension.RawResult{
				Requested:           false,
				ClientInput:         clientInputValue,
				ClientOutput:        clientOutputValue,
				AuthenticatorOutput: authenticatorOutputValue,
			}, "unrequested extension output ignored")
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
			}
			results = append(results, result)
			continue
		}
		if !known {
			result, err := extension.PreserveRaw(id, extension.RawResult{
				Requested:           requested,
				ClientInput:         clientInputValue,
				ClientOutput:        clientOutputValue,
				AuthenticatorOutput: authenticatorOutputValue,
			}, "unknown extension preserved")
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
			}
			results = append(results, result)
			continue
		}

		result, err := inputs.registry.VerifyOutput(ctx, extension.RawOutputRequest{
			Operation:            inputs.operation,
			ID:                   id,
			Requested:            requested,
			SelectedCredentialID: inputs.selectedCredentialID,
			ClientInput:          clientInputValue,
			ClientOutput:         clientOutputValue,
			AuthenticatorOutput:  authenticatorOutputValue,
		})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		results = append(results, result)
	}
	return results, nil
}

type extensionInputTransform func(string, any) any

func prepareExtensionInputs(operation extension.Operation, inputs protocol.ExtensionInputs, registry *extension.Registry, policy ExtensionInputPolicy, transform extensionInputTransform) (protocol.ExtensionInputs, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	if registry == nil {
		return nil, fmt.Errorf("%w: extension registry is required when extensions are requested", ErrExtensionPolicy)
	}
	out := make(protocol.ExtensionInputs, len(inputs))
	for _, id := range slices.Sorted(maps.Keys(inputs)) {
		if !protocolidentifier.Valid(id) {
			return nil, fmt.Errorf("%w: extension id is invalid", ErrExtensionPolicy)
		}
		value, err := extension.CloneValue(inputs[id])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		if transform != nil {
			value = transform(id, value)
		}
		known := registry.Contains(id)
		if !known {
			if policy.RejectUnknown {
				return nil, fmt.Errorf("%w: unknown extension input %s", ErrExtensionPolicy, id)
			}
			out[id] = value
			continue
		}
		raw, err := extension.NewRawValue(value)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		normalized, err := registry.ValidateInput(extension.InputRequest{Operation: operation, ID: id, Input: raw})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		cloned, err := normalized.Clone()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		out[id] = cloned
	}
	return out, nil
}

func cloneExtensionInputs(inputs protocol.ExtensionInputs) (protocol.ExtensionInputs, error) {
	if inputs == nil {
		return nil, nil
	}
	out := make(protocol.ExtensionInputs, len(inputs))
	for id, value := range inputs {
		cloned, err := extension.CloneValue(value)
		if err != nil {
			return nil, err
		}
		out[id] = cloned
	}
	return out, nil
}

func rawExtensionValue(value any, present bool) (extension.RawValue, error) {
	if !present {
		return extension.RawValue{}, nil
	}
	return extension.NewRawValue(value)
}
