package webauthn

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

type registrationExtensionInputs struct {
	state                   RegistrationState
	policy                  RegistrationExtensionPolicy
	registry                *extension.Registry
	clientExtensionResults  map[string]any
	authenticatorExtensions codec.ExtensionMap
}

func verifyRegistrationExtensions(ctx context.Context, inputs registrationExtensionInputs) ([]extension.Result, error) {
	return verifyExtensions(ctx, extensionVerificationInputs{
		operation:               extension.OperationRegistration,
		requestedExtensions:     inputs.state.RequestedExtensions,
		policy:                  extensionOutputPolicy{rejectUnrequested: inputs.policy.RejectUnrequested, rejectUnknown: inputs.policy.RejectUnknown},
		registry:                inputs.registry,
		clientExtensionResults:  inputs.clientExtensionResults,
		authenticatorExtensions: inputs.authenticatorExtensions,
	})
}

func lookupExtensionHandler(registry *extension.Registry, id string) (extension.Handler, bool) {
	if registry == nil {
		return nil, false
	}
	return registry.Lookup(id)
}

type extensionOutputPolicy struct {
	rejectUnrequested bool
	rejectUnknown     bool
}

type extensionVerificationInputs struct {
	operation               extension.Operation
	requestedExtensions     protocol.ExtensionInputs
	policy                  extensionOutputPolicy
	registry                *extension.Registry
	clientExtensionResults  map[string]any
	authenticatorExtensions codec.ExtensionMap
	clientInputTransform    func(string, any) any
}

func verifyExtensions(ctx context.Context, inputs extensionVerificationInputs) ([]extension.Result, error) {
	ids := map[string]struct{}{}
	for id := range inputs.requestedExtensions {
		ids[id] = struct{}{}
	}
	for id := range inputs.clientExtensionResults {
		ids[id] = struct{}{}
	}
	for id := range inputs.authenticatorExtensions {
		ids[id] = struct{}{}
	}

	results := make([]extension.Result, 0, len(ids))
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		clientInput, requested := inputs.requestedExtensions[id]
		if inputs.clientInputTransform != nil {
			clientInput = inputs.clientInputTransform(id, clientInput)
		}
		clientOutput, hasClientOutput := inputs.clientExtensionResults[id]
		authenticatorOutput, hasAuthenticatorOutput := inputs.authenticatorExtensions[id]
		var err error
		clientInput, err = extension.CloneValue(clientInput)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		clientOutput, err = extension.CloneValue(clientOutput)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		authenticatorOutput, err = extension.CloneValue(authenticatorOutput)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}

		handler, known := lookupExtensionHandler(inputs.registry, id)
		hasOutput := hasClientOutput || hasAuthenticatorOutput
		if !known && hasOutput && inputs.policy.rejectUnknown {
			return nil, ErrExtensionPolicy
		}
		if !requested && hasOutput {
			if inputs.policy.rejectUnrequested {
				return nil, ErrExtensionPolicy
			}
			results = append(results, rawExtensionResult(id, rawExtensionInputs{
				requested:              requested,
				clientInput:            clientInput,
				clientOutput:           clientOutput,
				hasClientOutput:        hasClientOutput,
				authenticatorOutput:    authenticatorOutput,
				hasAuthenticatorOutput: hasAuthenticatorOutput,
				warning:                "unrequested extension output ignored",
			}))
			continue
		}
		if !known {
			results = append(results, rawExtensionResult(id, rawExtensionInputs{
				requested:              requested,
				clientInput:            clientInput,
				clientOutput:           clientOutput,
				hasClientOutput:        hasClientOutput,
				authenticatorOutput:    authenticatorOutput,
				hasAuthenticatorOutput: hasAuthenticatorOutput,
				warning:                "unknown extension preserved",
			}))
			continue
		}

		result, err := handler.VerifyOutput(ctx, extension.OutputRequest{
			Operation:           inputs.operation,
			ID:                  id,
			Requested:           requested,
			ClientInput:         clientInput,
			ClientOutput:        clientOutput,
			AuthenticatorOutput: authenticatorOutput,
		})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		if result.ID != id {
			return nil, fmt.Errorf("%w: handler returned mismatched extension id", ErrExtensionPolicy)
		}
		cloned, err := extension.CloneResult(result)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		results = append(results, cloned)
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
		if id == "" {
			return nil, fmt.Errorf("%w: extension id is empty", ErrExtensionPolicy)
		}
		value, err := extension.CloneValue(inputs[id])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		if transform != nil {
			value = transform(id, value)
		}
		handler, known := registry.Lookup(id)
		if !known {
			if policy.RejectUnknown {
				return nil, fmt.Errorf("%w: unknown extension input %s", ErrExtensionPolicy, id)
			}
			out[id] = value
			continue
		}
		normalized, err := handler.ValidateInput(extension.InputRequest{Operation: operation, ID: id, Input: value})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		cloned, err := extension.CloneValue(normalized)
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

type rawExtensionInputs struct {
	requested              bool
	clientInput            any
	clientOutput           any
	hasClientOutput        bool
	authenticatorOutput    any
	hasAuthenticatorOutput bool
	warning                string
}

func rawExtensionResult(id string, input rawExtensionInputs) extension.Result {
	outputs := map[string]any{"requested": input.requested}
	if input.clientInput != nil {
		outputs["clientInput"] = input.clientInput
	}
	if input.hasClientOutput {
		outputs["clientOutput"] = input.clientOutput
	}
	if input.hasAuthenticatorOutput {
		outputs["authenticatorOutput"] = input.authenticatorOutput
	}
	return extension.Result{ID: id, Accepted: false, Outputs: outputs, Warnings: []string{input.warning}}
}
