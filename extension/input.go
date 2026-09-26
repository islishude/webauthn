package extension

import "github.com/islishude/webauthn/protocol"

// RawInput explicitly carries an unknown or restored wire input. Known
// extensions should use BoolInput, StringInput, PRFInput, or LargeBlobInput.
// Its zero value represents explicit null, not an absent map entry.
type RawInput struct{ value RawValue }

// NewRawInput validates and copies a wire value at an adapter boundary.
func NewRawInput(value any) (RawInput, error) {
	raw, err := NewRawValue(value)
	return RawInput{value: raw}, err
}

// CloneExtensionInput returns an independent copy of the raw input.
func (v RawInput) CloneExtensionInput() (protocol.ExtensionInput, error) {
	value, err := v.value.Clone()
	if err != nil {
		return nil, err
	}
	return NewRawInput(value)
}

// Value returns a defensive copy for a wire encoder or extension handler.
func (v RawInput) Value() (any, error) { return v.value.Clone() }

// CloneExtensionInput returns an independent PRF input.
func (v PRFInput) CloneExtensionInput() (protocol.ExtensionInput, error) {
	if _, err := CloneValue(v); err != nil {
		return nil, err
	}
	return clonePRFInput(v), nil
}

// CloneExtensionInput returns an independent largeBlob input.
func (v LargeBlobInput) CloneExtensionInput() (protocol.ExtensionInput, error) {
	if _, err := CloneValue(v); err != nil {
		return nil, err
	}
	return cloneLargeBlobInput(v), nil
}

// SetInput sets an input under the handler's identifier. The input type is
// inferred from the handler, preventing mismatched values at compile time.
// Ceremony-specific validation still runs at start and finish.
func SetInput[I, O any](inputs protocol.ExtensionInputs, handler Handler[I, O], value I) error {
	if inputs == nil || nilLike(handler) {
		return ErrInvalidRequest
	}
	input, err := NormalizeInput(value)
	if err != nil {
		return err
	}
	inputs[handler.ID()] = input
	return nil
}

// NormalizeInput copies a decoded or handler-normalized value into the typed
// protocol input boundary. Adapters use this when restoring wire values.
func NormalizeInput(value any) (protocol.ExtensionInput, error) {
	switch v := value.(type) {
	case protocol.ExtensionInput:
		return CloneInput(v)
	case bool:
		return protocol.BoolInput(v), nil
	case string:
		return CloneInput(protocol.StringInput(v))
	default:
		return NewRawInput(value)
	}
}

// CloneInput copies a typed input, enforces built-in input budgets, and rejects
// missing or typed-nil values.
// Use NewRawInput(nil) when an unknown extension explicitly carries null.
func CloneInput(input protocol.ExtensionInput) (protocol.ExtensionInput, error) {
	if nilLike(input) {
		return nil, ErrInvalidRequest
	}
	cloned, err := input.CloneExtensionInput()
	if err != nil {
		return nil, err
	}
	if nilLike(cloned) {
		return nil, ErrInvalidRequest
	}
	// StringInput's protocol-level copy is immutable and has no dependency on
	// extension budgets, so enforce its budget at this boundary.
	if value, ok := cloned.(protocol.StringInput); ok {
		if _, err := CloneValue(value); err != nil {
			return nil, err
		}
	}
	return cloned, nil
}

// InputValue unwraps an input for codecs and the heterogeneous handler registry.
// Application code should use concrete input types and SetInput instead.
func InputValue(input protocol.ExtensionInput) (any, error) {
	if nilLike(input) {
		return nil, ErrInvalidRequest
	}
	switch v := input.(type) {
	case protocol.BoolInput:
		return bool(v), nil
	case protocol.StringInput:
		return CloneValue(v)
	case RawInput:
		return v.Value()
	default:
		return CloneInput(input)
	}
}

// PRFInputWithCredentials replaces untrusted allowCredentials with the IDs
// bound to the ceremony. Semantic PRF validation runs after this binding.
func PRFInputWithCredentials(input protocol.ExtensionInput, credentials []string) (PRFInput, error) {
	raw, err := InputValue(input)
	if err != nil {
		return PRFInput{}, err
	}
	parsed, err := parsePRFInput(raw)
	if err != nil {
		return PRFInput{}, err
	}
	parsed.AllowCredentials = append([]string(nil), credentials...)
	return parsed, nil
}
