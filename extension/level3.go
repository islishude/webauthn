package extension

import (
	"context"
	"encoding/base64"
	"slices"
)

const (
	// IDPRF is the pseudo-random function extension identifier.
	IDPRF = "prf"
)

// Level3Handlers returns handlers for WebAuthn Level 3 recommended extensions.
func Level3Handlers() []Handler {
	return []Handler{
		AppIDHandler{},
		AppIDExcludeHandler{},
		CredPropsHandler{},
		LargeBlobHandler{},
		PRFHandler{},
	}
}

// Level3HandlersWithDeprecated returns Level 3 handlers plus deprecated
// extensions that remain supported.
func Level3HandlersWithDeprecated() []Handler {
	return []Handler{
		AppIDHandler{},
		AppIDExcludeHandler{},
		CredPropsHandler{},
		LargeBlobHandler{},
		PRFHandler{},
		UVMHandler{},
	}
}

// NewLevel3Registry builds a registry with WebAuthn Level 3 recommended extensions.
func NewLevel3Registry() (*Registry, error) {
	return NewRegistry(Level3Handlers()...)
}

// NewLevel3RegistryWithDeprecated builds a Level 3 registry including
// deprecated extensions that are still parsed.
func NewLevel3RegistryWithDeprecated() (*Registry, error) {
	return NewRegistry(Level3HandlersWithDeprecated()...)
}

// PRFValues contains one or two PRF input or output values.
type PRFValues struct {
	First  []byte
	Second []byte
}

// PRFInput is the typed prf client extension input.
type PRFInput struct {
	Eval             *PRFValues
	EvalByCredential map[string]PRFValues
	AllowCredentials []string
}

// PRFResult is the parsed prf input and client output.
type PRFResult struct {
	Eval             *PRFValues
	EvalByCredential map[string]PRFValues
	Enabled          *bool
	Results          *PRFValues
}

// PRFHandler validates the pseudo-random function extension.
type PRFHandler struct{}

// ID returns "prf".
func (PRFHandler) ID() string {
	return IDPRF
}

// HandleExtension validates and parses prf input and client output.
func (PRFHandler) HandleExtension(_ context.Context, request Request) (Result, error) {
	if err := requireOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return Result{}, err
	}
	if !request.Requested {
		return Result{}, invalidRequest("prf must be requested")
	}
	if request.AuthenticatorOutput != nil {
		return Result{}, invalidRequest("prf has no authenticator output")
	}

	input, err := parsePRFInput(request.ClientInput)
	if err != nil {
		return Result{}, err
	}
	if request.Operation == OperationRegistration && len(input.EvalByCredential) != 0 {
		return Result{}, invalidRequest("prf evalByCredential is authentication-only")
	}
	if request.Operation == OperationAuthentication && len(input.EvalByCredential) != 0 {
		if len(input.AllowCredentials) == 0 {
			return Result{}, invalidRequest("prf evalByCredential requires allowCredentials")
		}
		for id := range input.EvalByCredential {
			if id == "" || !slices.Contains(input.AllowCredentials, id) {
				return Result{}, invalidRequest("prf evalByCredential credential is not allowed")
			}
			if _, err := base64.RawURLEncoding.DecodeString(id); err != nil {
				return Result{}, invalidRequest("prf evalByCredential credential must be base64url")
			}
		}
	}

	output := PRFResult{
		Eval:             clonePRFValuesPtr(input.Eval),
		EvalByCredential: clonePRFValuesMap(input.EvalByCredential),
	}
	if request.ClientOutput == nil {
		return Result{ID: IDPRF, Outputs: map[string]any{IDPRF: output}}, nil
	}
	if err := parsePRFOutput(request.ClientOutput, &output); err != nil {
		return Result{}, err
	}

	return Result{ID: IDPRF, Accepted: true, Outputs: map[string]any{IDPRF: output}}, nil
}

func parsePRFInput(value any) (PRFInput, error) {
	switch input := value.(type) {
	case PRFInput:
		return clonePRFInput(input), nil
	case map[string]any:
		return prfInputFromFields(input)
	default:
		if value == nil {
			return PRFInput{}, invalidRequest("prf input must be an object")
		}
		return PRFInput{}, invalidRequest("prf input must be an object")
	}
}

func prfInputFromFields(fields map[string]any) (PRFInput, error) {
	var input PRFInput
	if raw, ok := fields["eval"]; ok {
		values, err := parsePRFValues(raw, false)
		if err != nil {
			return PRFInput{}, err
		}
		input.Eval = &values
	}
	if raw, ok := fields["evalByCredential"]; ok {
		entries, ok := raw.(map[string]any)
		if !ok {
			return PRFInput{}, invalidRequest("prf evalByCredential must be an object")
		}
		input.EvalByCredential = make(map[string]PRFValues, len(entries))
		for id, rawValues := range entries {
			values, err := parsePRFValues(rawValues, false)
			if err != nil {
				return PRFInput{}, err
			}
			input.EvalByCredential[id] = values
		}
	}
	if raw, ok := fields["allowCredentials"]; ok {
		credentials, ok := raw.([]string)
		if !ok {
			return PRFInput{}, invalidRequest("prf allowCredentials must be strings")
		}
		input.AllowCredentials = slices.Clone(credentials)
	}

	return input, nil
}

func parsePRFOutput(value any, output *PRFResult) error {
	if typed, ok := value.(PRFResult); ok {
		*output = clonePRFResult(typed)
		return validatePRFResult(output.Results)
	}
	fields, ok := objectFields(value)
	if !ok {
		return invalidRequest("prf client output must be an object")
	}
	if raw, ok := fields["enabled"]; ok {
		enabled, ok := raw.(bool)
		if !ok {
			return invalidRequest("prf enabled must be boolean")
		}
		output.Enabled = boolPtr(enabled)
	}
	if raw, ok := fields["results"]; ok {
		values, err := parsePRFValues(raw, true)
		if err != nil {
			return err
		}
		output.Results = &values
	}

	return nil
}

func parsePRFValues(value any, requireOutputLength bool) (PRFValues, error) {
	switch values := value.(type) {
	case PRFValues:
		out := clonePRFValues(values)
		return out, validatePRFValues(out, requireOutputLength)
	case *PRFValues:
		if values == nil {
			return PRFValues{}, invalidRequest("prf values must be an object")
		}
		out := clonePRFValues(*values)
		return out, validatePRFValues(out, requireOutputLength)
	default:
		fields, ok := objectFields(value)
		if !ok {
			return PRFValues{}, invalidRequest("prf values must be an object")
		}
		first, err := requiredBytesField(fields, "first")
		if err != nil {
			return PRFValues{}, err
		}
		out := PRFValues{First: first}
		if raw, ok := fields["second"]; ok {
			second, ok := raw.([]byte)
			if !ok {
				return PRFValues{}, invalidRequest("prf second must be bytes")
			}
			out.Second = slices.Clone(second)
		}
		return out, validatePRFValues(out, requireOutputLength)
	}
}

func requiredBytesField(fields map[string]any, name string) ([]byte, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, invalidRequest("prf " + name + " is required")
	}
	bytes, ok := raw.([]byte)
	if !ok {
		return nil, invalidRequest("prf " + name + " must be bytes")
	}

	return slices.Clone(bytes), nil
}

func validatePRFResult(values *PRFValues) error {
	if values == nil {
		return nil
	}

	return validatePRFValues(*values, true)
}

func validatePRFValues(values PRFValues, requireOutputLength bool) error {
	if values.First == nil {
		return invalidRequest("prf first is required")
	}
	if requireOutputLength {
		if len(values.First) != 32 {
			return invalidRequest("prf first result must be 32 bytes")
		}
		if values.Second != nil && len(values.Second) != 32 {
			return invalidRequest("prf second result must be 32 bytes")
		}
	}

	return nil
}

func clonePRFInput(input PRFInput) PRFInput {
	return PRFInput{
		Eval:             clonePRFValuesPtr(input.Eval),
		EvalByCredential: clonePRFValuesMap(input.EvalByCredential),
		AllowCredentials: slices.Clone(input.AllowCredentials),
	}
}

func clonePRFResult(input PRFResult) PRFResult {
	return PRFResult{
		Eval:             clonePRFValuesPtr(input.Eval),
		EvalByCredential: clonePRFValuesMap(input.EvalByCredential),
		Enabled:          cloneBoolPtr(input.Enabled),
		Results:          clonePRFValuesPtr(input.Results),
	}
}

func clonePRFValuesPtr(value *PRFValues) *PRFValues {
	if value == nil {
		return nil
	}

	cloned := clonePRFValues(*value)
	return &cloned
}

func clonePRFValues(value PRFValues) PRFValues {
	return PRFValues{
		First:  slices.Clone(value.First),
		Second: slices.Clone(value.Second),
	}
}

func clonePRFValuesMap(values map[string]PRFValues) map[string]PRFValues {
	if values == nil {
		return nil
	}

	out := make(map[string]PRFValues, len(values))
	for key, value := range values {
		out[key] = clonePRFValues(value)
	}

	return out
}
