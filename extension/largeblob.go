package extension

import (
	"context"
	"slices"
)

// LargeBlobSupport identifies registration-time large blob support policy.
type LargeBlobSupport string

const (
	// LargeBlobSupportRequired requires a large-blob-capable authenticator.
	LargeBlobSupportRequired LargeBlobSupport = "required"
	// LargeBlobSupportPreferred asks for large blob support when available.
	LargeBlobSupportPreferred LargeBlobSupport = "preferred"
)

// LargeBlobInput is a typed largeBlob client extension input.
type LargeBlobInput struct {
	Support LargeBlobSupport
	Read    *bool
	Write   []byte
}

// LargeBlobResult is the parsed largeBlob input and output.
type LargeBlobResult struct {
	Support   LargeBlobSupport
	Read      *bool
	Write     []byte
	Supported *bool
	Blob      []byte
	Written   *bool
}

// LargeBlobHandler validates the large blob extension.
type LargeBlobHandler struct{}

// ID returns "largeBlob".
func (LargeBlobHandler) ID() string {
	return IDLargeBlob
}

// ValidateInput validates and normalizes largeBlob input at ceremony start.
func (LargeBlobHandler) ValidateInput(request InputRequest) (any, error) {
	if err := requireInputOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return nil, err
	}
	input, presence, err := parseLargeBlobInput(request.Input)
	if err != nil {
		return nil, err
	}
	if err := validateLargeBlobInput(request.Operation, input, presence); err != nil {
		return nil, err
	}
	return input, nil
}

// VerifyOutput validates and parses largeBlob output after core verification.
func (handler LargeBlobHandler) VerifyOutput(_ context.Context, request OutputRequest) (Result, error) {
	if err := requireOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return Result{}, err
	}
	if !request.Requested {
		return Result{}, invalidRequest("largeBlob must be requested")
	}
	normalized, err := handler.ValidateInput(InputRequest{Operation: request.Operation, ID: request.ID, Input: request.ClientInput})
	if err != nil {
		return Result{}, err
	}
	input := normalized.(LargeBlobInput)
	presence := largeBlobInputPresence{support: input.Support != "", read: input.Read != nil, write: input.Write != nil}
	if request.AuthenticatorOutput != nil {
		return Result{}, invalidRequest("largeBlob has no authenticator output")
	}

	output := largeBlobResultFromInput(input)
	if request.ClientOutput == nil {
		return Result{ID: IDLargeBlob, Outputs: map[string]any{IDLargeBlob: output}}, nil
	}
	if err := parseLargeBlobOutput(request.Operation, input, presence, request.ClientOutput, &output); err != nil {
		return Result{}, err
	}
	return Result{ID: IDLargeBlob, Accepted: true, Outputs: map[string]any{IDLargeBlob: output}}, nil
}

type largeBlobInputPresence struct {
	support bool
	read    bool
	write   bool
}

type largeBlobOutputPresence struct {
	supported bool
	blob      bool
	written   bool
}

func parseLargeBlobInput(value any) (LargeBlobInput, largeBlobInputPresence, error) {
	switch input := value.(type) {
	case LargeBlobInput:
		return cloneLargeBlobInput(input), largeBlobInputPresence{support: input.Support != "", read: input.Read != nil, write: input.Write != nil}, nil
	case map[string]any, map[string]string, map[string]bool:
		fields, _ := objectFields(value)
		return largeBlobInputFromFields(fields)
	default:
		return LargeBlobInput{}, largeBlobInputPresence{}, invalidRequest("largeBlob input must be an object")
	}
}

func largeBlobInputFromFields(fields map[string]any) (LargeBlobInput, largeBlobInputPresence, error) {
	var input LargeBlobInput
	var presence largeBlobInputPresence
	if raw, ok := fields["support"]; ok {
		support, ok := raw.(string)
		if !ok {
			return LargeBlobInput{}, largeBlobInputPresence{}, invalidRequest("largeBlob support must be a string")
		}
		input.Support = LargeBlobSupport(support)
		presence.support = true
	}
	if raw, ok := fields["read"]; ok {
		read, ok := raw.(bool)
		if !ok {
			return LargeBlobInput{}, largeBlobInputPresence{}, invalidRequest("largeBlob read must be boolean")
		}
		input.Read = boolPtr(read)
		presence.read = true
	}
	if raw, ok := fields["write"]; ok {
		write, ok := raw.([]byte)
		if !ok {
			return LargeBlobInput{}, largeBlobInputPresence{}, invalidRequest("largeBlob write must be bytes")
		}
		input.Write = slices.Clone(write)
		presence.write = true
	}
	return input, presence, nil
}

func validateLargeBlobInput(operation Operation, input LargeBlobInput, presence largeBlobInputPresence) error {
	if presence.support && input.Support != LargeBlobSupportRequired && input.Support != LargeBlobSupportPreferred {
		return invalidRequest("largeBlob support must be required or preferred")
	}
	switch operation {
	case OperationRegistration:
		if presence.read || presence.write {
			return invalidRequest("largeBlob read and write are authentication-only inputs")
		}
	case OperationAuthentication:
		if presence.support {
			return invalidRequest("largeBlob support is registration-only input")
		}
		if presence.read && presence.write {
			return invalidRequest("largeBlob read and write are mutually exclusive")
		}
	}
	return nil
}

func parseLargeBlobOutput(operation Operation, input LargeBlobInput, presence largeBlobInputPresence, value any, output *LargeBlobResult) error {
	var outputPresence largeBlobOutputPresence
	if typed, ok := value.(LargeBlobResult); ok {
		typed = cloneLargeBlobResult(typed)
		outputPresence = largeBlobOutputPresence{supported: typed.Supported != nil, blob: typed.Blob != nil, written: typed.Written != nil}
		typed.Support = output.Support
		typed.Read = cloneBoolPtr(output.Read)
		typed.Write = slices.Clone(output.Write)
		*output = typed
		return validateLargeBlobOutput(operation, input, presence, outputPresence, output)
	}
	fields, ok := objectFields(value)
	if !ok {
		return invalidRequest("largeBlob client output must be an object")
	}
	if raw, ok := fields["supported"]; ok {
		supported, ok := raw.(bool)
		if !ok {
			return invalidRequest("largeBlob supported must be boolean")
		}
		output.Supported = boolPtr(supported)
		outputPresence.supported = true
	}
	if raw, ok := fields["blob"]; ok {
		blob, ok := raw.([]byte)
		if !ok {
			return invalidRequest("largeBlob blob must be bytes")
		}
		output.Blob = slices.Clone(blob)
		outputPresence.blob = true
	}
	if raw, ok := fields["written"]; ok {
		written, ok := raw.(bool)
		if !ok {
			return invalidRequest("largeBlob written must be boolean")
		}
		output.Written = boolPtr(written)
		outputPresence.written = true
	}
	return validateLargeBlobOutput(operation, input, presence, outputPresence, output)
}

func validateLargeBlobOutput(operation Operation, input LargeBlobInput, inputPresence largeBlobInputPresence, outputPresence largeBlobOutputPresence, output *LargeBlobResult) error {
	switch operation {
	case OperationRegistration:
		if outputPresence.blob || outputPresence.written {
			return invalidRequest("largeBlob blob and written are authentication-only outputs")
		}
		if inputPresence.support && input.Support == LargeBlobSupportRequired && outputPresence.supported && output.Supported != nil && !*output.Supported {
			return invalidRequest("largeBlob required support was not provided")
		}
	case OperationAuthentication:
		if outputPresence.supported {
			return invalidRequest("largeBlob supported is registration-only output")
		}
		readRequested := inputPresence.read && input.Read != nil && *input.Read
		if outputPresence.blob && !readRequested {
			return invalidRequest("largeBlob blob requires read input")
		}
		if outputPresence.written && !inputPresence.write {
			return invalidRequest("largeBlob written requires write input")
		}
	}
	return nil
}

func largeBlobResultFromInput(input LargeBlobInput) LargeBlobResult {
	return LargeBlobResult{Support: input.Support, Read: cloneBoolPtr(input.Read), Write: slices.Clone(input.Write)}
}

func cloneLargeBlobInput(input LargeBlobInput) LargeBlobInput {
	return LargeBlobInput{Support: input.Support, Read: cloneBoolPtr(input.Read), Write: slices.Clone(input.Write)}
}

func cloneLargeBlobResult(input LargeBlobResult) LargeBlobResult {
	return LargeBlobResult{
		Support:   input.Support,
		Read:      cloneBoolPtr(input.Read),
		Write:     slices.Clone(input.Write),
		Supported: cloneBoolPtr(input.Supported),
		Blob:      slices.Clone(input.Blob),
		Written:   cloneBoolPtr(input.Written),
	}
}
