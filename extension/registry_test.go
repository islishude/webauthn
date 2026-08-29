package extension_test

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/webauthn/extension"
)

func TestRegistryLookupIsCaseSensitive(t *testing.T) {
	t.Parallel()

	registry, err := extension.NewRegistry(
		extension.Register[bool, bool](fakeHandler{id: "credProps"}),
		extension.Register[bool, bool](fakeHandler{id: "CredProps"}),
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	if !registry.Contains("credProps") {
		t.Fatal("Contains(credProps) = false, want true")
	}
	if !registry.Contains("CredProps") {
		t.Fatal("Contains(CredProps) = false, want true")
	}
	if registry.Contains("CREDPROPS") {
		t.Fatal("Contains(CREDPROPS) = true, want false")
	}
}

func TestRegistryRejectsDuplicateAndEmptyIDs(t *testing.T) {
	t.Parallel()

	_, err := extension.NewRegistry(
		extension.Register[bool, bool](fakeHandler{id: "credProps"}),
		extension.Register[bool, bool](fakeHandler{id: "credProps"}),
	)
	if !errors.Is(err, extension.ErrDuplicateID) {
		t.Fatalf("NewRegistry() error = %v, want ErrDuplicateID", err)
	}

	_, err = extension.NewRegistry(extension.Register[bool, bool](fakeHandler{id: ""}))
	if !errors.Is(err, extension.ErrInvalidID) {
		t.Fatalf("NewRegistry() error = %v, want ErrInvalidID", err)
	}
	for _, id := range []string{"not valid", `not"valid`, `not\valid`, "012345678901234567890123456789012", "扩展"} {
		if _, err := extension.NewRegistry(extension.Register[bool, bool](fakeHandler{id: id})); !errors.Is(err, extension.ErrInvalidID) {
			t.Fatalf("NewRegistry(%q) error = %v, want ErrInvalidID", id, err)
		}
	}
	if _, err := extension.NewRegistry(nil); !errors.Is(err, extension.ErrInvalidID) {
		t.Fatalf("NewRegistry(nil) error = %v, want ErrInvalidID", err)
	}
	var nilHandler *typedHandler
	if _, err := extension.NewRegistry(extension.Register(nilHandler)); !errors.Is(err, extension.ErrInvalidID) {
		t.Fatalf("NewRegistry(typed nil) error = %v, want ErrInvalidID", err)
	}
}

func TestRegistryDispatchAndTypedFindDefensivelyCopy(t *testing.T) {
	t.Parallel()

	bytes := []byte{0x01}
	handler := typedHandler{id: "typed", output: cloneableValue{Bytes: bytes}}
	registry, err := extension.NewRegistry(extension.Register(handler))
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	input := rawValue(t, true)
	normalized, err := registry.ValidateInput(extension.InputRequest{
		Operation: extension.OperationAuthentication,
		ID:        "typed",
		Input:     input,
	})
	if err != nil {
		t.Fatalf("ValidateInput() error = %v", err)
	}
	if _, err := registry.ValidateInput(extension.InputRequest{ID: "missing", Input: input}); !errors.Is(err, extension.ErrUnknownID) {
		t.Fatalf("ValidateInput(missing) error = %v, want ErrUnknownID", err)
	}
	if _, err := registry.ValidateInput(extension.InputRequest{ID: "typed", Input: rawValue(t, "true")}); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("ValidateInput(malformed) error = %v, want ErrInvalidRequest", err)
	}
	result, err := registry.VerifyOutput(context.Background(), extension.RawOutputRequest{
		Operation:    extension.OperationAuthentication,
		ID:           "typed",
		Requested:    true,
		ClientInput:  normalized,
		ClientOutput: rawValue(t, nil),
	})
	if err != nil {
		t.Fatalf("VerifyOutput() error = %v", err)
	}
	bytes[0] = 0xff
	typed, ok := extension.Find(extension.Results{result}, handler)
	if !ok || !typed.Accepted || typed.Output.Bytes[0] != 0x01 {
		t.Fatalf("Find() = %+v, %t", typed, ok)
	}
	typed.Output.Bytes[0] = 0xee
	again, ok := extension.Find(extension.Results{result}, handler)
	if !ok || again.Output.Bytes[0] != 0x01 {
		t.Fatalf("second Find() = %+v, %t", again, ok)
	}
	if _, ok := extension.Find(extension.Results{result}, fakeHandler{id: "typed"}); ok {
		t.Fatal("Find() with mismatched handler output type = true, want false")
	}
	if _, err := registry.VerifyOutput(context.Background(), extension.RawOutputRequest{ID: "missing"}); !errors.Is(err, extension.ErrUnknownID) {
		t.Fatalf("VerifyOutput(missing) error = %v, want ErrUnknownID", err)
	}
}

type fakeHandler struct {
	id string
}

func (h fakeHandler) ID() string {
	return h.id
}

func (h fakeHandler) ValidateInput(request extension.InputRequest) (bool, error) {
	value, ok := extension.As[bool](request.Input)
	if !ok {
		return false, extension.ErrInvalidRequest
	}
	return value, nil
}

func (h fakeHandler) VerifyOutput(context.Context, extension.OutputRequest[bool]) (extension.Verification[bool], error) {
	return extension.Verification[bool]{Accepted: true, Output: true}, nil
}

var _ extension.Handler[bool, bool] = fakeHandler{}

type typedHandler struct {
	id     string
	output cloneableValue
}

func (h typedHandler) ID() string {
	return h.id
}

func (typedHandler) ValidateInput(request extension.InputRequest) (bool, error) {
	value, ok := extension.As[bool](request.Input)
	if !ok {
		return false, extension.ErrInvalidRequest
	}
	return value, nil
}

func (h typedHandler) VerifyOutput(_ context.Context, request extension.OutputRequest[bool]) (extension.Verification[cloneableValue], error) {
	if !request.ClientOutput.Present() || !request.ClientOutput.Null() {
		return extension.Verification[cloneableValue]{}, extension.ErrInvalidRequest
	}
	return extension.Verification[cloneableValue]{Accepted: true, Output: h.output}, nil
}

var _ extension.Handler[bool, cloneableValue] = typedHandler{}
