package extension_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/islishude/webauthn/extension"
)

func TestRegistryLookupIsCaseSensitive(t *testing.T) {
	t.Parallel()

	registry, err := extension.NewRegistry(
		extension.Register[bool, bool](fakeHandler{id: "custom"}),
		extension.Register[bool, bool](fakeHandler{id: "Custom"}),
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	if !registry.Contains("custom") {
		t.Fatal("Contains(custom) = false, want true")
	}
	if !registry.Contains("Custom") {
		t.Fatal("Contains(Custom) = false, want true")
	}
	if registry.Contains("CUSTOM") {
		t.Fatal("Contains(CUSTOM) = true, want false")
	}
}

func TestRegistryRejectsDuplicateAndEmptyIDs(t *testing.T) {
	t.Parallel()

	_, err := extension.NewRegistry(
		extension.Register[bool, bool](fakeHandler{id: "custom"}),
		extension.Register[bool, bool](fakeHandler{id: "custom"}),
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

func TestRegistryBoundsEntriesAndReservesBuiltInBindings(t *testing.T) {
	t.Parallel()

	entries := make([]extension.HandlerEntry, extension.MaxEntries+1)
	for i := range entries {
		entries[i] = extension.Register[bool, bool](fakeHandler{id: fmt.Sprintf("x%02d", i)})
	}
	if _, err := extension.NewRegistry(entries...); !errors.Is(err, extension.ErrTooManyEntries) {
		t.Fatalf("NewRegistry(too many) error = %v, want ErrTooManyEntries", err)
	}

	binding, ok := extension.BuiltInBinding(extension.IDCredProps)
	if !ok || binding != (extension.Binding{ID: extension.IDCredProps, Revision: extension.RevisionLevel3Recommendation}) {
		t.Fatalf("BuiltInBinding(credProps) = %+v, %t", binding, ok)
	}
	if _, ok := extension.BuiltInBinding("future"); ok {
		t.Fatal("BuiltInBinding(future) = known, want unknown")
	}
	if _, err := extension.NewRegistry(extension.Register[bool, bool](fakeHandler{id: extension.IDCredProps})); !errors.Is(err, extension.ErrInvalidRevision) {
		t.Fatalf("NewRegistry(reserved revision) error = %v, want ErrInvalidRevision", err)
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

func TestRegistryFreezesHandlerIdentity(t *testing.T) {
	t.Parallel()

	handler := &mutableHandler{id: "first", revision: "revision-1"}
	registry, err := extension.NewRegistry(extension.Register[bool, bool](handler))
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	result, err := registry.VerifyOutput(context.Background(), extension.RawOutputRequest{ID: "first", Requested: true})
	if err != nil {
		t.Fatalf("VerifyOutput() error = %v", err)
	}
	handler.revision = "revision-2"
	if _, ok := extension.Find(extension.Results{result}, handler); ok {
		t.Fatal("Find() accepted a handler with a different semantic revision")
	}
	matching := &mutableHandler{id: "first", revision: "revision-1"}
	if typed, ok := extension.Find(extension.Results{result}, matching); !ok || !typed.Accepted || !typed.Output {
		t.Fatalf("Find() frozen revision = %+v, %t", typed, ok)
	}
	handler.id = "second"
	if !registry.Contains("first") || registry.Contains("second") {
		t.Fatal("registry identity changed after construction")
	}
	binding, ok := registry.Binding("first")
	if !ok || binding.Revision != "revision-1" {
		t.Fatalf("Binding(first) = %+v, %t", binding, ok)
	}
}

type fakeHandler struct {
	id string
}

func (h fakeHandler) ID() string {
	return h.id
}

func (fakeHandler) Revision() string {
	return "test-v1"
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

func (typedHandler) Revision() string {
	return "test-v1"
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

type mutableHandler struct {
	id       string
	revision string
}

func (handler *mutableHandler) ID() string       { return handler.id }
func (handler *mutableHandler) Revision() string { return handler.revision }
func (*mutableHandler) ValidateInput(extension.InputRequest) (bool, error) {
	return true, nil
}
func (*mutableHandler) VerifyOutput(context.Context, extension.OutputRequest[bool]) (extension.Verification[bool], error) {
	return extension.Verification[bool]{Accepted: true, Output: true}, nil
}
