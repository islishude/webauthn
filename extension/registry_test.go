package extension_test

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/webauthn/extension"
)

func TestRegistryLookupIsCaseSensitive(t *testing.T) {
	t.Parallel()

	registry, err := extension.NewRegistry(fakeHandler{id: "credProps"}, fakeHandler{id: "CredProps"})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	if _, ok := registry.Lookup("credProps"); !ok {
		t.Fatal("Lookup(credProps) = false, want true")
	}
	if _, ok := registry.Lookup("CredProps"); !ok {
		t.Fatal("Lookup(CredProps) = false, want true")
	}
	if _, ok := registry.Lookup("CREDPROPS"); ok {
		t.Fatal("Lookup(CREDPROPS) = true, want false")
	}
}

func TestRegistryRejectsDuplicateAndEmptyIDs(t *testing.T) {
	t.Parallel()

	_, err := extension.NewRegistry(fakeHandler{id: "credProps"}, fakeHandler{id: "credProps"})
	if !errors.Is(err, extension.ErrDuplicateID) {
		t.Fatalf("NewRegistry() error = %v, want ErrDuplicateID", err)
	}

	_, err = extension.NewRegistry(fakeHandler{id: ""})
	if !errors.Is(err, extension.ErrInvalidID) {
		t.Fatalf("NewRegistry() error = %v, want ErrInvalidID", err)
	}
}

type fakeHandler struct {
	id string
}

func (h fakeHandler) ID() string {
	return h.id
}

func (h fakeHandler) ValidateInput(request extension.InputRequest) (any, error) {
	return request.Input, nil
}

func (h fakeHandler) VerifyOutput(context.Context, extension.OutputRequest) (extension.Result, error) {
	return extension.Result{ID: h.id, Accepted: true}, nil
}

var _ extension.Handler = fakeHandler{}
