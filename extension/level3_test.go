package extension_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/islishude/webauthn/extension"
)

func TestLevel3Registries(t *testing.T) {
	t.Parallel()

	registry, err := extension.NewLevel3Registry()
	if err != nil {
		t.Fatalf("NewLevel3Registry() error = %v", err)
	}
	for _, id := range []string{
		extension.IDAppID,
		extension.IDAppIDExclude,
		extension.IDCredProps,
		extension.IDLargeBlob,
		extension.IDPRF,
	} {
		if _, ok := registry.Lookup(id); !ok {
			t.Fatalf("Lookup(%s) = false, want true", id)
		}
	}
	if _, ok := registry.Lookup(extension.IDUVM); ok {
		t.Fatal("Lookup(uvm) = true, want false for default Level 3 registry")
	}

	withDeprecated, err := extension.NewLevel3RegistryWithDeprecated()
	if err != nil {
		t.Fatalf("NewLevel3RegistryWithDeprecated() error = %v", err)
	}
	if _, ok := withDeprecated.Lookup(extension.IDUVM); !ok {
		t.Fatal("Lookup(uvm) = false, want true in deprecated registry")
	}
}

func TestPRFHandler(t *testing.T) {
	t.Parallel()

	handler := extension.PRFHandler{}
	first := bytes.Repeat([]byte{0x01}, 32)
	second := bytes.Repeat([]byte{0x02}, 32)

	t.Run("valid registration", func(t *testing.T) {
		t.Parallel()

		enabled := true
		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDPRF,
			Requested:   true,
			ClientInput: extension.PRFInput{Eval: &extension.PRFValues{First: []byte("salt-1"), Second: []byte("salt-2")}},
			ClientOutput: map[string]any{
				"enabled": enabled,
				"results": map[string]any{
					"first":  first,
					"second": second,
				},
			},
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		output := typedOutput[extension.PRFResult](t, result, extension.IDPRF)
		if !result.Accepted || output.Enabled == nil || !*output.Enabled ||
			output.Results == nil || !bytes.Equal(output.Results.First, first) || !bytes.Equal(output.Results.Second, second) {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("valid authentication evalByCredential", func(t *testing.T) {
		t.Parallel()

		credential := base64.RawURLEncoding.EncodeToString([]byte("credential-1"))
		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation: extension.OperationAuthentication,
			ID:        extension.IDPRF,
			Requested: true,
			ClientInput: extension.PRFInput{
				EvalByCredential: map[string]extension.PRFValues{
					credential: {First: []byte("salt-1")},
				},
				AllowCredentials: []string{credential},
			},
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		output := typedOutput[extension.PRFResult](t, result, extension.IDPRF)
		if result.Accepted || len(output.EvalByCredential) != 1 {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("reject registration evalByCredential", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation: extension.OperationRegistration,
			ID:        extension.IDPRF,
			Requested: true,
			ClientInput: extension.PRFInput{EvalByCredential: map[string]extension.PRFValues{
				base64.RawURLEncoding.EncodeToString([]byte("credential-1")): {First: []byte("salt")},
			}},
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("reject unallowed evalByCredential", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation: extension.OperationAuthentication,
			ID:        extension.IDPRF,
			Requested: true,
			ClientInput: extension.PRFInput{EvalByCredential: map[string]extension.PRFValues{
				base64.RawURLEncoding.EncodeToString([]byte("credential-1")): {First: []byte("salt")},
			}},
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("reject short result", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationAuthentication,
			ID:          extension.IDPRF,
			Requested:   true,
			ClientInput: extension.PRFInput{Eval: &extension.PRFValues{First: []byte("salt")}},
			ClientOutput: map[string]any{
				"results": map[string]any{"first": []byte("short")},
			},
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidRequest", err)
		}
	})
}
