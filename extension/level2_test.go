package extension_test

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/webauthn/extension"
)

func TestLevel2RegistryRegistersDefinedExtensions(t *testing.T) {
	t.Parallel()

	registry, err := extension.NewLevel2Registry()
	if err != nil {
		t.Fatalf("NewLevel2Registry() error = %v", err)
	}

	for _, id := range []string{
		extension.IDAppID,
		extension.IDAppIDExclude,
		extension.IDUVM,
		extension.IDCredProps,
		extension.IDLargeBlob,
	} {
		if _, ok := registry.Lookup(id); !ok {
			t.Fatalf("Lookup(%s) = false, want true", id)
		}
	}
}

func TestAppIDHandler(t *testing.T) {
	t.Parallel()

	handler := extension.AppIDHandler{}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDAppID,
			Requested:    true,
			ClientInput:  "https://legacy.example/appid",
			ClientOutput: true,
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		output := typedOutput[extension.AppIDResult](t, result, extension.IDAppID)
		if !result.Accepted || !output.Used || output.AppID != "https://legacy.example/appid" {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("absent output", func(t *testing.T) {
		t.Parallel()

		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationAuthentication,
			ID:          extension.IDAppID,
			Requested:   true,
			ClientInput: "https://legacy.example/appid",
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("malformed output", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDAppID,
			Requested:    true,
			ClientInput:  "https://legacy.example/appid",
			ClientOutput: "true",
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("wrong operation", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDAppID,
			Requested:   true,
			ClientInput: "https://legacy.example/appid",
		})
		if !errors.Is(err, extension.ErrInvalidOperation) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidOperation", err)
		}
	})
}

func TestAppIDExcludeHandler(t *testing.T) {
	t.Parallel()

	handler := extension.AppIDExcludeHandler{}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDAppIDExclude,
			Requested:    true,
			ClientInput:  "https://legacy.example/appid",
			ClientOutput: true,
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		output := typedOutput[extension.AppIDExcludeResult](t, result, extension.IDAppIDExclude)
		if !result.Accepted || !output.Excluded || output.AppID != "https://legacy.example/appid" {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("absent output", func(t *testing.T) {
		t.Parallel()

		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDAppIDExclude,
			Requested:   true,
			ClientInput: "https://legacy.example/appid",
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("malformed input", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDAppIDExclude,
			Requested:   true,
			ClientInput: true,
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("wrong operation", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationAuthentication,
			ID:          extension.IDAppIDExclude,
			Requested:   true,
			ClientInput: "https://legacy.example/appid",
		})
		if !errors.Is(err, extension.ErrInvalidOperation) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidOperation", err)
		}
	})
}

func TestUVMHandler(t *testing.T) {
	t.Parallel()

	handler := extension.UVMHandler{}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDUVM,
			Requested:    true,
			ClientInput:  true,
			ClientOutput: []any{[]any{uint64(2), uint64(4), uint64(2)}},
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		//nolint:staticcheck // UVM is intentionally tested as deprecated Level 3 support.
		output := typedOutput[extension.UVMResult](t, result, extension.IDUVM)
		if !result.Accepted || !result.Deprecated || len(output.Entries) != 1 || output.Entries[0].UserVerificationMethod != 2 {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("absent output", func(t *testing.T) {
		t.Parallel()

		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDUVM,
			Requested:   true,
			ClientInput: true,
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("malformed output", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDUVM,
			Requested:    true,
			ClientInput:  true,
			ClientOutput: []any{[]any{uint64(2), uint64(4)}},
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("wrong operation", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			ID:          extension.IDUVM,
			Requested:   true,
			ClientInput: true,
		})
		if !errors.Is(err, extension.ErrInvalidOperation) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidOperation", err)
		}
	})
}

func TestCredPropsHandler(t *testing.T) {
	t.Parallel()

	handler := extension.CredPropsHandler{}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDCredProps,
			Requested:    true,
			ClientInput:  true,
			ClientOutput: map[string]any{"rk": true},
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		output := typedOutput[extension.CredentialPropertiesResult](t, result, extension.IDCredProps)
		if !result.Accepted || output.ResidentKey == nil || !*output.ResidentKey {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("absent output", func(t *testing.T) {
		t.Parallel()

		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDCredProps,
			Requested:   true,
			ClientInput: true,
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("malformed output", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDCredProps,
			Requested:    true,
			ClientInput:  true,
			ClientOutput: map[string]any{"rk": "true"},
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("wrong operation", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationAuthentication,
			ID:          extension.IDCredProps,
			Requested:   true,
			ClientInput: true,
		})
		if !errors.Is(err, extension.ErrInvalidOperation) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidOperation", err)
		}
	})
}

func TestLargeBlobHandler(t *testing.T) {
	t.Parallel()

	handler := extension.LargeBlobHandler{}

	t.Run("valid registration", func(t *testing.T) {
		t.Parallel()

		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDLargeBlob,
			Requested:    true,
			ClientInput:  map[string]any{"support": "required"},
			ClientOutput: map[string]any{"supported": true},
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		output := typedOutput[extension.LargeBlobResult](t, result, extension.IDLargeBlob)
		if !result.Accepted || output.Supported == nil || !*output.Supported || output.Support != extension.LargeBlobSupportRequired {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("valid authentication", func(t *testing.T) {
		t.Parallel()

		read := true
		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDLargeBlob,
			Requested:    true,
			ClientInput:  extension.LargeBlobInput{Read: &read},
			ClientOutput: map[string]any{"blob": []byte("blob")},
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		output := typedOutput[extension.LargeBlobResult](t, result, extension.IDLargeBlob)
		if !result.Accepted || string(output.Blob) != "blob" || output.Read == nil || !*output.Read {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("absent output", func(t *testing.T) {
		t.Parallel()

		result, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDLargeBlob,
			Requested:   true,
			ClientInput: map[string]any{"support": "preferred"},
		})
		if err != nil {
			t.Fatalf("HandleExtension() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("malformed input", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDLargeBlob,
			Requested:   true,
			ClientInput: map[string]any{"read": true},
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("required support unavailable", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDLargeBlob,
			Requested:    true,
			ClientInput:  map[string]any{"support": "required"},
			ClientOutput: map[string]any{"supported": false},
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("wrong operation", func(t *testing.T) {
		t.Parallel()

		_, err := handler.HandleExtension(context.Background(), extension.Request{
			ID:          extension.IDLargeBlob,
			Requested:   true,
			ClientInput: map[string]any{},
		})
		if !errors.Is(err, extension.ErrInvalidOperation) {
			t.Fatalf("HandleExtension() error = %v, want ErrInvalidOperation", err)
		}
	})
}

func typedOutput[T any](t *testing.T, result extension.Result, id string) T {
	t.Helper()

	raw, ok := result.Outputs[id]
	if !ok {
		t.Fatalf("Outputs[%s] missing in %+v", id, result.Outputs)
	}
	output, ok := raw.(T)
	if !ok {
		t.Fatalf("Outputs[%s] = %T, want requested type", id, raw)
	}

	return output
}
