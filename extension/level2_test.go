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
		if !registry.Contains(id) {
			t.Fatalf("Contains(%s) = false, want true", id)
		}
	}
}

func TestAppIDHandler(t *testing.T) {
	t.Parallel()

	handler := extension.AppIDHandler{}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[string]{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDAppID,
			Requested:    true,
			ClientInput:  "https://legacy.example/appid",
			ClientOutput: rawValue(t, true),
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		output := result.Output
		if !result.Accepted || !output.Used || output.AppID != "https://legacy.example/appid" {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("absent output", func(t *testing.T) {
		t.Parallel()

		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[string]{
			Operation:   extension.OperationAuthentication,
			ID:          extension.IDAppID,
			Requested:   true,
			ClientInput: "https://legacy.example/appid",
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("malformed output", func(t *testing.T) {
		t.Parallel()

		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[string]{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDAppID,
			Requested:    true,
			ClientInput:  "https://legacy.example/appid",
			ClientOutput: rawValue(t, "true"),
		})

		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("wrong operation", func(t *testing.T) {
		t.Parallel()

		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[string]{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDAppID,
			Requested:   true,
			ClientInput: "https://legacy.example/appid",
		})

		if !errors.Is(err, extension.ErrInvalidOperation) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidOperation", err)
		}
	})
}

func TestAppIDExcludeHandler(t *testing.T) {
	t.Parallel()

	handler := extension.AppIDExcludeHandler{}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[string]{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDAppIDExclude,
			Requested:    true,
			ClientInput:  "https://legacy.example/appid",
			ClientOutput: rawValue(t, true),
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		output := result.Output
		if !result.Accepted || !output.ActedUpon || output.AppID != "https://legacy.example/appid" {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("absent output", func(t *testing.T) {
		t.Parallel()

		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[string]{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDAppIDExclude,
			Requested:   true,
			ClientInput: "https://legacy.example/appid",
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("malformed input", func(t *testing.T) {
		t.Parallel()

		_, err := handler.ValidateInput(extension.InputRequest{
			Operation: extension.OperationRegistration,
			ID:        extension.IDAppIDExclude,
			Input:     rawValue(t, true),
		})

		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("false output", func(t *testing.T) {
		t.Parallel()
		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[string]{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDAppIDExclude,
			Requested:    true,
			ClientInput:  "https://legacy.example/appid",
			ClientOutput: rawValue(t, false),
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("wrong operation", func(t *testing.T) {
		t.Parallel()

		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[string]{
			Operation:   extension.OperationAuthentication,
			ID:          extension.IDAppIDExclude,
			Requested:   true,
			ClientInput: "https://legacy.example/appid",
		})

		if !errors.Is(err, extension.ErrInvalidOperation) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidOperation", err)
		}
	})
}

func TestUVMHandler(t *testing.T) {
	t.Parallel()

	handler := extension.UVMHandler{}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[bool]{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDUVM,
			Requested:    true,
			ClientInput:  true,
			ClientOutput: rawValue(t, []any{[]any{uint64(2), uint64(4), uint64(2)}}),
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		//nolint:staticcheck // UVM is intentionally tested as deprecated Level 3 support.
		output := result.Output
		if !result.Accepted || !result.Deprecated || len(output.Entries) != 1 || output.Entries[0].UserVerificationMethod != 2 {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("absent output", func(t *testing.T) {
		t.Parallel()

		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[bool]{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDUVM,
			Requested:   true,
			ClientInput: true,
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("malformed output", func(t *testing.T) {
		t.Parallel()

		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[bool]{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDUVM,
			Requested:    true,
			ClientInput:  true,
			ClientOutput: rawValue(t, []any{[]any{uint64(2), uint64(4)}}),
		})

		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("wrong operation", func(t *testing.T) {
		t.Parallel()

		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[bool]{
			ID:          extension.IDUVM,
			Requested:   true,
			ClientInput: true,
		})

		if !errors.Is(err, extension.ErrInvalidOperation) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidOperation", err)
		}
	})
}

func TestCredPropsHandler(t *testing.T) {
	t.Parallel()

	handler := extension.CredPropsHandler{}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[bool]{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDCredProps,
			Requested:    true,
			ClientInput:  true,
			ClientOutput: rawValue(t, map[string]any{"rk": true}),
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		output := result.Output
		if !result.Accepted || output.ResidentKey == nil || !*output.ResidentKey {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("absent output", func(t *testing.T) {
		t.Parallel()

		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[bool]{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDCredProps,
			Requested:   true,
			ClientInput: true,
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("malformed output", func(t *testing.T) {
		t.Parallel()

		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[bool]{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDCredProps,
			Requested:    true,
			ClientInput:  true,
			ClientOutput: rawValue(t, map[string]any{"rk": "true"}),
		})

		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("wrong operation", func(t *testing.T) {
		t.Parallel()

		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[bool]{
			Operation:   extension.OperationAuthentication,
			ID:          extension.IDCredProps,
			Requested:   true,
			ClientInput: true,
		})

		if !errors.Is(err, extension.ErrInvalidOperation) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidOperation", err)
		}
	})
}

func TestLargeBlobHandler(t *testing.T) {
	t.Parallel()

	handler := extension.LargeBlobHandler{}

	t.Run("valid registration", func(t *testing.T) {
		t.Parallel()

		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.LargeBlobInput]{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDLargeBlob,
			Requested:    true,
			ClientInput:  extension.LargeBlobInput{Support: extension.LargeBlobSupportRequired},
			ClientOutput: rawValue(t, map[string]any{"supported": true}),
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		output := result.Output
		if !result.Accepted || output.Supported == nil || !*output.Supported || output.Support != extension.LargeBlobSupportRequired {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("valid authentication", func(t *testing.T) {
		t.Parallel()

		read := true
		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.LargeBlobInput]{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDLargeBlob,
			Requested:    true,
			ClientInput:  extension.LargeBlobInput{Read: &read},
			ClientOutput: rawValue(t, map[string]any{"blob": []byte("blob")}),
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		output := result.Output
		if !result.Accepted || string(output.Blob) != "blob" || output.Read == nil || !*output.Read {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("absent output", func(t *testing.T) {
		t.Parallel()

		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.LargeBlobInput]{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDLargeBlob,
			Requested:   true,
			ClientInput: extension.LargeBlobInput{Support: extension.LargeBlobSupportPreferred},
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("malformed input", func(t *testing.T) {
		t.Parallel()

		_, err := handler.ValidateInput(extension.InputRequest{
			Operation: extension.OperationRegistration,
			ID:        extension.IDLargeBlob,
			Input:     rawValue(t, map[string]any{"read": true}),
		})

		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("required support unavailable", func(t *testing.T) {
		t.Parallel()

		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.LargeBlobInput]{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDLargeBlob,
			Requested:    true,
			ClientInput:  extension.LargeBlobInput{Support: extension.LargeBlobSupportRequired},
			ClientOutput: rawValue(t, map[string]any{"supported": false}),
		})

		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("registration output missing supported", func(t *testing.T) {
		t.Parallel()
		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.LargeBlobInput]{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDLargeBlob,
			Requested:    true,
			ClientInput:  extension.LargeBlobInput{Support: extension.LargeBlobSupportPreferred},
			ClientOutput: rawValue(t, map[string]any{}),
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("write output missing written", func(t *testing.T) {
		t.Parallel()
		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.LargeBlobInput]{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDLargeBlob,
			Requested:    true,
			ClientInput:  extension.LargeBlobInput{Write: []byte("blob")},
			ClientOutput: rawValue(t, map[string]any{}),
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("wrong operation", func(t *testing.T) {
		t.Parallel()

		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.LargeBlobInput]{
			ID:          extension.IDLargeBlob,
			Requested:   true,
			ClientInput: extension.LargeBlobInput{},
		})

		if !errors.Is(err, extension.ErrInvalidOperation) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidOperation", err)
		}
	})
}
