package extension_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/islishude/webauthn/extension"
)

func TestRemoteClientDataJSONHandler(t *testing.T) {
	t.Parallel()

	handler := extension.RemoteClientDataJSONHandler{}
	registry, err := extension.NewRegistry(extension.Register(handler))
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	input := `{"type":"webauthn.create","challenge":"` + challenge + `","origin":"https://remote.example"}`
	result, err := registry.VerifyOutput(context.Background(), extension.RawOutputRequest{
		Operation:    extension.OperationRegistration,
		ID:           extension.IDRemoteClientDataJSON,
		Requested:    true,
		ClientInput:  rawValue(t, input),
		ClientOutput: rawValue(t, true),
	})
	if err != nil {
		t.Fatalf("VerifyOutput() error = %v", err)
	}
	typed, ok := extension.Find(extension.Results{result}, handler)
	if !ok || !typed.Accepted || !typed.Output.Used {
		t.Fatalf("result = %+v typed = %+v", result, typed)
	}

	for _, test := range []struct {
		name      string
		operation extension.Operation
		input     any
		output    any
	}{
		{name: "wrong ceremony", operation: extension.OperationAuthentication, input: input, output: true},
		{name: "malformed json", operation: extension.OperationRegistration, input: `{`, output: true},
		{name: "false output", operation: extension.OperationRegistration, input: input, output: false},
		{name: "non-boolean output", operation: extension.OperationRegistration, input: input, output: "true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := registry.VerifyOutput(context.Background(), extension.RawOutputRequest{
				Operation:    test.operation,
				ID:           extension.IDRemoteClientDataJSON,
				Requested:    true,
				ClientInput:  rawValue(t, test.input),
				ClientOutput: rawValue(t, test.output),
			})
			if !errors.Is(err, extension.ErrInvalidRequest) {
				t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
			}
		})
	}

	if _, err := registry.VerifyOutput(context.Background(), extension.RawOutputRequest{
		Operation:    extension.OperationRegistration,
		ID:           extension.IDRemoteClientDataJSON,
		Requested:    true,
		ClientInput:  rawValue(t, input),
		ClientOutput: rawValue(t, nil),
	}); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("VerifyOutput() explicit null error = %v, want ErrInvalidRequest", err)
	}
	if _, err := registry.VerifyOutput(context.Background(), extension.RawOutputRequest{
		Operation:   extension.OperationRegistration,
		ID:          extension.IDRemoteClientDataJSON,
		Requested:   true,
		ClientInput: rawValue(t, input),
	}); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("VerifyOutput() absent output error = %v, want ErrInvalidRequest", err)
	}
}
