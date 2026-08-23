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
	challenge := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	input := `{"type":"webauthn.create","challenge":"` + challenge + `","origin":"https://remote.example"}`
	result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest{
		Operation:    extension.OperationRegistration,
		ID:           extension.IDRemoteClientDataJSON,
		Requested:    true,
		ClientInput:  input,
		ClientOutput: true,
	})
	if err != nil {
		t.Fatalf("VerifyOutput() error = %v", err)
	}
	output := typedOutput[extension.RemoteClientDataJSONResult](t, result, extension.IDRemoteClientDataJSON)
	if !result.Accepted || !output.Used {
		t.Fatalf("result = %+v output = %+v", result, output)
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
			_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest{
				Operation:    test.operation,
				ID:           extension.IDRemoteClientDataJSON,
				Requested:    true,
				ClientInput:  test.input,
				ClientOutput: test.output,
			})
			if !errors.Is(err, extension.ErrInvalidRequest) {
				t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
			}
		})
	}

	if _, err := handler.VerifyOutput(context.Background(), extension.OutputRequest{
		Operation:           extension.OperationRegistration,
		ID:                  extension.IDRemoteClientDataJSON,
		Requested:           true,
		ClientInput:         input,
		ClientOutputPresent: true,
	}); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("VerifyOutput() explicit null error = %v, want ErrInvalidRequest", err)
	}
	if _, err := handler.VerifyOutput(context.Background(), extension.OutputRequest{
		Operation:   extension.OperationRegistration,
		ID:          extension.IDRemoteClientDataJSON,
		Requested:   true,
		ClientInput: input,
	}); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("VerifyOutput() absent output error = %v, want ErrInvalidRequest", err)
	}
}
