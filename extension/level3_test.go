package extension_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
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
		if !registry.Contains(id) {
			t.Fatalf("Contains(%s) = false, want true", id)
		}
	}
	if registry.Contains(extension.IDUVM) {
		t.Fatal("Contains(uvm) = true, want false for default Level 3 registry")
	}
	if registry.Contains(extension.IDRemoteClientDataJSON) {
		t.Fatal("Contains(remoteClientDataJSON) = true, want opt-in Editor's Draft handler")
	}

	withDeprecated, err := extension.NewLevel3RegistryWithDeprecated()
	if err != nil {
		t.Fatalf("NewLevel3RegistryWithDeprecated() error = %v", err)
	}
	if !withDeprecated.Contains(extension.IDUVM) {
		t.Fatal("Contains(uvm) = false, want true in deprecated registry")
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
		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.PRFInput]{
			Operation:   extension.OperationRegistration,
			ID:          extension.IDPRF,
			Requested:   true,
			ClientInput: extension.PRFInput{Eval: &extension.PRFValues{First: []byte("salt-1"), Second: []byte("salt-2")}},
			ClientOutput: rawValue(t, map[string]any{
				"enabled": enabled,
				"results": map[string]any{
					"first":  first,
					"second": second,
				},
			}),
		})

		if err != nil {
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		output := result.Output
		if !result.Accepted || output.Enabled == nil || !*output.Enabled ||
			output.Results == nil || !bytes.Equal(output.Results.First, first) || !bytes.Equal(output.Results.Second, second) {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("valid authentication evalByCredential", func(t *testing.T) {
		t.Parallel()

		credential := base64.RawURLEncoding.EncodeToString([]byte("credential-1"))
		result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.PRFInput]{
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
			t.Fatalf("VerifyOutput() error = %v", err)
		}
		output := result.Output
		if result.Accepted || len(output.EvalByCredential) != 1 {
			t.Fatalf("result = %+v output = %+v", result, output)
		}
	})

	t.Run("reject registration evalByCredential", func(t *testing.T) {
		t.Parallel()

		_, err := handler.ValidateInput(extension.InputRequest{
			Operation: extension.OperationRegistration,
			ID:        extension.IDPRF,
			Input: rawValue(t, extension.PRFInput{EvalByCredential: map[string]extension.PRFValues{
				base64.RawURLEncoding.EncodeToString([]byte("credential-1")): {First: []byte("salt")},
			}}),
		})

		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("reject registration empty evalByCredential", func(t *testing.T) {
		t.Parallel()

		for _, input := range []any{
			extension.PRFInput{EvalByCredential: map[string]extension.PRFValues{}},
			map[string]any{"evalByCredential": map[string]any{}},
		} {
			_, err := handler.ValidateInput(extension.InputRequest{
				Operation: extension.OperationRegistration,
				ID:        extension.IDPRF,
				Input:     rawValue(t, input),
			})
			if !errors.Is(err, extension.ErrInvalidRequest) {
				t.Fatalf("VerifyOutput(%T) error = %v, want ErrInvalidRequest", input, err)
			}
		}
	})

	t.Run("reject unallowed evalByCredential", func(t *testing.T) {
		t.Parallel()

		_, err := handler.ValidateInput(extension.InputRequest{
			Operation: extension.OperationAuthentication,
			ID:        extension.IDPRF,
			Input: rawValue(t, extension.PRFInput{EvalByCredential: map[string]extension.PRFValues{
				base64.RawURLEncoding.EncodeToString([]byte("credential-1")): {First: []byte("salt")},
			}}),
		})

		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("reject non-canonical evalByCredential", func(t *testing.T) {
		t.Parallel()

		credential := "_x"
		_, err := handler.ValidateInput(extension.InputRequest{
			Operation: extension.OperationAuthentication,
			ID:        extension.IDPRF,
			Input: rawValue(t, extension.PRFInput{
				EvalByCredential: map[string]extension.PRFValues{
					credential: {First: []byte("salt")},
				},
				AllowCredentials: []string{credential},
			}),
		})

		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("reject short result", func(t *testing.T) {
		t.Parallel()

		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.PRFInput]{
			Operation:   extension.OperationAuthentication,
			ID:          extension.IDPRF,
			Requested:   true,
			ClientInput: extension.PRFInput{Eval: &extension.PRFValues{First: []byte("salt")}},
			ClientOutput: rawValue(t, map[string]any{
				"results": map[string]any{"first": []byte("short")},
			}),
		})

		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("reject missing registration enabled", func(t *testing.T) {
		t.Parallel()
		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.PRFInput]{
			Operation:    extension.OperationRegistration,
			ID:           extension.IDPRF,
			Requested:    true,
			ClientInput:  extension.PRFInput{},
			ClientOutput: rawValue(t, map[string]any{}),
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("reject authentication enabled", func(t *testing.T) {
		t.Parallel()
		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.PRFInput]{
			Operation:    extension.OperationAuthentication,
			ID:           extension.IDPRF,
			Requested:    true,
			ClientInput:  extension.PRFInput{},
			ClientOutput: rawValue(t, map[string]any{"enabled": true}),
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("reject result cardinality mismatch", func(t *testing.T) {
		t.Parallel()
		_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.PRFInput]{
			Operation:   extension.OperationAuthentication,
			ID:          extension.IDPRF,
			Requested:   true,
			ClientInput: extension.PRFInput{Eval: &extension.PRFValues{First: []byte("salt")}},
			ClientOutput: rawValue(t, map[string]any{"results": map[string]any{
				"first":  first,
				"second": second,
			}}),
		})
		if !errors.Is(err, extension.ErrInvalidRequest) {
			t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("bind results to selected credential", func(t *testing.T) {
		t.Parallel()

		mappedRaw := []byte("credential-1")
		otherRaw := []byte("credential-2")
		mapped := base64.RawURLEncoding.EncodeToString(mappedRaw)
		other := base64.RawURLEncoding.EncodeToString(otherRaw)
		mappedID, err := protocol.NewCredentialID(mappedRaw)
		if err != nil {
			t.Fatalf("NewCredentialID(mapped) error = %v", err)
		}
		otherID, err := protocol.NewCredentialID(otherRaw)
		if err != nil {
			t.Fatalf("NewCredentialID(other) error = %v", err)
		}
		input := extension.PRFInput{
			Eval: &extension.PRFValues{First: []byte("fallback-1"), Second: []byte("fallback-2")},
			EvalByCredential: map[string]extension.PRFValues{
				mapped: {First: []byte("mapped")},
			},
			AllowCredentials: []string{mapped, other},
		}
		tests := []struct {
			name     string
			selected protocol.CredentialID
			results  map[string]any
			wantErr  bool
		}{
			{
				name:     "mapped credential rejects fallback cardinality",
				selected: mappedID,
				results:  map[string]any{"first": first, "second": second},
				wantErr:  true,
			},
			{
				name:     "other credential rejects mapped cardinality",
				selected: otherID,
				results:  map[string]any{"first": first},
				wantErr:  true,
			},
			{
				name:    "missing selected credential fails closed",
				results: map[string]any{"first": first},
				wantErr: true,
			},
			{
				name:     "mapped credential accepts mapped cardinality",
				selected: mappedID,
				results:  map[string]any{"first": first},
			},
			{
				name:     "other credential accepts fallback cardinality",
				selected: otherID,
				results:  map[string]any{"first": first, "second": second},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				_, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.PRFInput]{
					Operation:            extension.OperationAuthentication,
					ID:                   extension.IDPRF,
					Requested:            true,
					SelectedCredentialID: tt.selected,
					ClientInput:          input,
					ClientOutput:         rawValue(t, map[string]any{"results": tt.results}),
				})
				if tt.wantErr && !errors.Is(err, extension.ErrInvalidRequest) {
					t.Fatalf("VerifyOutput() error = %v, want ErrInvalidRequest", err)
				}
				if !tt.wantErr && err != nil {
					t.Fatalf("VerifyOutput() error = %v", err)
				}
			})
		}
	})
}

func TestPRFInputRequiresFirstValue(t *testing.T) {
	t.Parallel()

	// Recommendation section 10.1.4 requires first, while allowing byte
	// sequences of any length, including an explicitly empty sequence.
	for _, operation := range []extension.Operation{extension.OperationRegistration, extension.OperationAuthentication} {
		for _, test := range []struct {
			name    string
			values  extension.PRFValues
			wantErr bool
		}{
			{name: "missing first", wantErr: true},
			{name: "only second", values: extension.PRFValues{Second: []byte("salt")}, wantErr: true},
			{name: "empty first", values: extension.PRFValues{First: []byte{}}},
			{name: "empty first and second", values: extension.PRFValues{First: []byte{}, Second: []byte{}}},
			{name: "arbitrary length", values: extension.PRFValues{First: []byte("salt"), Second: []byte("other salt")}},
		} {
			t.Run(string(operation)+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				inputs := []extension.PRFInput{{Eval: &test.values}}
				if operation == extension.OperationAuthentication {
					inputs = append(inputs, extension.PRFInput{
						EvalByCredential: map[string]extension.PRFValues{"YQ": test.values},
						AllowCredentials: []string{"YQ"},
					})
				}
				for _, input := range inputs {
					_, err := (extension.PRFHandler{}).ValidateInput(extension.InputRequest{
						Operation: operation,
						ID:        extension.IDPRF,
						Input:     rawValue(t, input),
					})
					if test.wantErr && !errors.Is(err, extension.ErrInvalidRequest) {
						t.Fatalf("ValidateInput(%+v) error = %v, want ErrInvalidRequest", input, err)
					}
					if !test.wantErr && err != nil {
						t.Fatalf("ValidateInput(%+v) error = %v", input, err)
					}
				}
			})
		}
	}
}
