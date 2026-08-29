package webauthn_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

func TestW3CLevel3PRFWebAPIVectors(t *testing.T) {
	t.Parallel()

	fixture := loadW3CFixture[w3cPRFAPIFixture](t, "prf-api.json")
	handler := extension.PRFHandler{}
	for _, vector := range fixture.Cases {
		t.Run(vector.ID, func(t *testing.T) {
			t.Parallel()

			operation := extension.Operation(vector.Operation)
			input := w3cPRFInput(t, vector.Input, vector.AllowCredentials)
			selectedCredentialID := w3cPRFSelectedCredential(t, vector.SelectedCredential)
			clientOutput, wantFirst, wantSecond := w3cPRFClientOutput(t, vector)
			result, err := handler.VerifyOutput(context.Background(), extension.OutputRequest[extension.PRFInput]{
				Operation:            operation,
				ID:                   extension.IDPRF,
				Requested:            true,
				SelectedCredentialID: selectedCredentialID,
				ClientInput:          input,
				ClientOutput:         mustRawExtensionValue(t, clientOutput),
			})
			if err != nil {
				t.Fatalf("VerifyOutput() error = %v", err)
			}
			if !result.Accepted {
				t.Fatalf("result = %+v, want accepted", result)
			}
			output := result.Output
			if (output.Enabled != nil) != vector.Output.EnabledPresent ||
				(output.Enabled != nil && *output.Enabled != vector.Output.Enabled) {
				t.Fatalf("enabled = %v, fixture = %+v", output.Enabled, vector.Output)
			}
			if (output.Results != nil) != vector.Output.ResultsPresent {
				t.Fatalf("results = %+v, fixture = %+v", output.Results, vector.Output)
			}
			if output.Results != nil {
				if !bytes.Equal(output.Results.First, wantFirst) || (output.Results.Second != nil) != vector.Output.Results.SecondPresent {
					t.Fatalf("results = %+v, want first=%x second-present=%t", output.Results, wantFirst, vector.Output.Results.SecondPresent)
				}
				if vector.Output.Results.SecondPresent && !bytes.Equal(output.Results.Second, wantSecond) {
					t.Fatalf("second = %x, want %x", output.Results.Second, wantSecond)
				}
			}
		})
	}
}

func w3cPRFInput(t *testing.T, fixture w3cPRFInputFixture, allowed []string) extension.PRFInput {
	t.Helper()
	input := extension.PRFInput{AllowCredentials: append([]string{}, allowed...)}
	if fixture.Eval != nil {
		values := w3cPRFValues(t, *fixture.Eval)
		input.Eval = &values
	}
	if fixture.EvalByCredential != nil {
		input.EvalByCredential = make(map[string]extension.PRFValues, len(fixture.EvalByCredential))
		for id, values := range fixture.EvalByCredential {
			input.EvalByCredential[id] = w3cPRFValues(t, values)
		}
	}
	return input
}

func w3cPRFValues(t *testing.T, fixture w3cPRFValuesFixture) extension.PRFValues {
	t.Helper()
	values := extension.PRFValues{First: decodeW3CHex(t, fixture.First)}
	if fixture.Second != "" {
		values.Second = decodeW3CHex(t, fixture.Second)
	}
	return values
}

func w3cPRFSelectedCredential(t *testing.T, encoded string) protocol.CredentialID {
	t.Helper()
	if encoded == "" {
		return protocol.CredentialID{}
	}
	encoding := base64.RawURLEncoding.Strict()
	decoded, err := encoding.DecodeString(encoded)
	if err != nil || encoding.EncodeToString(decoded) != encoded {
		t.Fatalf("selected credential %q is not canonical base64url: %v", encoded, err)
	}
	credentialID, err := protocol.NewCredentialID(decoded)
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}
	return credentialID
}

func w3cPRFClientOutput(t *testing.T, vector w3cPRFAPICase) (map[string]any, []byte, []byte) {
	t.Helper()
	output := make(map[string]any, 2)
	if vector.Output.EnabledPresent {
		output["enabled"] = vector.Output.Enabled
	}
	var first, second []byte
	if vector.Output.ResultsPresent {
		if !vector.Output.Results.FirstPresent {
			t.Fatal("W3C PRF results fixture omits first")
		}
		first = w3cPRFOutputBytes(t, vector.ID, "first", vector.Output.Results.FirstHex)
		results := map[string]any{"first": first}
		if vector.Output.Results.SecondPresent {
			second = w3cPRFOutputBytes(t, vector.ID, "second", vector.Output.Results.SecondHex)
			results["second"] = second
		}
		output["results"] = results
	}
	return output, first, second
}

func w3cPRFOutputBytes(t *testing.T, caseID, field, exact string) []byte {
	t.Helper()
	if exact != "" {
		return decodeW3CHex(t, exact)
	}
	digest := sha256.Sum256([]byte(caseID + ":" + field))
	return append([]byte{}, digest[:]...)
}
