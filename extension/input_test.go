package extension_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

func TestTypedInputsCopyAndBindHandlerID(t *testing.T) {
	inputs := make(protocol.ExtensionInputs)
	first := []byte("salt")
	input := extension.PRFInput{Eval: &extension.PRFValues{First: first, Second: []byte{}}, EvalByCredential: map[string]extension.PRFValues{}}
	if err := extension.SetInput(inputs, extension.PRFHandler{}, input); err != nil {
		t.Fatal(err)
	}
	first[0] = 'X'
	stored, ok := inputs[extension.IDPRF].(extension.PRFInput)
	if !ok || !bytes.Equal(stored.Eval.First, []byte("salt")) || stored.Eval.Second == nil || stored.EvalByCredential == nil {
		t.Fatalf("input = %#v", stored)
	}
	copied, err := stored.CloneExtensionInput()
	if err != nil {
		t.Fatal(err)
	}
	copied.(extension.PRFInput).Eval.First[0] = 'Y'
	if stored.Eval.First[0] != 's' {
		t.Fatal("clone aliases input")
	}
	if err := extension.SetInput(inputs, extension.CredPropsHandler{}, true); err != nil {
		t.Fatal(err)
	}
	if inputs[extension.IDCredProps] != protocol.BoolInput(true) {
		t.Fatal("boolean input lost its type")
	}
	if err := extension.SetInput(nil, extension.CredPropsHandler{}, true); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatal(err)
	}
}

func TestRawInputBoundaryRejectsUnsupportedValues(t *testing.T) {
	if _, err := extension.NewRawInput(make(chan struct{})); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatal(err)
	}
	if _, err := extension.NewRawInput(map[any]any{new(int): true}); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatal(err)
	}
	var input *extension.PRFInput
	if _, err := extension.NormalizeInput(input); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatal(err)
	}
	if _, err := extension.InputValue(input); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatal(err)
	}
	if _, err := (extension.PRFInput{Eval: &extension.PRFValues{First: make([]byte, extension.DefaultMaxCloneBytes+1)}}).CloneExtensionInput(); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatal(err)
	}
	raw, err := extension.NewRawInput(nil)
	if err != nil {
		t.Fatal(err)
	}
	value, err := extension.InputValue(raw)
	if err != nil || value != nil {
		t.Fatalf("explicit null = %#v, %v", value, err)
	}
}

func TestClientOutputsPreserveNullAndCopy(t *testing.T) {
	data := []byte("blob")
	outputs, err := extension.ClientOutputsFromRaw(map[string]any{"null": nil, "bytes": data})
	if err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	if outputs["absent"].Present() || !outputs["null"].Null() {
		t.Fatal("absent and null collapsed")
	}
	copied, ok := extension.As[[]byte](outputs["bytes"])
	if !ok || string(copied) != "blob" {
		t.Fatal("output aliases decoded input")
	}
	copied[0] = 'Y'
	next, _ := extension.As[[]byte](outputs["bytes"])
	if string(next) != "blob" {
		t.Fatal("output accessor aliases stored value")
	}
	if _, err := extension.ClientOutputsFromRaw(make(map[string]any, 0)); err != nil {
		t.Fatal(err)
	}
	tooMany := make(map[string]any)
	for i := range extension.MaxEntries + 1 {
		tooMany[string(rune(i))] = true
	}
	if _, err := extension.ClientOutputsFromRaw(tooMany); !errors.Is(err, extension.ErrTooManyEntries) {
		t.Fatal(err)
	}
}
