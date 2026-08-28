package extension_test

import (
	"errors"
	"testing"

	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/extension"
)

func TestCloneValuePreservesComparableMapKeysAndCopiesValues(t *testing.T) {
	t.Parallel()

	bytes := []byte{0x01, 0x02}
	source := map[any]any{
		int64(1): map[any]any{"bytes": bytes},
	}
	clonedValue, err := extension.CloneValue(source)
	if err != nil {
		t.Fatalf("CloneValue() error = %v", err)
	}
	cloned, ok := clonedValue.(map[any]any)
	if !ok {
		t.Fatalf("CloneValue() = %T, want map[any]any", clonedValue)
	}
	nested, ok := cloned[int64(1)].(map[any]any)
	if !ok {
		t.Fatalf("nested clone = %T, want map[any]any", cloned[int64(1)])
	}
	clonedBytes, ok := nested["bytes"].([]byte)
	if !ok {
		t.Fatalf("cloned bytes = %T, want []byte", nested["bytes"])
	}
	bytes[0] = 0xff
	if clonedBytes[0] != 0x01 {
		t.Fatal("CloneValue() retained source byte slice alias")
	}
}

func TestCloneValuePreservesDecodedCBORComposite(t *testing.T) {
	t.Parallel()

	decoder := codeccbor.MustNewDecoder()
	decoded, err := decoder.DecodeExtensionMap([]byte{0xa1, 0x66, 'f', 'u', 't', 'u', 'r', 'e', 0xa1, 0x01, 0x61, 'x'})
	if err != nil {
		t.Fatalf("DecodeExtensionMap() error = %v", err)
	}
	clonedValue, err := extension.CloneValue(decoded["future"])
	if err != nil {
		t.Fatalf("CloneValue() error = %v", err)
	}
	cloned, ok := clonedValue.(map[any]any)
	if !ok || cloned[uint64(1)] != "x" {
		t.Fatalf("CloneValue() = %#v (%T), want integer-keyed map", clonedValue, clonedValue)
	}
}

func TestCloneValueRejectsReferenceMapKeysAndCycles(t *testing.T) {
	t.Parallel()

	key := new(int)
	if _, err := extension.CloneValue(map[any]any{key: true}); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("CloneValue(pointer key) error = %v, want ErrInvalidRequest", err)
	}

	cycle := map[string]any{}
	cycle["self"] = cycle
	if _, err := extension.CloneValue(cycle); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("CloneValue(cycle) error = %v, want ErrInvalidRequest", err)
	}
}
