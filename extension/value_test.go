package extension_test

import (
	"bytes"
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
		nil:      map[string]any{"present": true},
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
	nullKey, ok := cloned[nil].(map[string]any)
	if !ok || nullKey["present"] != true {
		t.Fatalf("nil-keyed clone = %#v, want preserved nested value", cloned[nil])
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

func TestCloneValueEnforcesAggregateBudgets(t *testing.T) {
	t.Parallel()

	if _, err := extension.CloneValue(bytes.Repeat([]byte{0x01}, extension.DefaultMaxCloneBytes+1)); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("oversized bytes error = %v, want ErrInvalidRequest", err)
	}
	values := make([]any, extension.DefaultMaxCloneNodes+1)
	if _, err := extension.CloneValue(values); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("oversized node tree error = %v, want ErrInvalidRequest", err)
	}
	if _, err := extension.CloneValueWithLimits([]any{true, false}, extension.CloneLimits{MaxNodes: 2}); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("custom node budget error = %v, want ErrInvalidRequest", err)
	}
	if _, err := extension.CloneValueWithLimits(true, extension.CloneLimits{MaxBytes: -1}); !errors.Is(err, extension.ErrInvalidRequest) {
		t.Fatalf("negative budget error = %v, want ErrInvalidRequest", err)
	}
}

func TestRawValueDistinguishesAbsenceNullAndType(t *testing.T) {
	t.Parallel()

	var absent extension.RawValue
	if absent.Present() || absent.Null() {
		t.Fatalf("absent = %+v, want absent and non-null", absent)
	}
	if _, ok := extension.As[bool](absent); ok {
		t.Fatal("As[bool](absent) = true, want false")
	}

	null := rawValue(t, nil)
	if !null.Present() || !null.Null() {
		t.Fatalf("null = %+v, want present null", null)
	}
	if _, ok := extension.As[any](null); ok {
		t.Fatal("As[any](null) = true, want false")
	}

	boolean := rawValue(t, true)
	if value, ok := extension.As[bool](boolean); !ok || !value {
		t.Fatalf("As[bool]() = %t, %t, want true, true", value, ok)
	}
	if _, ok := extension.As[string](boolean); ok {
		t.Fatal("As[string](bool) = true, want false")
	}
}

func TestRawValueAndAsDefensivelyCopy(t *testing.T) {
	t.Parallel()

	bytes := []byte{0x01}
	raw := rawValue(t, map[string]any{"bytes": bytes})
	bytes[0] = 0xff

	first, ok := extension.As[map[string]any](raw)
	if !ok || first["bytes"].([]byte)[0] != 0x01 {
		t.Fatalf("first copy = %#v, want original byte", first)
	}
	first["bytes"].([]byte)[0] = 0xee
	second, ok := extension.As[map[string]any](raw)
	if !ok || second["bytes"].([]byte)[0] != 0x01 {
		t.Fatalf("second copy = %#v, want independent original byte", second)
	}
}

type cloneableValue struct {
	Bytes []byte
}

func (value cloneableValue) Clone() cloneableValue {
	return cloneableValue{Bytes: append([]byte{}, value.Bytes...)}
}

func TestRawValueSupportsTypedCloneMethod(t *testing.T) {
	t.Parallel()

	bytes := []byte{0x01}
	raw := rawValue(t, cloneableValue{Bytes: bytes})
	bytes[0] = 0xff
	value, ok := extension.As[cloneableValue](raw)
	if !ok || value.Bytes[0] != 0x01 {
		t.Fatalf("As[cloneableValue]() = %+v, %t", value, ok)
	}
}
