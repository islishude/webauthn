package extension_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

func TestStringInputDefaultByteBudget(t *testing.T) {
	t.Parallel()
	paths := []struct {
		name string
		run  func(protocol.StringInput) error
	}{
		{"clone input", func(v protocol.StringInput) error { _, err := extension.CloneInput(v); return err }},
		{"normalize typed", func(v protocol.StringInput) error { _, err := extension.NormalizeInput(v); return err }},
		{"normalize string", func(v protocol.StringInput) error { _, err := extension.NormalizeInput(string(v)); return err }},
		{"set input", func(v protocol.StringInput) error {
			return extension.SetInput(make(protocol.ExtensionInputs), extension.AppIDHandler{}, string(v))
		}},
		{"input value", func(v protocol.StringInput) error { _, err := extension.InputValue(v); return err }},
		{"pointer input value", func(v protocol.StringInput) error { _, err := extension.InputValue(&v); return err }},
		{"raw value", func(v protocol.StringInput) error { _, err := extension.NewRawValue(v); return err }},
		{"pointer raw value", func(v protocol.StringInput) error { _, err := extension.NewRawValue(&v); return err }},
	}
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			for _, size := range []int{extension.DefaultMaxCloneBytes, extension.DefaultMaxCloneBytes + 1} {
				err := path.run(protocol.StringInput(strings.Repeat("x", size)))
				if size == extension.DefaultMaxCloneBytes && err != nil {
					t.Fatalf("boundary rejected: %v", err)
				}
				if size > extension.DefaultMaxCloneBytes && !errors.Is(err, extension.ErrInvalidRequest) {
					t.Fatalf("oversized input: %v, want ErrInvalidRequest", err)
				}
			}
		})
	}
}

func TestStringInputCustomAndAggregateByteBudget(t *testing.T) {
	t.Parallel()
	for _, size := range []int{1, 2} {
		// The budget counts UTF-8 bytes, not runes, for both scalar representations.
		typed := protocol.StringInput("é")
		for _, value := range []any{string(typed), typed, &typed, []any{protocol.StringInput("a"), protocol.StringInput("b")}} {
			_, err := extension.CloneValueWithLimits(value, extension.CloneLimits{MaxBytes: size})
			if size == 1 && !errors.Is(err, extension.ErrInvalidRequest) {
				t.Fatalf("%T exceeded budget: %v", value, err)
			}
			if size == 2 && err != nil {
				t.Fatalf("%T at boundary rejected: %v", value, err)
			}
		}
	}
}
