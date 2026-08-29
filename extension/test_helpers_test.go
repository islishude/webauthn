package extension_test

import (
	"testing"

	"github.com/islishude/webauthn/extension"
)

func rawValue(t *testing.T, value any) extension.RawValue {
	t.Helper()
	raw, err := extension.NewRawValue(value)
	if err != nil {
		t.Fatalf("NewRawValue() error = %v", err)
	}
	return raw
}
