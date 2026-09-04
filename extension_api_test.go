package webauthn_test

import (
	"testing"

	"github.com/islishude/webauthn/extension"
)

func mustRawExtensionValue(t *testing.T, value any) extension.RawValue {
	t.Helper()
	raw, err := extension.NewRawValue(value)
	if err != nil {
		t.Fatalf("NewRawValue() error = %v", err)
	}
	return raw
}

func mustExtensionBindings(t *testing.T, registry *extension.Registry, ids ...string) []extension.Binding {
	t.Helper()
	bindings := make([]extension.Binding, len(ids))
	for i, id := range ids {
		binding, ok := registry.Binding(id)
		if !ok {
			t.Fatalf("registry has no binding for %q", id)
		}
		bindings[i] = binding
	}
	return bindings
}
