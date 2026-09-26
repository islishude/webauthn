package storagejson_test

import (
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

// testInput adapts deliberately wire-shaped fixtures at the raw input boundary.
func testInput(value any) protocol.ExtensionInput {
	input, err := extension.NormalizeInput(value)
	if err != nil {
		panic(err)
	}
	return input
}
