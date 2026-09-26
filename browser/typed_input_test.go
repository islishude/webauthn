package browser_test

import (
	"errors"
	"math"
	"testing"

	"github.com/islishude/webauthn/browser"
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

func TestTypedJSONPreservesEmptyBinaryAndFalse(t *testing.T) {
	read := false
	options := protocol.PublicKeyCredentialRequestOptions{Extensions: protocol.ExtensionInputs{
		extension.IDLargeBlob: extension.LargeBlobInput{Read: &read, Write: []byte{}},
		extension.IDPRF:       extension.PRFInput{Eval: &extension.PRFValues{First: []byte{}, Second: []byte{}}},
	}}
	dto, err := browser.CredentialRequestOptionsFromProtocol(options)
	if err != nil {
		t.Fatal(err)
	}
	if string(dto.Extensions[extension.IDLargeBlob]) != `{"read":false,"write":""}` {
		t.Fatalf("largeBlob: %s", dto.Extensions[extension.IDLargeBlob])
	}
	if string(dto.Extensions[extension.IDPRF]) != `{"eval":{"first":"","second":""}}` {
		t.Fatalf("prf: %s", dto.Extensions[extension.IDPRF])
	}
}

func TestOptionConversionPropagatesInvalidExtension(t *testing.T) {
	unsupportedJSON, err := extension.NewRawInput(math.NaN())
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []protocol.ExtensionInput{nil, unsupportedJSON} {
		inputs := protocol.ExtensionInputs{"future": input}
		if _, err := browser.CredentialCreationOptionsFromProtocol(protocol.PublicKeyCredentialCreationOptions{Extensions: inputs}); !errors.Is(err, browser.ErrInvalidProtocolValue) {
			t.Fatalf("creation: %v", err)
		}
		if _, err := browser.CredentialRequestOptionsFromProtocol(protocol.PublicKeyCredentialRequestOptions{Extensions: inputs}); !errors.Is(err, browser.ErrInvalidProtocolValue) {
			t.Fatalf("request: %v", err)
		}
	}
}
