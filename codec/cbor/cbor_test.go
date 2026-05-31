package cbor_test

import (
	"errors"
	"testing"

	fxcbor "github.com/fxamacker/cbor/v2"

	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/protocol"
)

func TestDecoderDecodesAttestationObject(t *testing.T) {
	t.Parallel()

	decoder := codeccbor.MustNewDecoder()
	authData, err := protocol.NewAuthenticatorData(make([]byte, protocol.MinAuthenticatorDataLength))
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}
	encoded := mustCBOR(t, map[string]any{
		"fmt":      "none",
		"authData": authData.Bytes(),
		"attStmt":  map[string]any{},
	})
	raw, err := protocol.NewAttestationObject(encoded)
	if err != nil {
		t.Fatalf("NewAttestationObject() error = %v", err)
	}

	decoded, err := decoder.DecodeAttestationObject(raw)
	if err != nil {
		t.Fatalf("DecodeAttestationObject() error = %v", err)
	}
	if decoded.Format != "none" {
		t.Fatalf("Format = %q, want none", decoded.Format)
	}
}

func TestDecoderRejectsDuplicateMapKeys(t *testing.T) {
	t.Parallel()

	decoder := codeccbor.MustNewDecoder()

	_, err := decoder.DecodeExtensionMap([]byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02})
	if !errors.Is(err, codeccbor.ErrMalformedCBOR) {
		t.Fatalf("DecodeExtensionMap() error = %v, want ErrMalformedCBOR", err)
	}
}

func TestDecoderCredentialPublicKeyReportsConsumedRaw(t *testing.T) {
	t.Parallel()

	decoder := codeccbor.MustNewDecoder()
	coseKey := mustCOSEKey(t)
	extensions := mustCBOR(t, map[string]any{"credProps": true})
	raw := append(append([]byte{}, coseKey...), extensions...)

	key, err := decoder.DecodeCredentialPublicKey(raw)
	if err != nil {
		t.Fatalf("DecodeCredentialPublicKey() error = %v", err)
	}
	if key.Algorithm != protocol.COSEAlgorithmIdentifier(-7) {
		t.Fatalf("Algorithm = %d, want -7", key.Algorithm)
	}
	if len(key.Raw()) != len(coseKey) {
		t.Fatalf("Raw length = %d, want consumed key length %d", len(key.Raw()), len(coseKey))
	}
}

func TestDecoderRejectsMalformedCBOR(t *testing.T) {
	t.Parallel()

	decoder := codeccbor.MustNewDecoder()

	_, err := decoder.DecodeExtensionMap([]byte{0x81})
	if !errors.Is(err, codeccbor.ErrMalformedCBOR) {
		t.Fatalf("DecodeExtensionMap() error = %v, want ErrMalformedCBOR", err)
	}
}

func mustCOSEKey(t *testing.T) []byte {
	t.Helper()

	return mustCBOR(t, map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: []byte("01234567890123456789012345678901"),
		-3: []byte("abcdefghijklmnopqrstuvwxyzabcdef"),
	})
}

func mustCBOR(t *testing.T, value any) []byte {
	t.Helper()

	encoded, err := fxcbor.Marshal(value)
	if err != nil {
		t.Fatalf("cbor.Marshal() error = %v", err)
	}

	return encoded
}
