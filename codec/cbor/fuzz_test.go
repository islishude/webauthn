package cbor_test

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	fxcbor "github.com/fxamacker/cbor/v2"

	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/protocol"
)

func FuzzDecodeAttestationObject(f *testing.F) {
	f.Add(seedCBOR(map[string]any{
		"fmt":      "none",
		"authData": seedRegistrationAuthenticatorData(),
		"attStmt":  map[string]any{},
	}))
	f.Add([]byte{0xa0})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		raw, err := protocol.NewAttestationObject(data)
		if err != nil {
			return
		}

		_, _ = codeccbor.MustNewDecoder().DecodeAttestationObject(raw)
	})
}

func FuzzDecodeCredentialPublicKey(f *testing.F) {
	f.Add(seedCBOR(map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: []byte("01234567890123456789012345678901"),
		-3: []byte("abcdefghijklmnopqrstuvwxyzabcdef"),
	}))
	f.Add(seedCBOR(map[int]any{
		1:  3,
		3:  -257,
		-1: append([]byte{0x01}, make([]byte, 255)...),
		-2: []byte{0x01, 0x00, 0x01},
	}))
	f.Add([]byte{0xa0})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = codeccbor.MustNewDecoder().DecodeCredentialPublicKey(data)
	})
}

func FuzzDecodeExtensionMap(f *testing.F) {
	f.Add(seedCBOR(map[string]any{"credProps": map[string]any{"rk": true}}))
	f.Add(seedCBOR(map[string]any{"uvm": []any{[]any{1, 2, 3}}}))
	f.Add([]byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = codeccbor.MustNewDecoder().DecodeExtensionMap(data)
	})
}

func seedCBOR(value any) []byte {
	encoded, err := fxcbor.Marshal(value)
	if err != nil {
		panic(err)
	}

	return encoded
}

func seedRegistrationAuthenticatorData() []byte {
	rpIDHash := sha256.Sum256([]byte("example.com"))
	out := append([]byte{}, rpIDHash[:]...)
	out = append(out, 0x01|0x40)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 7)
	out = append(out, counter...)
	out = append(out, make([]byte, protocol.AAGUIDLength)...)
	credentialID := []byte("credential-id")
	credentialIDLength := make([]byte, 2)
	binary.BigEndian.PutUint16(credentialIDLength, uint16(len(credentialID))) //nolint:gosec // fixed seed length.
	out = append(out, credentialIDLength...)
	out = append(out, credentialID...)
	out = append(out, seedCBOR(map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: []byte("01234567890123456789012345678901"),
		-3: []byte("abcdefghijklmnopqrstuvwxyzabcdef"),
	})...)

	return out
}
