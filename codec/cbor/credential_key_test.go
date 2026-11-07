package cbor_test

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"maps"
	"testing"

	"github.com/islishude/webauthn/codec"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/protocol"
)

// Fixtures are independently generated from the WebAuthn credential public-key
// profile and RFC 9052/9053 labels, not from another WebAuthn implementation.
func TestCredentialKeyRequiredFieldTypes(t *testing.T) {
	t.Parallel()
	x, y := curveCoordinates(elliptic.P256(), 32)
	base := coseKeyMap(-7, 1, x, y)
	for _, label := range []int{1, 3, -1, -2, -3} {
		for _, value := range []any{nil, true, "1", float64(1), []any{1}} {
			key := maps.Clone(base)
			key[label] = value
			if _, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, key)); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
				t.Fatalf("label %d value %#v: %v", label, value, err)
			}
		}
		key := maps.Clone(base)
		delete(key, label)
		if _, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, key)); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
			t.Fatalf("missing label %d: %v", label, err)
		}
	}
	for _, label := range []int{1, 3, -1} {
		for _, value := range []any{int64(0), int64(-1<<31 - 1), uint64(1 << 31), uint64(1 << 63), uint64(^uint64(0)), []byte{1}} {
			key := maps.Clone(base)
			key[label] = value
			if _, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, key)); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
				t.Fatalf("label %d value %#v: %v", label, value, err)
			}
		}
	}
}

func TestCredentialKeyUnknownAlgorithmsPreserveWireValue(t *testing.T) {
	t.Parallel()
	x, y := curveCoordinates(elliptic.P256(), 32)
	for _, alg := range []int64{-1 << 31, 1<<31 - 1, -65537} {
		raw := mustCBOR(t, map[int]any{1: 2, 3: alg, -1: 1, -2: x, -3: y})
		key, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(raw)
		if err != nil || key.Algorithm != protocol.COSEAlgorithmIdentifier(alg) || !bytes.Equal(raw, key.Raw()) || key.PublicKeyMaterial().EC2 == nil {
			t.Fatalf("algorithm %d: key=%+v err=%v", alg, key, err)
		}
	}
	// Unknown key types are raw adapter inputs, never implicitly trusted keys.
	raw := mustCBOR(t, map[int]any{1: 42, 3: -65537, -1: []byte{1}})
	key, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(raw)
	if err != nil || !bytes.Equal(key.Raw(), raw) || key.PublicKeyMaterial().EC2 != nil || key.PublicKeyMaterial().RSA != nil || key.PublicKeyMaterial().OKP != nil {
		t.Fatalf("unknown key: %+v, %v", key, err)
	}
	for _, label := range []int{2, 4, 5} {
		if _, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, map[int]any{1: 42, 3: -65537, label: 1})); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
			t.Fatalf("unknown key optional label %d: %v", label, err)
		}
	}
}

func TestCredentialKeyAllECAlgorithms(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		curve      elliptic.Curve
		size       int
		label      int
		algorithms []int
	}{
		{elliptic.P256(), 32, 1, []int{-7, -9}},
		{elliptic.P384(), 48, 2, []int{-35, -51}},
		{elliptic.P521(), 66, 3, []int{-36, -52}},
	} {
		x, y := curveCoordinates(tc.curve, tc.size)
		for _, alg := range tc.algorithms {
			raw := mustCBOR(t, coseKeyMap(alg, tc.label, x, y))
			key, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(append(bytes.Clone(raw), 0xff))
			if err != nil || !bytes.Equal(key.Raw(), raw) || key.Algorithm != protocol.COSEAlgorithmIdentifier(alg) {
				t.Fatalf("algorithm %d: %v", alg, err)
			}
		}
	}
}

func TestCredentialKeyMalformedContainers(t *testing.T) {
	t.Parallel()
	for _, raw := range [][]byte{
		{0xf6}, {0x80}, {0xa0},
		{0xa2, 1, 2, 1, 2},            // Duplicate labels.
		{0xa2, 0x61, '1', 2, 3, 0x26}, // String label.
		{0xa2, 0x18, 1, 2, 3, 0x26},   // Non-minimal integer encoding.
		{0xbf, 1, 2, 3, 0x26, 0xff},   // Indefinite map.
		{0xc0, 0xa2, 1, 2, 3, 0x26},   // Tagged map.
		mustCBOR(t, map[int]any{1: 42, 3: -65537, -1: bytes.Repeat([]byte{1}, codec.MaxCredentialPublicKeyBytes)}),
	} {
		if _, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(raw); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
			t.Fatalf("malformed container length %d: %v", len(raw), err)
		}
	}
}
