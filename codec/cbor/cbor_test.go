package cbor_test

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"fmt"
	"maps"
	"testing"

	fxcbor "github.com/fxamacker/cbor/v2"

	"github.com/islishude/webauthn/codec"
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

func TestDecoderDecodesCompoundAttestationObject(t *testing.T) {
	t.Parallel()

	decoder := codeccbor.MustNewDecoder()
	authData, err := protocol.NewAuthenticatorData(make([]byte, protocol.MinAuthenticatorDataLength))
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}
	encoded := mustCBOR(t, map[string]any{
		"fmt":      "compound",
		"authData": authData.Bytes(),
		"attStmt": []any{
			map[string]any{"fmt": "none", "attStmt": map[string]any{}},
			map[string]any{"fmt": "packed", "attStmt": map[string]any{"alg": -7, "sig": []byte("signature")}},
		},
	})
	raw, err := protocol.NewAttestationObject(encoded)
	if err != nil {
		t.Fatalf("NewAttestationObject() error = %v", err)
	}

	decoded, err := decoder.DecodeAttestationObject(raw)
	if err != nil {
		t.Fatalf("DecodeAttestationObject() error = %v", err)
	}
	statements, ok := decoded.Statement[codec.CompoundSubStatementsKey].([]codec.CompoundSubStatement)
	if !ok || len(statements) != 2 {
		t.Fatalf("compound statements = %#v, want two", decoded.Statement[codec.CompoundSubStatementsKey])
	}
	if statements[0].Format != "none" || statements[1].Format != "packed" {
		t.Fatalf("compound statements = %#v", statements)
	}
}

func TestDecoderRejectsMalformedCompoundAttestationObject(t *testing.T) {
	t.Parallel()

	decoder := codeccbor.MustNewDecoder()
	authData, err := protocol.NewAuthenticatorData(make([]byte, protocol.MinAuthenticatorDataLength))
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}

	tests := []struct {
		name    string
		stmt    any
		wantErr error
	}{
		{
			name:    "one sub-statement",
			stmt:    []any{map[string]any{"fmt": "none", "attStmt": map[string]any{}}},
			wantErr: codeccbor.ErrMalformedCBOR,
		},
		{
			name: "nested compound",
			stmt: []any{
				map[string]any{"fmt": "none", "attStmt": map[string]any{}},
				map[string]any{"fmt": "compound", "attStmt": []any{}},
			},
			wantErr: codeccbor.ErrMalformedCBOR,
		},
		{
			name: "missing statement",
			stmt: []any{
				map[string]any{"fmt": "none", "attStmt": map[string]any{}},
				map[string]any{"fmt": "packed"},
			},
			wantErr: codeccbor.ErrMalformedCBOR,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoded := mustCBOR(t, map[string]any{
				"fmt":      "compound",
				"authData": authData.Bytes(),
				"attStmt":  tt.stmt,
			})
			raw, err := protocol.NewAttestationObject(encoded)
			if err != nil {
				t.Fatalf("NewAttestationObject() error = %v", err)
			}

			_, err = decoder.DecodeAttestationObject(raw)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("DecodeAttestationObject() error = %v, want %v", err, tt.wantErr)
			}
		})
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

func TestDecoderRejectsNonCanonicalCBOR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "tag", raw: []byte{0xc0, 0xa0}},
		{name: "indefinite map", raw: []byte{0xbf, 0xff}},
		{name: "non-minimal integer", raw: []byte{0xa1, 0x61, 0x61, 0x18, 0x01}},
		{name: "map key order", raw: []byte{0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := codeccbor.MustNewDecoder().DecodeExtensionMap(test.raw); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
				t.Fatalf("DecodeExtensionMap() error = %v, want ErrMalformedCBOR", err)
			}
		})
	}
}

func TestDecoderRejectsUnexpectedAttestationObjectField(t *testing.T) {
	t.Parallel()

	raw, err := protocol.NewAttestationObject(mustCBOR(t, map[string]any{
		"fmt":        "none",
		"authData":   make([]byte, protocol.MinAuthenticatorDataLength),
		"attStmt":    map[string]any{},
		"unexpected": true,
	}))
	if err != nil {
		t.Fatalf("NewAttestationObject() error = %v", err)
	}
	if _, err := codeccbor.MustNewDecoder().DecodeAttestationObject(raw); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
		t.Fatalf("DecodeAttestationObject() error = %v, want ErrMalformedCBOR", err)
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

func TestDecoderCredentialPublicKeyReportsU2FPublicKey(t *testing.T) {
	t.Parallel()

	key, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCOSEKey(t))
	if err != nil {
		t.Fatalf("DecodeCredentialPublicKey() error = %v", err)
	}

	x, y := curveCoordinates(elliptic.P256(), 32)
	want := append([]byte{0x04}, x...)
	want = append(want, y...)
	if got := key.U2FPublicKey(); len(got) != 65 || !equalBytes(got, want) {
		t.Fatalf("U2FPublicKey() = %x, want %x", got, want)
	}
}

func TestDecoderCredentialPublicKeyReportsPublicKeyMaterial(t *testing.T) {
	t.Parallel()
	p256X, p256Y := curveCoordinates(elliptic.P256(), 32)
	p384X, p384Y := curveCoordinates(elliptic.P384(), 48)

	tests := []struct {
		name string
		key  map[int]any
		want func(codecMaterial) bool
	}{
		{
			name: "ec2 p256",
			key:  coseKeyMap(-7, 1, p256X, p256Y),
			want: func(material codecMaterial) bool {
				return material.ec2Curve == "P-256" &&
					bytes.Equal(material.ec2X, p256X) &&
					bytes.Equal(material.ec2Y, p256Y)
			},
		},
		{
			name: "ec2 p384",
			key:  coseKeyMap(-35, 2, p384X, p384Y),
			want: func(material codecMaterial) bool {
				return material.ec2Curve == "P-384" &&
					bytes.Equal(material.ec2X, p384X) &&
					bytes.Equal(material.ec2Y, p384Y)
			},
		},
		{
			name: "rsa",
			key: map[int]any{
				1:  3,
				3:  -257,
				-1: bytes.Repeat([]byte{0x83}, 256),
				-2: []byte{0x01, 0x00, 0x01},
			},
			want: func(material codecMaterial) bool {
				return bytes.Equal(material.rsaModulus, bytes.Repeat([]byte{0x83}, 256)) && material.rsaExponent == 65537
			},
		},
		{
			name: "okp ed25519",
			key: map[int]any{
				1:  1,
				3:  -8,
				-1: 6,
				-2: bytes.Repeat([]byte{0x04}, 32),
			},
			want: func(material codecMaterial) bool {
				return material.okpCurve == codec.OKPCurveEd25519 &&
					bytes.Equal(material.okpX, bytes.Repeat([]byte{0x04}, 32))
			},
		},
		{
			name: "okp ed448",
			key: map[int]any{
				1:  1,
				3:  -53,
				-1: 7,
				-2: bytes.Repeat([]byte{0x05}, 57),
			},
			want: func(material codecMaterial) bool {
				return material.okpCurve == codec.OKPCurveEd448 &&
					bytes.Equal(material.okpX, bytes.Repeat([]byte{0x05}, 57))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, tt.key))
			if err != nil {
				t.Fatalf("DecodeCredentialPublicKey() error = %v", err)
			}
			if !tt.want(materialView(key.PublicKeyMaterial())) {
				t.Fatalf("PublicKeyMaterial() = %+v", key.PublicKeyMaterial())
			}
		})
	}
}

func TestDecoderRejectsInvalidRSARequirements(t *testing.T) {
	t.Parallel()

	validModulus := bytes.Repeat([]byte{0x83}, 256)
	for _, tt := range []struct {
		name     string
		modulus  []byte
		exponent []byte
	}{
		{name: "1024-bit modulus", modulus: bytes.Repeat([]byte{0x83}, 128), exponent: []byte{0x01, 0x00, 0x01}},
		{name: "modulus leading zero", modulus: append([]byte{0}, validModulus...), exponent: []byte{0x01, 0x00, 0x01}},
		{name: "exponent leading zero", modulus: validModulus, exponent: []byte{0x00, 0x01, 0x00, 0x01}},
		{name: "oversized modulus", modulus: bytes.Repeat([]byte{0x83}, codec.MaxRSAModulusBits/8+1), exponent: []byte{0x01, 0x00, 0x01}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, map[int]any{
				1: 3, 3: -257, -1: tt.modulus, -2: tt.exponent,
			}))
			if !errors.Is(err, codeccbor.ErrMalformedCBOR) {
				t.Fatalf("DecodeCredentialPublicKey() error = %v, want ErrMalformedCBOR", err)
			}
		})
	}
}

func TestDecoderCredentialPublicKeyRejectsWrongKnownKeyShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  map[int]any
	}{
		{name: "ec2 short x", key: coseKeyMap(-7, 1, []byte("short"), bytes.Repeat([]byte{0x02}, 32))},
		{name: "ec2 unknown curve", key: coseKeyMap(-7, 9, bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32))},
		{name: "rsa missing exponent", key: map[int]any{1: 3, 3: -257, -1: bytes.Repeat([]byte{0x03}, 256)}},
		{name: "rsa oversized exponent", key: map[int]any{1: 3, 3: -257, -1: bytes.Repeat([]byte{0x03}, 256), -2: []byte{0x01, 0x00, 0x00, 0x00, 0x01}}},
		{name: "okp wrong curve for eddsa", key: map[int]any{1: 1, 3: -8, -1: 7, -2: bytes.Repeat([]byte{0x04}, 57)}},
		{name: "okp short x", key: map[int]any{1: 1, 3: -8, -1: 6, -2: []byte("short")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, tt.key))
			if !errors.Is(err, codeccbor.ErrMalformedCBOR) {
				t.Fatalf("DecodeCredentialPublicKey() error = %v, want ErrMalformedCBOR", err)
			}
		})
	}
}

func TestDecoderCredentialPublicKeyRejectsOptionalParameters(t *testing.T) {
	t.Parallel()

	x, y := curveCoordinates(elliptic.P256(), 32)
	base := coseKeyMap(-7, 1, x, y)
	tests := []struct {
		name  string
		key   int
		value any
	}{
		{name: "kid", key: 2, value: []byte("kid")},
		{name: "key ops", key: 4, value: []any{2}},
		{name: "base iv", key: 5, value: []byte("iv")},
		{name: "private key", key: -4, value: bytes.Repeat([]byte{0x03}, 32)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			key := make(map[int]any, len(base)+1)
			maps.Copy(key, base)
			key[test.key] = test.value
			if _, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, key)); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
				t.Fatalf("DecodeCredentialPublicKey() error = %v, want ErrMalformedCBOR", err)
			}
		})
	}
}

func TestDecoderCredentialPublicKeyRejectsU2FKnownKeyMismatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  map[int]any
	}{
		{
			name: "wrong algorithm",
			key:  coseKeyMap(-257, 1, []byte("01234567890123456789012345678901"), []byte("abcdefghijklmnopqrstuvwxyzabcdef")),
		},
		{
			name: "wrong curve",
			key:  coseKeyMap(-7, 2, []byte("01234567890123456789012345678901"), []byte("abcdefghijklmnopqrstuvwxyzabcdef")),
		},
		{
			name: "short x",
			key:  coseKeyMap(-7, 1, []byte("short"), []byte("abcdefghijklmnopqrstuvwxyzabcdef")),
		},
		{
			name: "missing y",
			key: map[int]any{
				1:  2,
				3:  -7,
				-1: 1,
				-2: []byte("01234567890123456789012345678901"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, tt.key))
			if !errors.Is(err, codeccbor.ErrMalformedCBOR) {
				t.Fatalf("DecodeCredentialPublicKey() error = %v, want ErrMalformedCBOR", err)
			}
		})
	}
}

func TestDecoderCredentialPublicKeyRejectsMalformedDependencyShape(t *testing.T) {
	t.Parallel()

	_, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey([]byte("\xa500102070 \xf7"))
	if !errors.Is(err, codeccbor.ErrMalformedCBOR) {
		t.Fatalf("DecodeCredentialPublicKey() error = %v, want ErrMalformedCBOR", err)
	}
}

type codecMaterial struct {
	ec2Curve    string
	ec2X        []byte
	ec2Y        []byte
	rsaModulus  []byte
	rsaExponent uint32
	okpCurve    string
	okpX        []byte
}

func materialView(material codec.CredentialPublicKeyMaterial) codecMaterial {
	var out codecMaterial
	if material.EC2 != nil {
		out.ec2Curve = material.EC2.Curve
		out.ec2X = material.EC2.X
		out.ec2Y = material.EC2.Y
	}
	if material.RSA != nil {
		out.rsaModulus = material.RSA.Modulus
		out.rsaExponent = material.RSA.Exponent
	}
	if material.OKP != nil {
		out.okpCurve = material.OKP.Curve
		out.okpX = material.OKP.X
	}

	return out
}

func TestDecoderRejectsMalformedCBOR(t *testing.T) {
	t.Parallel()

	decoder := codeccbor.MustNewDecoder()

	_, err := decoder.DecodeExtensionMap([]byte{0x81})
	if !errors.Is(err, codeccbor.ErrMalformedCBOR) {
		t.Fatalf("DecodeExtensionMap() error = %v, want ErrMalformedCBOR", err)
	}
}

func TestNilDecoderFailsWithoutPanicking(t *testing.T) {
	t.Parallel()

	var decoder *codeccbor.Decoder
	if _, err := decoder.DecodeCredentialPublicKey(mustCOSEKey(t)); err == nil {
		t.Fatal("DecodeCredentialPublicKey() error = nil, want nil decoder error")
	}
}

func TestDecoderEnforcesAggregateWorkBounds(t *testing.T) {
	t.Parallel()

	oversizedArray := make([]any, codeccbor.MaxArrayElements+1)
	if _, err := codeccbor.MustNewDecoder().DecodeExtensionMap(mustCBOR(t, map[string]any{"future": oversizedArray})); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
		t.Fatalf("oversized array error = %v, want ErrMalformedCBOR", err)
	}
	oversizedMap := make(map[string]any, codeccbor.MaxMapPairs+1)
	for i := range codeccbor.MaxMapPairs + 1 {
		oversizedMap[fmt.Sprintf("k%02d", i)] = true
	}
	if _, err := codeccbor.MustNewDecoder().DecodeExtensionMap(mustCBOR(t, oversizedMap)); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
		t.Fatalf("oversized map error = %v, want ErrMalformedCBOR", err)
	}
	if _, err := codeccbor.MustNewDecoder().DecodeExtensionMap(bytes.Repeat([]byte{0x00}, codeccbor.MaxCBORBytes+1)); !errors.Is(err, codeccbor.ErrMalformedCBOR) {
		t.Fatalf("oversized bytes error = %v, want ErrMalformedCBOR", err)
	}
}

func mustCOSEKey(t *testing.T) []byte {
	t.Helper()
	x, y := curveCoordinates(elliptic.P256(), 32)

	return mustCBOR(t, coseKeyMap(
		-7,
		1,
		x,
		y,
	))
}

func curveCoordinates(curve elliptic.Curve, length int) ([]byte, []byte) {
	return curve.Params().Gx.FillBytes(make([]byte, length)), curve.Params().Gy.FillBytes(make([]byte, length))
}

func coseKeyMap(algorithm int, curve int, x []byte, y []byte) map[int]any {
	return map[int]any{
		1:  2,
		3:  algorithm,
		-1: curve,
		-2: x,
		-3: y,
	}
}

func mustCBOR(t *testing.T, value any) []byte {
	t.Helper()

	mode, err := fxcbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("CTAP2 EncMode() error = %v", err)
	}
	encoded, err := mode.Marshal(value)
	if err != nil {
		t.Fatalf("cbor.Marshal() error = %v", err)
	}

	return encoded
}

func equalBytes(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
