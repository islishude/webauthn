package cbor_test

import (
	"bytes"
	"errors"
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

	want := append([]byte{0x04}, []byte("01234567890123456789012345678901")...)
	want = append(want, []byte("abcdefghijklmnopqrstuvwxyzabcdef")...)
	if got := key.U2FPublicKey(); len(got) != 65 || !equalBytes(got, want) {
		t.Fatalf("U2FPublicKey() = %x, want %x", got, want)
	}
}

func TestDecoderCredentialPublicKeyReportsPublicKeyMaterial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  map[int]any
		want func(codecMaterial) bool
	}{
		{
			name: "ec2 p256",
			key:  coseKeyMap(-7, 1, []byte("01234567890123456789012345678901"), []byte("abcdefghijklmnopqrstuvwxyzabcdef")),
			want: func(material codecMaterial) bool {
				return material.ec2Curve == "P-256" &&
					bytes.Equal(material.ec2X, []byte("01234567890123456789012345678901")) &&
					bytes.Equal(material.ec2Y, []byte("abcdefghijklmnopqrstuvwxyzabcdef"))
			},
		},
		{
			name: "ec2 p384",
			key:  coseKeyMap(-35, 2, bytes.Repeat([]byte{0x01}, 48), bytes.Repeat([]byte{0x02}, 48)),
			want: func(material codecMaterial) bool {
				return material.ec2Curve == "P-384" &&
					bytes.Equal(material.ec2X, bytes.Repeat([]byte{0x01}, 48)) &&
					bytes.Equal(material.ec2Y, bytes.Repeat([]byte{0x02}, 48))
			},
		},
		{
			name: "rsa",
			key: map[int]any{
				1:  3,
				3:  -257,
				-1: bytes.Repeat([]byte{0x03}, 256),
				-2: []byte{0x01, 0x00, 0x01},
			},
			want: func(material codecMaterial) bool {
				return bytes.Equal(material.rsaModulus, bytes.Repeat([]byte{0x03}, 256)) && material.rsaExponent == 65537
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

func TestDecoderCredentialPublicKeyOmitsPublicKeyMaterialForWrongShape(t *testing.T) {
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

			key, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, tt.key))
			if err != nil {
				t.Fatalf("DecodeCredentialPublicKey() error = %v", err)
			}
			material := key.PublicKeyMaterial()
			if material.EC2 != nil || material.RSA != nil || material.OKP != nil {
				t.Fatalf("PublicKeyMaterial() = %+v, want empty", material)
			}
		})
	}
}

func TestDecoderCredentialPublicKeyOmitsU2FPublicKeyForWrongShape(t *testing.T) {
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

			key, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(mustCBOR(t, tt.key))
			if err != nil {
				t.Fatalf("DecodeCredentialPublicKey() error = %v", err)
			}
			if got := key.U2FPublicKey(); got != nil {
				t.Fatalf("U2FPublicKey() = %x, want nil", got)
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

func mustCOSEKey(t *testing.T) []byte {
	t.Helper()

	return mustCBOR(t, coseKeyMap(
		-7,
		1,
		[]byte("01234567890123456789012345678901"),
		[]byte("abcdefghijklmnopqrstuvwxyzabcdef"),
	))
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

	encoded, err := fxcbor.Marshal(value)
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
