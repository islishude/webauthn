package codec_test

import (
	"bytes"
	"testing"

	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/protocol"
)

func TestCodecContractsAcceptTestDouble(t *testing.T) {
	t.Parallel()

	adapter := fakeDecoders{}
	rawObject, err := protocol.NewAttestationObject([]byte{0xa3})
	if err != nil {
		t.Fatalf("NewAttestationObject() error = %v", err)
	}

	decoded, err := adapter.DecodeAttestationObject(rawObject)
	if err != nil {
		t.Fatalf("DecodeAttestationObject() error = %v", err)
	}
	if decoded.Format != "none" {
		t.Fatalf("Format = %q, want none", decoded.Format)
	}

	key, err := adapter.DecodeCredentialPublicKey([]byte{0xa5, 0x01})
	if err != nil {
		t.Fatalf("DecodeCredentialPublicKey() error = %v", err)
	}
	if key.Algorithm != protocol.COSEAlgorithmIdentifier(-7) {
		t.Fatalf("Algorithm = %d, want -7", key.Algorithm)
	}

	rawKey := key.Raw()
	rawKey[0] = 0xff
	if bytes.Equal(rawKey, key.Raw()) {
		t.Fatal("CredentialPublicKey.Raw() returned an alias")
	}

	extensions, err := adapter.DecodeExtensionMap([]byte{0xa1})
	if err != nil {
		t.Fatalf("DecodeExtensionMap() error = %v", err)
	}
	if extensions["credProps"] != true {
		t.Fatalf("credProps = %v, want true", extensions["credProps"])
	}
}

func TestCredentialPublicKeyPublicKeyMaterialDefensiveCopies(t *testing.T) {
	t.Parallel()

	x := []byte{0x01, 0x02}
	modulus := []byte{0x03, 0x04}
	okpX := []byte{0x07, 0x08}
	key := codec.NewCredentialPublicKeyWithMaterial(
		-7,
		"public-key",
		[]byte{0xa0},
		nil,
		codec.CredentialPublicKeyMaterial{
			EC2: &codec.EC2PublicKeyMaterial{
				Curve: codec.EC2CurveP256,
				X:     x,
				Y:     []byte{0x05, 0x06},
			},
			RSA: &codec.RSAPublicKeyMaterial{
				Modulus:  modulus,
				Exponent: 65537,
			},
			OKP: &codec.OKPPublicKeyMaterial{
				Curve: codec.OKPCurveEd25519,
				X:     okpX,
			},
		},
	)
	x[0] = 0xff
	modulus[0] = 0xff
	okpX[0] = 0xff

	material := key.PublicKeyMaterial()
	material.EC2.X[0] = 0xee
	material.RSA.Modulus[0] = 0xee
	material.OKP.X[0] = 0xee
	material = key.PublicKeyMaterial()
	if material.EC2.X[0] != 0x01 || material.RSA.Modulus[0] != 0x03 || material.OKP.X[0] != 0x07 {
		t.Fatalf("PublicKeyMaterial() returned aliased material: %+v", material)
	}
}

type fakeDecoders struct{}

func (fakeDecoders) DecodeAttestationObject(raw protocol.AttestationObject) (codec.DecodedAttestationObject, error) {
	authData, err := protocol.NewAuthenticatorData(bytes.Repeat([]byte{0x01}, protocol.MinAuthenticatorDataLength))
	if err != nil {
		return codec.DecodedAttestationObject{}, err
	}

	return codec.DecodedAttestationObject{
		Format:            "none",
		AuthenticatorData: authData,
		Statement:         codec.AttestationStatement{},
		Raw:               raw,
	}, nil
}

func (fakeDecoders) DecodeCredentialPublicKey(raw []byte) (codec.CredentialPublicKey, error) {
	return codec.NewCredentialPublicKey(protocol.COSEAlgorithmIdentifier(-7), "public-key", raw), nil
}

func (fakeDecoders) DecodeExtensionMap([]byte) (codec.ExtensionMap, error) {
	return codec.ExtensionMap{"credProps": true}, nil
}

var (
	_ codec.AttestationObjectDecoder = fakeDecoders{}
	_ codec.COSEKeyDecoder           = fakeDecoders{}
	_ codec.ExtensionMapDecoder      = fakeDecoders{}
)
