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

var _ codec.Decoders = fakeDecoders{}
