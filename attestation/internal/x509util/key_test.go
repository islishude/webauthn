package x509util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/islishude/webauthn/codec"
)

func TestECDSAKeyMaterial(t *testing.T) {
	unsupported, mismatch := errors.New("unsupported"), errors.New("mismatch")
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			material, ok := PublicKeyMaterial(&key.PublicKey)
			if !ok {
				t.Fatal("supported key rejected")
			}
			size := (curve.Params().BitSize + 7) / 8
			if len(material.EC2.X) != size || len(material.EC2.Y) != size {
				t.Fatal("coordinates lost fixed width")
			}
			if err := ValidatePublicKey(&key.PublicKey, material, unsupported, mismatch); err != nil {
				t.Fatal(err)
			}
			material.EC2.X[0] ^= 1
			if err := ValidatePublicKey(&key.PublicKey, material, unsupported, mismatch); !errors.Is(err, mismatch) {
				t.Fatalf("mismatch: %v", err)
			}
		})
	}
	for _, key := range []*ecdsa.PublicKey{nil, {}, {Curve: elliptic.P256()}, {Curve: elliptic.P224()}} {
		if _, ok := PublicKeyMaterial(key); ok {
			t.Fatal("invalid key accepted")
		}
		if err := ValidatePublicKey(key, codec.CredentialPublicKeyMaterial{}, unsupported, mismatch); !errors.Is(err, unsupported) {
			t.Fatalf("invalid key: %v", err)
		}
	}
}
