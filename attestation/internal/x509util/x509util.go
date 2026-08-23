// Package x509util provides small shared X.509 helpers for attestation
// statement verifiers.
package x509util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
)

const (
	asn1TagSequence = 16
	asn1TagSet      = 17
)

// NameAttribute is one ASN.1 AttributeTypeAndValue from an X.509 Name while
// retaining the source string tag needed by attestation certificate profiles.
type NameAttribute struct {
	Type  asn1.ObjectIdentifier
	Value string
	Tag   int
}

// ParseCertificateChain parses a non-empty leaf-first X.509 certificate chain
// and returns both the public trust-path representation and parsed
// certificates.
func ParseCertificateChain(rawChain [][]byte, invalid error) (webcrypto.CertificateChain, []*x509.Certificate, error) {
	if len(rawChain) == 0 {
		return nil, nil, invalid
	}

	chain := make(webcrypto.CertificateChain, len(rawChain))
	certificates := make([]*x509.Certificate, len(rawChain))
	for i, raw := range rawChain {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", invalid, err)
		}
		chain[i] = webcrypto.NewCertificate(raw)
		certificates[i] = certificate
	}

	return chain, certificates, nil
}

// FindExtension returns the certificate extension with oid.
func FindExtension(certificate *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			return extension, true
		}
	}

	return pkix.Extension{}, false
}

// HasExtension reports whether certificate contains oid.
func HasExtension(certificate *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	_, ok := FindExtension(certificate, oid)
	return ok
}

// ParseNameAttributes decodes an X.509 Name and retains each value's ASN.1
// string tag. It accepts only the standard SEQUENCE of SETs of attribute
// SEQUENCEs used by X.509 names.
func ParseNameAttributes(raw []byte) ([]NameAttribute, error) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1TagSequence || !sequence.IsCompound {
		return nil, errors.New("invalid x509 name")
	}
	sets, err := rawItems(sequence.Bytes)
	if err != nil {
		return nil, err
	}
	attributes := make([]NameAttribute, 0, len(sets))
	for _, set := range sets {
		if set.Class != asn1.ClassUniversal || set.Tag != asn1TagSet || !set.IsCompound {
			return nil, errors.New("invalid x509 name set")
		}
		items, err := rawItems(set.Bytes)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if item.Class != asn1.ClassUniversal || item.Tag != asn1TagSequence || !item.IsCompound {
				return nil, errors.New("invalid x509 name attribute")
			}
			var oid asn1.ObjectIdentifier
			remainder, err := asn1.Unmarshal(item.Bytes, &oid)
			if err != nil || len(remainder) == 0 {
				return nil, errors.New("invalid x509 name attribute oid")
			}
			var value asn1.RawValue
			trailing, err := asn1.Unmarshal(remainder, &value)
			if err != nil || len(trailing) != 0 {
				return nil, errors.New("invalid x509 name attribute value")
			}
			var text string
			if trailing, err := asn1.Unmarshal(value.FullBytes, &text); err != nil || len(trailing) != 0 {
				return nil, errors.New("invalid x509 name attribute string")
			}
			attributes = append(attributes, NameAttribute{Type: oid, Value: text, Tag: value.Tag})
		}
	}
	return attributes, nil
}

func rawItems(data []byte) ([]asn1.RawValue, error) {
	items := make([]asn1.RawValue, 0)
	for len(data) > 0 {
		var item asn1.RawValue
		rest, err := asn1.Unmarshal(data, &item)
		if err != nil || len(rest) == len(data) {
			return nil, errors.New("invalid asn1 items")
		}
		items = append(items, item)
		data = rest
	}
	return items, nil
}

// ValidatePublicKey verifies that publicKey matches codec-derived credential
// public-key material. It returns unsupported for missing or unsupported key
// shapes and mismatch for otherwise comparable keys with different material.
func ValidatePublicKey(publicKey any, material codec.CredentialPublicKeyMaterial, unsupported error, mismatch error) error {
	switch typed := publicKey.(type) {
	case *ecdsa.PublicKey:
		if typed == nil || typed.X == nil || typed.Y == nil {
			return unsupported
		}
		if material.EC2 == nil {
			return unsupported
		}
		curve, coordinateLength, ok := curveMaterial(typed)
		if !ok || curve != material.EC2.Curve {
			return unsupported
		}
		x := fixedBytes(typed.X, coordinateLength)
		y := fixedBytes(typed.Y, coordinateLength)
		if !bytes.Equal(x, material.EC2.X) || !bytes.Equal(y, material.EC2.Y) {
			return mismatch
		}
	case *rsa.PublicKey:
		if typed == nil || typed.N == nil {
			return unsupported
		}
		if material.RSA == nil {
			return unsupported
		}
		if typed.E <= 0 || uint64(typed.E) > uint64(^uint32(0)) {
			return unsupported
		}
		if uint32(typed.E) != material.RSA.Exponent || !bytes.Equal(typed.N.Bytes(), material.RSA.Modulus) {
			return mismatch
		}
	default:
		return unsupported
	}

	return nil
}

// PublicKeyMaterial converts a standard-library X.509 public key into the
// typed material accepted by crypto signature adapters.
func PublicKeyMaterial(publicKey any) (codec.CredentialPublicKeyMaterial, bool) {
	switch typed := publicKey.(type) {
	case *ecdsa.PublicKey:
		if typed == nil || typed.X == nil || typed.Y == nil {
			return codec.CredentialPublicKeyMaterial{}, false
		}
		curve, coordinateLength, ok := curveMaterial(typed)
		if !ok {
			return codec.CredentialPublicKeyMaterial{}, false
		}
		return codec.CredentialPublicKeyMaterial{EC2: &codec.EC2PublicKeyMaterial{
			Curve: curve,
			X:     fixedBytes(typed.X, coordinateLength),
			Y:     fixedBytes(typed.Y, coordinateLength),
		}}, true
	case *rsa.PublicKey:
		if typed == nil || typed.N == nil || typed.E < 3 || typed.E%2 == 0 || uint64(typed.E) > uint64(^uint32(0)) {
			return codec.CredentialPublicKeyMaterial{}, false
		}
		return codec.CredentialPublicKeyMaterial{RSA: &codec.RSAPublicKeyMaterial{
			Modulus:  typed.N.Bytes(),
			Exponent: uint32(typed.E),
		}}, true
	case ed25519.PublicKey:
		if len(typed) != ed25519.PublicKeySize {
			return codec.CredentialPublicKeyMaterial{}, false
		}
		return codec.CredentialPublicKeyMaterial{OKP: &codec.OKPPublicKeyMaterial{
			Curve: codec.OKPCurveEd25519,
			X:     bytes.Clone(typed),
		}}, true
	default:
		return codec.CredentialPublicKeyMaterial{}, false
	}
}

func curveMaterial(publicKey *ecdsa.PublicKey) (string, int, bool) {
	if publicKey == nil || publicKey.Curve == nil {
		return "", 0, false
	}

	switch publicKey.Curve.Params().Name {
	case "P-256":
		return codec.EC2CurveP256, 32, true
	case "P-384":
		return codec.EC2CurveP384, 48, true
	case "P-521":
		return codec.EC2CurveP521, 66, true
	default:
		return "", 0, false
	}
}

func fixedBytes(value *big.Int, length int) []byte {
	if value == nil {
		return nil
	}
	bytes := value.Bytes()
	if len(bytes) >= length {
		return bytes[len(bytes)-length:]
	}
	out := make([]byte, length)
	copy(out[length-len(bytes):], bytes)

	return out
}
