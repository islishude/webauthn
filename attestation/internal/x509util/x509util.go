// Package x509util provides small shared X.509 helpers for attestation
// statement verifiers.
package x509util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
)

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
