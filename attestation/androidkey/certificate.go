package androidkey

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

var oidExtensionAndroidKeyAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

func parseCertificateChain(rawChain [][]byte) (webcrypto.CertificateChain, []*x509.Certificate, error) {
	if len(rawChain) == 0 {
		return nil, nil, ErrInvalidStatement
	}

	chain := make(webcrypto.CertificateChain, len(rawChain))
	certificates := make([]*x509.Certificate, len(rawChain))
	for i, raw := range rawChain {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
		}
		chain[i] = webcrypto.NewCertificate(raw)
		certificates[i] = certificate
	}

	return chain, certificates, nil
}

func validateCertificatePublicKey(certificate *x509.Certificate, material codec.CredentialPublicKeyMaterial) error {
	switch publicKey := certificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if material.EC2 == nil {
			return ErrUnsupportedKey
		}
		curve, coordinateLength, ok := curveMaterial(publicKey)
		if !ok || curve != material.EC2.Curve {
			return ErrUnsupportedKey
		}
		x := fixedBytes(publicKey.X, coordinateLength)
		y := fixedBytes(publicKey.Y, coordinateLength)
		if !bytes.Equal(x, material.EC2.X) || !bytes.Equal(y, material.EC2.Y) {
			return ErrPublicKeyMismatch
		}
	case *rsa.PublicKey:
		if material.RSA == nil {
			return ErrUnsupportedKey
		}
		if publicKey.E <= 0 || uint64(publicKey.E) > uint64(^uint32(0)) {
			return ErrUnsupportedKey
		}
		if uint32(publicKey.E) != material.RSA.Exponent || !bytes.Equal(publicKey.N.Bytes(), material.RSA.Modulus) {
			return ErrPublicKeyMismatch
		}
	default:
		return ErrUnsupportedKey
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

func findExtension(certificate *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			return extension, true
		}
	}

	return pkix.Extension{}, false
}
