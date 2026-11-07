package cbor

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/protocol"
)

// These COSE_Key types are used only for WebAuthn credential public keys
// (RFC 9053 section 7 and RFC 8230 section 4).
const (
	credentialKeyOKP = 1
	credentialKeyEC2 = 2
	credentialKeyRSA = 3
)

// DecodeCredentialPublicKey decodes the first CBOR item as a COSE_Key and
// stores only the consumed COSE_Key bytes in the returned Raw value.
func (d *Decoder) DecodeCredentialPublicKey(raw []byte) (codec.CredentialPublicKey, error) {
	if d == nil || d.mode == nil || d.canonicalMode == nil {
		return codec.CredentialPublicKey{}, errors.New("nil cbor decoder")
	}
	if len(raw) == 0 || len(raw) > MaxCBORBytes {
		return codec.CredentialPublicKey{}, ErrMalformedCBOR
	}

	var value any
	rest, err := d.mode.UnmarshalFirst(raw, &value)
	if err != nil {
		return codec.CredentialPublicKey{}, fmt.Errorf("%w: %w", ErrMalformedCBOR, err)
	}

	consumed := len(raw) - len(rest)
	if consumed <= 0 || consumed > codec.MaxCredentialPublicKeyBytes {
		return codec.CredentialPublicKey{}, ErrMalformedCBOR
	}
	encodedKey := raw[:consumed]
	canonicalValue, err := d.validateCanonical(encodedKey)
	if err != nil {
		return codec.CredentialPublicKey{}, err
	}
	key, ok := integerMap(canonicalValue)
	if !ok {
		return codec.CredentialPublicKey{}, ErrMalformedCBOR
	}
	keyType, err := credentialKeyInteger(key, 1)
	if err != nil || keyType == 0 {
		return codec.CredentialPublicKey{}, ErrMalformedCBOR
	}
	if err := validateCredentialPublicKeyParameters(key, keyType); err != nil {
		return codec.CredentialPublicKey{}, err
	}

	algorithmValue, err := credentialKeyInteger(key, 3)
	if err != nil || algorithmValue == 0 {
		return codec.CredentialPublicKey{}, ErrMalformedCBOR
	}
	algorithm := protocol.COSEAlgorithmIdentifier(algorithmValue)
	if err := algorithm.Validate(); err != nil {
		return codec.CredentialPublicKey{}, ErrMalformedCBOR
	}
	material := publicKeyMaterial(key, keyType)
	if err := validateCredentialPublicKey(algorithm, material); err != nil {
		return codec.CredentialPublicKey{}, err
	}

	return codec.NewCredentialPublicKey(algorithm, encodedKey, material), nil
}

func validateCredentialPublicKeyParameters(parameters map[int64]any, keyType int64) error {
	if _, ok := parameters[1]; !ok {
		return ErrMalformedCBOR
	}
	if _, ok := parameters[3]; !ok {
		return ErrMalformedCBOR
	}

	var allowed map[int64]struct{}
	switch keyType {
	case credentialKeyEC2:
		allowed = keySet(1, 3, -1, -2, -3)
	case credentialKeyRSA, credentialKeyOKP:
		allowed = keySet(1, 3, -1, -2)
	default:
		for _, optional := range []int64{2, 4, 5} {
			if _, present := parameters[optional]; present {
				return ErrMalformedCBOR
			}
		}
		return nil
	}
	if len(parameters) != len(allowed) {
		return ErrMalformedCBOR
	}
	for parameter := range parameters {
		if _, ok := allowed[parameter]; !ok {
			return ErrMalformedCBOR
		}
	}
	return nil
}

func publicKeyMaterial(key map[int64]any, keyType int64) codec.CredentialPublicKeyMaterial {
	switch keyType {
	case credentialKeyEC2:
		return ec2PublicKeyMaterial(key)
	case credentialKeyRSA:
		return rsaPublicKeyMaterial(key)
	case credentialKeyOKP:
		return okpPublicKeyMaterial(key)
	default:
		return codec.CredentialPublicKeyMaterial{}
	}
}

func validateCredentialPublicKey(algorithm protocol.COSEAlgorithmIdentifier, material codec.CredentialPublicKeyMaterial) error {
	switch algorithm {
	case protocol.AlgorithmES256, protocol.AlgorithmESP256:
		return validateEC2Material(material, codec.EC2CurveP256, ecdh.P256())
	case protocol.AlgorithmES384, protocol.AlgorithmESP384:
		return validateEC2Material(material, codec.EC2CurveP384, ecdh.P384())
	case protocol.AlgorithmES512, protocol.AlgorithmESP512:
		return validateEC2Material(material, codec.EC2CurveP521, ecdh.P521())
	case protocol.AlgorithmRS256, protocol.AlgorithmRS384, protocol.AlgorithmRS512,
		protocol.AlgorithmPS256, protocol.AlgorithmPS384, protocol.AlgorithmPS512:
		if material.RSA == nil || material.EC2 != nil || material.OKP != nil || !material.RSA.Valid() {
			return ErrMalformedCBOR
		}
	case protocol.AlgorithmEdDSA, protocol.AlgorithmEd25519:
		if material.OKP == nil || material.EC2 != nil || material.RSA != nil || material.OKP.Curve != codec.OKPCurveEd25519 || len(material.OKP.X) != 32 {
			return ErrMalformedCBOR
		}
	case protocol.AlgorithmEd448:
		if material.OKP == nil || material.EC2 != nil || material.RSA != nil || material.OKP.Curve != codec.OKPCurveEd448 || len(material.OKP.X) != 57 {
			return ErrMalformedCBOR
		}
	}

	return nil
}

func validateEC2Material(material codec.CredentialPublicKeyMaterial, curveName string, curve ecdh.Curve) error {
	if material.EC2 == nil || material.RSA != nil || material.OKP != nil || material.EC2.Curve != curveName {
		return ErrMalformedCBOR
	}
	raw := make([]byte, 1, 1+len(material.EC2.X)+len(material.EC2.Y))
	raw[0] = 0x04
	raw = append(raw, material.EC2.X...)
	raw = append(raw, material.EC2.Y...)
	if _, err := curve.NewPublicKey(raw); err != nil {
		return ErrMalformedCBOR
	}
	return nil
}

func ec2PublicKeyMaterial(key map[int64]any) codec.CredentialPublicKeyMaterial {
	curve, err := credentialKeyInteger(key, -1)
	if err != nil {
		return codec.CredentialPublicKeyMaterial{}
	}
	x, err := credentialKeyBytes(key, -2)
	if err != nil {
		return codec.CredentialPublicKeyMaterial{}
	}
	y, err := credentialKeyBytes(key, -3)
	if err != nil {
		return codec.CredentialPublicKeyMaterial{}
	}

	curveName, coordinateLength, ok := ec2Curve(curve)
	if !ok || len(x) != coordinateLength || len(y) != coordinateLength {
		return codec.CredentialPublicKeyMaterial{}
	}

	return codec.CredentialPublicKeyMaterial{EC2: &codec.EC2PublicKeyMaterial{
		Curve: curveName,
		X:     x,
		Y:     y,
	}}
}

func okpPublicKeyMaterial(key map[int64]any) codec.CredentialPublicKeyMaterial {
	curve, err := credentialKeyInteger(key, -1)
	if err != nil {
		return codec.CredentialPublicKeyMaterial{}
	}
	x, err := credentialKeyBytes(key, -2)
	if err != nil {
		return codec.CredentialPublicKeyMaterial{}
	}

	curveName, coordinateLength, ok := okpCurve(curve)
	if !ok || len(x) != coordinateLength {
		return codec.CredentialPublicKeyMaterial{}
	}
	algorithm, _ := credentialKeyInteger(key, 3)
	switch protocol.COSEAlgorithmIdentifier(algorithm) {
	case protocol.AlgorithmEdDSA, protocol.AlgorithmEd25519:
		if curve != 6 {
			return codec.CredentialPublicKeyMaterial{}
		}
	case protocol.AlgorithmEd448:
		if curve != 7 {
			return codec.CredentialPublicKeyMaterial{}
		}
	}

	return codec.CredentialPublicKeyMaterial{OKP: &codec.OKPPublicKeyMaterial{
		Curve: curveName,
		X:     x,
	}}
}

func rsaPublicKeyMaterial(key map[int64]any) codec.CredentialPublicKeyMaterial {
	modulus, err := credentialKeyBytes(key, -1)
	if err != nil || len(modulus) == 0 || modulus[0] == 0 {
		return codec.CredentialPublicKeyMaterial{}
	}
	exponentBytes, err := credentialKeyBytes(key, -2)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 || exponentBytes[0] == 0 {
		return codec.CredentialPublicKeyMaterial{}
	}

	var padded [4]byte
	copy(padded[len(padded)-len(exponentBytes):], exponentBytes)
	exponent := binary.BigEndian.Uint32(padded[:])
	if exponent == 0 {
		return codec.CredentialPublicKeyMaterial{}
	}

	return codec.CredentialPublicKeyMaterial{RSA: &codec.RSAPublicKeyMaterial{
		Modulus:  modulus,
		Exponent: exponent,
	}}
}

func ec2Curve(curve int64) (string, int, bool) {
	switch curve {
	case 1:
		return codec.EC2CurveP256, 32, true
	case 2:
		return codec.EC2CurveP384, 48, true
	case 3:
		return codec.EC2CurveP521, 66, true
	default:
		return "", 0, false
	}
}

func okpCurve(curve int64) (string, int, bool) {
	switch curve {
	case 6:
		return codec.OKPCurveEd25519, 32, true
	case 7:
		return codec.OKPCurveEd448, 57, true
	default:
		return "", 0, false
	}
}

// credentialKeyInteger requires an explicit integer, without algorithm inference.
// WebAuthn algorithm identifiers use the Web IDL signed 32-bit long range.
func credentialKeyInteger(key map[int64]any, label int64) (int64, error) {
	value, ok := integerKey(key[label])
	if !ok || value < -1<<31 || value > 1<<31-1 {
		return 0, ErrMalformedCBOR
	}
	return value, nil
}

func credentialKeyBytes(key map[int64]any, label int64) ([]byte, error) {
	value, ok := key[label].([]byte)
	if !ok {
		return nil, ErrMalformedCBOR
	}
	return value, nil
}
