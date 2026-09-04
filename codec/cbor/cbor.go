// Package cbor provides concrete CBOR and COSE_Key decoders behind the codec
// contracts.
package cbor

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"

	fxcbor "github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/iana"
	cosekey "github.com/ldclabs/cose/key"

	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/internal/protocolidentifier"
	"github.com/islishude/webauthn/protocol"
)

var (
	// ErrMalformedCBOR reports a decoded shape that is not valid WebAuthn input.
	ErrMalformedCBOR = errors.New("malformed cbor")
)

const (
	// MaxCBORBytes bounds a single WebAuthn CBOR value before decoding.
	MaxCBORBytes = 1 << 20
	// MaxNestedLevels bounds recursive CBOR containers.
	MaxNestedLevels = 16
	// MaxArrayElements bounds array work, including compound attestations.
	MaxArrayElements = 64
	// MaxMapPairs bounds map work, including extension maps.
	MaxMapPairs = 64
)

// Decoder decodes WebAuthn CBOR structures using strict duplicate-key checks.
type Decoder struct {
	mode          fxcbor.DecMode
	canonicalMode fxcbor.EncMode
}

// NewDecoder creates a decoder with duplicate map-key rejection.
func NewDecoder() (*Decoder, error) {
	mode, err := fxcbor.DecOptions{
		DupMapKey:        fxcbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  MaxNestedLevels,
		MaxArrayElements: MaxArrayElements,
		MaxMapPairs:      MaxMapPairs,
		IndefLength:      fxcbor.IndefLengthForbidden,
		TagsMd:           fxcbor.TagsForbidden,
		UTF8:             fxcbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		return nil, err
	}

	canonicalMode, err := fxcbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	return &Decoder{mode: mode, canonicalMode: canonicalMode}, nil
}

// MustNewDecoder creates a decoder or panics. It is intended for tests and
// package-level fixtures.
func MustNewDecoder() *Decoder {
	decoder, err := NewDecoder()
	if err != nil {
		panic(err)
	}

	return decoder
}

// DecodeAttestationObject decodes a WebAuthn attestationObject CBOR map.
func (d *Decoder) DecodeAttestationObject(raw protocol.AttestationObject) (codec.DecodedAttestationObject, error) {
	data := raw.Bytes()
	decodedValue, err := d.validateCanonical(data)
	if err != nil {
		return codec.DecodedAttestationObject{}, err
	}
	fields, ok := stringMap(decodedValue)
	if !ok || len(fields) != 3 {
		return codec.DecodedAttestationObject{}, ErrMalformedCBOR
	}
	format, ok := fields["fmt"].(string)
	if !ok || !protocolidentifier.Valid(format) {
		return codec.DecodedAttestationObject{}, ErrMalformedCBOR
	}
	authenticatorData, ok := fields["authData"].([]byte)
	if !ok || len(authenticatorData) == 0 {
		return codec.DecodedAttestationObject{}, ErrMalformedCBOR
	}
	statementValue, ok := fields["attStmt"]
	if !ok || statementValue == nil {
		return codec.DecodedAttestationObject{}, ErrMalformedCBOR
	}
	statement, err := decodeAttestationStatement(format, statementValue)
	if err != nil {
		return codec.DecodedAttestationObject{}, err
	}

	authData, err := protocol.NewAuthenticatorData(authenticatorData)
	if err != nil {
		return codec.DecodedAttestationObject{}, err
	}

	return codec.DecodedAttestationObject{
		Format:            format,
		AuthenticatorData: authData,
		Statement:         statement,
		Raw:               raw,
	}, nil
}

func decodeAttestationStatement(format string, value any) (codec.AttestationStatement, error) {
	if format != "compound" {
		statement, ok := stringMap(value)
		if !ok {
			return nil, ErrMalformedCBOR
		}
		return codec.AttestationStatement(statement), nil
	}

	rawStatements, ok := value.([]any)
	if !ok || len(rawStatements) < 2 {
		return nil, ErrMalformedCBOR
	}

	statements := make([]codec.CompoundSubStatement, 0, len(rawStatements))
	for _, rawStatement := range rawStatements {
		fields, ok := stringMap(rawStatement)
		if !ok {
			return nil, ErrMalformedCBOR
		}
		format, ok := fields["fmt"].(string)
		if !ok || !protocolidentifier.Valid(format) || format == "compound" {
			return nil, ErrMalformedCBOR
		}
		statement, ok := stringMap(fields["attStmt"])
		if !ok {
			return nil, ErrMalformedCBOR
		}
		statements = append(statements, codec.CompoundSubStatement{
			Format:    format,
			Statement: codec.AttestationStatement(statement),
		})
	}

	return codec.AttestationStatement{codec.CompoundSubStatementsKey: statements}, nil
}

// DecodeCredentialPublicKey decodes the first CBOR item as a COSE_Key and
// stores only the consumed COSE_Key bytes in the returned Raw value.
func (d *Decoder) DecodeCredentialPublicKey(raw []byte) (decoded codec.CredentialPublicKey, err error) {
	defer func() {
		if recover() != nil {
			decoded = codec.CredentialPublicKey{}
			err = fmt.Errorf("%w: malformed cose key", ErrMalformedCBOR)
		}
	}()
	if d == nil || d.mode == nil || d.canonicalMode == nil {
		return codec.CredentialPublicKey{}, errors.New("nil cbor decoder")
	}
	if len(raw) == 0 || len(raw) > MaxCBORBytes {
		return codec.CredentialPublicKey{}, ErrMalformedCBOR
	}

	var key cosekey.Key
	rest, err := d.mode.UnmarshalFirst(raw, &key)
	if err != nil {
		return codec.CredentialPublicKey{}, err
	}

	consumed := len(raw) - len(rest)
	if consumed <= 0 || consumed > codec.MaxCredentialPublicKeyBytes || key == nil {
		return codec.CredentialPublicKey{}, ErrMalformedCBOR
	}
	encodedKey := raw[:consumed]
	canonicalValue, err := d.validateCanonical(encodedKey)
	if err != nil {
		return codec.CredentialPublicKey{}, err
	}
	if err := validateCredentialPublicKeyParameters(canonicalValue, key.Kty()); err != nil {
		return codec.CredentialPublicKey{}, err
	}

	algorithm := protocol.COSEAlgorithmIdentifier(key.Alg())
	if err := algorithm.Validate(); err != nil {
		return codec.CredentialPublicKey{}, ErrMalformedCBOR
	}
	material := publicKeyMaterial(key)
	if err := validateCredentialPublicKey(algorithm, material); err != nil {
		return codec.CredentialPublicKey{}, err
	}

	return codec.NewCredentialPublicKey(algorithm, encodedKey, material), nil
}

// DecodeExtensionMap decodes authenticator extension output CBOR.
func (d *Decoder) DecodeExtensionMap(raw []byte) (codec.ExtensionMap, error) {
	decodedValue, err := d.validateCanonical(raw)
	if err != nil {
		return nil, err
	}
	extensions, ok := stringMap(decodedValue)
	if !ok {
		return nil, ErrMalformedCBOR
	}

	return codec.ExtensionMap(extensions), nil
}

func (d *Decoder) validateCanonical(data []byte) (any, error) {
	if d == nil || d.mode == nil || d.canonicalMode == nil {
		return nil, errors.New("nil cbor decoder")
	}
	if len(data) == 0 || len(data) > MaxCBORBytes {
		return nil, ErrMalformedCBOR
	}
	var decoded any
	if err := d.mode.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedCBOR, err)
	}
	encoded, err := d.canonicalMode.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedCBOR, err)
	}
	if !bytes.Equal(encoded, data) {
		return nil, ErrMalformedCBOR
	}
	return decoded, nil
}

func validateCredentialPublicKeyParameters(value any, keyType int) error {
	parameters, ok := integerMap(value)
	if !ok {
		return ErrMalformedCBOR
	}
	if _, ok := parameters[1]; !ok {
		return ErrMalformedCBOR
	}
	if _, ok := parameters[3]; !ok {
		return ErrMalformedCBOR
	}

	var allowed map[int64]struct{}
	switch keyType {
	case iana.KeyTypeEC2:
		allowed = keySet(1, 3, -1, -2, -3)
	case iana.KeyTypeRSA, iana.KeyTypeOKP:
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

func stringMap(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, true
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			name, ok := key.(string)
			if !ok {
				return nil, false
			}
			out[name] = item
		}
		return out, true
	default:
		return nil, false
	}
}

func integerMap(value any) (map[int64]any, bool) {
	typed, ok := value.(map[any]any)
	if !ok {
		return nil, false
	}
	out := make(map[int64]any, len(typed))
	for key, item := range typed {
		integer, ok := integerKey(key)
		if !ok {
			return nil, false
		}
		out[integer] = item
	}
	return out, true
}

func integerKey(value any) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case uint64:
		if typed > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(typed), true
	case int:
		return int64(typed), true
	case uint:
		if uint64(typed) > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}

func keySet(keys ...int64) map[int64]struct{} {
	out := make(map[int64]struct{}, len(keys))
	for _, key := range keys {
		out[key] = struct{}{}
	}
	return out
}

func publicKeyMaterial(key cosekey.Key) codec.CredentialPublicKeyMaterial {
	switch key.Kty() {
	case iana.KeyTypeEC2:
		return ec2PublicKeyMaterial(key)
	case iana.KeyTypeRSA:
		return rsaPublicKeyMaterial(key)
	case iana.KeyTypeOKP:
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

func ec2PublicKeyMaterial(key cosekey.Key) codec.CredentialPublicKeyMaterial {
	curve, err := key.GetInt(iana.EC2KeyParameterCrv)
	if err != nil {
		return codec.CredentialPublicKeyMaterial{}
	}
	x, err := key.GetBytes(iana.EC2KeyParameterX)
	if err != nil {
		return codec.CredentialPublicKeyMaterial{}
	}
	y, err := key.GetBytes(iana.EC2KeyParameterY)
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

func okpPublicKeyMaterial(key cosekey.Key) codec.CredentialPublicKeyMaterial {
	curve, err := key.GetInt(iana.OKPKeyParameterCrv)
	if err != nil {
		return codec.CredentialPublicKeyMaterial{}
	}
	x, err := key.GetBytes(iana.OKPKeyParameterX)
	if err != nil {
		return codec.CredentialPublicKeyMaterial{}
	}

	curveName, coordinateLength, ok := okpCurve(curve)
	if !ok || len(x) != coordinateLength {
		return codec.CredentialPublicKeyMaterial{}
	}
	switch protocol.COSEAlgorithmIdentifier(key.Alg()) {
	case protocol.AlgorithmEdDSA, protocol.AlgorithmEd25519:
		if curve != iana.EllipticCurveEd25519 {
			return codec.CredentialPublicKeyMaterial{}
		}
	case protocol.AlgorithmEd448:
		if curve != iana.EllipticCurveEd448 {
			return codec.CredentialPublicKeyMaterial{}
		}
	}

	return codec.CredentialPublicKeyMaterial{OKP: &codec.OKPPublicKeyMaterial{
		Curve: curveName,
		X:     x,
	}}
}

func rsaPublicKeyMaterial(key cosekey.Key) codec.CredentialPublicKeyMaterial {
	modulus, err := key.GetBytes(iana.RSAKeyParameterN)
	if err != nil || len(modulus) == 0 || modulus[0] == 0 {
		return codec.CredentialPublicKeyMaterial{}
	}
	exponentBytes, err := key.GetBytes(iana.RSAKeyParameterE)
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

func ec2Curve(curve int) (string, int, bool) {
	switch curve {
	case iana.EllipticCurveP_256:
		return codec.EC2CurveP256, 32, true
	case iana.EllipticCurveP_384:
		return codec.EC2CurveP384, 48, true
	case iana.EllipticCurveP_521:
		return codec.EC2CurveP521, 66, true
	default:
		return "", 0, false
	}
}

func okpCurve(curve int) (string, int, bool) {
	switch curve {
	case iana.EllipticCurveEd25519:
		return codec.OKPCurveEd25519, 32, true
	case iana.EllipticCurveEd448:
		return codec.OKPCurveEd448, 57, true
	default:
		return "", 0, false
	}
}

var (
	_ codec.AttestationObjectDecoder = (*Decoder)(nil)
	_ codec.COSEKeyDecoder           = (*Decoder)(nil)
	_ codec.ExtensionMapDecoder      = (*Decoder)(nil)
)
