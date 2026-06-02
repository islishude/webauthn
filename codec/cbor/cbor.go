// Package cbor provides concrete CBOR and COSE_Key decoders behind the codec
// contracts.
package cbor

import (
	"encoding/binary"
	"errors"
	"fmt"

	fxcbor "github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/iana"
	cosekey "github.com/ldclabs/cose/key"

	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/protocol"
)

var (
	// ErrMalformedCBOR reports a decoded shape that is not valid WebAuthn input.
	ErrMalformedCBOR = errors.New("malformed cbor")
)

// Decoder decodes WebAuthn CBOR structures using strict duplicate-key checks.
type Decoder struct {
	mode fxcbor.DecMode
}

// NewDecoder creates a decoder with duplicate map-key rejection.
func NewDecoder() (*Decoder, error) {
	mode, err := fxcbor.DecOptions{
		DupMapKey:   fxcbor.DupMapKeyEnforcedAPF,
		IndefLength: fxcbor.IndefLengthForbidden,
		UTF8:        fxcbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		return nil, err
	}

	return &Decoder{mode: mode}, nil
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
	var decoded struct {
		Format            string            `cbor:"fmt"`
		AuthenticatorData []byte            `cbor:"authData"`
		Statement         fxcbor.RawMessage `cbor:"attStmt"`
	}

	if err := d.decode(raw.Bytes(), &decoded); err != nil {
		return codec.DecodedAttestationObject{}, err
	}
	if decoded.Format == "" || len(decoded.AuthenticatorData) == 0 || decoded.Statement == nil {
		return codec.DecodedAttestationObject{}, ErrMalformedCBOR
	}
	statement, err := d.decodeAttestationStatement(decoded.Format, decoded.Statement)
	if err != nil {
		return codec.DecodedAttestationObject{}, err
	}

	authData, err := protocol.NewAuthenticatorData(decoded.AuthenticatorData)
	if err != nil {
		return codec.DecodedAttestationObject{}, err
	}

	return codec.DecodedAttestationObject{
		Format:            decoded.Format,
		AuthenticatorData: authData,
		Statement:         statement,
		Raw:               raw,
	}, nil
}

func (d *Decoder) decodeAttestationStatement(format string, raw fxcbor.RawMessage) (codec.AttestationStatement, error) {
	if format != "compound" {
		var statement codec.AttestationStatement
		if err := d.decode(raw, &statement); err != nil {
			return nil, err
		}
		if statement == nil {
			return nil, ErrMalformedCBOR
		}

		return statement, nil
	}

	var rawStatements []struct {
		Format    string                     `cbor:"fmt"`
		Statement codec.AttestationStatement `cbor:"attStmt"`
	}
	if err := d.decode(raw, &rawStatements); err != nil {
		return nil, err
	}
	if len(rawStatements) < 2 {
		return nil, ErrMalformedCBOR
	}

	statements := make([]codec.CompoundSubStatement, 0, len(rawStatements))
	for _, rawStatement := range rawStatements {
		if rawStatement.Format == "" || rawStatement.Format == "compound" || rawStatement.Statement == nil {
			return nil, ErrMalformedCBOR
		}
		statements = append(statements, codec.CompoundSubStatement{
			Format:    rawStatement.Format,
			Statement: rawStatement.Statement,
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

	var key cosekey.Key
	rest, err := d.mode.UnmarshalFirst(raw, &key)
	if err != nil {
		return codec.CredentialPublicKey{}, err
	}

	consumed := len(raw) - len(rest)
	if consumed <= 0 || key == nil {
		return codec.CredentialPublicKey{}, ErrMalformedCBOR
	}

	return codec.NewCredentialPublicKeyWithMaterial(
		protocol.COSEAlgorithmIdentifier(key.Alg()),
		key,
		raw[:consumed],
		u2fPublicKey(key),
		publicKeyMaterial(key),
	), nil
}

// DecodeExtensionMap decodes authenticator extension output CBOR.
func (d *Decoder) DecodeExtensionMap(raw []byte) (codec.ExtensionMap, error) {
	var extensions codec.ExtensionMap
	if err := d.decode(raw, &extensions); err != nil {
		return nil, err
	}
	if extensions == nil {
		return nil, ErrMalformedCBOR
	}

	return extensions, nil
}

func (d *Decoder) decode(data []byte, out any) error {
	if d == nil {
		return errors.New("nil cbor decoder")
	}
	if err := d.mode.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedCBOR, err)
	}

	return nil
}

func u2fPublicKey(key cosekey.Key) []byte {
	if key.Kty() != iana.KeyTypeEC2 || int(key.Alg()) != iana.AlgorithmES256 {
		return nil
	}

	curve, err := key.GetInt(iana.EC2KeyParameterCrv)
	if err != nil || curve != iana.EllipticCurveP_256 {
		return nil
	}
	x, err := key.GetBytes(iana.EC2KeyParameterX)
	if err != nil || len(x) != 32 {
		return nil
	}
	y, err := key.GetBytes(iana.EC2KeyParameterY)
	if err != nil || len(y) != 32 {
		return nil
	}

	out := make([]byte, 1, 65)
	out[0] = 0x04
	out = append(out, x...)
	out = append(out, y...)

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
	if protocol.COSEAlgorithmIdentifier(key.Alg()) == protocol.AlgorithmEdDSA && curve != iana.EllipticCurveEd25519 {
		return codec.CredentialPublicKeyMaterial{}
	}

	return codec.CredentialPublicKeyMaterial{OKP: &codec.OKPPublicKeyMaterial{
		Curve: curveName,
		X:     x,
	}}
}

func rsaPublicKeyMaterial(key cosekey.Key) codec.CredentialPublicKeyMaterial {
	modulus, err := key.GetBytes(iana.RSAKeyParameterN)
	if err != nil || len(modulus) == 0 {
		return codec.CredentialPublicKeyMaterial{}
	}
	exponentBytes, err := key.GetBytes(iana.RSAKeyParameterE)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
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
