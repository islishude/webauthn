// Package cbor provides concrete CBOR and COSE_Key decoders behind the codec
// contracts.
package cbor

import (
	"bytes"
	"errors"
	"fmt"

	fxcbor "github.com/fxamacker/cbor/v2"

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
		if !ok || len(fields) != 2 {
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

var (
	_ codec.AttestationObjectDecoder = (*Decoder)(nil)
	_ codec.COSEKeyDecoder           = (*Decoder)(nil)
	_ codec.ExtensionMapDecoder      = (*Decoder)(nil)
)
