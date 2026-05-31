package packed

import (
	"fmt"
	"math"

	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/protocol"
)

type packedStatement struct {
	algorithm protocol.COSEAlgorithmIdentifier
	signature []byte
	x5c       [][]byte
	hasX5C    bool
}

func parseStatement(statement codec.AttestationStatement) (packedStatement, error) {
	if len(statement) == 0 {
		return packedStatement{}, ErrInvalidStatement
	}
	for key := range statement {
		switch key {
		case "alg", "sig", "x5c":
		default:
			return packedStatement{}, fmt.Errorf("%w: unexpected field %q", ErrInvalidStatement, key)
		}
	}

	algorithm, err := statementAlgorithm(statement["alg"])
	if err != nil {
		return packedStatement{}, err
	}
	signature, err := statementBytes(statement["sig"])
	if err != nil {
		return packedStatement{}, err
	}

	parsed := packedStatement{algorithm: algorithm, signature: signature}
	if x5cValue, ok := statement["x5c"]; ok {
		x5c, err := statementX5C(x5cValue)
		if err != nil {
			return packedStatement{}, err
		}
		parsed.x5c = x5c
		parsed.hasX5C = true
	}

	return parsed, nil
}

func statementAlgorithm(value any) (protocol.COSEAlgorithmIdentifier, error) {
	switch typed := value.(type) {
	case protocol.COSEAlgorithmIdentifier:
		return typed, nil
	case int:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case int8:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case int16:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case int32:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case int64:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case uint:
		return uintAlgorithm(uint64(typed))
	case uint8:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case uint16:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case uint32:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case uint64:
		return uintAlgorithm(typed)
	default:
		return 0, fmt.Errorf("%w: alg field has type %T", ErrInvalidStatement, value)
	}
}

func uintAlgorithm(value uint64) (protocol.COSEAlgorithmIdentifier, error) {
	if value > math.MaxInt64 {
		return 0, ErrInvalidStatement
	}

	return protocol.COSEAlgorithmIdentifier(value), nil
}

func statementBytes(value any) ([]byte, error) {
	bytes, ok := value.([]byte)
	if !ok || len(bytes) == 0 {
		return nil, fmt.Errorf("%w: bytes field has type %T", ErrInvalidStatement, value)
	}

	return append([]byte{}, bytes...), nil
}

func statementX5C(value any) ([][]byte, error) {
	switch typed := value.(type) {
	case [][]byte:
		return cloneByteSlices(typed)
	case []any:
		out := make([][]byte, 0, len(typed))
		for _, item := range typed {
			bytes, ok := item.([]byte)
			if !ok || len(bytes) == 0 {
				return nil, fmt.Errorf("%w: x5c entry has type %T", ErrInvalidStatement, item)
			}
			out = append(out, append([]byte{}, bytes...))
		}
		if len(out) == 0 {
			return nil, ErrInvalidStatement
		}

		return out, nil
	default:
		return nil, fmt.Errorf("%w: x5c field has type %T", ErrInvalidStatement, value)
	}
}

func cloneByteSlices(values [][]byte) ([][]byte, error) {
	if len(values) == 0 {
		return nil, ErrInvalidStatement
	}

	out := make([][]byte, len(values))
	for i, value := range values {
		if len(value) == 0 {
			return nil, ErrInvalidStatement
		}
		out[i] = append([]byte{}, value...)
	}

	return out, nil
}
