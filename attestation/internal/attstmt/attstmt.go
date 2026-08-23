// Package attstmt provides small shared helpers for attestation statement
// fields used by optional format packages.
package attstmt

import (
	"fmt"
	"math"

	"github.com/islishude/webauthn/protocol"
)

// Algorithm parses a COSE algorithm identifier from a decoded attStmt value.
func Algorithm(value any, invalid error) (protocol.COSEAlgorithmIdentifier, error) {
	var algorithm protocol.COSEAlgorithmIdentifier
	switch typed := value.(type) {
	case protocol.COSEAlgorithmIdentifier:
		algorithm = typed
	case int:
		algorithm = protocol.COSEAlgorithmIdentifier(typed)
	case int8:
		algorithm = protocol.COSEAlgorithmIdentifier(typed)
	case int16:
		algorithm = protocol.COSEAlgorithmIdentifier(typed)
	case int32:
		algorithm = protocol.COSEAlgorithmIdentifier(typed)
	case int64:
		algorithm = protocol.COSEAlgorithmIdentifier(typed)
	case uint:
		parsed, err := uintAlgorithm(uint64(typed), invalid)
		if err != nil {
			return 0, err
		}
		algorithm = parsed
	case uint8:
		algorithm = protocol.COSEAlgorithmIdentifier(typed)
	case uint16:
		algorithm = protocol.COSEAlgorithmIdentifier(typed)
	case uint32:
		algorithm = protocol.COSEAlgorithmIdentifier(typed)
	case uint64:
		parsed, err := uintAlgorithm(typed, invalid)
		if err != nil {
			return 0, err
		}
		algorithm = parsed
	default:
		return 0, fmt.Errorf("%w: alg field has type %T", invalid, value)
	}
	if err := algorithm.Validate(); err != nil {
		return 0, fmt.Errorf("%w: %w", invalid, err)
	}
	return algorithm, nil
}

func uintAlgorithm(value uint64, invalid error) (protocol.COSEAlgorithmIdentifier, error) {
	if value > math.MaxInt64 {
		return 0, invalid
	}

	return protocol.COSEAlgorithmIdentifier(value), nil
}

// Bytes parses a non-empty byte string from a decoded attStmt value.
func Bytes(value any, invalid error) ([]byte, error) {
	bytes, ok := value.([]byte)
	if !ok || len(bytes) == 0 {
		return nil, fmt.Errorf("%w: bytes field has type %T", invalid, value)
	}

	return append([]byte{}, bytes...), nil
}

// String parses a non-empty string from a decoded attStmt value.
func String(value any, invalid error) (string, error) {
	out, ok := value.(string)
	if !ok || out == "" {
		return "", fmt.Errorf("%w: string field has type %T", invalid, value)
	}

	return out, nil
}

// X5C parses a non-empty leaf-first x5c certificate array.
func X5C(value any, invalid error) ([][]byte, error) {
	switch typed := value.(type) {
	case [][]byte:
		return cloneByteSlices(typed, invalid)
	case []any:
		out := make([][]byte, 0, len(typed))
		for _, item := range typed {
			bytes, ok := item.([]byte)
			if !ok || len(bytes) == 0 {
				return nil, fmt.Errorf("%w: x5c entry has type %T", invalid, item)
			}
			out = append(out, append([]byte{}, bytes...))
		}
		if len(out) == 0 {
			return nil, invalid
		}

		return out, nil
	default:
		return nil, fmt.Errorf("%w: x5c field has type %T", invalid, value)
	}
}

// SingleX5C parses x5c and requires exactly one certificate.
func SingleX5C(value any, invalid error) ([]byte, error) {
	x5c, err := X5C(value, invalid)
	if err != nil {
		return nil, err
	}
	if len(x5c) != 1 {
		return nil, invalid
	}

	return x5c[0], nil
}

func cloneByteSlices(values [][]byte, invalid error) ([][]byte, error) {
	if len(values) == 0 {
		return nil, invalid
	}

	out := make([][]byte, len(values))
	for i, value := range values {
		if len(value) == 0 {
			return nil, invalid
		}
		out[i] = append([]byte{}, value...)
	}

	return out, nil
}
