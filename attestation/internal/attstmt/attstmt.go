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
		return uintAlgorithm(uint64(typed), invalid)
	case uint8:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case uint16:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case uint32:
		return protocol.COSEAlgorithmIdentifier(typed), nil
	case uint64:
		return uintAlgorithm(typed, invalid)
	default:
		return 0, fmt.Errorf("%w: alg field has type %T", invalid, value)
	}
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
