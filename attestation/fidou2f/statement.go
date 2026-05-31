package fidou2f

import (
	"fmt"

	"github.com/islishude/webauthn/codec"
)

type u2fStatement struct {
	x5c       []byte
	signature []byte
}

func parseStatement(statement codec.AttestationStatement) (u2fStatement, error) {
	if len(statement) != 2 {
		return u2fStatement{}, ErrInvalidStatement
	}
	for key := range statement {
		switch key {
		case "x5c", "sig":
		default:
			return u2fStatement{}, fmt.Errorf("%w: unexpected field %q", ErrInvalidStatement, key)
		}
	}

	x5c, err := statementX5C(statement["x5c"])
	if err != nil {
		return u2fStatement{}, err
	}
	signature, err := statementBytes(statement["sig"])
	if err != nil {
		return u2fStatement{}, err
	}

	return u2fStatement{x5c: x5c, signature: signature}, nil
}

func statementX5C(value any) ([]byte, error) {
	switch typed := value.(type) {
	case [][]byte:
		if len(typed) != 1 || len(typed[0]) == 0 {
			return nil, ErrInvalidStatement
		}

		return append([]byte{}, typed[0]...), nil
	case []any:
		if len(typed) != 1 {
			return nil, ErrInvalidStatement
		}

		return statementBytes(typed[0])
	default:
		return nil, fmt.Errorf("%w: x5c field has type %T", ErrInvalidStatement, value)
	}
}

func statementBytes(value any) ([]byte, error) {
	bytes, ok := value.([]byte)
	if !ok || len(bytes) == 0 {
		return nil, fmt.Errorf("%w: bytes field has type %T", ErrInvalidStatement, value)
	}

	return append([]byte{}, bytes...), nil
}
