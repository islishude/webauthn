package fidou2f

import (
	"fmt"

	"github.com/islishude/webauthn/attestation/internal/attstmt"
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

	x5c, err := attstmt.SingleX5C(statement["x5c"], ErrInvalidStatement)
	if err != nil {
		return u2fStatement{}, err
	}
	signature, err := attstmt.Bytes(statement["sig"], ErrInvalidStatement)
	if err != nil {
		return u2fStatement{}, err
	}

	return u2fStatement{x5c: x5c, signature: signature}, nil
}
