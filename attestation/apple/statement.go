package apple

import (
	"fmt"

	"github.com/islishude/webauthn/attestation/internal/attstmt"
	"github.com/islishude/webauthn/codec"
)

type appleStatement struct {
	x5c [][]byte
}

func parseStatement(statement codec.AttestationStatement) (appleStatement, error) {
	if len(statement) != 1 {
		return appleStatement{}, ErrInvalidStatement
	}
	for key := range statement {
		if key != "x5c" {
			return appleStatement{}, fmt.Errorf("%w: unexpected field %q", ErrInvalidStatement, key)
		}
	}

	x5c, err := attstmt.X5C(statement["x5c"], ErrInvalidStatement)
	if err != nil {
		return appleStatement{}, err
	}

	return appleStatement{x5c: x5c}, nil
}
