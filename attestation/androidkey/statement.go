package androidkey

import (
	"fmt"

	"github.com/islishude/webauthn/attestation/internal/attstmt"
	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/protocol"
)

type androidKeyStatement struct {
	algorithm protocol.COSEAlgorithmIdentifier
	signature []byte
	x5c       [][]byte
}

func parseStatement(statement codec.AttestationStatement) (androidKeyStatement, error) {
	if len(statement) != 3 {
		return androidKeyStatement{}, ErrInvalidStatement
	}
	for key := range statement {
		switch key {
		case "alg", "sig", "x5c":
		default:
			return androidKeyStatement{}, fmt.Errorf("%w: unexpected field %q", ErrInvalidStatement, key)
		}
	}

	algorithm, err := attstmt.Algorithm(statement["alg"], ErrInvalidStatement)
	if err != nil {
		return androidKeyStatement{}, err
	}
	signature, err := attstmt.Bytes(statement["sig"], ErrInvalidStatement)
	if err != nil {
		return androidKeyStatement{}, err
	}
	x5c, err := attstmt.X5C(statement["x5c"], ErrInvalidStatement)
	if err != nil {
		return androidKeyStatement{}, err
	}

	return androidKeyStatement{algorithm: algorithm, signature: signature, x5c: x5c}, nil
}
