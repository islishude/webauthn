package packed

import (
	"fmt"

	"github.com/islishude/webauthn/attestation/internal/attstmt"
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

	algorithm, err := attstmt.Algorithm(statement["alg"], ErrInvalidStatement)
	if err != nil {
		return packedStatement{}, err
	}
	signature, err := attstmt.Bytes(statement["sig"], ErrInvalidStatement)
	if err != nil {
		return packedStatement{}, err
	}

	parsed := packedStatement{algorithm: algorithm, signature: signature}
	if x5cValue, ok := statement["x5c"]; ok {
		x5c, err := attstmt.X5C(x5cValue, ErrInvalidStatement)
		if err != nil {
			return packedStatement{}, err
		}
		parsed.x5c = x5c
		parsed.hasX5C = true
	}

	return parsed, nil
}
