package androidsafetynet

import (
	"fmt"

	"github.com/islishude/webauthn/attestation/internal/attstmt"
	"github.com/islishude/webauthn/codec"
)

type safetyNetStatement struct {
	version  string
	response []byte
}

func parseStatement(statement codec.AttestationStatement) (safetyNetStatement, error) {
	if len(statement) != 2 {
		return safetyNetStatement{}, ErrInvalidStatement
	}
	for key := range statement {
		switch key {
		case "ver", "response":
		default:
			return safetyNetStatement{}, fmt.Errorf("%w: unexpected field %q", ErrInvalidStatement, key)
		}
	}

	version, err := attstmt.String(statement["ver"], ErrInvalidStatement)
	if err != nil {
		return safetyNetStatement{}, err
	}
	response, err := attstmt.Bytes(statement["response"], ErrInvalidStatement)
	if err != nil {
		return safetyNetStatement{}, err
	}

	return safetyNetStatement{version: version, response: response}, nil
}
