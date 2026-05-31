package tpm

import (
	"fmt"

	"github.com/islishude/webauthn/attestation/internal/attstmt"
	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/protocol"
)

type tpmStatement struct {
	version    string
	algorithm  protocol.COSEAlgorithmIdentifier
	x5c        [][]byte
	signature  []byte
	certInfo   []byte
	publicArea []byte
}

func parseStatement(statement codec.AttestationStatement) (tpmStatement, error) {
	if len(statement) != 6 {
		return tpmStatement{}, ErrInvalidStatement
	}
	for key := range statement {
		switch key {
		case "ver", "alg", "x5c", "sig", "certInfo", "pubArea":
		default:
			return tpmStatement{}, fmt.Errorf("%w: unexpected field %q", ErrInvalidStatement, key)
		}
	}

	version, err := attstmt.String(statement["ver"], ErrInvalidStatement)
	if err != nil {
		return tpmStatement{}, err
	}
	algorithm, err := attstmt.Algorithm(statement["alg"], ErrInvalidStatement)
	if err != nil {
		return tpmStatement{}, err
	}
	x5c, err := attstmt.X5C(statement["x5c"], ErrInvalidStatement)
	if err != nil {
		return tpmStatement{}, err
	}
	signature, err := attstmt.Bytes(statement["sig"], ErrInvalidStatement)
	if err != nil {
		return tpmStatement{}, err
	}
	certInfo, err := attstmt.Bytes(statement["certInfo"], ErrInvalidStatement)
	if err != nil {
		return tpmStatement{}, err
	}
	publicArea, err := attstmt.Bytes(statement["pubArea"], ErrInvalidStatement)
	if err != nil {
		return tpmStatement{}, err
	}

	return tpmStatement{
		version:    version,
		algorithm:  algorithm,
		x5c:        x5c,
		signature:  signature,
		certInfo:   certInfo,
		publicArea: publicArea,
	}, nil
}
