package none_test

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	"github.com/islishude/webauthn/codec"
)

func TestVerifierAcceptsEmptyNoneStatement(t *testing.T) {
	t.Parallel()

	result, err := attnone.New().VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:    "none",
		Statement: attestationStatement(),
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if result.Type != attestation.TypeNone || !result.CryptographicallyValid {
		t.Fatalf("result = %+v, want valid none attestation", result)
	}
}

func TestVerifierRejectsNonEmptyNoneStatement(t *testing.T) {
	t.Parallel()

	_, err := attnone.New().VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:    "none",
		Statement: codec.AttestationStatement{"sig": []byte("unexpected")},
	})
	if !errors.Is(err, attnone.ErrInvalidStatement) {
		t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidStatement", err)
	}
}

func attestationStatement() codec.AttestationStatement {
	return codec.AttestationStatement{}
}
