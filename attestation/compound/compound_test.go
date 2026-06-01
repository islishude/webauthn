package compound_test

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/compound"
	"github.com/islishude/webauthn/codec"
)

func TestVerifierAcceptsCompoundSubStatements(t *testing.T) {
	t.Parallel()

	registry, err := attestation.NewRegistry(
		fakeVerifier{format: "one"},
		fakeVerifier{format: "two", attestationType: attestation.TypeSelf},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	result, err := compound.New(registry).VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:    compound.Format,
		Statement: compoundStatement("one", "two"),
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if !result.CryptographicallyValid || result.Type != attestation.TypeUncertain {
		t.Fatalf("result = %+v", result)
	}
	results, ok := result.TrustPath.Raw.([]attestation.VerificationResult)
	if !ok || len(results) != 2 {
		t.Fatalf("TrustPath.Raw = %#v, want two sub-results", result.TrustPath.Raw)
	}
}

func TestVerifierAppliesMinimumSuccessfulPolicy(t *testing.T) {
	t.Parallel()

	registry, err := attestation.NewRegistry(
		fakeVerifier{format: "one"},
		fakeVerifier{format: "two", err: errors.New("invalid signature")},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	_, err = compound.New(registry).VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:    compound.Format,
		Statement: compoundStatement("one", "two"),
	})
	if !errors.Is(err, compound.ErrInsufficientStatements) {
		t.Fatalf("VerifyAttestation() error = %v, want ErrInsufficientStatements", err)
	}

	result, err := compound.NewWithPolicy(registry, compound.Policy{MinimumSuccessful: 1}).VerifyAttestation(context.Background(), attestation.VerificationRequest{
		Format:    compound.Format,
		Statement: compoundStatement("one", "two"),
	})
	if err != nil {
		t.Fatalf("VerifyAttestation() with threshold error = %v", err)
	}
	if !result.CryptographicallyValid || len(result.Warnings) != 1 {
		t.Fatalf("result = %+v, want valid with one warning", result)
	}
}

func TestVerifierRejectsMalformedCompoundStatements(t *testing.T) {
	t.Parallel()

	registry, err := attestation.NewRegistry(fakeVerifier{format: "one"})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	tests := []struct {
		name      string
		registry  *attestation.Registry
		statement codec.AttestationStatement
	}{
		{
			name:      "missing registry",
			registry:  nil,
			statement: compoundStatement("one", "two"),
		},
		{
			name:     "too few sub-statements",
			registry: registry,
			statement: codec.AttestationStatement{codec.CompoundSubStatementsKey: []codec.CompoundSubStatement{{
				Format:    "one",
				Statement: codec.AttestationStatement{},
			}}},
		},
		{
			name:     "nested compound",
			registry: registry,
			statement: codec.AttestationStatement{codec.CompoundSubStatementsKey: []codec.CompoundSubStatement{
				{Format: "one", Statement: codec.AttestationStatement{}},
				{Format: compound.Format, Statement: codec.AttestationStatement{}},
			}},
		},
		{
			name:      "wrong key",
			registry:  registry,
			statement: codec.AttestationStatement{"other": []codec.CompoundSubStatement{}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := compound.New(test.registry).VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:    compound.Format,
				Statement: test.statement,
			})
			if err == nil {
				t.Fatal("VerifyAttestation() error = nil, want error")
			}
		})
	}
}

func compoundStatement(formats ...string) codec.AttestationStatement {
	statements := make([]codec.CompoundSubStatement, 0, len(formats))
	for _, format := range formats {
		statements = append(statements, codec.CompoundSubStatement{
			Format:    format,
			Statement: codec.AttestationStatement{},
		})
	}

	return codec.AttestationStatement{codec.CompoundSubStatementsKey: statements}
}

type fakeVerifier struct {
	format          string
	attestationType attestation.Type
	err             error
}

func (v fakeVerifier) Format() string {
	return v.format
}

func (v fakeVerifier) VerifyAttestation(_ context.Context, request attestation.VerificationRequest) (attestation.VerificationResult, error) {
	if v.err != nil {
		return attestation.VerificationResult{}, v.err
	}
	if request.Format != v.format {
		return attestation.VerificationResult{}, errors.New("wrong format")
	}
	attestationType := v.attestationType
	if attestationType == "" {
		attestationType = attestation.TypeBasic
	}

	return attestation.VerificationResult{
		Type:                   attestationType,
		CryptographicallyValid: true,
	}, nil
}

var _ attestation.Verifier = fakeVerifier{}
