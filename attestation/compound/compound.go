// Package compound verifies WebAuthn "compound" attestation statements.
package compound

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/codec"
)

const (
	// Format is the WebAuthn attestation format identifier for compound
	// attestation.
	Format = "compound"
)

var (
	// ErrInvalidStatement reports a malformed compound attestation statement.
	ErrInvalidStatement = errors.New("invalid compound attestation statement")
	// ErrVerifier reports a missing or unusable sub-statement verifier.
	ErrVerifier = errors.New("compound attestation verifier invalid")
	// ErrInsufficientStatements reports that RP policy did not accept enough
	// sub-statements.
	ErrInsufficientStatements = errors.New("insufficient valid compound attestation statements")
)

// Policy controls how many sub-statements must verify successfully.
type Policy struct {
	// MinimumSuccessful is the number of sub-statements that must verify.
	// The zero value requires all sub-statements.
	MinimumSuccessful int
	// RequireAll forces all sub-statements to verify even when
	// MinimumSuccessful is set.
	RequireAll bool
}

// Verifier verifies the exact "compound" attestation format.
type Verifier struct {
	registry *attestation.Registry
	policy   Policy
}

// New returns a compound attestation verifier that requires every
// sub-statement to verify.
func New(registry *attestation.Registry) Verifier {
	return Verifier{registry: registry}
}

// NewWithPolicy returns a compound attestation verifier using policy.
func NewWithPolicy(registry *attestation.Registry, policy Policy) Verifier {
	return Verifier{registry: registry, policy: policy}
}

// Format returns the WebAuthn attestation format identifier.
func (Verifier) Format() string {
	return Format
}

// VerifyAttestation verifies the configured number of sub-statements.
func (v Verifier) VerifyAttestation(ctx context.Context, request attestation.VerificationRequest) (attestation.VerificationResult, error) {
	if request.Format != Format {
		return attestation.VerificationResult{}, ErrInvalidStatement
	}
	if v.registry == nil {
		return attestation.VerificationResult{}, ErrVerifier
	}

	statements, err := compoundSubStatements(request.Statement)
	if err != nil {
		return attestation.VerificationResult{}, err
	}
	required, err := v.requiredSuccesses(len(statements))
	if err != nil {
		return attestation.VerificationResult{}, err
	}

	results := make([]attestation.VerificationResult, 0, len(statements))
	warnings := make([]string, 0)
	successes := 0
	for _, statement := range statements {
		if statement.Format == Format {
			return attestation.VerificationResult{}, ErrInvalidStatement
		}
		verifier, ok := v.registry.Lookup(statement.Format)
		if !ok {
			warnings = append(warnings, "compound sub-statement verifier missing: "+statement.Format)
			continue
		}

		result, err := verifier.VerifyAttestation(ctx, attestation.VerificationRequest{
			Format:               statement.Format,
			AuthenticatorData:    request.AuthenticatorData,
			ClientDataHash:       slices.Clone(request.ClientDataHash),
			Statement:            statement.Statement,
			CredentialPublicKey:  request.CredentialPublicKey,
			RawAttestationObject: request.RawAttestationObject,
		})
		if err != nil {
			warnings = append(warnings, "compound sub-statement failed: "+statement.Format)
			continue
		}
		if !result.CryptographicallyValid {
			warnings = append(warnings, "compound sub-statement invalid: "+statement.Format)
			continue
		}
		successes++
		results = append(results, result)
	}

	if successes < required {
		return attestation.VerificationResult{}, fmt.Errorf("%w: got %d want %d", ErrInsufficientStatements, successes, required)
	}

	return attestation.VerificationResult{
		Type:                   attestation.TypeUncertain,
		TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathRaw, Raw: slices.Clone(results)},
		CryptographicallyValid: true,
		Warnings:               warnings,
		Evidence: map[string]any{
			"successfulStatements": successes,
			"requiredStatements":   required,
		},
	}, nil
}

func compoundSubStatements(statement codec.AttestationStatement) ([]codec.CompoundSubStatement, error) {
	if len(statement) != 1 {
		return nil, ErrInvalidStatement
	}

	raw, ok := statement[codec.CompoundSubStatementsKey]
	if !ok {
		return nil, ErrInvalidStatement
	}
	statements, ok := raw.([]codec.CompoundSubStatement)
	if !ok || len(statements) < 2 {
		return nil, ErrInvalidStatement
	}
	for _, statement := range statements {
		if statement.Format == "" || statement.Statement == nil {
			return nil, ErrInvalidStatement
		}
	}

	return slices.Clone(statements), nil
}

func (v Verifier) requiredSuccesses(total int) (int, error) {
	if total < 2 {
		return 0, ErrInvalidStatement
	}
	if v.policy.RequireAll || v.policy.MinimumSuccessful == 0 {
		return total, nil
	}
	if v.policy.MinimumSuccessful < 0 || v.policy.MinimumSuccessful > total {
		return 0, ErrInvalidStatement
	}

	return v.policy.MinimumSuccessful, nil
}

var _ attestation.Verifier = Verifier{}
