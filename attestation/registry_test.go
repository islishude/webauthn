package attestation_test

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/webauthn/attestation"
)

func TestRegistryLookupIsCaseSensitive(t *testing.T) {
	t.Parallel()

	registry, err := attestation.NewRegistry(fakeVerifier{format: "none"}, fakeVerifier{format: "None"})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	if _, ok := registry.Lookup("none"); !ok {
		t.Fatal("Lookup(none) = false, want true")
	}
	if _, ok := registry.Lookup("None"); !ok {
		t.Fatal("Lookup(None) = false, want true")
	}
	if _, ok := registry.Lookup("NONE"); ok {
		t.Fatal("Lookup(NONE) = true, want false")
	}
}

func TestRegistryRejectsDuplicateAndEmptyFormats(t *testing.T) {
	t.Parallel()

	_, err := attestation.NewRegistry(fakeVerifier{format: "none"}, fakeVerifier{format: "none"})
	if !errors.Is(err, attestation.ErrDuplicateFormat) {
		t.Fatalf("NewRegistry() error = %v, want ErrDuplicateFormat", err)
	}

	registry, err := attestation.NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	err = registry.Register(fakeVerifier{format: ""})
	if !errors.Is(err, attestation.ErrInvalidFormat) {
		t.Fatalf("Register() error = %v, want ErrInvalidFormat", err)
	}
}

type fakeVerifier struct {
	format string
}

func (v fakeVerifier) Format() string {
	return v.format
}

func (fakeVerifier) VerifyAttestation(context.Context, attestation.VerificationRequest) (attestation.VerificationResult, error) {
	return attestation.VerificationResult{
		Type:                   attestation.TypeNone,
		CryptographicallyValid: true,
	}, nil
}

var _ attestation.Verifier = fakeVerifier{}
