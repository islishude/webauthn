package attestation_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/islishude/webauthn/attestation"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

func TestBuiltInTypeAndFormatTrustPolicies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  attestation.TrustPolicy
		request attestation.TrustRequest
		want    bool
	}{
		{
			name:   "accept none accepts none",
			policy: attestation.AcceptNone(),
			request: attestation.TrustRequest{
				Result: attestation.VerificationResult{Type: attestation.TypeNone},
			},
			want: true,
		},
		{
			name:   "accept none rejects self",
			policy: attestation.AcceptNone(),
			request: attestation.TrustRequest{
				Result: attestation.VerificationResult{Type: attestation.TypeSelf},
			},
		},
		{
			name:   "reject none rejects none",
			policy: attestation.RejectNone(),
			request: attestation.TrustRequest{
				Result: attestation.VerificationResult{Type: attestation.TypeNone},
			},
		},
		{
			name:   "reject none accepts self",
			policy: attestation.RejectNone(),
			request: attestation.TrustRequest{
				Result: attestation.VerificationResult{Type: attestation.TypeSelf},
			},
			want: true,
		},
		{
			name:   "accept self accepts self",
			policy: attestation.AcceptSelf(),
			request: attestation.TrustRequest{
				Result: attestation.VerificationResult{Type: attestation.TypeSelf},
			},
			want: true,
		},
		{
			name:   "reject self rejects self",
			policy: attestation.RejectSelf(),
			request: attestation.TrustRequest{
				Result: attestation.VerificationResult{Type: attestation.TypeSelf},
			},
		},
		{
			name:   "allow type accepts listed type",
			policy: attestation.AllowTypes(attestation.TypeBasic),
			request: attestation.TrustRequest{
				Result: attestation.VerificationResult{Type: attestation.TypeBasic},
			},
			want: true,
		},
		{
			name:   "allow type rejects unlisted type",
			policy: attestation.AllowTypes(attestation.TypeBasic),
			request: attestation.TrustRequest{
				Result: attestation.VerificationResult{Type: attestation.TypeAttCA},
			},
		},
		{
			name:   "allow format accepts exact match",
			policy: attestation.AllowFormats("packed"),
			request: attestation.TrustRequest{
				Format: "packed",
				Result: attestation.VerificationResult{Type: attestation.TypeBasic},
			},
			want: true,
		},
		{
			name:   "allow format is case sensitive",
			policy: attestation.AllowFormats("packed"),
			request: attestation.TrustRequest{
				Format: "PACKED",
				Result: attestation.VerificationResult{Type: attestation.TypeBasic},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := tt.policy.EvaluateAttestationTrust(context.Background(), tt.request)
			if err != nil {
				t.Fatalf("EvaluateAttestationTrust() error = %v", err)
			}
			if result.Accepted != tt.want {
				t.Fatalf("Accepted = %t, want %t, result = %+v", result.Accepted, tt.want, result)
			}
		})
	}
}

func TestTrustRootPolicy(t *testing.T) {
	t.Parallel()

	t.Run("accepts trusted x5c path", func(t *testing.T) {
		t.Parallel()

		verifier := &certificateVerifier{result: webcrypto.CertificateVerification{
			Trusted:  true,
			Warnings: []string{"root warning"},
		}}
		policy := attestation.RequireTrustedRoots(verifier, webcrypto.CertificateVerificationContext{DNSName: "attestation.example"})

		result, err := policy.EvaluateAttestationTrust(context.Background(), trustPathRequest())
		if err != nil {
			t.Fatalf("EvaluateAttestationTrust() error = %v", err)
		}
		if !result.Accepted || result.Warnings[0] != "root warning" {
			t.Fatalf("result = %+v, want accepted with warning", result)
		}
		if verifier.context.DNSName != "attestation.example" {
			t.Fatalf("DNSName = %q, want attestation.example", verifier.context.DNSName)
		}
		if !bytes.Equal(verifier.chain[0].Raw(), []byte("leaf")) {
			t.Fatalf("chain[0] = %q, want leaf", verifier.chain[0].Raw())
		}
	})

	t.Run("rejects untrusted x5c path", func(t *testing.T) {
		t.Parallel()

		policy := attestation.RequireTrustedRoots(&certificateVerifier{}, webcrypto.CertificateVerificationContext{})

		result, err := policy.EvaluateAttestationTrust(context.Background(), trustPathRequest())
		if err != nil {
			t.Fatalf("EvaluateAttestationTrust() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("rejects missing x5c path", func(t *testing.T) {
		t.Parallel()

		policy := attestation.RequireTrustedRoots(&certificateVerifier{}, webcrypto.CertificateVerificationContext{})

		result, err := policy.EvaluateAttestationTrust(context.Background(), attestation.TrustRequest{
			Result: attestation.VerificationResult{Type: attestation.TypeSelf},
		})
		if err != nil {
			t.Fatalf("EvaluateAttestationTrust() error = %v", err)
		}
		if result.Accepted {
			t.Fatalf("Accepted = true, want false")
		}
	})

	t.Run("returns verifier errors", func(t *testing.T) {
		t.Parallel()

		errUnavailable := errors.New("roots unavailable")
		policy := attestation.RequireTrustedRoots(&certificateVerifier{err: errUnavailable}, webcrypto.CertificateVerificationContext{})

		_, err := policy.EvaluateAttestationTrust(context.Background(), trustPathRequest())
		if !errors.Is(err, errUnavailable) {
			t.Fatalf("EvaluateAttestationTrust() error = %v, want roots unavailable", err)
		}
	})
}

func TestAAGUIDPolicy(t *testing.T) {
	t.Parallel()

	allowed := testAAGUID(0x01)
	rejected := testAAGUID(0x02)
	policy := attestation.RequireAAGUID(allowed)

	result, err := policy.EvaluateAttestationTrust(context.Background(), attestation.TrustRequest{AAGUID: allowed})
	if err != nil {
		t.Fatalf("EvaluateAttestationTrust() error = %v", err)
	}
	if !result.Accepted {
		t.Fatalf("Accepted = false, want true")
	}

	result, err = policy.EvaluateAttestationTrust(context.Background(), attestation.TrustRequest{AAGUID: rejected})
	if err != nil {
		t.Fatalf("EvaluateAttestationTrust() error = %v", err)
	}
	if result.Accepted {
		t.Fatalf("Accepted = true, want false")
	}
}

func TestMetadataPolicy(t *testing.T) {
	t.Parallel()

	errUnavailable := errors.New("metadata unavailable")
	tests := []struct {
		name    string
		result  attestation.MetadataResult
		err     error
		want    bool
		wantErr error
	}{
		{
			name:   "trusted metadata",
			result: attestation.MetadataResult{Found: true, Trusted: true, Reason: "metadata trusted", Warnings: []string{"metadata warning"}},
			want:   true,
		},
		{
			name:   "metadata not found",
			result: attestation.MetadataResult{Found: false},
		},
		{
			name:   "metadata not trusted",
			result: attestation.MetadataResult{Found: true, Trusted: false},
		},
		{
			name:    "provider unavailable",
			err:     errUnavailable,
			wantErr: errUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			aaguid := testAAGUID(0x03)
			provider := &metadataProvider{result: tt.result, err: tt.err}
			policy := attestation.RequireTrustedMetadata(provider)
			request := trustPathRequest()
			request.AAGUID = aaguid

			result, err := policy.EvaluateAttestationTrust(context.Background(), request)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("EvaluateAttestationTrust() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("EvaluateAttestationTrust() error = %v", err)
			}
			if result.Accepted != tt.want {
				t.Fatalf("Accepted = %t, want %t, result = %+v", result.Accepted, tt.want, result)
			}
			if provider.request.AAGUID != aaguid || provider.request.Format != "packed" || provider.request.Type != attestation.TypeBasic {
				t.Fatalf("metadata request = %+v, want packed/basic/aaguid", provider.request)
			}
		})
	}
}

func TestCertificateStatusPolicy(t *testing.T) {
	t.Parallel()

	errUnavailable := errors.New("status unavailable")
	tests := []struct {
		name     string
		status   attestation.CertificateStatus
		allowed  []attestation.CertificateStatus
		err      error
		want     bool
		wantErr  error
		wantCall bool
	}{
		{name: "good accepted by default", status: attestation.CertificateStatusGood, want: true, wantCall: true},
		{name: "revoked rejected by default", status: attestation.CertificateStatusRevoked, wantCall: true},
		{name: "unknown accepted when configured", status: attestation.CertificateStatusUnknown, allowed: []attestation.CertificateStatus{attestation.CertificateStatusUnknown}, want: true, wantCall: true},
		{name: "unavailable status rejected", status: attestation.CertificateStatusUnavailable, wantCall: true},
		{name: "provider error returned", err: errUnavailable, wantErr: errUnavailable, wantCall: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &statusProvider{result: attestation.CertificateStatusResult{Status: tt.status}, err: tt.err}
			policy := attestation.RequireCertificateStatus(provider, tt.allowed...)

			result, err := policy.EvaluateAttestationTrust(context.Background(), trustPathRequest())
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("EvaluateAttestationTrust() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("EvaluateAttestationTrust() error = %v", err)
			}
			if result.Accepted != tt.want {
				t.Fatalf("Accepted = %t, want %t, result = %+v", result.Accepted, tt.want, result)
			}
			if provider.called != tt.wantCall {
				t.Fatalf("called = %t, want %t", provider.called, tt.wantCall)
			}
		})
	}
}

func TestCertificateStatusPolicyRejectsMissingX5C(t *testing.T) {
	t.Parallel()

	provider := &statusProvider{}
	policy := attestation.RequireCertificateStatus(provider)

	result, err := policy.EvaluateAttestationTrust(context.Background(), attestation.TrustRequest{
		Result: attestation.VerificationResult{Type: attestation.TypeSelf},
	})
	if err != nil {
		t.Fatalf("EvaluateAttestationTrust() error = %v", err)
	}
	if result.Accepted {
		t.Fatalf("Accepted = true, want false")
	}
	if provider.called {
		t.Fatalf("provider called for missing x5c path")
	}
}

func TestTrustPolicyCompositionShortCircuits(t *testing.T) {
	t.Parallel()

	t.Run("all of stops on rejection", func(t *testing.T) {
		t.Parallel()

		calls := 0
		policy := attestation.AllOf(
			attestation.TrustPolicyFunc(func(context.Context, attestation.TrustRequest) (attestation.TrustResult, error) {
				calls++
				return attestation.TrustResult{Accepted: false, Reason: "stop"}, nil
			}),
			attestation.TrustPolicyFunc(func(context.Context, attestation.TrustRequest) (attestation.TrustResult, error) {
				calls++
				return attestation.TrustResult{Accepted: true}, nil
			}),
		)

		result, err := policy.EvaluateAttestationTrust(context.Background(), attestation.TrustRequest{})
		if err != nil {
			t.Fatalf("EvaluateAttestationTrust() error = %v", err)
		}
		if result.Accepted || calls != 1 {
			t.Fatalf("result = %+v calls = %d, want rejected after one call", result, calls)
		}
	})

	t.Run("any of stops on acceptance", func(t *testing.T) {
		t.Parallel()

		calls := 0
		policy := attestation.AnyOf(
			attestation.TrustPolicyFunc(func(context.Context, attestation.TrustRequest) (attestation.TrustResult, error) {
				calls++
				return attestation.TrustResult{Accepted: true, Reason: "stop"}, nil
			}),
			attestation.TrustPolicyFunc(func(context.Context, attestation.TrustRequest) (attestation.TrustResult, error) {
				calls++
				return attestation.TrustResult{Accepted: false}, nil
			}),
		)

		result, err := policy.EvaluateAttestationTrust(context.Background(), attestation.TrustRequest{})
		if err != nil {
			t.Fatalf("EvaluateAttestationTrust() error = %v", err)
		}
		if !result.Accepted || calls != 1 {
			t.Fatalf("result = %+v calls = %d, want accepted after one call", result, calls)
		}
	})
}

func TestTrustPolicyCompositionRejectsNilPolicy(t *testing.T) {
	t.Parallel()

	policy := attestation.AllOf(attestation.AcceptNone(), nil)

	_, err := policy.EvaluateAttestationTrust(context.Background(), attestation.TrustRequest{
		Result: attestation.VerificationResult{Type: attestation.TypeNone},
	})
	if !errors.Is(err, attestation.ErrTrustPolicyConfiguration) {
		t.Fatalf("EvaluateAttestationTrust() error = %v, want ErrTrustPolicyConfiguration", err)
	}
}

func TestTrustPolicyCompositionRejectsEmptyAllOf(t *testing.T) {
	t.Parallel()

	policy := attestation.AllOf()

	_, err := policy.EvaluateAttestationTrust(context.Background(), attestation.TrustRequest{
		Result: attestation.VerificationResult{Type: attestation.TypeBasic},
	})
	if !errors.Is(err, attestation.ErrTrustPolicyConfiguration) {
		t.Fatalf("EvaluateAttestationTrust() error = %v, want ErrTrustPolicyConfiguration", err)
	}
}

func ExampleAllOf_restrictedEnrollment() {
	allowedAAGUID := protocol.AAGUID{0x42}
	policy := attestation.AllOf(
		attestation.AllowFormats("packed", "tpm"),
		attestation.AllowTypes(attestation.TypeBasic, attestation.TypeAttCA),
		attestation.RequireAAGUID(allowedAAGUID),
	)

	result, _ := policy.EvaluateAttestationTrust(context.Background(), attestation.TrustRequest{
		Format: "packed",
		AAGUID: allowedAAGUID,
		Result: attestation.VerificationResult{Type: attestation.TypeBasic},
	})

	fmt.Println(result.Accepted)
	// Output: true
}

func trustPathRequest() attestation.TrustRequest {
	return attestation.TrustRequest{
		Format: "packed",
		AAGUID: testAAGUID(0x01),
		Result: attestation.VerificationResult{
			Type: attestation.TypeBasic,
			TrustPath: attestation.TrustPath{
				Kind:         attestation.TrustPathX509,
				Certificates: webcrypto.CertificateChain{webcrypto.NewCertificate([]byte("leaf"))},
			},
			Evidence: map[string]any{"source": "test"},
		},
	}
}

func testAAGUID(first byte) protocol.AAGUID {
	var aaguid protocol.AAGUID
	aaguid[0] = first

	return aaguid
}

type certificateVerifier struct {
	result  webcrypto.CertificateVerification
	err     error
	chain   webcrypto.CertificateChain
	context webcrypto.CertificateVerificationContext
}

func (v *certificateVerifier) VerifyCertificateChain(_ context.Context, chain webcrypto.CertificateChain, verificationContext webcrypto.CertificateVerificationContext) (webcrypto.CertificateVerification, error) {
	v.chain = chain
	v.context = verificationContext
	if v.err != nil {
		return webcrypto.CertificateVerification{}, v.err
	}

	return v.result, nil
}

type metadataProvider struct {
	result  attestation.MetadataResult
	err     error
	request attestation.MetadataRequest
}

func (p *metadataProvider) LookupAttestationMetadata(_ context.Context, request attestation.MetadataRequest) (attestation.MetadataResult, error) {
	p.request = request
	if p.err != nil {
		return attestation.MetadataResult{}, p.err
	}

	return p.result, nil
}

type statusProvider struct {
	result attestation.CertificateStatusResult
	err    error
	called bool
}

func (p *statusProvider) CheckCertificateStatus(context.Context, attestation.CertificateStatusRequest) (attestation.CertificateStatusResult, error) {
	p.called = true
	if p.err != nil {
		return attestation.CertificateStatusResult{}, p.err
	}

	return p.result, nil
}
