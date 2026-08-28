package main

import (
	"context"
	"testing"

	"github.com/islishude/webauthn/attestation"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

func TestRestrictedEnrollmentPolicyRequiresTrustedRootAndGoodStatus(t *testing.T) {
	t.Parallel()

	var aaguid protocol.AAGUID
	aaguid[0] = 1
	request := attestation.TrustRequest{
		Format: "packed",
		AAGUID: aaguid,
		Result: attestation.VerificationResult{
			Type: attestation.TypeUncertain,
			TrustPath: attestation.TrustPath{
				Kind:         attestation.TrustPathX509,
				Certificates: webcrypto.CertificateChain{webcrypto.NewCertificate([]byte("leaf"))},
			},
			CryptographicallyValid: true,
		},
	}

	policy := restrictedEnrollmentPolicy(aaguid, certificateVerifier{trusted: false}, webcrypto.CertificateVerificationContext{}, certificateStatusProvider{status: attestation.CertificateStatusGood})
	result, err := policy.EvaluateAttestationTrust(context.Background(), request)
	if err != nil {
		t.Fatalf("EvaluateAttestationTrust() error = %v", err)
	}
	if result.Accepted {
		t.Fatal("untrusted self-signed path was accepted")
	}

	policy = restrictedEnrollmentPolicy(aaguid, certificateVerifier{trusted: true}, webcrypto.CertificateVerificationContext{}, certificateStatusProvider{status: attestation.CertificateStatusRevoked})
	result, err = policy.EvaluateAttestationTrust(context.Background(), request)
	if err != nil {
		t.Fatalf("EvaluateAttestationTrust() revoked error = %v", err)
	}
	if result.Accepted {
		t.Fatal("revoked path was accepted")
	}

	policy = restrictedEnrollmentPolicy(aaguid, certificateVerifier{trusted: true}, webcrypto.CertificateVerificationContext{}, certificateStatusProvider{status: attestation.CertificateStatusGood})
	result, err = policy.EvaluateAttestationTrust(context.Background(), request)
	if err != nil {
		t.Fatalf("EvaluateAttestationTrust() trusted error = %v", err)
	}
	if !result.Accepted {
		t.Fatalf("trusted path rejected: %+v", result)
	}
}

type certificateVerifier struct {
	trusted bool
}

func (v certificateVerifier) VerifyCertificateChain(context.Context, webcrypto.CertificateChain, webcrypto.CertificateVerificationContext) (webcrypto.CertificateVerification, error) {
	return webcrypto.CertificateVerification{Trusted: v.trusted}, nil
}

type certificateStatusProvider struct {
	status attestation.CertificateStatus
}

func (p certificateStatusProvider) CheckCertificateStatus(context.Context, attestation.CertificateStatusRequest) (attestation.CertificateStatusResult, error) {
	return attestation.CertificateStatusResult{Status: p.status}, nil
}
