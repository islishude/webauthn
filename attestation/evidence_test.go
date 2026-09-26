package attestation_test

import (
	"testing"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/androidsafetynet"
	"github.com/islishude/webauthn/attestation/compound"
)

func TestTypedEvidenceCopiesNestedMutableFields(t *testing.T) {
	original := attestation.VerificationResult{
		TrustPath: attestation.TrustPath{Kind: attestation.TrustPathCompound, Raw: []byte{1}, Statements: []attestation.VerificationResult{{Evidence: androidsafetynet.Evidence{APKCertificateSHA256: [][]byte{{2}}}}}},
		Evidence:  androidsafetynet.Evidence{APKCertificateSHA256: [][]byte{{3}}},
	}
	cloned := original.Clone()
	cloned.TrustPath.Raw[0] = 9
	child, ok := cloned.TrustPath.Statements[0].Evidence.(androidsafetynet.Evidence)
	if !ok {
		t.Fatal("missing typed child")
	}
	child.APKCertificateSHA256[0][0] = 9
	cloned.Evidence.(androidsafetynet.Evidence).APKCertificateSHA256[0][0] = 9
	if original.TrustPath.Raw[0] != 1 || original.TrustPath.Statements[0].Evidence.(androidsafetynet.Evidence).APKCertificateSHA256[0][0] != 2 || original.Evidence.(androidsafetynet.Evidence).APKCertificateSHA256[0][0] != 3 {
		t.Fatal("clone shares evidence")
	}
	evidence, ok := attestation.EvidenceAs[androidsafetynet.Evidence](original.Evidence)
	if !ok {
		t.Fatal("typed lookup failed")
	}
	evidence.APKCertificateSHA256[0][0] = 8
	if original.Evidence.(androidsafetynet.Evidence).APKCertificateSHA256[0][0] != 3 {
		t.Fatal("typed lookup aliases evidence")
	}
	if _, ok := attestation.EvidenceAs[compound.Evidence](original.Evidence); ok {
		t.Fatal("wrong format accepted")
	}
	var absent *androidsafetynet.Evidence
	if _, ok := attestation.EvidenceAs[*androidsafetynet.Evidence](absent); ok {
		t.Fatal("typed nil accepted")
	}
}
